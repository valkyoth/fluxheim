use std::time::Instant;

use fluxheim_config::UpstreamProxyProtocol;
use fluxheim_protocol::{proxy_protocol_v1_header, proxy_protocol_v2_header};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::pool::{
    IdleNativeHttp1Connection, native_http1_retry_method_allowed, pooled_connection_error_can_retry,
};
use super::request::{write_upstream_request, write_websocket_upgrade_request};
use super::socket::connect_upstream;
use super::upgrade::{
    validate_websocket_upgrade_response, websocket_downstream_upgrade_response_head,
    websocket_upgrade_response_head_limits,
};
use super::{
    NativeHttp1Stream, NativeHttp1Upstream, NativeNegotiatedHttpProtocol,
    NativeUpstreamHttpProtocol, timeout_error,
};
use crate::native_http1_upstream_response::{
    parsed_upstream_response_head, read_upstream_response, read_upstream_response_for_pool,
    read_upstream_response_head,
};
use crate::{
    NativeHttp1ConnectionStream, NativeHttp1Error, NativeHttp1Request, NativeHttp1Response,
};

impl NativeHttp1Upstream {
    pub async fn send(
        &self,
        request: &mut NativeHttp1Request,
    ) -> Result<NativeHttp1Response, NativeHttp1Error> {
        match self.protocol {
            NativeUpstreamHttpProtocol::Http2 => return self.send_http2(request).await,
            NativeUpstreamHttpProtocol::Http1AndHttp2 => {
                return self.send_http1_and_http2(request).await;
            }
            NativeUpstreamHttpProtocol::Http1 => {}
        }
        if self.pool.max_idle == 0 || self.proxy_protocol != UpstreamProxyProtocol::Off {
            let stream = self.connect_stream(request).await?;
            return self.send_on_stream(stream, request).await;
        }

        let (mut stream, reused) = self.connection(request).await?;
        let result = self.send_on_pooled_stream(&mut stream, request).await;
        let (response, reusable) = match result {
            Ok(result) => result,
            Err(error)
                if reused
                    && pooled_connection_error_can_retry(&error)
                    && request.body.is_empty()
                    && native_http1_retry_method_allowed(&request.method) =>
            {
                let fresh = self.connect_stream(request).await?;
                return self.send_on_stream(fresh, request).await;
            }
            Err(error) => return Err(error),
        };
        if reusable {
            self.return_connection(stream).await;
        }
        Ok(response)
    }

    pub async fn send_on_stream<S>(
        &self,
        mut stream: S,
        request: &NativeHttp1Request,
    ) -> Result<NativeHttp1Response, NativeHttp1Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        timeout(
            self.write_timeout,
            write_upstream_request(&mut stream, &self.authority, request, false),
        )
        .await
        .map_err(|_| timeout_error("native HTTP/1 upstream write timeout"))??;
        read_upstream_response(
            &mut stream,
            self.read_timeout,
            self.max_head_bytes,
            self.max_body_bytes,
            &request.method,
        )
        .await
    }

    pub(crate) async fn websocket_tunnel(
        &self,
        request: &NativeHttp1Request,
        prebuffered: Vec<u8>,
        mut downstream: NativeHttp1ConnectionStream,
    ) -> Result<(), NativeHttp1Error> {
        let mut upstream = self.connect_stream(request).await?;
        timeout(
            self.write_timeout,
            write_websocket_upgrade_request(&mut upstream, &self.authority, request),
        )
        .await
        .map_err(|_| timeout_error("native WebSocket upstream write timeout"))??;
        let response_head = timeout(
            self.read_timeout,
            read_upstream_response_head(
                &mut upstream,
                websocket_upgrade_response_head_limits(self.max_head_bytes),
            ),
        )
        .await
        .map_err(|_| timeout_error("native WebSocket upstream upgrade response timeout"))??;
        validate_websocket_upgrade_response(
            &response_head,
            websocket_upgrade_response_head_limits(self.max_head_bytes),
        )?;
        let parsed = parsed_upstream_response_head(
            &response_head,
            websocket_upgrade_response_head_limits(self.max_head_bytes),
        )?;
        let head_len = parsed.head_len;
        let downstream_head = websocket_downstream_upgrade_response_head(&parsed)?;
        downstream.write_all(&downstream_head).await?;
        if response_head.len() > head_len {
            downstream.write_all(&response_head[head_len..]).await?;
        }
        downstream.flush().await?;
        if !prebuffered.is_empty() {
            upstream.write_all(&prebuffered).await?;
            upstream.flush().await?;
        }
        timeout(
            self.read_timeout,
            tokio::io::copy_bidirectional(&mut upstream, &mut downstream),
        )
        .await
        .map_err(|_| timeout_error("native WebSocket tunnel timeout"))??;
        Ok(())
    }

    async fn send_on_pooled_stream(
        &self,
        stream: &mut NativeHttp1Stream,
        request: &NativeHttp1Request,
    ) -> Result<(NativeHttp1Response, bool), NativeHttp1Error> {
        timeout(
            self.write_timeout,
            write_upstream_request(stream, &self.authority, request, true),
        )
        .await
        .map_err(|_| timeout_error("native HTTP/1 upstream write timeout"))??;
        read_upstream_response_for_pool(
            stream,
            self.read_timeout,
            self.max_head_bytes,
            self.max_body_bytes,
            &request.method,
        )
        .await
    }

    async fn connection(
        &self,
        request: &NativeHttp1Request,
    ) -> Result<(NativeHttp1Stream, bool), NativeHttp1Error> {
        let now = Instant::now();
        let mut idle = self.pool.idle.lock().await;
        while let Some(connection) = idle.pop() {
            if self.pool.idle_timeout.is_some_and(|timeout| {
                now.saturating_duration_since(connection.inserted_at) > timeout
            }) {
                continue;
            }
            return Ok((connection.stream, true));
        }
        drop(idle);
        let stream = self.connect_stream(request).await?;
        Ok((stream, false))
    }

    async fn return_connection(&self, stream: NativeHttp1Stream) {
        let mut idle = self.pool.idle.lock().await;
        if idle.len() < self.pool.max_idle {
            idle.push(IdleNativeHttp1Connection {
                stream,
                inserted_at: Instant::now(),
            });
        }
    }

    async fn connect_stream(
        &self,
        request: &NativeHttp1Request,
    ) -> Result<NativeHttp1Stream, NativeHttp1Error> {
        if let Some(timeout_duration) = self.total_connection_timeout {
            return timeout(timeout_duration, self.connect_stream_inner(request))
                .await
                .map_err(|_| timeout_error("native HTTP/1 upstream total connection timeout"))?;
        }
        self.connect_stream_inner(request).await
    }

    pub(super) async fn connect_negotiated_stream(
        &self,
        request: &NativeHttp1Request,
    ) -> Result<(NativeHttp1Stream, NativeNegotiatedHttpProtocol), NativeHttp1Error> {
        if let Some(timeout_duration) = self.total_connection_timeout {
            return timeout(
                timeout_duration,
                self.connect_negotiated_stream_inner(request),
            )
            .await
            .map_err(|_| timeout_error("native HTTP/1 upstream total connection timeout"))?;
        }
        self.connect_negotiated_stream_inner(request).await
    }

    async fn connect_negotiated_stream_inner(
        &self,
        request: &NativeHttp1Request,
    ) -> Result<(NativeHttp1Stream, NativeNegotiatedHttpProtocol), NativeHttp1Error> {
        let mut stream = timeout(
            self.connect_timeout,
            connect_upstream(
                &self.authority,
                self.recv_buffer_size,
                self.dscp,
                self.tcp_keepalive,
                self.tcp_user_timeout,
            ),
        )
        .await
        .map_err(|_| timeout_error("native HTTP/1 upstream connect timeout"))??;
        self.write_proxy_protocol_header(&mut stream, request)
            .await?;
        #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
        if let Some(tls) = &self.tls {
            return timeout(
                self.connect_timeout,
                tls.connect_with_negotiated_protocol(stream, &self.authority),
            )
            .await
            .map_err(|_| timeout_error("native HTTP/1 upstream TLS handshake timeout"))?;
        }
        Ok((
            Box::new(stream) as NativeHttp1Stream,
            NativeNegotiatedHttpProtocol::Http1,
        ))
    }

    async fn connect_stream_inner(
        &self,
        request: &NativeHttp1Request,
    ) -> Result<NativeHttp1Stream, NativeHttp1Error> {
        let mut stream = self.connect_tcp_stream().await?;
        self.write_proxy_protocol_header(&mut stream, request)
            .await?;
        self.finish_connect_stream(stream).await
    }

    pub(super) async fn connect_stream_inner_without_proxy_protocol(
        &self,
    ) -> Result<NativeHttp1Stream, NativeHttp1Error> {
        let stream = self.connect_tcp_stream().await?;
        self.finish_connect_stream(stream).await
    }

    async fn connect_tcp_stream(&self) -> Result<TcpStream, NativeHttp1Error> {
        timeout(
            self.connect_timeout,
            connect_upstream(
                &self.authority,
                self.recv_buffer_size,
                self.dscp,
                self.tcp_keepalive,
                self.tcp_user_timeout,
            ),
        )
        .await
        .map_err(|_| timeout_error("native HTTP/1 upstream connect timeout"))?
    }

    async fn finish_connect_stream(
        &self,
        stream: TcpStream,
    ) -> Result<NativeHttp1Stream, NativeHttp1Error> {
        #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
        if let Some(tls) = &self.tls {
            return timeout(self.connect_timeout, tls.connect(stream, &self.authority))
                .await
                .map_err(|_| timeout_error("native HTTP/1 upstream TLS handshake timeout"))?;
        }
        Ok(Box::new(stream) as NativeHttp1Stream)
    }

    async fn write_proxy_protocol_header(
        &self,
        stream: &mut TcpStream,
        request: &NativeHttp1Request,
    ) -> Result<(), NativeHttp1Error> {
        // If the effective client IP came from forwarded headers instead of
        // the direct peer socket, Fluxheim does not know the original client
        // port. PROXY protocol uses port 0 for that intentional unknown value.
        let header = match self.proxy_protocol {
            UpstreamProxyProtocol::Off => return Ok(()),
            UpstreamProxyProtocol::V1 => {
                proxy_protocol_v1_header(request.effective_client_addr, request.local_addr)
            }
            UpstreamProxyProtocol::V2 => {
                proxy_protocol_v2_header(request.effective_client_addr, request.local_addr)
            }
        };
        timeout(self.write_timeout, stream.write_all(&header))
            .await
            .map_err(|_| timeout_error("native upstream PROXY protocol write timeout"))?
            .map_err(|error| {
                NativeHttp1Error::Io(std::io::Error::new(
                    error.kind(),
                    format!("write native upstream PROXY protocol header: {error}"),
                ))
            })
    }

    pub(super) const fn cleartext_upstream(&self) -> bool {
        #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
        {
            self.tls.is_none()
        }
        #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
        {
            true
        }
    }
}
