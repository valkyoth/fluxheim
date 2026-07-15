use std::sync::Arc;

use bytes::Bytes;
use fluxheim_config::UpstreamProxyProtocol;
use h2::client::SendRequest;
use tokio::io::AsyncWriteExt;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::{Instant as TokioInstant, timeout, timeout_at};

use super::http2::{
    h2c_upgrade_error_can_fallback, h2c_upgrade_settings_header, native_http2_error,
    native_http2_error_is_connection_fatal, native_http2_error_retry_safe,
    native_http2_response_to_http1, native_http2_upstream_request, upstream_h2_scheme,
};
use super::pool::{NativeHttp2PooledConnection, native_http1_retry_method_allowed};
use super::upgrade::{h2c_upgrade_response_head_limits, validate_h2c_upgrade_response};
use super::{NativeHttp1Stream, NativeHttp1Upstream, NativeNegotiatedHttpProtocol, timeout_error};
use crate::native_http1_upstream_response::read_upstream_response_head;
use crate::native_http2_client::{
    native_http2_upstream_client_on_h2c_upgraded_io,
    native_http2_upstream_client_on_io_with_keepalive, send_native_http2_upstream_request,
};
use crate::{
    DownstreamHttp2Policy, NativeHttp1Error, NativeHttp1Request, NativeHttp1Response,
    NativeHttp2StackError,
};

impl NativeHttp1Upstream {
    pub(super) async fn send_http2(
        &self,
        request: &mut NativeHttp1Request,
    ) -> Result<NativeHttp1Response, NativeHttp1Error> {
        if self.proxy_protocol != UpstreamProxyProtocol::Off {
            return Err(NativeHttp1Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "native HTTP/2 upstream PROXY protocol is not supported",
            )));
        }
        let mut upstream_request = native_http2_upstream_request(
            request,
            &self.authority,
            upstream_h2_scheme({
                #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
                {
                    self.tls.is_some()
                }
                #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
                {
                    false
                }
            }),
        )?;
        let retry_allowed = request.body.is_empty()
            && native_http1_retry_method_allowed(upstream_request.method.as_str());
        let retry_request = retry_allowed
            .then(|| upstream_request.retry_snapshot())
            .flatten();
        let mut h2_stream_permit = Some(self.acquire_http2_stream_permit().await?);
        let (client, fresh_connection) = self.http2_client().await?;
        upstream_request = upstream_request.with_owned_body(request.take_body());
        let request_policy = self.http2_request_policy(fresh_connection);
        let response = if retry_allowed {
            let Some(retry_request) = retry_request else {
                return Err(NativeHttp1Error::Io(std::io::Error::other(
                    "body-bearing HTTP/2 request cannot be retained for retry",
                )));
            };
            match send_native_http2_upstream_request(client, request_policy, upstream_request).await
            {
                Ok(response) => response,
                Err(error) if native_http2_error_retry_safe(&error) => {
                    drop(h2_stream_permit.take());
                    self.invalidate_http2_connection().await;
                    log::debug!(
                        target: "fluxheim::native_http2",
                        "native HTTP/2 upstream request failed before safe retry: {error}"
                    );
                    let (client, fresh_connection) = self.http2_client().await?;
                    h2_stream_permit = Some(self.acquire_http2_stream_permit().await?);
                    let request_policy = self.http2_request_policy(fresh_connection);
                    send_native_http2_upstream_request(client, request_policy, retry_request)
                        .await
                        .map_err(native_http2_error)?
                }
                Err(error) => {
                    if native_http2_error_is_connection_fatal(&error) {
                        self.invalidate_http2_connection().await;
                    }
                    return Err(native_http2_error(error));
                }
            }
        } else {
            match send_native_http2_upstream_request(client, request_policy, upstream_request).await
            {
                Ok(response) => response,
                Err(error) => {
                    if native_http2_error_is_connection_fatal(&error) {
                        self.invalidate_http2_connection().await;
                    }
                    return Err(native_http2_error(error));
                }
            }
        };
        let response = native_http2_response_to_http1(response);
        drop(h2_stream_permit);
        response
    }

    async fn acquire_http2_stream_permit(&self) -> Result<OwnedSemaphorePermit, NativeHttp1Error> {
        timeout(
            self.read_timeout,
            self.http2_pool.stream_slots.clone().acquire_owned(),
        )
        .await
        .map_err(|_| {
            NativeHttp1Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "native HTTP/2 stream slot timeout: all upstream H2 capacity in use",
            ))
        })?
        .map_err(|_| std::io::Error::other("native HTTP/2 stream pool closed").into())
    }

    pub(super) async fn send_http1_and_http2(
        &self,
        request: &mut NativeHttp1Request,
    ) -> Result<NativeHttp1Response, NativeHttp1Error> {
        if self.h2c_upgrade && self.cleartext_upstream() {
            let body_was_empty = request.body.is_empty();
            match self.send_http2(request).await {
                Ok(response) => return Ok(response),
                Err(error)
                    if h2c_upgrade_error_can_fallback(&error)
                        && (body_was_empty || !request.body.is_empty()) =>
                {
                    self.invalidate_http2_connection().await;
                    log::debug!(
                        target: "fluxheim::native_http2",
                        "native h2c upgrade was not accepted by upstream {}, falling back to HTTP/1.1: {error}",
                        self.authority
                    );
                }
                Err(error) => return Err(error),
            }
        }
        let (stream, negotiated) = self.connect_negotiated_stream(request).await?;
        match negotiated {
            NativeNegotiatedHttpProtocol::Http2 => self.send_http2_on_stream(stream, request).await,
            NativeNegotiatedHttpProtocol::Http1 => self.send_on_stream(stream, request).await,
        }
    }

    async fn send_http2_on_stream(
        &self,
        stream: NativeHttp1Stream,
        request: &mut NativeHttp1Request,
    ) -> Result<NativeHttp1Response, NativeHttp1Error> {
        #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
        {
            drop(stream);
            let _ = request;
            Err(NativeHttp1Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "native HTTP/2 on negotiated upstream stream requires a TLS backend",
            )))
        }
        #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
        {
            let upstream_request =
                native_http2_upstream_request(request, &self.authority, "https")?;
            let (client, driver) = native_http2_upstream_client_on_io_with_keepalive(
                stream,
                self.http2_policy,
                self.http2_keepalive_interval,
            )
            .await
            .map_err(native_http2_error)?;
            let upstream_request = upstream_request.with_owned_body(request.take_body());
            let result =
                send_native_http2_upstream_request(client, self.http2_policy, upstream_request)
                    .await
                    .map(native_http2_response_to_http1)
                    .map_err(native_http2_error);
            driver.abort_and_join().await;
            result?
        }
    }

    fn http2_request_policy(&self, fresh_connection: bool) -> DownstreamHttp2Policy {
        if fresh_connection && let Some(timeout) = self.total_connection_timeout {
            return self
                .http2_policy
                .with_handler_timeout(self.http2_policy.handler_timeout().min(timeout));
        }
        self.http2_policy
    }

    async fn http2_client(&self) -> Result<(SendRequest<Bytes>, bool), NativeHttp1Error> {
        if let Some(pooled) = self.http2_pool.connection.lock().await.as_ref() {
            return Ok((pooled.client.clone(), false));
        }
        let setup = async {
            let _setup = self.http2_pool.setup.lock().await;
            if let Some(pooled) = self.http2_pool.connection.lock().await.as_ref() {
                return Ok((pooled.client.clone(), false));
            }
            let pooled = Arc::new(self.connect_http2_pooled_connection().await?);
            let client = pooled.client.clone();
            *self.http2_pool.connection.lock().await = Some(pooled);
            Ok((client, true))
        };
        if let Some(timeout_duration) = self.total_connection_timeout {
            timeout(timeout_duration, setup)
                .await
                .map_err(|_| timeout_error("native HTTP/2 upstream total connection timeout"))?
        } else {
            setup.await
        }
    }

    async fn connect_http2_pooled_connection(
        &self,
    ) -> Result<NativeHttp2PooledConnection, NativeHttp1Error> {
        if let Some(total_timeout) = self.total_connection_timeout {
            let deadline = TokioInstant::now() + total_timeout;
            let stream = timeout_at(deadline, self.connect_stream_inner_without_proxy_protocol())
                .await
                .map_err(|_| timeout_error("native HTTP/2 upstream total connection timeout"))??;
            let remaining = deadline
                .checked_duration_since(TokioInstant::now())
                .ok_or_else(|| timeout_error("native HTTP/2 upstream total connection timeout"))?;
            let stream = if self.h2c_upgrade && self.cleartext_upstream() {
                timeout_at(deadline, self.h2c_upgrade_stream(stream))
                    .await
                    .map_err(|_| timeout_error("native h2c upgrade timeout"))??
            } else {
                stream
            };
            let policy = self
                .http2_policy
                .with_handler_timeout(self.http2_policy.handler_timeout().min(remaining));
            let (client, driver) = if self.h2c_upgrade && self.cleartext_upstream() {
                timeout_at(
                    deadline,
                    native_http2_upstream_client_on_h2c_upgraded_io(
                        stream,
                        policy,
                        self.http2_keepalive_interval,
                    ),
                )
                .await
                .map_err(|_| timeout_error("native HTTP/2 upstream total connection timeout"))?
            } else {
                timeout_at(
                    deadline,
                    native_http2_upstream_client_on_io_with_keepalive(
                        stream,
                        policy,
                        self.http2_keepalive_interval,
                    ),
                )
                .await
                .map_err(|_| timeout_error("native HTTP/2 upstream total connection timeout"))?
            }
            .map_err(native_http2_error)?;
            let client = timeout_at(deadline, client.ready())
                .await
                .map_err(|_| timeout_error("native HTTP/2 upstream total connection timeout"))?
                .map_err(|error| native_http2_error(NativeHttp2StackError::RequestReady(error)))?;
            return Ok(NativeHttp2PooledConnection { client, driver });
        }
        let stream = self.connect_stream_inner_without_proxy_protocol().await?;
        let stream = if self.h2c_upgrade && self.cleartext_upstream() {
            self.h2c_upgrade_stream(stream).await?
        } else {
            stream
        };
        let (client, driver) = if self.h2c_upgrade && self.cleartext_upstream() {
            native_http2_upstream_client_on_h2c_upgraded_io(
                stream,
                self.http2_policy,
                self.http2_keepalive_interval,
            )
            .await
        } else {
            native_http2_upstream_client_on_io_with_keepalive(
                stream,
                self.http2_policy,
                self.http2_keepalive_interval,
            )
            .await
        }
        .map_err(native_http2_error)?;
        let client = timeout(self.http2_policy.handler_timeout(), client.ready())
            .await
            .map_err(|_| native_http2_error(NativeHttp2StackError::RequestReadyTimeout))?
            .map_err(|error| native_http2_error(NativeHttp2StackError::RequestReady(error)))?;
        Ok(NativeHttp2PooledConnection { client, driver })
    }

    async fn invalidate_http2_connection(&self) {
        self.http2_pool.connection.lock().await.take();
    }

    async fn h2c_upgrade_stream(
        &self,
        mut stream: NativeHttp1Stream,
    ) -> Result<NativeHttp1Stream, NativeHttp1Error> {
        let settings = h2c_upgrade_settings_header(self.http2_policy);
        let request = format!(
            "OPTIONS * HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: Upgrade, HTTP2-Settings\r\n\
             Upgrade: h2c\r\n\
             HTTP2-Settings: {settings}\r\n\
             Content-Length: 0\r\n\
             \r\n",
            self.authority
        );
        timeout(self.write_timeout, stream.write_all(request.as_bytes()))
            .await
            .map_err(|_| timeout_error("native h2c upgrade write timeout"))?
            .map_err(NativeHttp1Error::Io)?;
        let response_head = timeout(
            self.read_timeout,
            read_upstream_response_head(&mut stream, h2c_upgrade_response_head_limits()),
        )
        .await
        .map_err(|_| timeout_error("native h2c upgrade response timeout"))??;
        validate_h2c_upgrade_response(&response_head, h2c_upgrade_response_head_limits())?;
        Ok(stream)
    }
}
