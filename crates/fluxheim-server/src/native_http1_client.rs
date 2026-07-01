use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use fluxheim_config::UpstreamProxyProtocol;
use fluxheim_protocol::{
    Http1ParseError, http1_request_target, proxy_protocol_v1_header, proxy_protocol_v2_header,
};
use h2::client::SendRequest;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant as TokioInstant, timeout, timeout_at};

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
use crate::NativeHttp1UpstreamTls;
use crate::native_http1_forwarded::{
    valid_upstream_header_value, valid_upstream_request_header, write_owned_proxy_headers,
};
use crate::native_http1_upstream_response::{
    parsed_upstream_response_head, read_upstream_response, read_upstream_response_for_pool,
    read_upstream_response_head,
};
use crate::native_http2_client::{
    NativeHttp2ConnectionDriver, native_http2_upstream_client_on_h2c_upgraded_io,
    native_http2_upstream_client_on_io_with_keepalive, send_native_http2_upstream_request,
};
use crate::{
    DownstreamHttp1Policy, DownstreamHttp2Policy, NativeHttp1ConnectionStream, NativeHttp1Error,
    NativeHttp1Request, NativeHttp1Response, NativeHttp2StackError,
};

mod http2;
mod socket;
mod upgrade;

use http2::{
    h2c_upgrade_error_can_fallback, h2c_upgrade_settings_header, native_http2_error,
    native_http2_error_is_connection_fatal, native_http2_error_retry_safe,
    native_http2_response_to_http1, native_http2_upstream_request, upstream_h2_scheme,
};
use socket::connect_upstream;
#[cfg(test)]
use upgrade::validate_switching_protocols_response;
use upgrade::{
    h2c_upgrade_response_head_limits, validate_h2c_upgrade_response,
    validate_websocket_upgrade_response, websocket_downstream_upgrade_response_head,
    websocket_upgrade_response_head_limits,
};

pub(crate) trait NativeHttp1Io: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> NativeHttp1Io for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(crate) type NativeHttp1Stream = Box<dyn NativeHttp1Io>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")),
    allow(dead_code)
)]
pub(crate) enum NativeNegotiatedHttpProtocol {
    Http1,
    Http2,
}

#[derive(Clone)]
pub struct NativeHttp1Upstream {
    authority: String,
    protocol: NativeUpstreamHttpProtocol,
    h2c_upgrade: bool,
    http2_policy: DownstreamHttp2Policy,
    total_connection_timeout: Option<Duration>,
    connect_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
    recv_buffer_size: Option<u32>,
    dscp: Option<u8>,
    tcp_keepalive: Option<NativeTcpKeepalivePolicy>,
    tcp_user_timeout: Option<Duration>,
    http2_keepalive_interval: Option<Duration>,
    max_head_bytes: usize,
    max_body_bytes: usize,
    proxy_protocol: UpstreamProxyProtocol,
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
    tls: Option<NativeHttp1UpstreamTls>,
    pool: Arc<NativeHttp1Pool>,
    http2_pool: Arc<NativeHttp2Pool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeUpstreamHttpProtocol {
    Http1,
    Http2,
    Http1AndHttp2,
}

#[derive(Debug, Default)]
struct NativeHttp1Pool {
    max_idle: usize,
    idle_timeout: Option<Duration>,
    idle: Mutex<Vec<IdleNativeHttp1Connection>>,
}

#[derive(Debug)]
struct NativeHttp2Pool {
    stream_slots: Arc<Semaphore>,
    connection: Mutex<Option<Arc<NativeHttp2PooledConnection>>>,
    setup: Mutex<()>,
}

struct NativeHttp2PooledConnection {
    client: SendRequest<Bytes>,
    driver: NativeHttp2ConnectionDriver,
}

struct IdleNativeHttp1Connection {
    stream: NativeHttp1Stream,
    inserted_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeTcpKeepalivePolicy {
    idle: Duration,
    interval: Duration,
    count: u32,
}

impl NativeTcpKeepalivePolicy {
    pub const fn new(idle: Duration, interval: Duration, count: u32) -> Self {
        Self {
            idle,
            interval,
            count,
        }
    }

    pub const fn idle(&self) -> Duration {
        self.idle
    }

    pub const fn interval(&self) -> Duration {
        self.interval
    }

    pub const fn count(&self) -> u32 {
        self.count
    }
}

impl std::fmt::Debug for IdleNativeHttp1Connection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdleNativeHttp1Connection")
            .field("inserted_at", &self.inserted_at)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NativeHttp2PooledConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeHttp2PooledConnection")
            .finish_non_exhaustive()
    }
}

impl Drop for NativeHttp2PooledConnection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl NativeHttp2Pool {
    fn new(max_concurrent_streams: u32) -> Self {
        debug_assert!(
            (max_concurrent_streams as usize) <= Semaphore::MAX_PERMITS,
            "max_concurrent_streams exceeds Semaphore::MAX_PERMITS"
        );
        Self {
            stream_slots: Arc::new(Semaphore::new(max_concurrent_streams as usize)),
            connection: Mutex::new(None),
            setup: Mutex::new(()),
        }
    }
}

impl std::fmt::Debug for NativeHttp1Upstream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeHttp1Upstream")
            .field("authority", &self.authority)
            .field("protocol", &self.protocol)
            .field("h2c_upgrade", &self.h2c_upgrade)
            .field("http2_policy", &self.http2_policy)
            .field("total_connection_timeout", &self.total_connection_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("read_timeout", &self.read_timeout)
            .field("write_timeout", &self.write_timeout)
            .field("recv_buffer_size", &self.recv_buffer_size)
            .field("dscp", &self.dscp)
            .field("tcp_keepalive", &self.tcp_keepalive)
            .field("tcp_user_timeout", &self.tcp_user_timeout)
            .field("http2_keepalive_interval", &self.http2_keepalive_interval)
            .field("max_head_bytes", &self.max_head_bytes)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("proxy_protocol", &self.proxy_protocol)
            .field("tls", {
                #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
                {
                    &self.tls
                }
                #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
                {
                    &Option::<()>::None
                }
            })
            .field("pool_max_idle", &self.pool.max_idle)
            .field("pool_idle_timeout", &self.pool.idle_timeout)
            .field(
                "http2_max_concurrent_streams",
                &self.http2_policy.max_concurrent_streams(),
            )
            .finish_non_exhaustive()
    }
}

impl PartialEq for NativeHttp1Upstream {
    fn eq(&self, other: &Self) -> bool {
        self.authority == other.authority
            && self.protocol == other.protocol
            && self.h2c_upgrade == other.h2c_upgrade
            && self.http2_policy == other.http2_policy
            && self.total_connection_timeout == other.total_connection_timeout
            && self.connect_timeout == other.connect_timeout
            && self.read_timeout == other.read_timeout
            && self.write_timeout == other.write_timeout
            && self.recv_buffer_size == other.recv_buffer_size
            && self.dscp == other.dscp
            && self.tcp_keepalive == other.tcp_keepalive
            && self.tcp_user_timeout == other.tcp_user_timeout
            && self.http2_keepalive_interval == other.http2_keepalive_interval
            && self.max_head_bytes == other.max_head_bytes
            && self.max_body_bytes == other.max_body_bytes
            && self.proxy_protocol == other.proxy_protocol
            && {
                #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
                {
                    self.tls == other.tls
                }
                #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
                {
                    true
                }
            }
            && self.pool.max_idle == other.pool.max_idle
            && self.pool.idle_timeout == other.pool.idle_timeout
    }
}

impl Eq for NativeHttp1Upstream {}

impl NativeHttp1Upstream {
    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn with_authority(mut self, authority: impl Into<String>) -> Self {
        self.authority = authority.into();
        self.pool = Arc::new(NativeHttp1Pool {
            max_idle: self.pool.max_idle,
            idle_timeout: self.pool.idle_timeout,
            idle: Mutex::new(Vec::new()),
        });
        self.http2_pool = Arc::new(NativeHttp2Pool::new(
            self.http2_policy.max_concurrent_streams(),
        ));
        self
    }

    pub fn new(authority: impl Into<String>) -> Self {
        let policy = DownstreamHttp1Policy::default();
        Self {
            authority: authority.into(),
            protocol: NativeUpstreamHttpProtocol::Http1,
            h2c_upgrade: false,
            http2_policy: DownstreamHttp2Policy::default(),
            total_connection_timeout: None,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            recv_buffer_size: None,
            dscp: None,
            tcp_keepalive: None,
            tcp_user_timeout: None,
            http2_keepalive_interval: None,
            max_head_bytes: policy.max_head_bytes(),
            max_body_bytes: policy.max_body_bytes(),
            proxy_protocol: UpstreamProxyProtocol::Off,
            #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
            tls: None,
            pool: Arc::new(NativeHttp1Pool::default()),
            http2_pool: Arc::new(NativeHttp2Pool::new(
                DownstreamHttp2Policy::default().max_concurrent_streams(),
            )),
        }
    }

    pub fn from_policy(authority: impl Into<String>, policy: DownstreamHttp1Policy) -> Self {
        Self {
            authority: authority.into(),
            protocol: NativeUpstreamHttpProtocol::Http1,
            h2c_upgrade: false,
            http2_policy: DownstreamHttp2Policy::default(),
            total_connection_timeout: None,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            recv_buffer_size: None,
            dscp: None,
            tcp_keepalive: None,
            tcp_user_timeout: None,
            http2_keepalive_interval: None,
            max_head_bytes: policy.max_head_bytes(),
            max_body_bytes: policy.max_body_bytes(),
            proxy_protocol: UpstreamProxyProtocol::Off,
            #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
            tls: None,
            pool: Arc::new(NativeHttp1Pool::default()),
            http2_pool: Arc::new(NativeHttp2Pool::new(
                DownstreamHttp2Policy::default().max_concurrent_streams(),
            )),
        }
    }

    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub const fn with_total_connection_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.total_connection_timeout = timeout;
        self
    }

    pub const fn total_connection_timeout(&self) -> Option<Duration> {
        self.total_connection_timeout
    }

    pub fn with_http2_policy(mut self, policy: DownstreamHttp2Policy) -> Self {
        self.protocol = NativeUpstreamHttpProtocol::Http2;
        self.http2_policy = policy;
        self.http2_pool = Arc::new(NativeHttp2Pool::new(policy.max_concurrent_streams()));
        self
    }

    pub fn with_http1_and_http2_policy(mut self, policy: DownstreamHttp2Policy) -> Self {
        self.protocol = NativeUpstreamHttpProtocol::Http1AndHttp2;
        self.http2_policy = policy;
        self.http2_pool = Arc::new(NativeHttp2Pool::new(policy.max_concurrent_streams()));
        self
    }

    pub const fn with_h2c_upgrade(mut self, enabled: bool) -> Self {
        self.h2c_upgrade = enabled;
        self
    }

    pub const fn uses_http2(&self) -> bool {
        matches!(self.protocol, NativeUpstreamHttpProtocol::Http2)
    }

    #[cfg(test)]
    pub(crate) const fn http2_policy(&self) -> DownstreamHttp2Policy {
        self.http2_policy
    }

    pub const fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    pub const fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = timeout;
        self
    }

    pub const fn with_recv_buffer_size(mut self, size: Option<u32>) -> Self {
        self.recv_buffer_size = size;
        self
    }

    pub const fn recv_buffer_size(&self) -> Option<u32> {
        self.recv_buffer_size
    }

    pub const fn with_dscp(mut self, dscp: Option<u8>) -> Self {
        self.dscp = dscp;
        self
    }

    pub const fn dscp(&self) -> Option<u8> {
        self.dscp
    }

    pub const fn with_tcp_keepalive(mut self, keepalive: Option<NativeTcpKeepalivePolicy>) -> Self {
        self.tcp_keepalive = keepalive;
        self
    }

    pub const fn tcp_keepalive(&self) -> Option<NativeTcpKeepalivePolicy> {
        self.tcp_keepalive
    }

    pub const fn with_tcp_user_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.tcp_user_timeout = timeout;
        self
    }

    pub const fn tcp_user_timeout(&self) -> Option<Duration> {
        self.tcp_user_timeout
    }

    pub const fn with_http2_keepalive_interval(mut self, interval: Option<Duration>) -> Self {
        self.http2_keepalive_interval = interval;
        self
    }

    pub const fn http2_keepalive_interval(&self) -> Option<Duration> {
        self.http2_keepalive_interval
    }

    pub const fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    pub const fn with_proxy_protocol(mut self, proxy_protocol: UpstreamProxyProtocol) -> Self {
        self.proxy_protocol = proxy_protocol;
        self
    }

    #[cfg(test)]
    pub(crate) const fn proxy_protocol(&self) -> UpstreamProxyProtocol {
        self.proxy_protocol
    }

    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
    pub fn with_tls(mut self, tls: NativeHttp1UpstreamTls) -> Self {
        self.tls = Some(tls);
        self
    }

    pub fn with_pool_max_idle(mut self, max_idle: usize) -> Self {
        self.pool = Arc::new(NativeHttp1Pool {
            max_idle,
            idle_timeout: self.pool.idle_timeout,
            idle: Mutex::new(Vec::new()),
        });
        self
    }

    pub fn with_pool_idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.pool = Arc::new(NativeHttp1Pool {
            max_idle: self.pool.max_idle,
            idle_timeout: timeout,
            idle: Mutex::new(Vec::new()),
        });
        self
    }

    pub fn pool_max_idle(&self) -> usize {
        self.pool.max_idle
    }

    pub async fn idle_connection_count(&self) -> usize {
        self.pool.idle.lock().await.len()
    }

    pub async fn send(
        &self,
        request: &NativeHttp1Request,
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

    async fn send_http2(
        &self,
        request: &NativeHttp1Request,
    ) -> Result<NativeHttp1Response, NativeHttp1Error> {
        if self.proxy_protocol != UpstreamProxyProtocol::Off {
            return Err(NativeHttp1Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "native HTTP/2 upstream PROXY protocol is not supported",
            )));
        }
        let request = native_http2_upstream_request(
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
        let mut h2_stream_permit = Some(self.acquire_http2_stream_permit().await?);
        let (client, fresh_connection) = self.http2_client().await?;
        let retry_allowed = native_http1_retry_method_allowed(request.method.as_str());
        let request_policy = self.http2_request_policy(fresh_connection);
        let response = if retry_allowed {
            let retry_request = request.clone();
            match send_native_http2_upstream_request(client, request_policy, request).await {
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
            match send_native_http2_upstream_request(client, request_policy, request).await {
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

    async fn send_http1_and_http2(
        &self,
        request: &NativeHttp1Request,
    ) -> Result<NativeHttp1Response, NativeHttp1Error> {
        if self.h2c_upgrade && self.cleartext_upstream() {
            match self.send_http2(request).await {
                Ok(response) => return Ok(response),
                Err(error) if h2c_upgrade_error_can_fallback(&error) => {
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
        request: &NativeHttp1Request,
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
            let request = native_http2_upstream_request(request, &self.authority, "https")?;
            let (client, driver) = native_http2_upstream_client_on_io_with_keepalive(
                stream,
                self.http2_policy,
                self.http2_keepalive_interval,
            )
            .await
            .map_err(native_http2_error)?;
            let result = send_native_http2_upstream_request(client, self.http2_policy, request)
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

    async fn connect_negotiated_stream(
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

    async fn connect_stream_inner_without_proxy_protocol(
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

    const fn cleartext_upstream(&self) -> bool {
        #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
        {
            self.tls.is_none()
        }
        #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
        {
            true
        }
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

fn pooled_connection_error_can_retry(error: &NativeHttp1Error) -> bool {
    matches!(
        error,
        NativeHttp1Error::Io(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::UnexpectedEof
            )
    )
}

fn native_http1_retry_method_allowed(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE")
}

async fn write_upstream_request<S>(
    stream: &mut S,
    authority: &str,
    request: &NativeHttp1Request,
    keep_alive: bool,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    let target = upstream_origin_target(request)?;
    stream
        .write_all(format!("{} {target} HTTP/1.1\r\n", request.method).as_bytes())
        .await?;
    stream
        .write_all(format!("host: {}\r\n", valid_request_host(request, authority)?).as_bytes())
        .await?;
    if keep_alive {
        stream.write_all(b"connection: keep-alive\r\n").await?;
    } else {
        stream.write_all(b"connection: close\r\n").await?;
    }
    if !request.body.is_empty() {
        stream
            .write_all(format!("content-length: {}\r\n", request.body.len()).as_bytes())
            .await?;
    }
    let connection_tokens = connection_tokens(request);
    for (name, value) in &request.headers {
        if upstream_hop_by_hop_header(name, &connection_tokens)
            || upstream_owned_header_for_request(name, request)
        {
            continue;
        }
        if !valid_upstream_request_header(name, value) {
            return Err(Http1ParseError::InvalidHeaderValue.into());
        }
        stream
            .write_all(format!("{name}: {value}\r\n").as_bytes())
            .await?;
    }
    write_owned_proxy_headers(stream, request).await?;
    stream.write_all(b"\r\n").await?;
    stream.write_all(&request.body).await?;
    stream.flush().await?;
    Ok(())
}

async fn write_websocket_upgrade_request<S>(
    stream: &mut S,
    authority: &str,
    request: &NativeHttp1Request,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    if !request.body.is_empty() {
        return Err(NativeHttp1Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native WebSocket upgrade request body is not supported",
        )));
    }
    let target = upstream_origin_target(request)?;
    stream
        .write_all(format!("{} {target} HTTP/1.1\r\n", request.method).as_bytes())
        .await?;
    stream
        .write_all(format!("host: {}\r\n", valid_request_host(request, authority)?).as_bytes())
        .await?;
    stream.write_all(b"connection: Upgrade\r\n").await?;
    stream.write_all(b"upgrade: websocket\r\n").await?;
    let connection_tokens = connection_tokens(request);
    for (name, value) in &request.headers {
        if upstream_hop_by_hop_header(name, &connection_tokens)
            || upstream_websocket_owned_header_for_request(name, request)
        {
            continue;
        }
        if !valid_upstream_request_header(name, value) {
            return Err(Http1ParseError::InvalidHeaderValue.into());
        }
        stream
            .write_all(format!("{name}: {value}\r\n").as_bytes())
            .await?;
    }
    write_owned_proxy_headers(stream, request).await?;
    stream.write_all(b"\r\n").await?;
    stream.flush().await?;
    Ok(())
}

fn upstream_origin_target(request: &NativeHttp1Request) -> Result<String, NativeHttp1Error> {
    match http1_request_target(&request.method, &request.target)? {
        fluxheim_protocol::Http1RequestTarget::Origin { .. } => Ok(request.target.clone()),
        fluxheim_protocol::Http1RequestTarget::AbsoluteUri { path, query, .. } => {
            let Some(path) = path else {
                return Ok("/".to_owned());
            };
            Ok(query
                .map(|query| format!("{path}?{query}"))
                .unwrap_or_else(|| path.to_owned()))
        }
        fluxheim_protocol::Http1RequestTarget::Authority { .. }
        | fluxheim_protocol::Http1RequestTarget::Asterisk => {
            Err(Http1ParseError::InvalidRequestTarget.into())
        }
    }
}

fn upstream_owned_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("via")
}

fn upstream_owned_header_for_request(name: &str, request: &NativeHttp1Request) -> bool {
    upstream_owned_header(name)
        || (!native_client_request_is_peer_fill(request) && native_peer_fill_internal_header(name))
}

fn upstream_websocket_owned_header(name: &str) -> bool {
    upstream_owned_header(name)
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("proxy-connection")
}

fn upstream_websocket_owned_header_for_request(name: &str, request: &NativeHttp1Request) -> bool {
    upstream_websocket_owned_header(name)
        || (!native_client_request_is_peer_fill(request) && native_peer_fill_internal_header(name))
}

fn native_peer_fill_internal_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("x-fluxheim-peer-fill")
        || name.eq_ignore_ascii_case("x-fluxheim-peer-fill-nonce")
        || name.eq_ignore_ascii_case("x-fluxheim-peer-fill-request-signature")
        || name.eq_ignore_ascii_case("x-fluxheim-peer-fill-response-signature")
}

fn native_client_request_is_peer_fill(request: &NativeHttp1Request) -> bool {
    request.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("x-fluxheim-peer-fill") && value.trim() == "1"
    })
}

fn request_host(request: &NativeHttp1Request) -> Option<&str> {
    request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.as_str())
}

fn valid_request_host<'a>(
    request: &'a NativeHttp1Request,
    authority: &'a str,
) -> Result<&'a str, NativeHttp1Error> {
    let host = request_host(request).unwrap_or(authority);
    if valid_upstream_header_value(host) {
        Ok(host)
    } else {
        Err(Http1ParseError::InvalidHeaderValue.into())
    }
}

fn connection_tokens(request: &NativeHttp1Request) -> Vec<String> {
    request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn upstream_hop_by_hop_header(name: &str, connection_tokens: &[String]) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) || connection_tokens
        .iter()
        .any(|token| token.eq_ignore_ascii_case(name))
}

fn timeout_error(message: &'static str) -> NativeHttp1Error {
    NativeHttp1Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, message))
}

#[cfg(test)]
mod tests {
    use super::{
        h2c_upgrade_error_can_fallback, h2c_upgrade_settings_header, native_http2_error,
        native_http2_response_to_http1, native_http2_upstream_request,
        upstream_owned_header_for_request, validate_switching_protocols_response,
        websocket_downstream_upgrade_response_head, write_websocket_upgrade_request,
    };
    use crate::native_http1_upstream_response::parsed_upstream_response_head;
    use crate::{
        DownstreamHttp2Policy, NativeHttp1Error, NativeHttp1Request, NativeHttp2StackError,
        NativeHttp2UpstreamResponse,
    };

    #[test]
    fn h2c_settings_header_uses_url_safe_unpadded_base64() {
        let settings = h2c_upgrade_settings_header(DownstreamHttp2Policy::default());

        assert!(!settings.is_empty());
        assert!(!settings.contains('='));
        assert!(
            settings
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
    }

    #[test]
    fn upstream_request_filter_strips_peer_fill_internal_headers_only_for_normal_requests() {
        let normal = NativeHttp1Request {
            method: "GET".to_owned(),
            peer_addr: None,
            local_addr: None,
            effective_client_addr: None,
            downstream_tls: false,
            tls_identity: None,
            geo_context: None,
            target: "/".to_owned(),
            version: fluxheim_protocol::Http1Version::Http11,
            headers: Vec::new(),
            body: zeroize::Zeroizing::new(Vec::new()),
            trailers: Vec::new(),
        };
        let peer_fill = NativeHttp1Request {
            headers: vec![("x-fluxheim-peer-fill".to_owned(), "1".to_owned())],
            ..normal.clone()
        };

        for name in [
            "x-fluxheim-peer-fill",
            "x-fluxheim-peer-fill-nonce",
            "x-fluxheim-peer-fill-request-signature",
            "x-fluxheim-peer-fill-response-signature",
        ] {
            assert!(upstream_owned_header_for_request(name, &normal));
            assert!(!upstream_owned_header_for_request(name, &peer_fill));
        }
    }

    #[test]
    fn response_capacity_closed_does_not_trigger_h2c_fallback() {
        let error = native_http2_error(NativeHttp2StackError::ResponseCapacityClosed);

        assert!(!h2c_upgrade_error_can_fallback(&error));
        match error {
            NativeHttp1Error::Io(error) => assert_eq!(error.kind(), std::io::ErrorKind::Other),
            other => panic!("expected native HTTP/2 error to map to IO error, got {other:?}"),
        }
    }

    #[test]
    fn switching_protocols_validator_accepts_expected_upgrade_token() {
        validate_switching_protocols_response(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: h2c, websocket\r\n\r\n",
            fluxheim_protocol::Http1HeadLimits::default(),
            "websocket",
            "upgrade rejected",
            "missing upgrade",
        )
        .unwrap();
    }

    #[test]
    fn switching_protocols_validator_rejects_missing_upgrade_token() {
        let error = validate_switching_protocols_response(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: h2c\r\n\r\n",
            fluxheim_protocol::Http1HeadLimits::default(),
            "websocket",
            "upgrade rejected",
            "missing upgrade",
        )
        .unwrap_err();

        assert!(error.to_string().contains("missing upgrade"));
    }

    #[test]
    fn switching_protocols_validator_rejects_non_101_status() {
        let error = validate_switching_protocols_response(
            b"HTTP/1.1 200 OK\r\nUpgrade: websocket\r\n\r\n",
            fluxheim_protocol::Http1HeadLimits::default(),
            "websocket",
            "upgrade rejected",
            "missing upgrade",
        )
        .unwrap_err();

        assert!(error.to_string().contains("upgrade rejected"));
    }

    #[tokio::test]
    async fn websocket_upgrade_request_strips_hop_by_hop_headers() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let mut request = NativeHttp1Request {
            method: "GET".to_owned(),
            peer_addr: None,
            local_addr: None,
            effective_client_addr: None,
            downstream_tls: false,
            tls_identity: None,
            geo_context: None,
            target: "/socket".to_owned(),
            version: fluxheim_protocol::Http1Version::Http11,
            headers: vec![
                ("host".to_owned(), "client.test".to_owned()),
                ("connection".to_owned(), "Upgrade, x-secret-hop".to_owned()),
                ("upgrade".to_owned(), "websocket".to_owned()),
                ("proxy-authorization".to_owned(), "Basic secret".to_owned()),
                ("keep-alive".to_owned(), "timeout=5".to_owned()),
                ("x-secret-hop".to_owned(), "remove-me".to_owned()),
                ("sec-websocket-key".to_owned(), "abc".to_owned()),
            ],
            body: zeroize::Zeroizing::new(Vec::new()),
            trailers: Vec::new(),
        };
        request
            .headers
            .push(("x-keep".to_owned(), "yes".to_owned()));

        let writer = tokio::spawn(async move {
            write_websocket_upgrade_request(&mut client, "origin.test", &request)
                .await
                .unwrap();
        });
        let mut bytes = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut server, &mut bytes)
            .await
            .unwrap();
        writer.await.unwrap();
        let request = String::from_utf8(bytes).unwrap();

        assert!(request.contains("host: client.test\r\n"));
        assert!(!request.contains("host: origin.test\r\n"));
        assert!(request.contains("connection: Upgrade\r\n"));
        assert!(request.contains("upgrade: websocket\r\n"));
        assert!(request.contains("sec-websocket-key: abc\r\n"));
        assert!(request.contains("x-keep: yes\r\n"));
        assert!(!request.contains("proxy-authorization:"));
        assert!(!request.contains("keep-alive:"));
        assert!(!request.contains("x-secret-hop:"));
    }

    #[test]
    fn websocket_downstream_upgrade_response_strips_untrusted_headers() {
        let head = parsed_upstream_response_head(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Connection: upgrade\r\n\
              Upgrade: websocket\r\n\
              Sec-WebSocket-Accept: abc\r\n\
              Sec-WebSocket-Protocol: chat\r\n\
              Set-Cookie: sid=leak\r\n\
              Server: origin\r\n\
              X-Internal: secret\r\n\r\n",
            fluxheim_protocol::Http1HeadLimits::default(),
        )
        .unwrap();

        let response = websocket_downstream_upgrade_response_head(&head).unwrap();
        let response = String::from_utf8(response).unwrap();

        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(response.contains("connection: Upgrade\r\n"));
        assert!(response.contains("upgrade: websocket\r\n"));
        assert!(response.contains("sec-websocket-accept: abc\r\n"));
        assert!(response.contains("sec-websocket-protocol: chat\r\n"));
        assert!(!response.contains("Set-Cookie"));
        assert!(!response.contains("Server:"));
        assert!(!response.contains("X-Internal"));
    }

    #[test]
    fn h2_response_conversion_strips_hop_by_hop_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, "2".parse().unwrap());
        headers.insert(http::header::CONNECTION, "close".parse().unwrap());
        headers.insert(
            http::header::DATE,
            "Tue, 23 Jun 2026 00:00:00 GMT".parse().unwrap(),
        );
        headers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert("proxy-connection", "keep-alive".parse().unwrap());
        headers.insert("te", "trailers".parse().unwrap());
        headers.insert("trailer", "x-later".parse().unwrap());
        headers.insert("x-origin", "h2".parse().unwrap());

        let response = NativeHttp2UpstreamResponse::for_test(http::StatusCode::OK, headers, "ok");
        let response = native_http2_response_to_http1(response).unwrap();
        let header_names: Vec<_> = response
            .headers()
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();

        assert_eq!(response.body(), b"ok");
        assert!(header_names.contains(&"x-origin"));
        assert!(!header_names.contains(&"content-length"));
        assert!(!header_names.contains(&"connection"));
        assert!(!header_names.contains(&"date"));
        assert!(!header_names.contains(&"transfer-encoding"));
        assert!(!header_names.contains(&"upgrade"));
        assert!(!header_names.contains(&"keep-alive"));
        assert!(!header_names.contains(&"proxy-connection"));
        assert!(!header_names.contains(&"te"));
        assert!(!header_names.contains(&"trailer"));
    }

    #[test]
    fn h2_upstream_request_preserves_client_host_as_authority() {
        let request = NativeHttp1Request {
            method: "GET".to_owned(),
            peer_addr: None,
            local_addr: None,
            effective_client_addr: None,
            downstream_tls: true,
            tls_identity: None,
            geo_context: None,
            target: "/resource?x=1".to_owned(),
            version: fluxheim_protocol::Http1Version::Http11,
            headers: vec![("host".to_owned(), "client.example".to_owned())],
            body: zeroize::Zeroizing::new(Vec::new()),
            trailers: Vec::new(),
        };

        let request =
            native_http2_upstream_request(&request, "origin.internal:8443", "https").unwrap();

        assert_eq!(
            request.uri.authority().map(|authority| authority.as_str()),
            Some("client.example")
        );
        assert_eq!(
            request.uri.path_and_query().map(|target| target.as_str()),
            Some("/resource?x=1")
        );
    }

    #[test]
    fn h2_upstream_request_preserves_native_request_trailers() {
        let request = NativeHttp1Request {
            method: "POST".to_owned(),
            peer_addr: None,
            local_addr: None,
            effective_client_addr: None,
            downstream_tls: true,
            tls_identity: None,
            geo_context: None,
            target: "/grpc.Service/Call".to_owned(),
            version: fluxheim_protocol::Http1Version::Http11,
            headers: vec![
                ("host".to_owned(), "origin.test".to_owned()),
                ("content-type".to_owned(), "application/grpc".to_owned()),
            ],
            body: zeroize::Zeroizing::new(b"request".to_vec()),
            trailers: vec![("grpc-status".to_owned(), "0".to_owned())],
        };

        let request = native_http2_upstream_request(&request, "origin.test", "https").unwrap();
        let trailers = request.trailers.as_ref().expect("trailers");

        assert_eq!(
            trailers
                .get("grpc-status")
                .and_then(|value| value.to_str().ok()),
            Some("0")
        );
    }
}
