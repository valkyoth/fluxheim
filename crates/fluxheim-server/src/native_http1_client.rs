use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use fluxheim_protocol::{Http1ParseError, http1_request_target};
use h2::client::SendRequest;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use zeroize::Zeroizing;

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
use crate::NativeHttp1UpstreamTls;
use crate::native_http1_forwarded::{
    valid_upstream_header_value, valid_upstream_request_header, write_owned_proxy_headers,
};
use crate::native_http1_upstream_response::{
    read_upstream_response, read_upstream_response_for_pool,
};
use crate::native_http2_client::{
    native_http2_upstream_client_on_io, send_native_http2_upstream_request,
};
use crate::{
    DownstreamHttp1Policy, DownstreamHttp2Policy, NativeHttp1Error, NativeHttp1Request,
    NativeHttp1Response, NativeHttp2StackError, NativeHttp2UpstreamRequest,
    NativeHttp2UpstreamResponse,
};

pub(crate) trait NativeHttp1Io: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> NativeHttp1Io for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(crate) type NativeHttp1Stream = Box<dyn NativeHttp1Io>;

#[derive(Clone)]
pub struct NativeHttp1Upstream {
    authority: String,
    protocol: NativeUpstreamHttpProtocol,
    http2_policy: DownstreamHttp2Policy,
    total_connection_timeout: Option<Duration>,
    connect_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
    recv_buffer_size: Option<u32>,
    dscp: Option<u8>,
    tcp_keepalive: Option<NativeTcpKeepalivePolicy>,
    tcp_user_timeout: Option<Duration>,
    max_head_bytes: usize,
    max_body_bytes: usize,
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
    tls: Option<NativeHttp1UpstreamTls>,
    pool: Arc<NativeHttp1Pool>,
    http2_pool: Arc<NativeHttp2Pool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeUpstreamHttpProtocol {
    Http1,
    Http2,
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
    connection: Mutex<Option<NativeHttp2PooledConnection>>,
}

struct NativeHttp2PooledConnection {
    client: SendRequest<Bytes>,
    driver: JoinHandle<()>,
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
        Self {
            stream_slots: Arc::new(Semaphore::new(max_concurrent_streams as usize)),
            connection: Mutex::new(None),
        }
    }
}

impl std::fmt::Debug for NativeHttp1Upstream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeHttp1Upstream")
            .field("authority", &self.authority)
            .field("protocol", &self.protocol)
            .field("http2_policy", &self.http2_policy)
            .field("total_connection_timeout", &self.total_connection_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("read_timeout", &self.read_timeout)
            .field("write_timeout", &self.write_timeout)
            .field("recv_buffer_size", &self.recv_buffer_size)
            .field("dscp", &self.dscp)
            .field("tcp_keepalive", &self.tcp_keepalive)
            .field("tcp_user_timeout", &self.tcp_user_timeout)
            .field("max_head_bytes", &self.max_head_bytes)
            .field("max_body_bytes", &self.max_body_bytes)
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
            && self.http2_policy == other.http2_policy
            && self.total_connection_timeout == other.total_connection_timeout
            && self.connect_timeout == other.connect_timeout
            && self.read_timeout == other.read_timeout
            && self.write_timeout == other.write_timeout
            && self.recv_buffer_size == other.recv_buffer_size
            && self.dscp == other.dscp
            && self.tcp_keepalive == other.tcp_keepalive
            && self.tcp_user_timeout == other.tcp_user_timeout
            && self.max_head_bytes == other.max_head_bytes
            && self.max_body_bytes == other.max_body_bytes
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
    pub fn new(authority: impl Into<String>) -> Self {
        let policy = DownstreamHttp1Policy::default();
        Self {
            authority: authority.into(),
            protocol: NativeUpstreamHttpProtocol::Http1,
            http2_policy: DownstreamHttp2Policy::default(),
            total_connection_timeout: None,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            recv_buffer_size: None,
            dscp: None,
            tcp_keepalive: None,
            tcp_user_timeout: None,
            max_head_bytes: policy.max_head_bytes(),
            max_body_bytes: policy.max_body_bytes(),
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
            http2_policy: DownstreamHttp2Policy::default(),
            total_connection_timeout: None,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            recv_buffer_size: None,
            dscp: None,
            tcp_keepalive: None,
            tcp_user_timeout: None,
            max_head_bytes: policy.max_head_bytes(),
            max_body_bytes: policy.max_body_bytes(),
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

    pub const fn uses_http2(&self) -> bool {
        matches!(self.protocol, NativeUpstreamHttpProtocol::Http2)
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

    pub const fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
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
        if self.uses_http2() {
            return self.send_http2(request).await;
        }
        if self.pool.max_idle == 0 {
            let stream = self.connect_stream().await?;
            return self.send_on_stream(stream, request).await;
        }

        let (mut stream, reused) = self.connection().await?;
        let result = self.send_on_pooled_stream(&mut stream, request).await;
        let (response, reusable) = match result {
            Ok(result) => result,
            Err(error)
                if reused
                    && pooled_connection_error_can_retry(&error)
                    && native_http1_retry_method_allowed(&request.method) =>
            {
                let fresh = self.connect_stream().await?;
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

    async fn send_http2(
        &self,
        request: &NativeHttp1Request,
    ) -> Result<NativeHttp1Response, NativeHttp1Error> {
        let _slot = self
            .http2_pool
            .stream_slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| std::io::Error::other("native HTTP/2 stream pool closed"))?;
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
        let client = self.http2_client().await?;
        let retry_allowed = native_http1_retry_method_allowed(&request.method.to_string());
        let response = if retry_allowed {
            let retry_request = request.clone();
            match send_native_http2_upstream_request(client, self.http2_policy, request).await {
                Ok(response) => response,
                Err(error) if native_http2_error_retry_safe(&error) => {
                    self.invalidate_http2_connection().await;
                    log::debug!(
                        target: "fluxheim::native_http2",
                        "native HTTP/2 upstream request failed before safe retry: {error}"
                    );
                    let client = self.http2_client().await?;
                    send_native_http2_upstream_request(client, self.http2_policy, retry_request)
                        .await
                        .map_err(native_http2_error)?
                }
                Err(error) => {
                    self.invalidate_http2_connection().await;
                    return Err(native_http2_error(error));
                }
            }
        } else {
            match send_native_http2_upstream_request(client, self.http2_policy, request).await {
                Ok(response) => response,
                Err(error) => {
                    self.invalidate_http2_connection().await;
                    return Err(native_http2_error(error));
                }
            }
        };
        native_http2_response_to_http1(response)
    }

    async fn http2_client(&self) -> Result<SendRequest<Bytes>, NativeHttp1Error> {
        let mut connection = self.http2_pool.connection.lock().await;
        if let Some(pooled) = connection.as_ref() {
            return Ok(pooled.client.clone());
        }
        let stream = self.connect_stream().await?;
        let (client, driver) = native_http2_upstream_client_on_io(stream, self.http2_policy)
            .await
            .map_err(native_http2_error)?;
        *connection = Some(NativeHttp2PooledConnection {
            client: client.clone(),
            driver,
        });
        Ok(client)
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

    async fn connection(&self) -> Result<(NativeHttp1Stream, bool), NativeHttp1Error> {
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
        let stream = self.connect_stream().await?;
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

    async fn connect_stream(&self) -> Result<NativeHttp1Stream, NativeHttp1Error> {
        if let Some(timeout_duration) = self.total_connection_timeout {
            return timeout(timeout_duration, self.connect_stream_inner())
                .await
                .map_err(|_| timeout_error("native HTTP/1 upstream total connection timeout"))?;
        }
        self.connect_stream_inner().await
    }

    async fn connect_stream_inner(&self) -> Result<NativeHttp1Stream, NativeHttp1Error> {
        let stream = timeout(
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
        #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
        if let Some(tls) = &self.tls {
            return timeout(self.connect_timeout, tls.connect(stream, &self.authority))
                .await
                .map_err(|_| timeout_error("native HTTP/1 upstream TLS handshake timeout"))?;
        }
        Ok(Box::new(stream) as NativeHttp1Stream)
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

async fn connect_upstream(
    authority: &str,
    recv_buffer_size: Option<u32>,
    dscp: Option<u8>,
    tcp_keepalive: Option<NativeTcpKeepalivePolicy>,
    tcp_user_timeout: Option<Duration>,
) -> Result<TcpStream, NativeHttp1Error> {
    let mut addresses = tokio::net::lookup_host(authority)
        .await
        .map_err(NativeHttp1Error::Io)?;
    let address = addresses.next().ok_or_else(|| {
        NativeHttp1Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "upstream authority did not resolve",
        ))
    })?;
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(NativeHttp1Error::Io)?;
    if let Some(size) = recv_buffer_size {
        socket
            .set_recv_buffer_size(size)
            .map_err(NativeHttp1Error::Io)?;
    }
    if let Some(dscp) = dscp {
        set_socket_dscp(&socket, address, dscp)?;
    }
    if let Some(tcp_keepalive) = tcp_keepalive {
        set_socket_tcp_keepalive(&socket, tcp_keepalive)?;
    }
    if let Some(tcp_user_timeout) = tcp_user_timeout {
        set_socket_tcp_user_timeout(&socket, tcp_user_timeout)?;
    }
    socket.connect(address).await.map_err(NativeHttp1Error::Io)
}

fn set_socket_tcp_keepalive(
    socket: &TcpSocket,
    keepalive: NativeTcpKeepalivePolicy,
) -> Result<(), NativeHttp1Error> {
    let keepalive = TcpKeepalive::new()
        .with_time(keepalive.idle())
        .with_interval(keepalive.interval())
        .with_retries(keepalive.count());
    SockRef::from(socket)
        .set_tcp_keepalive(&keepalive)
        .map_err(NativeHttp1Error::Io)
}

#[cfg(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "cygwin",
))]
fn set_socket_tcp_user_timeout(
    socket: &TcpSocket,
    timeout: Duration,
) -> Result<(), NativeHttp1Error> {
    SockRef::from(socket)
        .set_tcp_user_timeout(Some(timeout))
        .map_err(NativeHttp1Error::Io)
}

#[cfg(not(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "cygwin",
)))]
fn set_socket_tcp_user_timeout(
    _socket: &TcpSocket,
    _timeout: Duration,
) -> Result<(), NativeHttp1Error> {
    Err(NativeHttp1Error::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "native HTTP/1 upstream TCP user timeout is not supported on this target",
    )))
}

fn set_socket_dscp(
    socket: &TcpSocket,
    address: std::net::SocketAddr,
    dscp: u8,
) -> Result<(), NativeHttp1Error> {
    let traffic_class = u32::from(dscp) << 2;
    if address.is_ipv4() {
        return set_socket_dscp_v4(socket, traffic_class);
    }
    set_socket_dscp_v6(socket, traffic_class)
}

#[cfg(not(any(
    target_os = "fuchsia",
    target_os = "redox",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "haiku",
    target_os = "wasi",
)))]
fn set_socket_dscp_v4(socket: &TcpSocket, traffic_class: u32) -> Result<(), NativeHttp1Error> {
    socket
        .set_tos_v4(traffic_class)
        .map_err(NativeHttp1Error::Io)
}

#[cfg(any(
    target_os = "fuchsia",
    target_os = "redox",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "haiku",
    target_os = "wasi",
))]
fn set_socket_dscp_v4(_socket: &TcpSocket, _traffic_class: u32) -> Result<(), NativeHttp1Error> {
    unsupported_dscp_error()
}

#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "cygwin",
))]
fn set_socket_dscp_v6(socket: &TcpSocket, traffic_class: u32) -> Result<(), NativeHttp1Error> {
    socket
        .set_tclass_v6(traffic_class)
        .map_err(NativeHttp1Error::Io)
}

#[cfg(not(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "cygwin",
)))]
fn set_socket_dscp_v6(_socket: &TcpSocket, _traffic_class: u32) -> Result<(), NativeHttp1Error> {
    unsupported_dscp_error()
}

#[cfg(any(
    target_os = "fuchsia",
    target_os = "redox",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "haiku",
    target_os = "wasi",
    not(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "cygwin",
    )),
))]
fn unsupported_dscp_error() -> Result<(), NativeHttp1Error> {
    Err(NativeHttp1Error::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "native HTTP/1 upstream DSCP is not supported on this target",
    )))
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
            || name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("via")
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

fn native_http2_upstream_request(
    request: &NativeHttp1Request,
    authority: &str,
    scheme: &'static str,
) -> Result<NativeHttp2UpstreamRequest, NativeHttp1Error> {
    let method = Method::from_bytes(request.method.as_bytes())
        .map_err(|_| Http1ParseError::InvalidRequestLine)?;
    let target = upstream_origin_target(request)?;
    let uri = Uri::try_from(format!("{scheme}://{authority}{target}"))
        .map_err(|_| Http1ParseError::InvalidRequestTarget)?;
    let mut headers = HeaderMap::new();
    let connection_tokens = connection_tokens(request);
    for (name, value) in &request.headers {
        if upstream_hop_by_hop_header(name, &connection_tokens)
            || name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("via")
        {
            continue;
        }
        if !valid_upstream_request_header(name, value) {
            return Err(Http1ParseError::InvalidHeaderValue.into());
        }
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| Http1ParseError::InvalidHeaderName)?;
        let value =
            HeaderValue::from_str(value).map_err(|_| Http1ParseError::InvalidHeaderValue)?;
        headers.append(name, value);
    }
    let via = request
        .headers
        .iter()
        .filter(|(name, value)| {
            name.eq_ignore_ascii_case("via") && valid_upstream_request_header(name, value)
        })
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    headers.insert(
        http::header::VIA,
        HeaderValue::from_str(&fluxheim_protocol::append_fluxheim_via_value(&via))
            .map_err(|_| Http1ParseError::InvalidHeaderValue)?,
    );
    Ok(NativeHttp2UpstreamRequest {
        method,
        uri,
        headers,
        body: Zeroizing::new(request.body.clone()),
        trailers: None,
    })
}

const fn upstream_h2_scheme(upstream_tls: bool) -> &'static str {
    if upstream_tls { "https" } else { "http" }
}

fn native_http2_response_to_http1(
    response: NativeHttp2UpstreamResponse,
) -> Result<NativeHttp1Response, NativeHttp1Error> {
    let status = response.status();
    let reason = status.canonical_reason().unwrap_or("");
    let mut native = NativeHttp1Response::new(status.as_u16(), reason, response.body().to_vec());
    for (name, value) in response.headers() {
        if name == http::header::CONTENT_LENGTH
            || name == http::header::CONNECTION
            || name == http::header::DATE
        {
            continue;
        }
        let value = value
            .to_str()
            .map_err(|_| Http1ParseError::InvalidHeaderValue)?;
        native = native.with_header(name.as_str(), value);
    }
    Ok(native)
}

fn native_http2_error(error: NativeHttp2StackError) -> NativeHttp1Error {
    let kind = match error {
        NativeHttp2StackError::BodyReadTimeout
        | NativeHttp2StackError::HandshakeTimeout
        | NativeHttp2StackError::HandlerTimeout
        | NativeHttp2StackError::RequestReadyTimeout
        | NativeHttp2StackError::ResponseWriteTimeout => std::io::ErrorKind::TimedOut,
        NativeHttp2StackError::TooManyHeaders { .. }
        | NativeHttp2StackError::UriTooLarge { .. }
        | NativeHttp2StackError::BodyTooLarge { .. }
        | NativeHttp2StackError::ProhibitedResponseHeader { .. }
        | NativeHttp2StackError::ResponseBuild(_) => std::io::ErrorKind::InvalidData,
        NativeHttp2StackError::ResponseCapacityClosed => std::io::ErrorKind::BrokenPipe,
        NativeHttp2StackError::Handshake(_)
        | NativeHttp2StackError::RequestReady(_)
        | NativeHttp2StackError::SendRequest(_)
        | NativeHttp2StackError::Stream(_)
        | NativeHttp2StackError::BodyData(_)
        | NativeHttp2StackError::BodyTrailers(_)
        | NativeHttp2StackError::SendResponse(_) => std::io::ErrorKind::Other,
    };
    NativeHttp1Error::Io(std::io::Error::new(kind, error.to_string()))
}

fn native_http2_error_retry_safe(error: &NativeHttp2StackError) -> bool {
    matches!(
        error,
        NativeHttp2StackError::RequestReadyTimeout
            | NativeHttp2StackError::RequestReady(_)
            | NativeHttp2StackError::SendRequest(_)
    )
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
