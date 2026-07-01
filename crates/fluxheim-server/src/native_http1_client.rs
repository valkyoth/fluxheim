use std::sync::Arc;
use std::time::Duration;

use fluxheim_config::UpstreamProxyProtocol;
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
use crate::NativeHttp1UpstreamTls;
use crate::{DownstreamHttp1Policy, DownstreamHttp2Policy, NativeHttp1Error};

mod http1_io;
mod http2;
mod http2_send;
mod pool;
mod request;
mod socket;
#[cfg(test)]
mod tests;
mod upgrade;

use pool::{NativeHttp1Pool, NativeHttp2Pool};

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
        self.pool = Arc::new(NativeHttp1Pool::new(
            self.pool.max_idle,
            self.pool.idle_timeout,
        ));
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
        self.pool = Arc::new(NativeHttp1Pool::new(max_idle, self.pool.idle_timeout));
        self
    }

    pub fn with_pool_idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.pool = Arc::new(NativeHttp1Pool::new(self.pool.max_idle, timeout));
        self
    }

    pub fn pool_max_idle(&self) -> usize {
        self.pool.max_idle
    }

    pub async fn idle_connection_count(&self) -> usize {
        self.pool.idle.lock().await.len()
    }
}

fn timeout_error(message: &'static str) -> NativeHttp1Error {
    NativeHttp1Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, message))
}
