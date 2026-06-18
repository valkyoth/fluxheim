use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

#[cfg(feature = "tls-rustls-backend")]
use crate::NativeHttp1UpstreamTls;
use crate::{NativeHttp1Handler, NativeHttp1Request, NativeHttp1Response, NativeHttp1Upstream};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1Proxy {
    upstream: NativeHttp1Upstream,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHttp1ProxyConfigError {
    DynamicUpstreamDiscovery,
    HttpPolicy,
    LoadBalancing,
    MissingUpstream,
    UpstreamHttp2,
    UpstreamProxyProtocol,
    UpstreamTls,
    UpstreamTlsPolicy,
    WebSocket,
}

impl std::fmt::Display for NativeHttp1ProxyConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DynamicUpstreamDiscovery => formatter
                .write_str("native HTTP/1 proxy does not yet support dynamic upstream discovery"),
            Self::HttpPolicy => formatter
                .write_str("native HTTP/1 proxy does not yet support Fluxheim HTTP policy layers"),
            Self::LoadBalancing => formatter.write_str(
                "native HTTP/1 proxy does not yet support multi-upstream load balancing",
            ),
            Self::MissingUpstream => {
                formatter.write_str("native HTTP/1 proxy requires an upstream")
            }
            Self::UpstreamHttp2 => {
                formatter.write_str("native HTTP/1 proxy does not yet support HTTP/2 upstreams")
            }
            Self::UpstreamProxyProtocol => formatter
                .write_str("native HTTP/1 proxy does not yet support upstream PROXY protocol"),
            Self::UpstreamTls => {
                formatter.write_str("native HTTP/1 proxy does not yet support upstream TLS")
            }
            Self::UpstreamTlsPolicy => {
                formatter.write_str("native HTTP/1 proxy rejected upstream TLS policy")
            }
            Self::WebSocket => {
                formatter.write_str("native HTTP/1 proxy does not yet support websocket upgrade")
            }
        }
    }
}

impl std::error::Error for NativeHttp1ProxyConfigError {}

impl NativeHttp1Proxy {
    pub const fn new(upstream: NativeHttp1Upstream) -> Self {
        Self { upstream }
    }

    pub const fn upstream(&self) -> &NativeHttp1Upstream {
        &self.upstream
    }

    pub fn from_proxy_config(
        proxy: &fluxheim_config::ProxyConfig,
        policy: crate::DownstreamHttp1Policy,
    ) -> Result<Option<Self>, NativeHttp1ProxyConfigError> {
        Self::from_proxy_config_with_pool_size(proxy, policy, 0)
    }

    pub fn from_proxy_config_with_pool_size(
        proxy: &fluxheim_config::ProxyConfig,
        policy: crate::DownstreamHttp1Policy,
        pool_max_idle: usize,
    ) -> Result<Option<Self>, NativeHttp1ProxyConfigError> {
        if !proxy.has_configured_upstream() {
            return Ok(None);
        }
        #[cfg(not(feature = "tls-rustls-backend"))]
        if proxy.upstream_tls {
            return Err(NativeHttp1ProxyConfigError::UpstreamTls);
        }
        if proxy.upstream_proxy_protocol != fluxheim_config::UpstreamProxyProtocol::Off {
            return Err(NativeHttp1ProxyConfigError::UpstreamProxyProtocol);
        }
        if proxy.websocket {
            return Err(NativeHttp1ProxyConfigError::WebSocket);
        }
        if proxy.upstream_http_version != fluxheim_config::UpstreamHttpVersion::Http1 {
            return Err(NativeHttp1ProxyConfigError::UpstreamHttp2);
        }
        if proxy.upstreams_file.is_some()
            || proxy.upstreams_http_url.is_some()
            || proxy.upstream_dns_refresh_secs.is_some()
        {
            return Err(NativeHttp1ProxyConfigError::DynamicUpstreamDiscovery);
        }
        if proxy_requires_load_balancer(proxy) {
            return Err(NativeHttp1ProxyConfigError::LoadBalancing);
        }
        let upstream = proxy
            .configured_primary_upstream()
            .ok_or(NativeHttp1ProxyConfigError::MissingUpstream)?;
        let mut upstream = NativeHttp1Upstream::from_policy(upstream, policy);
        #[cfg(feature = "tls-rustls-backend")]
        if let Some(tls) = NativeHttp1UpstreamTls::from_proxy_config(proxy)? {
            upstream = upstream.with_tls(tls);
        }
        if let Some(timeout) = proxy.connect_timeout_secs {
            upstream = upstream.with_connect_timeout(Duration::from_secs(timeout));
        }
        if let Some(timeout) = proxy.read_timeout_secs {
            upstream = upstream.with_read_timeout(Duration::from_secs(timeout));
        }
        if let Some(timeout) = proxy.send_timeout_secs {
            upstream = upstream.with_write_timeout(Duration::from_secs(timeout));
        }
        upstream = upstream
            .with_pool_idle_timeout(proxy.upstream_idle_timeout_secs.map(Duration::from_secs));
        upstream = upstream.with_pool_max_idle(pool_max_idle);
        Ok(Some(Self::new(upstream)))
    }
}

impl NativeHttp1Handler for NativeHttp1Proxy {
    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp1Response> + Send + 'a>> {
        Box::pin(async move {
            match self.upstream.send(&request).await {
                Ok(response) => response,
                Err(error) if native_proxy_error_is_timeout(&error) => {
                    NativeHttp1Response::new(504, "Gateway Timeout", b"gateway timeout\n")
                        .close_connection()
                }
                Err(error) => {
                    let _ = error;
                    NativeHttp1Response::new(502, "Bad Gateway", b"bad gateway\n")
                        .close_connection()
                }
            }
        })
    }
}

fn native_proxy_error_is_timeout(error: &crate::NativeHttp1Error) -> bool {
    matches!(
        error,
        crate::NativeHttp1Error::Io(error) if error.kind() == std::io::ErrorKind::TimedOut
    )
}

fn proxy_requires_load_balancer(proxy: &fluxheim_config::ProxyConfig) -> bool {
    proxy.upstreams.len() > 1
        || !proxy.upstream_weights.is_empty()
        || !proxy.upstream_priority_groups.is_empty()
        || !proxy.upstream_localities.is_empty()
        || !proxy.preferred_upstream_localities.is_empty()
        || !proxy.upstream_max_in_flight.is_empty()
        || !proxy.upstream_aliases.is_empty()
        || !proxy.upstream_tags.is_empty()
        || !proxy.backup_upstreams.is_empty()
        || !proxy.drain_upstreams.is_empty()
        || !proxy.disabled_upstreams.is_empty()
}
