use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

#[cfg(feature = "tls-rustls-backend")]
use crate::NativeHttp1UpstreamTls;
use crate::{NativeHttp1Handler, NativeHttp1Request, NativeHttp1Response, NativeHttp1Upstream};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1Proxy {
    upstreams: Vec<NativeHttp1Upstream>,
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
                "native HTTP/1 proxy does not yet support advanced load-balancer policy",
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
    pub fn new(upstream: NativeHttp1Upstream) -> Self {
        Self {
            upstreams: vec![upstream],
        }
    }

    pub fn from_upstreams(
        upstreams: Vec<NativeHttp1Upstream>,
    ) -> Result<Self, NativeHttp1ProxyConfigError> {
        if upstreams.is_empty() {
            return Err(NativeHttp1ProxyConfigError::MissingUpstream);
        }
        Ok(Self { upstreams })
    }

    pub fn upstream(&self) -> &NativeHttp1Upstream {
        &self.upstreams[0]
    }

    pub fn upstreams(&self) -> &[NativeHttp1Upstream] {
        &self.upstreams
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
        if proxy_requires_advanced_load_balancer(proxy) {
            return Err(NativeHttp1ProxyConfigError::LoadBalancing);
        }
        let upstreams = configured_native_upstreams(proxy)
            .ok_or(NativeHttp1ProxyConfigError::MissingUpstream)?;
        let mut native_upstreams = Vec::with_capacity(upstreams.len());
        #[cfg(feature = "tls-rustls-backend")]
        let tls = NativeHttp1UpstreamTls::from_proxy_config(proxy)?;
        for upstream in upstreams {
            let mut native_upstream = NativeHttp1Upstream::from_policy(upstream, policy);
            #[cfg(feature = "tls-rustls-backend")]
            if let Some(tls) = tls.clone() {
                native_upstream = native_upstream.with_tls(tls);
            }
            if let Some(timeout) = proxy.connect_timeout_secs {
                native_upstream =
                    native_upstream.with_connect_timeout(Duration::from_secs(timeout));
            }
            if let Some(timeout) = proxy.read_timeout_secs {
                native_upstream = native_upstream.with_read_timeout(Duration::from_secs(timeout));
            }
            if let Some(timeout) = proxy.send_timeout_secs {
                native_upstream = native_upstream.with_write_timeout(Duration::from_secs(timeout));
            }
            native_upstream = native_upstream
                .with_pool_idle_timeout(proxy.upstream_idle_timeout_secs.map(Duration::from_secs));
            native_upstream = native_upstream.with_pool_max_idle(pool_max_idle);
            native_upstreams.push(native_upstream);
        }
        Self::from_upstreams(native_upstreams).map(Some)
    }
}

impl NativeHttp1Handler for NativeHttp1Proxy {
    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp1Response> + Send + 'a>> {
        Box::pin(async move {
            let retry_allowed = native_http1_static_failover_method_allowed(&request.method);
            let mut last_error = None;
            for (index, upstream) in self.upstreams.iter().enumerate() {
                match upstream.send(&request).await {
                    Ok(response) => return response,
                    Err(error) if retry_allowed && index + 1 < self.upstreams.len() => {
                        last_error = Some(error);
                    }
                    Err(error) => {
                        last_error = Some(error);
                        break;
                    }
                }
            }
            if last_error
                .as_ref()
                .is_some_and(native_proxy_error_is_timeout)
            {
                NativeHttp1Response::new(504, "Gateway Timeout", b"gateway timeout\n")
                    .close_connection()
            } else {
                NativeHttp1Response::new(502, "Bad Gateway", b"bad gateway\n").close_connection()
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

fn configured_native_upstreams(proxy: &fluxheim_config::ProxyConfig) -> Option<Vec<String>> {
    if !proxy.upstreams.is_empty() {
        return Some(proxy.upstreams.clone());
    }
    proxy
        .configured_primary_upstream()
        .map(|upstream| vec![upstream.to_owned()])
}

fn proxy_requires_advanced_load_balancer(proxy: &fluxheim_config::ProxyConfig) -> bool {
    !proxy.upstream_weights.is_empty()
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

fn native_http1_static_failover_method_allowed(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE")
}
