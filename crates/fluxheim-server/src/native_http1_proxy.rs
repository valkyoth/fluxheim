use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
use crate::NativeHttp1UpstreamTls;
use crate::{
    NativeHttp1Handler, NativeHttp1Request, NativeHttp1Response, NativeHttp1StaticWeb,
    NativeHttp1Upstream,
};

#[derive(Clone, Debug)]
pub struct NativeHttp1Proxy {
    upstreams: Vec<NativeHttp1Upstream>,
    upstream_slots: Vec<usize>,
    error_pages: Vec<NativeHttp1ProxyErrorPage>,
    next_upstream: Arc<AtomicUsize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeHttp1ProxyErrorPage {
    status: u16,
    path: String,
    web: NativeHttp1StaticWeb,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHttp1ProxyConfigError {
    DynamicUpstreamDiscovery,
    DownstreamPolicy,
    ErrorPages,
    HttpPolicy,
    LoadBalancing,
    MissingUpstream,
    TrafficMirror,
    AuthRequest,
    UpstreamHttp2,
    UpstreamProxyProtocol,
    UpstreamTls,
    UpstreamTlsPolicy,
    UpstreamTransportPolicy,
    WebSocket,
}

impl std::fmt::Display for NativeHttp1ProxyConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DynamicUpstreamDiscovery => formatter
                .write_str("native HTTP/1 proxy does not yet support dynamic upstream discovery"),
            Self::DownstreamPolicy => formatter
                .write_str("native HTTP/1 proxy does not yet support per-proxy downstream policy"),
            Self::ErrorPages => {
                formatter.write_str("native HTTP/1 proxy rejected proxy error page config")
            }
            Self::HttpPolicy => formatter
                .write_str("native HTTP/1 proxy does not yet support Fluxheim HTTP policy layers"),
            Self::LoadBalancing => formatter.write_str(
                "native HTTP/1 proxy does not yet support advanced load-balancer policy",
            ),
            Self::MissingUpstream => {
                formatter.write_str("native HTTP/1 proxy requires an upstream")
            }
            Self::TrafficMirror => {
                formatter.write_str("native HTTP/1 proxy does not yet support traffic mirroring")
            }
            Self::AuthRequest => {
                formatter.write_str("native HTTP/1 proxy does not yet support auth subrequests")
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
            Self::UpstreamTransportPolicy => formatter.write_str(
                "native HTTP/1 proxy does not yet support advanced upstream transport policy",
            ),
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
            upstream_slots: vec![0],
            error_pages: Vec::new(),
            next_upstream: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn from_upstreams(
        upstreams: Vec<NativeHttp1Upstream>,
    ) -> Result<Self, NativeHttp1ProxyConfigError> {
        if upstreams.is_empty() {
            return Err(NativeHttp1ProxyConfigError::MissingUpstream);
        }
        let upstream_slots = (0..upstreams.len()).collect();
        Ok(Self {
            upstreams,
            upstream_slots,
            error_pages: Vec::new(),
            next_upstream: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn from_weighted_upstreams(
        upstreams: Vec<NativeHttp1Upstream>,
        weights: &[usize],
    ) -> Result<Self, NativeHttp1ProxyConfigError> {
        if upstreams.is_empty() {
            return Err(NativeHttp1ProxyConfigError::MissingUpstream);
        }
        let mut upstream_slots = Vec::new();
        for (index, _) in upstreams.iter().enumerate() {
            let weight = weights.get(index).copied().unwrap_or(1);
            upstream_slots.extend(std::iter::repeat_n(index, weight));
        }
        if upstream_slots.is_empty() {
            return Err(NativeHttp1ProxyConfigError::MissingUpstream);
        }
        Ok(Self {
            upstreams,
            upstream_slots,
            error_pages: Vec::new(),
            next_upstream: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn upstream(&self) -> &NativeHttp1Upstream {
        &self.upstreams[0]
    }

    pub fn upstreams(&self) -> &[NativeHttp1Upstream] {
        &self.upstreams
    }

    pub fn upstream_slots(&self) -> &[usize] {
        &self.upstream_slots
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
        if !proxy.upstream_tls
            && (proxy.upstream_ca_path.is_some()
                || proxy.upstream_client_cert_path.is_some()
                || proxy.upstream_client_key_path.is_some())
        {
            return Err(NativeHttp1ProxyConfigError::UpstreamTlsPolicy);
        }
        #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
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
        if proxy_requires_auth_request(proxy) {
            return Err(NativeHttp1ProxyConfigError::AuthRequest);
        }
        if proxy.mirror.enabled {
            return Err(NativeHttp1ProxyConfigError::TrafficMirror);
        }
        if proxy_requires_advanced_upstream_transport(proxy) {
            return Err(NativeHttp1ProxyConfigError::UpstreamTransportPolicy);
        }
        if proxy_requires_per_proxy_downstream_policy(proxy) {
            return Err(NativeHttp1ProxyConfigError::DownstreamPolicy);
        }
        if proxy_requires_advanced_load_balancer(proxy) {
            return Err(NativeHttp1ProxyConfigError::LoadBalancing);
        }
        let upstreams = configured_native_upstreams(proxy)
            .ok_or(NativeHttp1ProxyConfigError::MissingUpstream)?;
        let mut native_upstreams = Vec::with_capacity(upstreams.len());
        #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
        let tls = NativeHttp1UpstreamTls::from_proxy_config(proxy)?;
        for upstream in upstreams {
            let mut native_upstream = NativeHttp1Upstream::from_policy(upstream, policy);
            #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
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
        let mut native = Self::from_weighted_upstreams(native_upstreams, &proxy.upstream_weights)?;
        native.error_pages = native_error_pages_from_config(proxy)?;
        Ok(Some(native))
    }
}

impl PartialEq for NativeHttp1Proxy {
    fn eq(&self, other: &Self) -> bool {
        self.upstreams == other.upstreams
            && self.upstream_slots == other.upstream_slots
            && self.error_pages == other.error_pages
    }
}

impl Eq for NativeHttp1Proxy {}

impl NativeHttp1Handler for NativeHttp1Proxy {
    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp1Response> + Send + 'a>> {
        Box::pin(async move {
            let retry_allowed = native_http1_static_failover_method_allowed(&request.method);
            let mut last_error = None;
            let start = self.next_upstream.fetch_add(1, Ordering::Relaxed);
            let total = self.upstream_slots.len();
            let mut attempted = vec![false; self.upstreams.len()];
            let mut unique_attempts = 0usize;
            for attempt in 0..total {
                let slot = start.wrapping_add(attempt) % total;
                let index = self.upstream_slots[slot];
                if attempted[index] {
                    continue;
                }
                attempted[index] = true;
                unique_attempts += 1;
                let upstream = &self.upstreams[index];
                match upstream.send(&request).await {
                    Ok(response) => return response,
                    Err(error) if retry_allowed && unique_attempts < self.upstreams.len() => {
                        last_error = Some(error);
                    }
                    Err(error) => {
                        last_error = Some(error);
                        break;
                    }
                }
            }
            let status = if last_error
                .as_ref()
                .is_some_and(native_proxy_error_is_timeout)
            {
                504
            } else {
                502
            };
            self.error_page_response(&request, status)
                .unwrap_or_else(|| {
                    if status == 504 {
                        NativeHttp1Response::new(504, "Gateway Timeout", b"gateway timeout\n")
                            .close_connection()
                    } else {
                        NativeHttp1Response::new(502, "Bad Gateway", b"bad gateway\n")
                            .close_connection()
                    }
                })
        })
    }
}

impl NativeHttp1Proxy {
    fn error_page_response(
        &self,
        request: &NativeHttp1Request,
        status: u16,
    ) -> Option<NativeHttp1Response> {
        self.error_pages
            .iter()
            .find(|page| page.status == status)
            .and_then(|page| page.web.handle_error_page(request, &page.path, status))
            .map(NativeHttp1Response::close_connection)
    }
}

fn native_error_pages_from_config(
    proxy: &fluxheim_config::ProxyConfig,
) -> Result<Vec<NativeHttp1ProxyErrorPage>, NativeHttp1ProxyConfigError> {
    let mut pages = Vec::with_capacity(proxy.error_pages.len());
    for page in &proxy.error_pages {
        let web = NativeHttp1StaticWeb::from_config(&page.web)
            .map_err(|_| NativeHttp1ProxyConfigError::ErrorPages)?
            .ok_or(NativeHttp1ProxyConfigError::ErrorPages)?;
        pages.push(NativeHttp1ProxyErrorPage {
            status: page.status,
            path: page.path.clone(),
            web,
        });
    }
    Ok(pages)
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
    if proxy.load_balance != fluxheim_config::LoadBalanceConfig::default() {
        return true;
    }
    !proxy.upstream_priority_groups.is_empty()
        || !proxy.upstream_localities.is_empty()
        || !proxy.preferred_upstream_localities.is_empty()
        || !proxy.upstream_max_in_flight.is_empty()
        || !proxy.upstream_aliases.is_empty()
        || !proxy.upstream_tags.is_empty()
        || !proxy.backup_upstreams.is_empty()
        || !proxy.drain_upstreams.is_empty()
        || !proxy.disabled_upstreams.is_empty()
}

fn proxy_requires_auth_request(proxy: &fluxheim_config::ProxyConfig) -> bool {
    proxy.auth_request.enabled
        || proxy.auth_request.url.is_some()
        || !proxy.auth_request.forward_headers.is_empty()
        || !proxy.auth_request.allow_response_headers.is_empty()
}

fn proxy_requires_advanced_upstream_transport(proxy: &fluxheim_config::ProxyConfig) -> bool {
    proxy.upstream_total_connection_timeout_secs.is_some()
        || proxy.upstream_tcp_keepalive_idle_secs.is_some()
        || proxy.upstream_tcp_keepalive_interval_secs.is_some()
        || proxy.upstream_tcp_keepalive_count.is_some()
        || proxy.upstream_tcp_user_timeout_ms.is_some()
        || proxy.upstream_tcp_recv_buffer_bytes.is_some()
        || proxy.upstream_dscp.is_some()
        || proxy.upstream_tcp_fast_open
        || proxy.upstream_h2_max_streams.is_some()
        || proxy.upstream_h2_ping_interval_secs.is_some()
}

fn proxy_requires_per_proxy_downstream_policy(proxy: &fluxheim_config::ProxyConfig) -> bool {
    let defaults = fluxheim_config::ProxyConfig::default();
    proxy.downstream_read_timeout_secs != defaults.downstream_read_timeout_secs
        || proxy.downstream_write_timeout_secs != defaults.downstream_write_timeout_secs
        || proxy.downstream_total_response_timeout_secs
            != defaults.downstream_total_response_timeout_secs
        || proxy.downstream_min_send_rate_bytes_per_sec
            != defaults.downstream_min_send_rate_bytes_per_sec
}

fn native_http1_static_failover_method_allowed(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE")
}
