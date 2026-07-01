use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[cfg(not(feature = "privacy-mode"))]
use crate::ProxyProtocolTrustedSource;
use crate::native_http1_cache::{
    NativeMemoryCacheEntry, lock_native_memory_cache, native_disk_cache_supported,
    with_native_cache_status,
};
#[cfg(feature = "auth-request")]
use crate::native_http1_proxy_auth::{
    NativeAuthRequest, NativeAuthRequestDecision, apply_native_auth_request_headers,
    native_auth_status_reason,
};
use crate::native_http1_proxy_cache_fill::NativeCacheFillGate;
use crate::native_http1_proxy_cache_headers::{
    native_cache_revalidation_request, native_request_cache_only_if_cached,
};
use crate::native_http1_proxy_cache_policy::native_cache_stale_event_for_error;
use crate::native_http1_proxy_cache_response::native_cached_hit_response;
use crate::native_http1_proxy_cache_slice::native_origin_slice_request;
#[cfg(feature = "load-balancer")]
use crate::native_http1_proxy_config::native_load_balancer_from_config;
#[cfg(not(feature = "auth-request"))]
use crate::native_http1_proxy_config::proxy_requires_auth_request;
use crate::native_http1_proxy_config::{
    configured_native_upstreams, native_http1_static_failover_method_allowed,
    native_upstream_from_proxy_config, proxy_requires_advanced_load_balancer,
    proxy_requires_advanced_upstream_transport, proxy_uses_dynamic_upstream_discovery,
};
pub use crate::native_http1_proxy_config_error::NativeHttp1ProxyConfigError;
#[cfg(feature = "load-balancer")]
use crate::native_http1_proxy_error_page::native_proxy_status_reason;
use crate::native_http1_proxy_error_page::{
    NativeHttp1ProxyErrorPage, native_error_page_response, native_error_pages_from_config,
};
use crate::native_http1_proxy_memory_cache::{
    NativePeerFillDecision, NativeProxyCacheLookup, NativeProxyMemoryCache,
};
use crate::native_http1_proxy_metrics::record_native_proxy_outcome;
#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
use crate::native_http1_proxy_mirror::{
    NativeTrafficMirror, native_request_has_valid_mirror_marker,
    strip_native_traffic_mirror_headers,
};
use crate::native_http1_proxy_peer_fill::{
    native_peer_fill_supported, native_request_is_peer_fill, strip_native_peer_fill_header,
};
use crate::native_http1_proxy_peer_fill_auth::{
    native_peer_fill_request_signature_matches, native_peer_fill_sign_response,
};
use crate::native_http1_proxy_request::{
    native_proxy_error_is_timeout, native_request_is_websocket_upgrade,
    native_response_write_policy_from_config,
};
#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
use crate::native_http1_route_compression::apply_native_response_compression;
use crate::native_http1_route_request_headers::{
    NativeRouteRequestHeaderPolicy, default_native_request_header_policy,
};
use crate::native_http1_route_response_headers::NativeRouteResponseHeaderPolicy;
use crate::{
    NativeHttp1ConnectionStream, NativeHttp1Handler, NativeHttp1Request, NativeHttp1Response,
    NativeHttp1ResponseWritePolicy, NativeHttp1Upstream,
};
use fluxheim_cache::{CacheSliceBounds, CacheStaleEvent};
use fluxheim_config::CacheConfig;

#[cfg(feature = "load-balancer")]
type NativeProxyConfigBuild = (
    NativeHttp1Proxy,
    Option<fluxheim_load_balancer::UpstreamLoadBalancerService>,
);

#[cfg(not(feature = "load-balancer"))]
type NativeProxyConfigBuild = NativeHttp1Proxy;

#[cfg(feature = "load-balancer")]
#[derive(Clone)]
pub struct NativeLoadBalancerAdminPool {
    pub vhost: Arc<str>,
    pub route: Option<Arc<str>>,
    pub load_balancer: fluxheim_load_balancer::UpstreamLoadBalancer,
}

#[derive(Clone, Debug)]
pub struct NativeHttp1Proxy {
    upstreams: Vec<NativeHttp1Upstream>,
    upstream_slots: Vec<usize>,
    #[cfg(feature = "load-balancer")]
    load_balancer: Option<fluxheim_load_balancer::UpstreamLoadBalancer>,
    #[cfg(feature = "load-balancer")]
    load_balancer_upstream_template: Option<NativeHttp1Upstream>,
    error_pages: Vec<NativeHttp1ProxyErrorPage>,
    request_headers: NativeRouteRequestHeaderPolicy,
    response_headers: NativeRouteResponseHeaderPolicy,
    response_write_policy: NativeHttp1ResponseWritePolicy,
    request_body_timeout: Option<Duration>,
    websocket: bool,
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    compression: Option<fluxheim_config::CompressionConfig>,
    #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
    mirror: Option<NativeTrafficMirror>,
    #[cfg(feature = "auth-request")]
    auth_request: Option<NativeAuthRequest>,
    cache: Option<NativeProxyMemoryCache>,
    metrics_vhost: Arc<str>,
    metrics_route: Option<Arc<str>>,
    next_upstream: Arc<AtomicUsize>,
}

impl NativeHttp1Proxy {
    pub fn new(upstream: NativeHttp1Upstream) -> Self {
        Self {
            upstreams: vec![upstream],
            upstream_slots: vec![0],
            #[cfg(feature = "load-balancer")]
            load_balancer: None,
            #[cfg(feature = "load-balancer")]
            load_balancer_upstream_template: None,
            error_pages: Vec::new(),
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            response_write_policy: NativeHttp1ResponseWritePolicy::default(),
            request_body_timeout: None,
            websocket: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
            mirror: None,
            #[cfg(feature = "auth-request")]
            auth_request: None,
            cache: None,
            metrics_vhost: Arc::from("native"),
            metrics_route: None,
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
            #[cfg(feature = "load-balancer")]
            load_balancer: None,
            #[cfg(feature = "load-balancer")]
            load_balancer_upstream_template: None,
            error_pages: Vec::new(),
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            response_write_policy: NativeHttp1ResponseWritePolicy::default(),
            request_body_timeout: None,
            websocket: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
            mirror: None,
            #[cfg(feature = "auth-request")]
            auth_request: None,
            cache: None,
            metrics_vhost: Arc::from("native"),
            metrics_route: None,
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
            #[cfg(feature = "load-balancer")]
            load_balancer: None,
            #[cfg(feature = "load-balancer")]
            load_balancer_upstream_template: None,
            error_pages: Vec::new(),
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            response_write_policy: NativeHttp1ResponseWritePolicy::default(),
            request_body_timeout: None,
            websocket: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
            mirror: None,
            #[cfg(feature = "auth-request")]
            auth_request: None,
            cache: None,
            metrics_vhost: Arc::from("native"),
            metrics_route: None,
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

    pub const fn response_write_policy(&self) -> NativeHttp1ResponseWritePolicy {
        self.response_write_policy
    }

    pub const fn request_body_timeout(&self) -> Option<Duration> {
        self.request_body_timeout
    }

    #[cfg(feature = "load-balancer")]
    pub(crate) fn load_balancer_admin_pool(
        &self,
        vhost: &str,
        route: Option<&str>,
    ) -> Option<NativeLoadBalancerAdminPool> {
        self.load_balancer
            .as_ref()
            .map(|load_balancer| NativeLoadBalancerAdminPool {
                vhost: Arc::from(vhost),
                route: route.map(Arc::from),
                load_balancer: load_balancer.clone(),
            })
    }

    pub const fn with_request_body_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.request_body_timeout = timeout;
        self
    }

    pub const fn with_websocket_enabled(mut self, enabled: bool) -> Self {
        self.websocket = enabled;
        self
    }

    pub fn with_header_policy(mut self, headers: &fluxheim_config::HeaderPolicyConfig) -> Self {
        self.request_headers = NativeRouteRequestHeaderPolicy::from_policy(&headers.request);
        self.response_headers = NativeRouteResponseHeaderPolicy::from_policy(&headers.response);
        self
    }

    pub fn with_metrics_scope(mut self, vhost: &str, route: Option<&str>) -> Self {
        self.metrics_vhost = Arc::from(vhost);
        self.metrics_route = route.map(Arc::from);
        self
    }

    pub(crate) fn without_header_policy(mut self) -> Self {
        self.request_headers = NativeRouteRequestHeaderPolicy::default();
        self.response_headers = NativeRouteResponseHeaderPolicy::default();
        self
    }

    #[cfg(not(feature = "privacy-mode"))]
    pub fn with_trusted_sources(mut self, trusted_sources: &[ProxyProtocolTrustedSource]) -> Self {
        self.request_headers
            .set_trusted_sources(trusted_sources.to_vec());
        self
    }

    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    pub fn with_compression_config(
        mut self,
        compression: fluxheim_config::CompressionConfig,
    ) -> Self {
        self.compression = Some(compression);
        self
    }

    pub fn proxy_cache_supported(cache: &CacheConfig) -> bool {
        cache.enabled
            && (cache.memory.enabled || (cache.disk.enabled && native_disk_cache_supported(cache)))
            && native_peer_fill_supported(cache)
    }

    pub fn proxy_cache_supported_for_proxy(
        cache: &CacheConfig,
        proxy: &fluxheim_config::ProxyConfig,
    ) -> bool {
        Self::proxy_cache_supported(cache) && native_slice_cache_supported_for_proxy(cache, proxy)
    }

    pub fn with_proxy_cache_config(mut self, cache: &CacheConfig) -> Self {
        if let Some(cache) = NativeProxyMemoryCache::from_config(cache) {
            self.cache = Some(cache);
        }
        self
    }

    pub fn with_proxy_cache_config_for(
        mut self,
        cache: &CacheConfig,
        vhost: &str,
        route: Option<&str>,
    ) -> Self {
        if let Some(cache) = NativeProxyMemoryCache::from_config_with_metrics(cache, vhost, route) {
            self.cache = Some(cache);
        }
        self
    }

    pub fn from_proxy_config(
        proxy: &fluxheim_config::ProxyConfig,
        policy: crate::DownstreamHttp1Policy,
    ) -> Result<Option<Self>, NativeHttp1ProxyConfigError> {
        Self::from_proxy_config_with_pool_size(proxy, policy, 0)
    }

    pub fn from_root_config(
        config: &fluxheim_config::Config,
        policy: crate::DownstreamHttp1Policy,
        pool_max_idle: usize,
    ) -> Result<Option<Self>, NativeHttp1ProxyConfigError> {
        let native = Self::from_proxy_config_with_pool_size(&config.proxy, policy, pool_max_idle)?
            .map(|proxy| {
                proxy
                    .with_metrics_scope("root", None)
                    .with_header_policy(&config.headers)
            });
        let native = native.map(|proxy| {
            if Self::proxy_cache_supported_for_proxy(&config.cache, &config.proxy) {
                proxy.with_proxy_cache_config_for(&config.cache, "root", None)
            } else {
                proxy
            }
        });
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        let native = native.map(|proxy| {
            if config.compression.enabled {
                proxy.with_compression_config(config.compression.clone())
            } else {
                proxy
            }
        });
        Ok(native)
    }

    pub fn from_proxy_config_with_pool_size(
        proxy: &fluxheim_config::ProxyConfig,
        policy: crate::DownstreamHttp1Policy,
        pool_max_idle: usize,
    ) -> Result<Option<Self>, NativeHttp1ProxyConfigError> {
        #[cfg(feature = "load-balancer")]
        {
            Self::from_proxy_config_with_pool_size_and_load_balancer(
                proxy,
                policy,
                pool_max_idle,
                None,
            )
            .map(|result| result.map(|build| build.0))
        }
        #[cfg(not(feature = "load-balancer"))]
        {
            Self::from_proxy_config_with_pool_size_and_load_balancer(proxy, policy, pool_max_idle)
        }
    }

    #[cfg(feature = "load-balancer")]
    pub fn from_proxy_config_with_native_load_balancer(
        name: &str,
        vhost: &str,
        route: Option<&str>,
        proxy: &fluxheim_config::ProxyConfig,
        policy: crate::DownstreamHttp1Policy,
        pool_max_idle: usize,
    ) -> Result<
        Option<(
            Self,
            Option<fluxheim_load_balancer::UpstreamLoadBalancerService>,
        )>,
        NativeHttp1ProxyConfigError,
    > {
        Self::from_proxy_config_with_pool_size_and_load_balancer(
            proxy,
            policy,
            pool_max_idle,
            Some((name, vhost, route)),
        )
    }

    fn from_proxy_config_with_pool_size_and_load_balancer(
        proxy: &fluxheim_config::ProxyConfig,
        policy: crate::DownstreamHttp1Policy,
        pool_max_idle: usize,
        #[cfg(feature = "load-balancer")] load_balancer_scope: Option<(&str, &str, Option<&str>)>,
    ) -> Result<Option<NativeProxyConfigBuild>, NativeHttp1ProxyConfigError> {
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
        if proxy.upstream_http_version == fluxheim_config::UpstreamHttpVersion::Http1AndHttp2
            && !proxy.upstream_h2c_upgrade
        {
            return Err(NativeHttp1ProxyConfigError::UpstreamHttp2);
        }
        #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
        if proxy.upstream_tls {
            return Err(NativeHttp1ProxyConfigError::UpstreamTls);
        }
        if proxy.websocket
            && proxy.upstream_http_version != fluxheim_config::UpstreamHttpVersion::Http1
        {
            return Err(NativeHttp1ProxyConfigError::WebSocket);
        }
        match proxy.upstream_http_version {
            fluxheim_config::UpstreamHttpVersion::Http1
                if proxy.upstream_h2_max_streams.is_none() => {}
            fluxheim_config::UpstreamHttpVersion::Http2 => {}
            fluxheim_config::UpstreamHttpVersion::Http1AndHttp2 if proxy.upstream_tls => {}
            fluxheim_config::UpstreamHttpVersion::Http1AndHttp2 if proxy.upstream_h2c_upgrade => {}
            fluxheim_config::UpstreamHttpVersion::Http1AndHttp2 => {
                return Err(NativeHttp1ProxyConfigError::UpstreamHttp2);
            }
            fluxheim_config::UpstreamHttpVersion::Http1 => {
                return Err(NativeHttp1ProxyConfigError::UpstreamTransportPolicy);
            }
        }
        if proxy.upstream_proxy_protocol != fluxheim_config::UpstreamProxyProtocol::Off
            && proxy.upstream_http_version != fluxheim_config::UpstreamHttpVersion::Http1
        {
            return Err(NativeHttp1ProxyConfigError::UpstreamProxyProtocol);
        }
        #[cfg(not(feature = "auth-request"))]
        if proxy_requires_auth_request(proxy) {
            return Err(NativeHttp1ProxyConfigError::AuthRequest);
        }
        #[cfg(not(all(feature = "traffic-mirror", not(feature = "privacy-mode"))))]
        if proxy.mirror.enabled {
            return Err(NativeHttp1ProxyConfigError::TrafficMirror);
        }
        if proxy_requires_advanced_upstream_transport(proxy) {
            return Err(NativeHttp1ProxyConfigError::UpstreamTransportPolicy);
        }
        #[cfg(feature = "load-balancer")]
        let load_balancer = native_load_balancer_from_config(proxy, load_balancer_scope)?;
        #[cfg(feature = "load-balancer")]
        let native_load_balancer_enabled = load_balancer.is_some();
        #[cfg(not(feature = "load-balancer"))]
        let native_load_balancer_enabled = false;
        if proxy_uses_dynamic_upstream_discovery(proxy) && !native_load_balancer_enabled {
            return Err(NativeHttp1ProxyConfigError::DynamicUpstreamDiscovery);
        }
        if proxy_requires_advanced_load_balancer(proxy, native_load_balancer_enabled) {
            return Err(NativeHttp1ProxyConfigError::LoadBalancing);
        }
        let upstreams = configured_native_upstreams(proxy).unwrap_or_default();
        let mut native_upstreams = Vec::with_capacity(upstreams.len());
        for upstream in upstreams {
            native_upstreams.push(native_upstream_from_proxy_config(
                upstream,
                proxy,
                policy,
                pool_max_idle,
            )?);
        }
        #[cfg(feature = "load-balancer")]
        let template = native_load_balancer_enabled
            .then(|| {
                native_upstream_from_proxy_config(
                    "127.0.0.1:0",
                    proxy,
                    policy,
                    if proxy_uses_dynamic_upstream_discovery(proxy) {
                        0
                    } else {
                        pool_max_idle
                    },
                )
            })
            .transpose()?;
        let mut native = if native_upstreams.is_empty() {
            Self {
                upstreams: Vec::new(),
                upstream_slots: Vec::new(),
                #[cfg(feature = "load-balancer")]
                load_balancer: None,
                #[cfg(feature = "load-balancer")]
                load_balancer_upstream_template: None,
                error_pages: Vec::new(),
                request_headers: default_native_request_header_policy(),
                response_headers: NativeRouteResponseHeaderPolicy::default(),
                response_write_policy: NativeHttp1ResponseWritePolicy::default(),
                request_body_timeout: None,
                websocket: false,
                #[cfg(any(
                    feature = "compression-brotli",
                    feature = "compression-gzip",
                    feature = "compression-zstd"
                ))]
                compression: None,
                #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
                mirror: None,
                #[cfg(feature = "auth-request")]
                auth_request: None,
                cache: None,
                metrics_vhost: Arc::from("native"),
                metrics_route: None,
                next_upstream: Arc::new(AtomicUsize::new(0)),
            }
        } else {
            Self::from_weighted_upstreams(native_upstreams, &proxy.upstream_weights)?
        };
        native.error_pages = native_error_pages_from_config(proxy)?;
        native.response_write_policy = native_response_write_policy_from_config(proxy);
        native.request_body_timeout = proxy.downstream_read_timeout_secs.map(Duration::from_secs);
        native.websocket = proxy.websocket;
        #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
        {
            native.mirror = NativeTrafficMirror::from_config(&proxy.mirror);
        }
        #[cfg(feature = "auth-request")]
        {
            native.auth_request = NativeAuthRequest::from_config(&proxy.auth_request);
        }
        #[cfg(feature = "load-balancer")]
        {
            native.load_balancer = load_balancer
                .as_ref()
                .map(|(load_balancer, _)| load_balancer.clone());
            native.load_balancer_upstream_template = template;
            let service = load_balancer.and_then(|(_, service)| service);
            Ok(Some((native, service)))
        }
        #[cfg(not(feature = "load-balancer"))]
        {
            Ok(Some(native))
        }
    }
}

impl PartialEq for NativeHttp1Proxy {
    fn eq(&self, other: &Self) -> bool {
        let base_equal = self.upstreams == other.upstreams
            && self.upstream_slots == other.upstream_slots
            && self.error_pages == other.error_pages
            && self.request_headers == other.request_headers
            && self.response_headers == other.response_headers
            && self.response_write_policy == other.response_write_policy
            && self.request_body_timeout == other.request_body_timeout
            && self.websocket == other.websocket
            && self.cache == other.cache;
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd",
            feature = "auth-request",
            feature = "load-balancer",
            all(feature = "traffic-mirror", not(feature = "privacy-mode"))
        ))]
        let mut equal = base_equal;
        #[cfg(feature = "load-balancer")]
        {
            equal = equal
                && self.load_balancer_upstream_template == other.load_balancer_upstream_template;
        }
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        {
            equal = equal && self.compression == other.compression;
        }
        #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
        {
            equal = equal && self.mirror == other.mirror;
        }
        #[cfg(feature = "auth-request")]
        {
            equal = equal && self.auth_request == other.auth_request;
        }
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd",
            feature = "auth-request",
            feature = "load-balancer",
            all(feature = "traffic-mirror", not(feature = "privacy-mode"))
        ))]
        {
            equal
        }
        #[cfg(not(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd",
            feature = "auth-request",
            feature = "load-balancer",
            all(feature = "traffic-mirror", not(feature = "privacy-mode"))
        )))]
        {
            base_equal
        }
    }
}

impl Eq for NativeHttp1Proxy {}

fn native_slice_cache_supported_for_proxy(
    cache: &CacheConfig,
    proxy: &fluxheim_config::ProxyConfig,
) -> bool {
    !cache.range.slice.enabled || proxy.configured_primary_upstream().is_some()
}

impl NativeHttp1Handler for NativeHttp1Proxy {
    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp1Response> + Send + 'a>> {
        Box::pin(async move {
            let retry_allowed = native_http1_static_failover_method_allowed(&request.method);
            let mut request = request;
            #[cfg(feature = "auth-request")]
            if let Some(auth_request) = &self.auth_request {
                match auth_request.authorize(&request).await {
                    Ok(NativeAuthRequestDecision::Allow { headers }) => {
                        apply_native_auth_request_headers(&mut request, &headers);
                    }
                    Ok(NativeAuthRequestDecision::Deny { status, body }) => {
                        return NativeHttp1Response::new(
                            status,
                            native_auth_status_reason(status),
                            body,
                        )
                        .close_connection();
                    }
                    Err(error) => {
                        log::debug!(
                            target: "fluxheim::auth_request",
                            "native auth_request failed: {error}"
                        );
                        return NativeHttp1Response::new(
                            502,
                            "Bad Gateway",
                            b"auth_request failed\n".as_slice(),
                        )
                        .close_connection();
                    }
                }
            }
            #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
            {
                let already_mirrored = native_request_has_valid_mirror_marker(&request);
                strip_native_traffic_mirror_headers(&mut request);
                if !already_mirrored && let Some(mirror) = &self.mirror {
                    mirror.spawn_if_selected(&request);
                }
            }
            if self.rejects_invalid_authenticated_peer_fill(&request) {
                return NativeHttp1Response::new(
                    403,
                    "Forbidden",
                    b"invalid peer-fill authentication\n".as_slice(),
                )
                .close_connection();
            }
            strip_native_peer_fill_header(&mut request);
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            let compression_request = self.compression.as_ref().map(|_| request.clone());
            self.request_headers.apply(&mut request, None);
            #[cfg(feature = "load-balancer")]
            if self.load_balancer.is_some() {
                return self
                    .handle_load_balanced(
                        request,
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request.as_ref(),
                    )
                    .await;
            }
            let mut proxy_cache_fill = None::<(
                NativeProxyMemoryCache,
                String,
                &'static str,
                Option<&'static str>,
                Option<NativeMemoryCacheEntry>,
            )>;
            let mut proxy_cache_status = None::<(
                &CacheConfig,
                &'static str,
                Option<&'static str>,
                Option<u64>,
            )>;
            if let Some(cache) = &self.cache {
                if let Some(slice) = cache.slice_response(&request, self).await {
                    return self.finish_response(
                        &request,
                        slice.response,
                        Some((
                            &cache.config,
                            if slice.filled { "MISS" } else { "HIT" },
                            Some(if slice.filled { "slice-fill" } else { "slice" }),
                            None,
                        )),
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request.as_ref(),
                    );
                }
                match cache.lookup(&request).await {
                    NativeProxyCacheLookup::Hit { entry, range } => {
                        let response = native_cached_hit_response(&entry, &request, range);
                        return self.finish_response(
                            &request,
                            response,
                            Some((&cache.config, "HIT", None, Some(entry.age_secs()))),
                            #[cfg(any(
                                feature = "compression-brotli",
                                feature = "compression-gzip",
                                feature = "compression-zstd"
                            ))]
                            compression_request.as_ref(),
                        );
                    }
                    NativeProxyCacheLookup::StaleWhileRevalidate { key, entry } => {
                        cache.record_policy_activity("stale");
                        self.spawn_cache_revalidation(
                            cache.clone(),
                            key,
                            request.clone(),
                            entry.clone(),
                        );
                        return self.finish_response(
                            &request,
                            entry.to_response(),
                            Some((
                                &cache.config,
                                "STALE-UPDATING",
                                Some("stale-while-revalidate"),
                                Some(entry.age_secs()),
                            )),
                            #[cfg(any(
                                feature = "compression-brotli",
                                feature = "compression-gzip",
                                feature = "compression-zstd"
                            ))]
                            compression_request.as_ref(),
                        );
                    }
                    NativeProxyCacheLookup::Miss {
                        key,
                        status,
                        reason,
                    } => {
                        if status == "REVALIDATED" {
                            cache.record_policy_activity("revalidate");
                        }
                        proxy_cache_fill = Some((cache.clone(), key, status, reason, None));
                    }
                    NativeProxyCacheLookup::Revalidate { key, entry } => {
                        cache.record_policy_activity("revalidate");
                        request = native_cache_revalidation_request(request, &entry);
                        proxy_cache_fill = Some((cache.clone(), key, "EXPIRED", None, Some(entry)));
                    }
                    NativeProxyCacheLookup::Bypass(reason) => {
                        cache.record_policy_activity("bypass");
                        proxy_cache_status = Some((&cache.config, "BYPASS", Some(reason), None));
                    }
                }
            }
            if let Some((cache, key, _, _, _)) = proxy_cache_fill.as_ref() {
                if native_request_cache_only_if_cached(&request) {
                    let response =
                        NativeHttp1Response::new(504, "Gateway Timeout", b"cache miss\n")
                            .close_connection();
                    return self.finish_response(
                        &request,
                        response,
                        Some((&cache.config, "MISS", Some("only-if-cached-miss"), None)),
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request.as_ref(),
                    );
                }
                match cache.peer_fill(key, &request).await {
                    NativePeerFillDecision::Skip => {}
                    NativePeerFillDecision::Hit(response) => {
                        return self.finish_response(
                            &request,
                            response,
                            Some((&cache.config, "PEER-HIT", None, None)),
                            #[cfg(any(
                                feature = "compression-brotli",
                                feature = "compression-gzip",
                                feature = "compression-zstd"
                            ))]
                            compression_request.as_ref(),
                        );
                    }
                    NativePeerFillDecision::FailClosed(reason) => {
                        let response =
                            NativeHttp1Response::new(504, "Gateway Timeout", b"cache miss\n")
                                .close_connection();
                        return self.finish_response(
                            &request,
                            response,
                            Some((&cache.config, "MISS", Some(reason), None)),
                            #[cfg(any(
                                feature = "compression-brotli",
                                feature = "compression-gzip",
                                feature = "compression-zstd"
                            ))]
                            compression_request.as_ref(),
                        );
                    }
                }
            }
            let _cache_fill_permit = if let Some((cache, key, _, _, _)) = proxy_cache_fill.as_ref()
            {
                loop {
                    match cache.cache_fill_gate(key) {
                        NativeCacheFillGate::Disabled => break None,
                        NativeCacheFillGate::Writer(permit) => break Some(permit),
                        NativeCacheFillGate::Waiter { notify, timeout } => {
                            if let Some(entry) = cache
                                .wait_for_cache_fill(notify, timeout, key, &request)
                                .await
                            {
                                return self.finish_response(
                                    &request,
                                    entry.to_response(),
                                    Some((&cache.config, "HIT", None, Some(entry.age_secs()))),
                                    #[cfg(any(
                                        feature = "compression-brotli",
                                        feature = "compression-gzip",
                                        feature = "compression-zstd"
                                    ))]
                                    compression_request.as_ref(),
                                );
                            }
                        }
                    }
                }
            } else {
                None
            };
            let _origin_fill_permit = if let Some((cache, _, _, _, _)) = proxy_cache_fill.as_ref() {
                match cache.acquire_origin_fill_permit() {
                    Some(permit) => permit,
                    None => {
                        let response = NativeHttp1Response::new(
                            503,
                            "Service Unavailable",
                            b"cache origin fill budget exhausted\n",
                        )
                        .close_connection();
                        return self.finish_response(
                            &request,
                            response,
                            Some((&cache.config, "BYPASS", Some("origin-protected"), None)),
                            #[cfg(any(
                                feature = "compression-brotli",
                                feature = "compression-gzip",
                                feature = "compression-zstd"
                            ))]
                            compression_request.as_ref(),
                        );
                    }
                }
            } else {
                None
            };
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
                    Ok(response) => {
                        let mut cache_status = proxy_cache_status;
                        if let Some((cache, key, status, reason, stale_entry)) =
                            proxy_cache_fill.as_ref()
                        {
                            if let Some(stale) = cache
                                .get_stale(
                                    key,
                                    &request,
                                    CacheStaleEvent::UpstreamHttpStatus(response.status()),
                                )
                                .await
                            {
                                cache.record_policy_activity("stale");
                                return self.finish_response(
                                    &request,
                                    stale.to_response(),
                                    Some((
                                        &cache.config,
                                        "STALE",
                                        Some("upstream-status"),
                                        Some(stale.age_secs()),
                                    )),
                                    #[cfg(any(
                                        feature = "compression-brotli",
                                        feature = "compression-gzip",
                                        feature = "compression-zstd"
                                    ))]
                                    compression_request.as_ref(),
                                );
                            }
                            let revalidated = if response.status() == 304 {
                                if let Some(entry) = stale_entry.as_ref() {
                                    cache
                                        .store_not_modified_revalidated(
                                            key, &request, entry, &response,
                                        )
                                        .await
                                        .ok()
                                } else {
                                    None
                                }
                            } else {
                                None
                            };
                            if let Some(revalidated) = revalidated {
                                return self.finish_response(
                                    &request,
                                    revalidated.to_response(),
                                    Some((
                                        &cache.config,
                                        "REVALIDATED",
                                        None,
                                        Some(revalidated.age_secs()),
                                    )),
                                    #[cfg(any(
                                        feature = "compression-brotli",
                                        feature = "compression-gzip",
                                        feature = "compression-zstd"
                                    ))]
                                    compression_request.as_ref(),
                                );
                            }
                            let store_result = if *status == "REVALIDATED" {
                                cache.store_revalidated(key, &request, &response).await
                            } else {
                                cache.store(key, &request, &response).await
                            };
                            cache_status = Some(match store_result {
                                Ok(()) => (&cache.config, *status, *reason, None),
                                Err(reason) => (&cache.config, "BYPASS", Some(reason), None),
                            });
                        }
                        return self.finish_response(
                            &request,
                            response,
                            cache_status,
                            #[cfg(any(
                                feature = "compression-brotli",
                                feature = "compression-gzip",
                                feature = "compression-zstd"
                            ))]
                            compression_request.as_ref(),
                        );
                    }
                    Err(error) if retry_allowed && unique_attempts < self.upstreams.len() => {
                        log::debug!(
                            target: "fluxheim::native_http1",
                            "native HTTP/1 upstream attempt failed before retry: {error:?}"
                        );
                        last_error = Some(error);
                    }
                    Err(error) => {
                        log::debug!(
                            target: "fluxheim::native_http1",
                            "native HTTP/1 upstream attempt failed: {error:?}"
                        );
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
            if let (Some((cache, key, _, _, _)), Some(error)) =
                (proxy_cache_fill.as_ref(), last_error.as_ref())
                && let Some(stale) = cache
                    .get_stale(key, &request, native_cache_stale_event_for_error(error))
                    .await
            {
                cache.record_policy_activity("stale");
                return self.finish_response(
                    &request,
                    stale.to_response(),
                    Some((
                        &cache.config,
                        "STALE",
                        Some("upstream-error"),
                        Some(stale.age_secs()),
                    )),
                    #[cfg(any(
                        feature = "compression-brotli",
                        feature = "compression-gzip",
                        feature = "compression-zstd"
                    ))]
                    compression_request.as_ref(),
                );
            }
            let error_response = native_error_page_response(
                &self.error_pages,
                self.response_write_policy,
                &request,
                status,
            )
            .unwrap_or_else(|| {
                if status == 504 {
                    NativeHttp1Response::new(504, "Gateway Timeout", b"gateway timeout\n")
                        .close_connection()
                } else {
                    NativeHttp1Response::new(502, "Bad Gateway", b"bad gateway\n")
                        .close_connection()
                }
            });
            self.finish_response(
                &request,
                error_response,
                proxy_cache_status,
                #[cfg(any(
                    feature = "compression-brotli",
                    feature = "compression-gzip",
                    feature = "compression-zstd"
                ))]
                compression_request.as_ref(),
            )
        })
    }

    fn request_body_timeout(&self, _request: &NativeHttp1Request) -> Option<Duration> {
        self.request_body_timeout
    }

    fn handles_connection_takeover(&self, request: &NativeHttp1Request) -> bool {
        self.websocket && native_request_is_websocket_upgrade(request)
    }

    fn handle_connection_takeover<'a>(
        &'a self,
        mut request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        stream: NativeHttp1ConnectionStream,
    ) -> Pin<Box<dyn Future<Output = Result<(), crate::NativeHttp1Error>> + Send + 'a>> {
        Box::pin(async move {
            self.request_headers.apply(&mut request, None);
            #[cfg(feature = "load-balancer")]
            if self.load_balancer.is_some() {
                return self
                    .handle_load_balanced_connection_takeover(request, prebuffered, stream)
                    .await;
            }
            let start = self.next_upstream.fetch_add(1, Ordering::Relaxed);
            let total = self.upstream_slots.len();
            if total == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "native WebSocket proxy has no upstream",
                )
                .into());
            }
            let index = self.upstream_slots[start % total];
            self.upstreams[index]
                .websocket_tunnel(&request, prebuffered, stream)
                .await
        })
    }
}

impl NativeHttp1Proxy {
    fn spawn_cache_revalidation(
        &self,
        cache: NativeProxyMemoryCache,
        key: String,
        request: NativeHttp1Request,
        entry: NativeMemoryCacheEntry,
    ) {
        {
            let mut state = lock_native_memory_cache(&cache.state, "proxy");
            if !state.revalidating.insert(key.clone()) {
                return;
            }
        }
        let proxy = self.clone();
        tokio::spawn(async move {
            proxy
                .revalidate_cache_entry(cache.clone(), key.clone(), request, entry)
                .await;
            let mut state = lock_native_memory_cache(&cache.state, "proxy");
            state.revalidating.remove(&key);
        });
    }

    async fn revalidate_cache_entry(
        self,
        cache: NativeProxyMemoryCache,
        key: String,
        request: NativeHttp1Request,
        entry: NativeMemoryCacheEntry,
    ) {
        let _origin_fill_permit = match cache.acquire_origin_fill_permit() {
            Some(permit) => permit,
            None => return,
        };
        let request = native_cache_revalidation_request(request, &entry);
        match self.send_cache_revalidation_request(&request).await {
            Ok(response) => {
                let result = if response.status() == 304 {
                    cache
                        .store_not_modified_revalidated(&key, &request, &entry, &response)
                        .await
                        .map(|_| ())
                } else {
                    cache.store_revalidated(&key, &request, &response).await
                };
                if let Err(reason) = result {
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "native proxy cache stale-while-revalidate refresh bypassed storage: {reason}"
                    );
                }
            }
            Err(error) => {
                log::debug!(
                    target: "fluxheim::native_http1",
                    "native proxy cache stale-while-revalidate refresh failed: {error:?}"
                );
            }
        }
    }

    pub(crate) async fn fetch_origin_slice(
        &self,
        request: &NativeHttp1Request,
        bounds: CacheSliceBounds,
    ) -> Option<NativeHttp1Response> {
        let cache = self.cache.as_ref()?;
        let max_body_bytes = cache.config.range.slice.size_bytes.as_u64();
        let capped_body_bytes = usize::try_from(max_body_bytes.saturating_add(1)).ok()?;
        let request = native_origin_slice_request(request, bounds)?;
        let start = self.next_upstream.fetch_add(1, Ordering::Relaxed);
        let total = self.upstream_slots.len();
        let mut attempted = vec![false; self.upstreams.len()];
        for attempt in 0..total {
            let slot = start.wrapping_add(attempt) % total;
            let index = self.upstream_slots[slot];
            if attempted[index] {
                continue;
            }
            attempted[index] = true;
            let upstream = self.upstreams[index]
                .clone()
                .with_max_body_bytes(capped_body_bytes);
            match upstream.send(&request).await {
                Ok(response) if response.body().len() as u64 <= max_body_bytes => {
                    return Some(response);
                }
                Ok(_) => return None,
                Err(error) => {
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "native proxy cache slice fill failed: {error:?}"
                    );
                }
            }
        }
        None
    }

    #[cfg(not(feature = "load-balancer"))]
    async fn send_cache_revalidation_request(
        &self,
        request: &NativeHttp1Request,
    ) -> Result<NativeHttp1Response, crate::NativeHttp1Error> {
        let retry_allowed = native_http1_static_failover_method_allowed(&request.method);
        let start = self.next_upstream.fetch_add(1, Ordering::Relaxed);
        let total = self.upstream_slots.len();
        let mut attempted = vec![false; self.upstreams.len()];
        let mut unique_attempts = 0usize;
        let mut last_error = None;
        for attempt in 0..total {
            let slot = start.wrapping_add(attempt) % total;
            let index = self.upstream_slots[slot];
            if attempted[index] {
                continue;
            }
            attempted[index] = true;
            unique_attempts += 1;
            match self.upstreams[index].send(request).await {
                Ok(response) => return Ok(response),
                Err(error) if retry_allowed && unique_attempts < self.upstreams.len() => {
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "native proxy cache refresh has no upstream",
            )
            .into()
        }))
    }

    #[cfg(feature = "load-balancer")]
    async fn send_cache_revalidation_request(
        &self,
        request: &NativeHttp1Request,
    ) -> Result<NativeHttp1Response, crate::NativeHttp1Error> {
        let Some(load_balancer) = &self.load_balancer else {
            return self.send_static_cache_revalidation_request(request).await;
        };
        let client_ip = request
            .effective_client_addr
            .or(request.peer_addr)
            .map(|address| address.ip());
        let Some(selected) = load_balancer.select_or_wait(request, client_ip).await else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "native proxy cache refresh did not select an upstream",
            )
            .into());
        };
        let authority = selected.authority();
        let dynamic_upstream = self
            .upstream_for_authority(&authority)
            .is_none()
            .then(|| self.dynamic_upstream_for_authority(&authority))
            .flatten();
        let Some(upstream) = self
            .upstream_for_authority(&authority)
            .or(dynamic_upstream.as_ref())
        else {
            if let Some(reporter) = selected.reporter() {
                reporter.record_failure();
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                format!(
                    "native proxy cache refresh selected upstream {authority} without transport"
                ),
            )
            .into());
        };
        let result = upstream.send(request).await;
        if let Some(reporter) = selected.reporter() {
            match &result {
                Ok(response) => reporter.record_status(response.status(), None),
                Err(_) => reporter.record_failure(),
            };
        }
        result
    }

    #[cfg(feature = "load-balancer")]
    async fn send_static_cache_revalidation_request(
        &self,
        request: &NativeHttp1Request,
    ) -> Result<NativeHttp1Response, crate::NativeHttp1Error> {
        let retry_allowed = native_http1_static_failover_method_allowed(&request.method);
        let start = self.next_upstream.fetch_add(1, Ordering::Relaxed);
        let total = self.upstream_slots.len();
        let mut attempted = vec![false; self.upstreams.len()];
        let mut unique_attempts = 0usize;
        let mut last_error = None;
        for attempt in 0..total {
            let slot = start.wrapping_add(attempt) % total;
            let index = self.upstream_slots[slot];
            if attempted[index] {
                continue;
            }
            attempted[index] = true;
            unique_attempts += 1;
            match self.upstreams[index].send(request).await {
                Ok(response) => return Ok(response),
                Err(error) if retry_allowed && unique_attempts < self.upstreams.len() => {
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "native proxy cache refresh has no upstream",
            )
            .into()
        }))
    }

    #[cfg(feature = "load-balancer")]
    async fn handle_load_balanced_connection_takeover(
        &self,
        request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        stream: NativeHttp1ConnectionStream,
    ) -> Result<(), crate::NativeHttp1Error> {
        let Some(load_balancer) = &self.load_balancer else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "native WebSocket load balancer is not configured",
            )
            .into());
        };
        let client_ip = request
            .effective_client_addr
            .or(request.peer_addr)
            .map(|address| address.ip());
        let Some(selected) = load_balancer.select_or_wait(&request, client_ip).await else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "native WebSocket load balancer did not select an upstream",
            )
            .into());
        };
        let authority = selected.authority();
        let dynamic_upstream = self
            .upstream_for_authority(&authority)
            .is_none()
            .then(|| self.dynamic_upstream_for_authority(&authority))
            .flatten();
        let Some(upstream) = self
            .upstream_for_authority(&authority)
            .or(dynamic_upstream.as_ref())
        else {
            if let Some(reporter) = selected.reporter() {
                reporter.record_failure();
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                format!("native WebSocket selected upstream {authority} has no transport"),
            )
            .into());
        };
        let result = upstream
            .websocket_tunnel(&request, prebuffered, stream)
            .await;
        if let Some(reporter) = selected.reporter() {
            if result.is_ok() {
                reporter.record_status(101, None);
            } else {
                reporter.record_failure();
            }
        }
        result
    }

    #[cfg(feature = "load-balancer")]
    async fn handle_load_balanced(
        &self,
        mut request: NativeHttp1Request,
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        compression_request: Option<&NativeHttp1Request>,
    ) -> NativeHttp1Response {
        let Some(load_balancer) = &self.load_balancer else {
            return NativeHttp1Response::new(502, "Bad Gateway", b"bad gateway\n")
                .close_connection();
        };
        let retry_allowed = native_http1_static_failover_method_allowed(&request.method);
        let client_ip = request
            .effective_client_addr
            .or(request.peer_addr)
            .map(|address| address.ip());
        let mut proxy_cache_fill = None::<(
            NativeProxyMemoryCache,
            String,
            &'static str,
            Option<&'static str>,
            Option<NativeMemoryCacheEntry>,
        )>;
        let mut proxy_cache_status = None::<(
            &CacheConfig,
            &'static str,
            Option<&'static str>,
            Option<u64>,
        )>;
        if let Some(cache) = &self.cache {
            if let Some(slice) = cache.slice_response(&request, self).await {
                return self.finish_response(
                    &request,
                    slice.response,
                    Some((
                        &cache.config,
                        if slice.filled { "MISS" } else { "HIT" },
                        Some(if slice.filled { "slice-fill" } else { "slice" }),
                        None,
                    )),
                    #[cfg(any(
                        feature = "compression-brotli",
                        feature = "compression-gzip",
                        feature = "compression-zstd"
                    ))]
                    compression_request,
                );
            }
            match cache.lookup(&request).await {
                NativeProxyCacheLookup::Hit { entry, range } => {
                    let response = native_cached_hit_response(&entry, &request, range);
                    return self.finish_response(
                        &request,
                        response,
                        Some((&cache.config, "HIT", None, Some(entry.age_secs()))),
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request,
                    );
                }
                NativeProxyCacheLookup::StaleWhileRevalidate { key, entry } => {
                    cache.record_policy_activity("stale");
                    self.spawn_cache_revalidation(
                        cache.clone(),
                        key,
                        request.clone(),
                        entry.clone(),
                    );
                    return self.finish_response(
                        &request,
                        entry.to_response(),
                        Some((
                            &cache.config,
                            "STALE-UPDATING",
                            Some("stale-while-revalidate"),
                            Some(entry.age_secs()),
                        )),
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request,
                    );
                }
                NativeProxyCacheLookup::Miss {
                    key,
                    status,
                    reason,
                } => {
                    if status == "REVALIDATED" {
                        cache.record_policy_activity("revalidate");
                    }
                    proxy_cache_fill = Some((cache.clone(), key, status, reason, None));
                }
                NativeProxyCacheLookup::Revalidate { key, entry } => {
                    cache.record_policy_activity("revalidate");
                    request = native_cache_revalidation_request(request, &entry);
                    proxy_cache_fill = Some((cache.clone(), key, "EXPIRED", None, Some(entry)));
                }
                NativeProxyCacheLookup::Bypass(reason) => {
                    cache.record_policy_activity("bypass");
                    proxy_cache_status = Some((&cache.config, "BYPASS", Some(reason), None));
                }
            }
        }
        if let Some((cache, key, _, _, _)) = proxy_cache_fill.as_ref() {
            if native_request_cache_only_if_cached(&request) {
                let response = NativeHttp1Response::new(504, "Gateway Timeout", b"cache miss\n")
                    .close_connection();
                return self.finish_response(
                    &request,
                    response,
                    Some((&cache.config, "MISS", Some("only-if-cached-miss"), None)),
                    #[cfg(any(
                        feature = "compression-brotli",
                        feature = "compression-gzip",
                        feature = "compression-zstd"
                    ))]
                    compression_request,
                );
            }
            match cache.peer_fill(key, &request).await {
                NativePeerFillDecision::Skip => {}
                NativePeerFillDecision::Hit(response) => {
                    return self.finish_response(
                        &request,
                        response,
                        Some((&cache.config, "PEER-HIT", None, None)),
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request,
                    );
                }
                NativePeerFillDecision::FailClosed(reason) => {
                    let response =
                        NativeHttp1Response::new(504, "Gateway Timeout", b"cache miss\n")
                            .close_connection();
                    return self.finish_response(
                        &request,
                        response,
                        Some((&cache.config, "MISS", Some(reason), None)),
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request,
                    );
                }
            }
        }
        let _cache_fill_permit = if let Some((cache, key, _, _, _)) = proxy_cache_fill.as_ref() {
            loop {
                match cache.cache_fill_gate(key) {
                    NativeCacheFillGate::Disabled => break None,
                    NativeCacheFillGate::Writer(permit) => break Some(permit),
                    NativeCacheFillGate::Waiter { notify, timeout } => {
                        if let Some(entry) = cache
                            .wait_for_cache_fill(notify, timeout, key, &request)
                            .await
                        {
                            return self.finish_response(
                                &request,
                                entry.to_response(),
                                Some((&cache.config, "HIT", None, Some(entry.age_secs()))),
                                #[cfg(any(
                                    feature = "compression-brotli",
                                    feature = "compression-gzip",
                                    feature = "compression-zstd"
                                ))]
                                compression_request,
                            );
                        }
                    }
                }
            }
        } else {
            None
        };
        let _origin_fill_permit = if let Some((cache, _, _, _, _)) = proxy_cache_fill.as_ref() {
            match cache.acquire_origin_fill_permit() {
                Some(permit) => permit,
                None => {
                    let response = NativeHttp1Response::new(
                        503,
                        "Service Unavailable",
                        b"cache origin fill budget exhausted\n",
                    )
                    .close_connection();
                    return self.finish_response(
                        &request,
                        response,
                        Some((&cache.config, "BYPASS", Some("origin-protected"), None)),
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request,
                    );
                }
            }
        } else {
            None
        };
        let mut last_error = None;
        let max_attempts = self.upstreams.len().max(1);
        for attempt in 0..max_attempts {
            let Some(selected) = load_balancer.select_or_wait(&request, client_ip).await else {
                if attempt == 0 {
                    let status = load_balancer.all_down_status();
                    if let Some((cache, key, _, _, _)) = proxy_cache_fill.as_ref()
                        && let Some(stale) = cache
                            .get_stale(
                                key,
                                &request,
                                CacheStaleEvent::UpstreamError(
                                    fluxheim_config::CacheStaleErrorKind::Connect,
                                ),
                            )
                            .await
                    {
                        cache.record_policy_activity("stale");
                        return self.finish_response(
                            &request,
                            stale.to_response(),
                            Some((
                                &cache.config,
                                "STALE",
                                Some("upstream-error"),
                                Some(stale.age_secs()),
                            )),
                            #[cfg(any(
                                feature = "compression-brotli",
                                feature = "compression-gzip",
                                feature = "compression-zstd"
                            ))]
                            compression_request,
                        );
                    }
                    let error_response = native_error_page_response(
                        &self.error_pages,
                        self.response_write_policy,
                        &request,
                        status,
                    )
                    .unwrap_or_else(|| {
                        NativeHttp1Response::new(
                            status,
                            native_proxy_status_reason(status),
                            b"service unavailable\n",
                        )
                        .close_connection()
                    });
                    return self.finish_response(
                        &request,
                        error_response,
                        proxy_cache_status,
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request,
                    );
                }
                break;
            };
            let authority = selected.authority();
            let dynamic_upstream = self
                .upstream_for_authority(&authority)
                .is_none()
                .then(|| self.dynamic_upstream_for_authority(&authority))
                .flatten();
            let upstream = self
                .upstream_for_authority(&authority)
                .or(dynamic_upstream.as_ref());
            let Some(upstream) = upstream else {
                if let Some(reporter) = selected.reporter() {
                    reporter.record_failure();
                }
                log::debug!(
                    target: "fluxheim::native_http1",
                    "native load-balanced upstream {authority} has no configured transport"
                );
                continue;
            };
            let managed_affinity_cookie = selected
                .managed_affinity_cookie()
                .map(|cookie| cookie.header_value.clone());
            match upstream.send(&request).await {
                Ok(mut response) => {
                    if let Some(reporter) = selected.reporter() {
                        reporter.record_status(response.status(), None);
                    }
                    let mut cache_status = proxy_cache_status;
                    if let Some((cache, key, status, reason, stale_entry)) =
                        proxy_cache_fill.as_ref()
                    {
                        if let Some(stale) = cache
                            .get_stale(
                                key,
                                &request,
                                CacheStaleEvent::UpstreamHttpStatus(response.status()),
                            )
                            .await
                        {
                            cache.record_policy_activity("stale");
                            return self.finish_response(
                                &request,
                                stale.to_response(),
                                Some((
                                    &cache.config,
                                    "STALE",
                                    Some("upstream-status"),
                                    Some(stale.age_secs()),
                                )),
                                #[cfg(any(
                                    feature = "compression-brotli",
                                    feature = "compression-gzip",
                                    feature = "compression-zstd"
                                ))]
                                compression_request,
                            );
                        }
                        let revalidated = if response.status() == 304 {
                            if let Some(entry) = stale_entry.as_ref() {
                                cache
                                    .store_not_modified_revalidated(key, &request, entry, &response)
                                    .await
                                    .ok()
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        if let Some(revalidated) = revalidated {
                            return self.finish_response(
                                &request,
                                revalidated.to_response(),
                                Some((
                                    &cache.config,
                                    "REVALIDATED",
                                    None,
                                    Some(revalidated.age_secs()),
                                )),
                                #[cfg(any(
                                    feature = "compression-brotli",
                                    feature = "compression-gzip",
                                    feature = "compression-zstd"
                                ))]
                                compression_request,
                            );
                        }
                        let store_result = if *status == "REVALIDATED" {
                            cache.store_revalidated(key, &request, &response).await
                        } else {
                            cache.store(key, &request, &response).await
                        };
                        cache_status = Some(match store_result {
                            Ok(()) => (&cache.config, *status, *reason, None),
                            Err(reason) => (&cache.config, "BYPASS", Some(reason), None),
                        });
                    }
                    if (200..400).contains(&response.status())
                        && let Some(cookie) = managed_affinity_cookie
                    {
                        response.push_header("set-cookie", cookie);
                    }
                    return self.finish_response(
                        &request,
                        response,
                        cache_status,
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request,
                    );
                }
                Err(error) if retry_allowed && attempt + 1 < max_attempts => {
                    if let Some(reporter) = selected.reporter() {
                        reporter.record_failure();
                    }
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "native load-balanced upstream attempt failed before retry: {error:?}"
                    );
                    last_error = Some(error);
                }
                Err(error) => {
                    if let Some(reporter) = selected.reporter() {
                        reporter.record_failure();
                    }
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "native load-balanced upstream attempt failed: {error:?}"
                    );
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
        if let (Some((cache, key, _, _, _)), Some(error)) =
            (proxy_cache_fill.as_ref(), last_error.as_ref())
            && let Some(stale) = cache
                .get_stale(key, &request, native_cache_stale_event_for_error(error))
                .await
        {
            cache.record_policy_activity("stale");
            return self.finish_response(
                &request,
                stale.to_response(),
                Some((
                    &cache.config,
                    "STALE",
                    Some("upstream-error"),
                    Some(stale.age_secs()),
                )),
                #[cfg(any(
                    feature = "compression-brotli",
                    feature = "compression-gzip",
                    feature = "compression-zstd"
                ))]
                compression_request,
            );
        }
        let error_response = native_error_page_response(
            &self.error_pages,
            self.response_write_policy,
            &request,
            status,
        )
        .unwrap_or_else(|| {
            if status == 504 {
                NativeHttp1Response::new(504, "Gateway Timeout", b"gateway timeout\n")
                    .close_connection()
            } else {
                NativeHttp1Response::new(502, "Bad Gateway", b"bad gateway\n").close_connection()
            }
        });
        self.finish_response(
            &request,
            error_response,
            proxy_cache_status,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression_request,
        )
    }

    #[cfg(feature = "load-balancer")]
    fn upstream_for_authority(&self, authority: &str) -> Option<&NativeHttp1Upstream> {
        self.upstreams
            .iter()
            .find(|upstream| upstream.authority() == authority)
    }

    #[cfg(feature = "load-balancer")]
    fn dynamic_upstream_for_authority(&self, authority: &str) -> Option<NativeHttp1Upstream> {
        self.load_balancer_upstream_template
            .clone()
            .map(|upstream| upstream.with_authority(authority.to_owned()))
    }

    fn finish_response(
        &self,
        request: &NativeHttp1Request,
        mut response: NativeHttp1Response,
        cache_status: Option<(
            &CacheConfig,
            &'static str,
            Option<&'static str>,
            Option<u64>,
        )>,
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        compression_request: Option<&NativeHttp1Request>,
    ) -> NativeHttp1Response {
        record_native_proxy_outcome(&self.metrics_vhost, &request.method, response.status());
        if let Some((cache, status, reason, age_secs)) = cache_status {
            response = with_native_cache_status(response, cache, status, reason, age_secs);
        }
        self.response_headers.apply(&mut response);
        response = response.with_write_policy(self.response_write_policy);
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        {
            if let Some(compression) = &self.compression
                && let Some(compression_request) = compression_request
            {
                apply_native_response_compression(compression_request, &mut response, compression);
            }
        }
        if let Some(cache) = &self.cache
            && let Some(auth) = cache.peer_fill_auth.as_deref()
        {
            native_peer_fill_sign_response(auth, request, &mut response);
        }
        response
    }

    fn rejects_invalid_authenticated_peer_fill(&self, request: &NativeHttp1Request) -> bool {
        if !native_request_is_peer_fill(request) {
            return false;
        }
        let Some(cache) = &self.cache else {
            return false;
        };
        let Some(auth) = cache.peer_fill_auth.as_deref() else {
            return false;
        };
        !native_peer_fill_request_signature_matches(auth, request)
    }
}
