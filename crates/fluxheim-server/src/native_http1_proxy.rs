use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

#[cfg(not(feature = "privacy-mode"))]
use crate::ProxyProtocolTrustedSource;
use crate::native_http1_cache::native_disk_cache_supported;
#[cfg(feature = "auth-request")]
use crate::native_http1_proxy_auth::NativeAuthRequest;
#[cfg(feature = "load-balancer")]
use crate::native_http1_proxy_config::native_load_balancer_from_config;
#[cfg(not(feature = "auth-request"))]
use crate::native_http1_proxy_config::proxy_requires_auth_request;
use crate::native_http1_proxy_config::{
    configured_native_upstreams, native_upstream_from_proxy_config,
    proxy_requires_advanced_load_balancer, proxy_requires_advanced_upstream_transport,
    proxy_uses_dynamic_upstream_discovery,
};
pub use crate::native_http1_proxy_config_error::NativeHttp1ProxyConfigError;
use crate::native_http1_proxy_error_page::{
    NativeHttp1ProxyErrorPage, native_error_pages_from_config,
};
use crate::native_http1_proxy_memory_cache::NativeProxyMemoryCache;
#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
use crate::native_http1_proxy_mirror::NativeTrafficMirror;
use crate::native_http1_proxy_peer_fill::native_peer_fill_supported;
use crate::native_http1_proxy_request::native_response_write_policy_from_config;
use crate::native_http1_route_request_headers::{
    NativeRouteRequestHeaderPolicy, default_native_request_header_policy,
};
use crate::native_http1_route_response_headers::NativeRouteResponseHeaderPolicy;
use crate::{NativeHttp1ResponseWritePolicy, NativeHttp1Upstream};
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
    pub(crate) upstreams: Vec<NativeHttp1Upstream>,
    pub(crate) upstream_slots: Vec<usize>,
    #[cfg(feature = "load-balancer")]
    pub(crate) load_balancer: Option<fluxheim_load_balancer::UpstreamLoadBalancer>,
    #[cfg(feature = "load-balancer")]
    pub(crate) load_balancer_upstream_template: Option<NativeHttp1Upstream>,
    pub(crate) error_pages: Vec<NativeHttp1ProxyErrorPage>,
    pub(crate) request_headers: NativeRouteRequestHeaderPolicy,
    pub(crate) response_headers: NativeRouteResponseHeaderPolicy,
    pub(crate) response_write_policy: NativeHttp1ResponseWritePolicy,
    pub(crate) request_body_timeout: Option<Duration>,
    pub(crate) websocket: bool,
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    pub(crate) compression: Option<fluxheim_config::CompressionConfig>,
    #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
    pub(crate) mirror: Option<NativeTrafficMirror>,
    #[cfg(feature = "auth-request")]
    pub(crate) auth_request: Option<NativeAuthRequest>,
    pub(crate) cache: Option<NativeProxyMemoryCache>,
    pub(crate) metrics_vhost: Arc<str>,
    pub(crate) metrics_route: Option<Arc<str>>,
    pub(crate) next_upstream: Arc<AtomicUsize>,
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
