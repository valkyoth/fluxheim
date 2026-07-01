use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[cfg(not(feature = "privacy-mode"))]
use crate::ProxyProtocolTrustedSource;
use crate::native_http1_cache::{
    NativeDiskCache, NativeDiskCacheStoreKey, NativeMemoryCacheCounter, NativeMemoryCacheEntry,
    NativeMemoryCacheFill, NativeMemoryCacheState, NativeMemoryCacheVariant,
    lock_native_memory_cache, native_cache_entry_weight, native_cache_ttl,
    native_disk_cache_supported, native_peer_fill_cache_ttl, native_response_header_map,
    prune_native_memory_cache, register_native_disk_cache_purge_handle,
    remove_native_memory_cache_entry, remove_native_memory_cache_variants,
    with_native_cache_status,
};
#[cfg(feature = "auth-request")]
use crate::native_http1_proxy_auth::{
    NativeAuthRequest, NativeAuthRequestDecision, apply_native_auth_request_headers,
    native_auth_status_reason,
};
use crate::native_http1_proxy_cache_fill::{
    NativeCacheFillGate, NativeCacheFillPermit, NativeOriginFillPermit, NativePeerFillPermit,
    acquire_native_origin_fill_permit, acquire_native_peer_fill_permit,
};
use crate::native_http1_proxy_cache_slice::{
    NativeCacheSliceObject, NativeCacheSliceResponse, native_cached_full_body_range_request,
    native_cached_range_response, native_compose_slice_response,
    native_if_range_matches_slice_identity, native_origin_slice_request,
    native_response_has_non_identity_encoding, native_slice_cache_key, native_slice_identity,
    native_slice_not_satisfiable_response, native_slice_object_from_entry,
    native_slice_request_within_policy,
};
#[cfg(feature = "load-balancer")]
use crate::native_http1_proxy_config::native_load_balancer_from_config;
#[cfg(not(feature = "auth-request"))]
use crate::native_http1_proxy_config::proxy_requires_auth_request;
use crate::native_http1_proxy_config::{
    configured_native_upstreams, native_http1_static_failover_method_allowed,
    native_upstream_from_proxy_config, proxy_requires_advanced_load_balancer,
    proxy_requires_advanced_upstream_transport, proxy_uses_dynamic_upstream_discovery,
};
#[cfg(feature = "load-balancer")]
use crate::native_http1_proxy_error_page::native_proxy_status_reason;
use crate::native_http1_proxy_error_page::{
    NativeHttp1ProxyErrorPage, native_error_page_response, native_error_pages_from_config,
};
use crate::native_http1_proxy_metrics::{
    record_native_cache_activity, record_native_cache_activity_scope,
    record_native_cache_operation_duration, record_native_proxy_outcome,
};
#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
use crate::native_http1_proxy_mirror::{
    NativeTrafficMirror, native_request_has_valid_mirror_marker,
    strip_native_traffic_mirror_headers,
};
use crate::native_http1_proxy_peer_fill::{
    NativePeerFillPeer, native_peer_fill_fetch, native_peer_fill_peers, native_peer_fill_supported,
    native_request_is_peer_fill, strip_native_peer_fill_header,
};
use crate::native_http1_proxy_peer_fill_auth::{
    NativePeerFillAuth, native_peer_fill_auth_from_config,
    native_peer_fill_request_signature_matches, native_peer_fill_sign_response,
};
use crate::native_http1_proxy_runtime::{
    register_native_cache_stats_handle, register_native_memory_cache_purge_handle,
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
use fluxheim_cache::{
    CacheRangeRequest, CacheRequest, CacheRequestView, CacheSliceBounds, CacheStaleEvent,
    VaryCachePolicy, VaryRequestHashField, cache_key_with_component,
    cache_method_temporarily_bypassed, cache_should_serve_stale, cache_vary_policy,
    collect_cache_tags, image_cache_key, range_response_cache_admission_rejection,
    request_cache_bypass_reason, request_cache_revalidation_requested, resolve_client_slice_ranges,
    response_age_secs, response_cache_admission_rejection,
    response_range_cache_admission_rejection, selected_cache_range_request,
    selected_cache_slice_range_request, vary_request_hash_material,
};
use fluxheim_config::{CacheConfig, CacheStaleErrorKind};
use tokio::sync::Notify;

const NATIVE_CACHE_PREDICTOR_COUNTER_TTL: Duration = Duration::from_secs(600);
static NATIVE_PROXY_CACHE_ID: AtomicUsize = AtomicUsize::new(0);
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

#[derive(Clone, Debug)]
struct NativeProxyMemoryCache {
    config: CacheConfig,
    max_bytes: u64,
    state: Arc<Mutex<NativeMemoryCacheState>>,
    disk: Option<Arc<NativeDiskCache>>,
    metrics_vhost: Arc<str>,
    metrics_route: Option<Arc<str>>,
    origin_fill_key: Arc<str>,
    peer_fill_key: Arc<str>,
    peer_fill_peers: Vec<NativePeerFillPeer>,
    peer_fill_auth: Option<Arc<NativePeerFillAuth>>,
}

impl Eq for NativeProxyMemoryCache {}

impl PartialEq for NativeProxyMemoryCache {
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config && self.max_bytes == other.max_bytes
    }
}

#[derive(Debug)]
enum NativeProxyCacheLookup {
    Bypass(&'static str),
    Miss {
        key: String,
        status: &'static str,
        reason: Option<&'static str>,
    },
    Hit {
        entry: NativeMemoryCacheEntry,
        range: Option<CacheRangeRequest>,
    },
    StaleWhileRevalidate {
        key: String,
        entry: NativeMemoryCacheEntry,
    },
    Revalidate {
        key: String,
        entry: NativeMemoryCacheEntry,
    },
}

#[derive(Debug)]
enum NativePeerFillDecision {
    Skip,
    Hit(NativeHttp1Response),
    FailClosed(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeCacheStoreMode {
    Origin,
    Revalidated,
    PeerFill,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHttp1ProxyConfigError {
    CachePolicy,
    DynamicUpstreamDiscovery,
    ErrorPages,
    HttpPolicy,
    LoadBalancing,
    MissingUpstream,
    RecvBufferTooLarge,
    TrafficMirror,
    AuthRequest,
    PhpFpm,
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
            Self::CachePolicy => {
                formatter.write_str("native HTTP/1 proxy does not yet support cache policy")
            }
            Self::DynamicUpstreamDiscovery => formatter
                .write_str("native HTTP/1 proxy does not yet support dynamic upstream discovery"),
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
            Self::RecvBufferTooLarge => {
                formatter.write_str("native HTTP/1 proxy upstream receive buffer size is too large")
            }
            Self::TrafficMirror => {
                formatter.write_str(
                    "native HTTP/1 proxy traffic mirroring requires the traffic-mirror feature and a non-privacy build",
                )
            }
            Self::AuthRequest => {
                formatter.write_str(
                    "native HTTP/1 proxy auth subrequests require the auth-request feature",
                )
            }
            Self::PhpFpm => {
                formatter.write_str("native HTTP/1 proxy rejected PHP-FPM policy")
            }
            Self::UpstreamHttp2 => formatter.write_str(
                "native HTTP/1 proxy rejected unsupported upstream HTTP/2 mode",
            ),
            Self::UpstreamProxyProtocol => formatter
                .write_str("native HTTP/1 proxy only supports upstream PROXY protocol with forced HTTP/1 origins"),
            Self::UpstreamTls => {
                formatter.write_str("native HTTP/1 proxy does not yet support upstream TLS")
            }
            Self::UpstreamTlsPolicy => {
                formatter.write_str("native HTTP/1 proxy rejected upstream TLS policy")
            }
            Self::UpstreamTransportPolicy => formatter.write_str(
                "native HTTP/1 proxy does not yet support advanced upstream transport policy",
            ),
            Self::WebSocket => formatter.write_str(
                "native HTTP/1 proxy only supports websocket upgrade with forced HTTP/1 static upstreams",
            ),
        }
    }
}

impl std::error::Error for NativeHttp1ProxyConfigError {}

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

impl NativeProxyMemoryCache {
    fn from_config(config: &CacheConfig) -> Option<Self> {
        Self::from_config_with_metrics(config, "native", None)
    }

    fn from_config_with_metrics(
        config: &CacheConfig,
        vhost: &str,
        route: Option<&str>,
    ) -> Option<Self> {
        let id = NATIVE_PROXY_CACHE_ID.fetch_add(1, Ordering::Relaxed);
        if !NativeHttp1Proxy::proxy_cache_supported(config) {
            return None;
        }
        let peer_fill_auth = match native_peer_fill_auth_from_config(config) {
            Ok(auth) => auth,
            Err(error) => {
                log::error!(
                    target: "fluxheim::security",
                    "native peer-fill shared secret could not be loaded; disabling native proxy cache for this policy: {error}"
                );
                return None;
            }
        };
        let disk = NativeDiskCache::from_config(config).map(Arc::new);
        if !config.memory.enabled && disk.is_none() {
            return None;
        }
        let state = Arc::new(Mutex::new(NativeMemoryCacheState::default()));
        let metrics_vhost = Arc::<str>::from(vhost);
        let metrics_route = route.map(Arc::<str>::from);
        if config.memory.enabled {
            register_native_memory_cache_purge_handle(
                metrics_vhost.clone(),
                metrics_route.clone(),
                &state,
            );
        }
        if let Some(disk) = disk.as_ref() {
            register_native_disk_cache_purge_handle(
                metrics_vhost.clone(),
                metrics_route.clone(),
                disk,
            );
        }
        register_native_cache_stats_handle(
            config.memory.enabled,
            config.memory.max_size_bytes.as_u64(),
            &state,
            disk.as_ref(),
        );
        Some(Self {
            config: config.clone(),
            max_bytes: if config.memory.enabled {
                config.memory.max_size_bytes.as_u64()
            } else {
                0
            },
            state,
            disk,
            metrics_vhost,
            metrics_route,
            origin_fill_key: Arc::from(format!("native-proxy-cache:{id}:origin")),
            peer_fill_key: Arc::from(format!("native-proxy-cache:{id}:peer-fill")),
            peer_fill_peers: native_peer_fill_peers(config),
            peer_fill_auth,
        })
    }

    fn memory_enabled(&self) -> bool {
        self.config.memory.enabled
    }

    fn user_tag(&self) -> String {
        self.metrics_route
            .as_deref()
            .map(|route| format!("{}:route:{route}", self.metrics_vhost))
            .unwrap_or_else(|| self.metrics_vhost.to_string())
    }

    fn record_policy_activity(&self, event: &'static str) {
        self.record_activity("policy", event);
        self.record_activity_scope("policy", event);
    }

    fn record_activity(&self, tier: &'static str, event: &'static str) {
        record_native_cache_activity(tier, event);
    }

    fn record_activity_scope(&self, tier: &'static str, event: &'static str) {
        record_native_cache_activity_scope(
            &self.metrics_vhost,
            self.metrics_route.as_deref(),
            tier,
            event,
        );
    }

    fn record_operation_duration(
        &self,
        phase: &'static str,
        operation: &'static str,
        duration: Duration,
    ) {
        record_native_cache_operation_duration(
            &self.metrics_vhost,
            self.metrics_route.as_deref(),
            phase,
            operation,
            duration,
        );
    }

    async fn lookup(&self, request: &NativeHttp1Request) -> NativeProxyCacheLookup {
        if cache_method_temporarily_bypassed(request.method()) {
            return NativeProxyCacheLookup::Bypass("method-head");
        }
        if let Some(reason) = request_cache_bypass_reason(request, &self.config) {
            return NativeProxyCacheLookup::Bypass(reason);
        }
        if request.contains_header("authorization") {
            return NativeProxyCacheLookup::Bypass("request-authorization");
        }
        let Some(key) = self.key(request) else {
            return NativeProxyCacheLookup::Bypass("proxy-ineligible");
        };
        if self.cache_pass_should_bypass(&key) {
            return NativeProxyCacheLookup::Bypass("cache-pass");
        }
        let lookup_started_at = Instant::now();
        let range = selected_cache_range_request(request, &self.config);
        let range_requested = self.config.range.enabled && request.contains_header("range");
        if range_requested && range.is_none() {
            return NativeProxyCacheLookup::Bypass("range-unsupported");
        }
        let revalidation = request_cache_revalidation_requested(request, &self.config);
        if !revalidation && let Some(hit) = self.get(&key, request).await {
            self.record_operation_duration("hit", "lookup", lookup_started_at.elapsed());
            return NativeProxyCacheLookup::Hit { entry: hit, range };
        }
        let range_key =
            range.map(|range| cache_key_with_component(&key, "range", &range.component()));
        if !revalidation
            && let Some(range_key) = range_key.as_deref()
            && let Some(hit) = self.get(range_key, request).await
        {
            self.record_operation_duration("hit", "lookup", lookup_started_at.elapsed());
            return NativeProxyCacheLookup::Hit {
                entry: hit,
                range: None,
            };
        }
        if !revalidation
            && !range_requested
            && let Some(stale) = self.get_stale_while_revalidate(&key, request).await
        {
            self.record_operation_duration("hit", "lookup", lookup_started_at.elapsed());
            return NativeProxyCacheLookup::StaleWhileRevalidate { key, entry: stale };
        }
        if !revalidation
            && !range_requested
            && let Some(entry) = self.get_revalidatable(&key, request).await
        {
            self.record_operation_duration("hit", "lookup", lookup_started_at.elapsed());
            return NativeProxyCacheLookup::Revalidate { key, entry };
        }
        if range_key.is_some() && !self.config.range.slice.enabled {
            self.record_operation_duration("miss", "lookup", lookup_started_at.elapsed());
            return NativeProxyCacheLookup::Bypass("range-miss");
        }
        if let Some(range_key) = range_key {
            self.record_operation_duration("miss", "lookup", lookup_started_at.elapsed());
            return NativeProxyCacheLookup::Miss {
                key: range_key,
                status: "MISS",
                reason: Some("range-miss"),
            };
        }
        self.record_operation_duration("miss", "lookup", lookup_started_at.elapsed());
        NativeProxyCacheLookup::Miss {
            key,
            status: if revalidation { "REVALIDATED" } else { "MISS" },
            reason: revalidation.then_some("request-refresh"),
        }
    }

    fn acquire_origin_fill_permit(&self) -> Option<Option<NativeOriginFillPermit>> {
        if !self.config.origin_protection.enabled {
            return Some(None);
        }
        acquire_native_origin_fill_permit(
            self.origin_fill_key.as_ref().to_owned(),
            self.config.origin_protection.max_concurrent_fills,
        )
        .map(Some)
    }

    fn cache_fill_gate(&self, key: &str) -> NativeCacheFillGate {
        if !self.config.lock.enabled {
            return NativeCacheFillGate::Disabled;
        }
        let mut state = lock_native_memory_cache(&self.state, "proxy");
        let now = std::time::Instant::now();
        let age_timeout = Duration::from_secs(self.config.lock.age_timeout_secs);
        if let Some(fill) = state.filling.get(key) {
            if now.saturating_duration_since(fill.started_at) < age_timeout {
                return NativeCacheFillGate::Waiter {
                    notify: fill.notify.clone(),
                    timeout: Duration::from_secs(self.config.lock.wait_timeout_secs),
                };
            }
            let expired = state.filling.remove(key);
            if let Some(expired) = expired {
                expired.notify.notify_waiters();
            }
        }

        let notify = Arc::new(Notify::new());
        state.filling.insert(
            key.to_owned(),
            NativeMemoryCacheFill {
                notify: notify.clone(),
                started_at: now,
            },
        );
        NativeCacheFillGate::Writer(NativeCacheFillPermit::new(
            self.state.clone(),
            key.to_owned(),
            notify,
        ))
    }

    async fn wait_for_cache_fill(
        &self,
        notify: Arc<Notify>,
        timeout: Duration,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
        let _ = tokio::time::timeout(timeout, notify.notified()).await;
        self.get(key, request).await
    }

    async fn slice_response(
        &self,
        request: &NativeHttp1Request,
        proxy: &NativeHttp1Proxy,
    ) -> Option<NativeCacheSliceResponse> {
        if !self.config.range.enabled || !self.config.range.slice.enabled {
            return None;
        }
        if request_cache_bypass_reason(request, &self.config).is_some()
            || self.cache_pass_should_bypass(&self.key(request)?)
        {
            return None;
        }
        let slice_request = selected_cache_slice_range_request(request, &self.config)?;
        let base_key = self.key(request)?;
        let slice_size = self.config.range.slice.size_bytes.as_u64();
        let (total, first_slice, first_filled) = self
            .discover_slice_total(&base_key, request, proxy, slice_size)
            .await?;
        let ranges = resolve_client_slice_ranges(&slice_request.ranges, total)?;
        if ranges.is_empty()
            || !native_slice_request_within_policy(
                &ranges,
                self.config.range.max_bytes.as_u64(),
                usize::try_from(self.config.range.slice.max_slices).ok()?,
                slice_size,
            )
        {
            return Some(NativeCacheSliceResponse {
                response: native_slice_not_satisfiable_response(total),
                filled: false,
            });
        }

        let identity = native_slice_identity(&first_slice);
        if let Some(if_range) = slice_request.if_range.as_deref()
            && !native_if_range_matches_slice_identity(if_range, &identity)
        {
            return None;
        }

        let mut filled = first_filled;
        let mut slices = HashMap::<(u64, u64), NativeCacheSliceObject>::new();
        slices.insert(
            (first_slice.bounds.start, first_slice.bounds.end),
            first_slice,
        );
        for bounds in fluxheim_cache::required_slice_bounds(&ranges, slice_size, total) {
            if slices.contains_key(&(bounds.start, bounds.end)) {
                continue;
            }
            let result = self
                .lookup_or_fill_slice(&base_key, request, proxy, bounds)
                .await?;
            filled |= result.1;
            if native_slice_identity(&result.0) != identity {
                return None;
            }
            slices.insert((result.0.bounds.start, result.0.bounds.end), result.0);
        }

        native_compose_slice_response(&ranges, &slices, &identity, filled)
    }

    async fn discover_slice_total(
        &self,
        base_key: &str,
        request: &NativeHttp1Request,
        proxy: &NativeHttp1Proxy,
        slice_size: u64,
    ) -> Option<(u64, NativeCacheSliceObject, bool)> {
        let first_bounds = CacheSliceBounds {
            start: 0,
            end: slice_size.saturating_sub(1),
        };
        let (slice, filled) = self
            .lookup_or_fill_slice(base_key, request, proxy, first_bounds)
            .await?;
        Some((slice.total, slice, filled))
    }

    async fn lookup_or_fill_slice(
        &self,
        base_key: &str,
        request: &NativeHttp1Request,
        proxy: &NativeHttp1Proxy,
        bounds: CacheSliceBounds,
    ) -> Option<(NativeCacheSliceObject, bool)> {
        let key = native_slice_cache_key(base_key, bounds.range_request());
        if let Some(slice) = self.lookup_cached_slice(&key) {
            return Some((slice, false));
        }
        if !self.config.range.slice.fill_missing {
            return None;
        }
        let _permit = self.acquire_origin_fill_permit()?;
        if let Some(slice) = self.lookup_cached_slice(&key) {
            return Some((slice, false));
        }
        let response = proxy.fetch_origin_slice(request, bounds).await?;
        let slice = self.store_origin_slice(base_key, &key, request, bounds, &response)?;
        Some((slice, true))
    }

    fn lookup_cached_slice(&self, key: &str) -> Option<NativeCacheSliceObject> {
        let now = std::time::Instant::now();
        let mut state = lock_native_memory_cache(&self.state, "proxy");
        match state.objects.get(key) {
            Some(entry) if entry.expires_at > now => native_slice_object_from_entry(entry.clone()),
            Some(entry) => {
                let weight = entry.weight;
                remove_native_memory_cache_entry(&mut state, key);
                state.bytes = state.bytes.saturating_sub(weight);
                None
            }
            None => None,
        }
    }

    fn store_origin_slice(
        &self,
        base_key: &str,
        key: &str,
        request: &NativeHttp1Request,
        bounds: CacheSliceBounds,
        response: &NativeHttp1Response,
    ) -> Option<NativeCacheSliceObject> {
        if response.status() == 416 {
            return None;
        }
        let headers = native_response_header_map(response);
        if fluxheim_cache::range_response_cache_admission_rejection(
            response.status(),
            &headers,
            Some(bounds.range_request()),
        )
        .is_some()
            || response_range_cache_admission_rejection(&headers, &self.config).is_some()
            || native_response_has_non_identity_encoding(response)
        {
            return None;
        }
        let ttl = native_cache_ttl(response.status(), &headers, &self.config)?;
        if ttl.is_zero() {
            return None;
        }
        let now = std::time::Instant::now();
        let (expires_at, stale_while_revalidate_until, stale_if_error_until) =
            native_cache_expiry_times(
                now,
                ttl,
                self.config.stale_while_revalidate_secs,
                self.config.stale_if_error_secs,
            )?;
        let body_len = response.body().len() as u64;
        if body_len > self.config.range.slice.size_bytes.as_u64() || body_len > self.max_bytes {
            return None;
        }
        let mut entry = NativeMemoryCacheEntry {
            status: response.status(),
            reason: response.reason().to_owned(),
            headers: cached_proxy_headers(response, &self.config),
            content_length: response.content_length(),
            body: Arc::from(response.body().to_vec()),
            expires_at,
            stale_while_revalidate_until,
            stale_if_error_until,
            stored_at: now,
            weight: native_cache_entry_weight(key, response, body_len),
        };
        let slice = native_slice_object_from_entry(entry.clone())?;
        entry.weight = native_cache_entry_weight(key, response, body_len);
        let cache_tags = native_response_cache_tags(response, &self.config);
        let needs_prune = {
            let mut state = lock_native_memory_cache(&self.state, "proxy");
            if let Some(previous) = remove_native_memory_cache_entry(&mut state, key) {
                state.bytes = state.bytes.saturating_sub(previous.weight);
            }
            state.bytes = state.bytes.saturating_add(entry.weight);
            state.purge_index.insert_with_path_and_tags(
                key.to_owned(),
                base_key.to_owned(),
                self.user_tag(),
                Some(request.path().to_owned()),
                cache_tags,
            );
            state.objects.insert(key.to_owned(), entry);
            state.bytes > self.max_bytes
        };
        if needs_prune {
            let mut state = lock_native_memory_cache(&self.state, "proxy");
            prune_native_memory_cache(&mut state, self.max_bytes);
        }
        Some(slice)
    }

    fn acquire_peer_fill_permit(&self) -> Option<NativePeerFillPermit> {
        acquire_native_peer_fill_permit(
            self.peer_fill_key.as_ref().to_owned(),
            self.config.peer_fill.max_concurrent_requests,
        )
    }

    async fn peer_fill(&self, key: &str, request: &NativeHttp1Request) -> NativePeerFillDecision {
        if !self.config.peer_fill.enabled
            || request.method != "GET"
            || (native_request_is_peer_fill(request)
                && native_request_cache_only_if_cached(request))
        {
            return NativePeerFillDecision::Skip;
        }
        let Some(_permit) = self.acquire_peer_fill_permit() else {
            return if self.config.peer_fill.fail_open {
                self.record_policy_activity("peer_fill_fallback");
                NativePeerFillDecision::Skip
            } else {
                self.record_policy_activity("peer_fill_fail_closed");
                NativePeerFillDecision::FailClosed("peer-fill-concurrency-limit")
            };
        };
        let max_body_bytes = self
            .config
            .peer_fill
            .max_object_bytes
            .unwrap_or(self.config.max_object_bytes)
            .as_u64()
            .min(self.config.max_object_bytes.as_u64());

        for peer in &self.peer_fill_peers {
            match native_peer_fill_fetch(
                peer,
                &self.config,
                self.peer_fill_auth.as_deref(),
                request,
                max_body_bytes,
            )
            .await
            {
                Ok(Some(response)) => {
                    if response.status() != 200 {
                        continue;
                    }
                    if self.store_peer_fill(key, request, &response).await.is_err() {
                        self.record_policy_activity("peer_fill_error");
                        continue;
                    }
                    self.record_policy_activity("peer_fill_hit");
                    return NativePeerFillDecision::Hit(response);
                }
                Ok(None) => {}
                Err(error) => {
                    self.record_policy_activity("peer_fill_error");
                    log::warn!(
                        target: "fluxheim::native_http1",
                        "native peer fill from {} failed: {error:?}",
                        peer.name
                    );
                }
            }
        }

        if self.config.peer_fill.fail_open {
            self.record_policy_activity("peer_fill_miss");
            self.record_policy_activity("peer_fill_fallback");
            NativePeerFillDecision::Skip
        } else {
            self.record_policy_activity("peer_fill_miss");
            self.record_policy_activity("peer_fill_fail_closed");
            NativePeerFillDecision::FailClosed("peer-fill-miss")
        }
    }

    fn key(&self, request: &NativeHttp1Request) -> Option<String> {
        image_cache_key(
            &self.config,
            &CacheRequest {
                method: request.method(),
                host: native_request_header(request, "host"),
                path: request.path(),
                query: request.query(),
            },
        )
        .map(|key| key.as_str().to_owned())
    }

    async fn get(&self, key: &str, request: &NativeHttp1Request) -> Option<NativeMemoryCacheEntry> {
        let now = std::time::Instant::now();
        if self.memory_enabled() {
            let mut state = lock_native_memory_cache(&self.state, "proxy");

            if let Some(variants) = state.variants.get(key).cloned() {
                for variant in variants {
                    let Some(variant_key) = native_vary_cache_key(key, &variant.fields, request)
                    else {
                        continue;
                    };
                    if variant_key != variant.key {
                        continue;
                    }
                    match state.objects.get(&variant.key) {
                        Some(entry) if entry.expires_at > now => return Some(entry.clone()),
                        Some(entry) => {
                            if !native_cache_entry_has_stale_window(entry, now) {
                                let weight = entry.weight;
                                remove_native_memory_cache_entry(&mut state, &variant.key);
                                state.bytes = state.bytes.saturating_sub(weight);
                            }
                            break;
                        }
                        None => {}
                    }
                }
            }

            if !state.variants.contains_key(key) {
                match state.objects.get(key) {
                    Some(entry) if entry.expires_at > now => return Some(entry.clone()),
                    Some(entry) if !native_cache_entry_has_stale_window(entry, now) => {
                        let weight = entry.weight;
                        remove_native_memory_cache_entry(&mut state, key);
                        state.bytes = state.bytes.saturating_sub(weight);
                    }
                    _ => {}
                }
            }
        }
        self.get_disk_fresh(key, request).await
    }

    async fn get_stale_while_revalidate(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
        let now = std::time::Instant::now();
        if self.memory_enabled() {
            let state = lock_native_memory_cache(&self.state, "proxy");
            if let Some(variants) = state.variants.get(key).cloned() {
                for variant in variants {
                    let Some(variant_key) = native_vary_cache_key(key, &variant.fields, request)
                    else {
                        continue;
                    };
                    if variant_key != variant.key {
                        continue;
                    }
                    if let Some(entry) = state.objects.get(&variant.key)
                        && native_cache_entry_serve_stale_while_revalidate(entry, now)
                    {
                        return Some(entry.clone());
                    }
                }
            }

            if !state.variants.contains_key(key)
                && let Some(entry) = state.objects.get(key)
                && native_cache_entry_serve_stale_while_revalidate(entry, now)
            {
                return Some(entry.clone());
            }
        }
        self.get_disk_stale_while_revalidate(key, request).await
    }

    async fn get_stale(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        event: CacheStaleEvent,
    ) -> Option<NativeMemoryCacheEntry> {
        if !cache_should_serve_stale(&self.config, event) {
            return None;
        }

        let now = std::time::Instant::now();
        if self.memory_enabled() {
            let mut state = lock_native_memory_cache(&self.state, "proxy");
            if let Some(variants) = state.variants.get(key).cloned() {
                for variant in variants {
                    let Some(variant_key) = native_vary_cache_key(key, &variant.fields, request)
                    else {
                        continue;
                    };
                    if variant_key != variant.key {
                        continue;
                    }
                    match state.objects.get(&variant.key) {
                        Some(entry)
                            if entry.expires_at <= now
                                && entry.stale_if_error_until.is_some_and(|until| until > now) =>
                        {
                            return Some(entry.clone());
                        }
                        Some(entry)
                            if entry.stale_if_error_until.is_some_and(|until| until <= now) =>
                        {
                            let weight = entry.weight;
                            remove_native_memory_cache_entry(&mut state, &variant.key);
                            state.bytes = state.bytes.saturating_sub(weight);
                            break;
                        }
                        _ => {}
                    }
                }
            }

            if !state.variants.contains_key(key) {
                match state.objects.get(key) {
                    Some(entry)
                        if entry.expires_at <= now
                            && entry.stale_if_error_until.is_some_and(|until| until > now) =>
                    {
                        return Some(entry.clone());
                    }
                    Some(entry) if entry.stale_if_error_until.is_some_and(|until| until <= now) => {
                        let weight = entry.weight;
                        remove_native_memory_cache_entry(&mut state, key);
                        state.bytes = state.bytes.saturating_sub(weight);
                    }
                    _ => {}
                }
            }
        }
        self.get_disk_stale_if_error(key, request).await
    }

    async fn get_revalidatable(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
        let now = std::time::Instant::now();
        if self.memory_enabled() {
            let state = lock_native_memory_cache(&self.state, "proxy");
            if let Some(variants) = state.variants.get(key).cloned() {
                for variant in variants {
                    let Some(variant_key) = native_vary_cache_key(key, &variant.fields, request)
                    else {
                        continue;
                    };
                    if variant_key != variant.key {
                        continue;
                    }
                    if let Some(entry) = state.objects.get(&variant.key)
                        && native_cache_entry_revalidatable(entry, now)
                    {
                        return Some(entry.clone());
                    }
                }
            }

            if !state.variants.contains_key(key)
                && let Some(entry) = state.objects.get(key)
                && native_cache_entry_revalidatable(entry, now)
            {
                return Some(entry.clone());
            }
        }
        self.get_disk_revalidatable(key, request).await
    }

    async fn get_disk_fresh(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
        let entry = self.disk_entry(key, request).await?;
        (entry.expires_at > std::time::Instant::now()).then(|| {
            self.record_activity("disk", "hit");
            self.record_activity_scope("disk", "hit");
            self.promote_disk_entry(key, request, &entry);
            entry
        })
    }

    async fn get_disk_stale_while_revalidate(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
        let entry = self.disk_entry(key, request).await?;
        native_cache_entry_serve_stale_while_revalidate(&entry, std::time::Instant::now())
            .then_some(entry)
    }

    async fn get_disk_stale_if_error(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
        let entry = self.disk_entry(key, request).await?;
        let now = std::time::Instant::now();
        (entry.expires_at <= now && entry.stale_if_error_until.is_some_and(|until| until > now))
            .then_some(entry)
    }

    async fn get_disk_revalidatable(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
        let entry = self.disk_entry(key, request).await?;
        native_cache_entry_revalidatable(&entry, std::time::Instant::now()).then_some(entry)
    }

    async fn disk_entry(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
        let disk = self.disk.as_ref()?.clone();
        let key = key.to_owned();
        let request = request.clone();
        match tokio::task::spawn_blocking(move || {
            disk.get(&key, |fields| native_vary_cache_key(&key, fields, &request))
        })
        .await
        {
            Ok(entry) => entry,
            Err(error) => {
                log::debug!(
                    target: "fluxheim::native_http1",
                    "native disk cache lookup task failed: {error}"
                );
                None
            }
        }
    }

    fn promote_disk_entry(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        entry: &NativeMemoryCacheEntry,
    ) {
        if !self.memory_enabled() || entry.weight > self.max_bytes {
            return;
        }
        let headers = native_response_header_map(&entry.to_response());
        let vary_fields = match cache_vary_policy(&headers, &self.config) {
            VaryCachePolicy::None => None,
            VaryCachePolicy::Fields(fields) => Some(fields),
            VaryCachePolicy::Uncacheable(_) => return,
        };
        let store_key = if let Some(fields) = vary_fields.as_ref() {
            let Some(key) = native_vary_cache_key(key, fields, request) else {
                return;
            };
            key
        } else {
            key.to_owned()
        };
        let needs_prune = {
            let mut state = lock_native_memory_cache(&self.state, "proxy");
            if let Some(fields) = vary_fields {
                let variants = state.variants.entry(key.to_owned()).or_default();
                variants.retain(|variant| variant.key != store_key);
                variants.push(NativeMemoryCacheVariant {
                    fields,
                    key: store_key.clone(),
                });
            }
            if let Some(previous) = state.objects.insert(store_key, entry.clone()) {
                state.bytes = state.bytes.saturating_sub(previous.weight);
            }
            state.bytes = state.bytes.saturating_add(entry.weight);
            state.bytes > self.max_bytes
        };
        if needs_prune {
            let mut state = lock_native_memory_cache(&self.state, "proxy");
            prune_native_memory_cache(&mut state, self.max_bytes);
        }
    }

    async fn store(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        response: &NativeHttp1Response,
    ) -> Result<(), &'static str> {
        let result = self
            .store_inner(key, request, response, NativeCacheStoreMode::Origin)
            .await;
        if let Err(reason) = result
            && reason != "cache-min-uses"
        {
            self.record_uncacheable(key);
        }
        result
    }

    async fn store_revalidated(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        response: &NativeHttp1Response,
    ) -> Result<(), &'static str> {
        let result = self
            .store_inner(key, request, response, NativeCacheStoreMode::Revalidated)
            .await;
        if let Err(reason) = result
            && reason != "cache-min-uses"
        {
            self.record_uncacheable(key);
        }
        result
    }

    async fn store_not_modified_revalidated(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        entry: &NativeMemoryCacheEntry,
        response: &NativeHttp1Response,
    ) -> Result<NativeMemoryCacheEntry, &'static str> {
        if response.status() != 304 {
            return Err("not-modified-status");
        }
        let headers = native_response_header_map(response);
        let ttl = native_cache_ttl(response.status(), &headers, &self.config)
            .or_else(|| native_cache_ttl(entry.status, &headers, &self.config))
            .ok_or("ttl-missing")?;
        if ttl.is_zero() {
            return Err("ttl-zero");
        }
        let now = std::time::Instant::now();
        let (expires_at, stale_while_revalidate_until, stale_if_error_until) =
            native_cache_expiry_times(
                now,
                ttl,
                self.config.stale_while_revalidate_secs,
                self.config.stale_if_error_secs,
            )
            .ok_or("ttl-overflow")?;
        let mut refreshed = entry.to_response();
        for (name, value) in cached_proxy_headers(response, &self.config) {
            if native_not_modified_refresh_header_skipped(&name) {
                continue;
            }
            refreshed.remove_header(&name);
            refreshed.push_header(name, value);
        }
        let mut refreshed_entry = NativeMemoryCacheEntry {
            status: entry.status,
            reason: entry.reason.clone(),
            headers: cached_proxy_headers(&refreshed, &self.config),
            content_length: refreshed.content_length(),
            body: entry.body.clone(),
            expires_at,
            stale_while_revalidate_until,
            stale_if_error_until,
            stored_at: now,
            weight: native_cache_entry_weight(key, &refreshed, entry.body.len() as u64),
        };
        refreshed_entry.weight =
            native_cache_entry_weight(key, &refreshed, entry.body.len() as u64);
        self.store_inner(
            key,
            request,
            &refreshed_entry.to_response(),
            NativeCacheStoreMode::Revalidated,
        )
        .await?;
        Ok(refreshed_entry)
    }

    async fn store_peer_fill(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        response: &NativeHttp1Response,
    ) -> Result<(), &'static str> {
        let result = self
            .store_inner(key, request, response, NativeCacheStoreMode::PeerFill)
            .await;
        if let Err(reason) = result
            && reason != "cache-min-uses"
        {
            self.record_uncacheable(key);
        }
        result
    }

    async fn store_inner(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        response: &NativeHttp1Response,
        mode: NativeCacheStoreMode,
    ) -> Result<(), &'static str> {
        let body_len = response.body().len() as u64;
        if body_len > self.config.max_object_bytes.as_u64() {
            return Err("object-too-large");
        }
        let headers = native_response_header_map(response);
        let vary_fields = match cache_vary_policy(&headers, &self.config) {
            VaryCachePolicy::None => None,
            VaryCachePolicy::Fields(fields) => Some(fields),
            VaryCachePolicy::Uncacheable(reason) => return Err(reason),
        };
        let range = selected_cache_range_request(request, &self.config);
        if response.status() == 206 {
            if let Some(reason) =
                range_response_cache_admission_rejection(response.status(), &headers, range)
            {
                return Err(reason);
            }
            if let Some(reason) = response_range_cache_admission_rejection(&headers, &self.config) {
                return Err(reason);
            }
        } else {
            if let Some(reason) =
                range_response_cache_admission_rejection(response.status(), &headers, None)
            {
                return Err(reason);
            }
            if let Some(reason) =
                response_cache_admission_rejection(response.status(), &headers, &self.config)
            {
                return Err(reason);
            }
        }
        let ttl = match mode {
            NativeCacheStoreMode::Origin | NativeCacheStoreMode::Revalidated => {
                native_cache_ttl(response.status(), &headers, &self.config)
            }
            NativeCacheStoreMode::PeerFill => {
                native_peer_fill_cache_ttl(response.status(), &headers, &self.config)
            }
        };
        let Some(ttl) = ttl else {
            return Err("ttl-missing");
        };
        if body_len == 0 && !self.config.status_ttls.contains_key(&response.status()) {
            return Err("empty-body");
        }
        if ttl.is_zero() {
            return Err("ttl-zero");
        }
        self.record_cacheable(key);
        if mode == NativeCacheStoreMode::Origin && !self.min_uses_allows_store(key) {
            return Err("cache-min-uses");
        }

        let store_key = if let Some(fields) = vary_fields.as_ref() {
            native_vary_cache_key(key, fields, request).ok_or("vary-invalid")?
        } else {
            key.to_owned()
        };
        let now = std::time::Instant::now();
        let stored_at = if mode == NativeCacheStoreMode::PeerFill {
            now.checked_sub(Duration::from_secs(response_age_secs(&headers)))
                .unwrap_or(now)
        } else {
            now
        };
        let Some((expires_at, stale_while_revalidate_until, stale_if_error_until)) =
            native_cache_expiry_times(
                now,
                ttl,
                self.config.stale_while_revalidate_secs,
                self.config.stale_if_error_secs,
            )
        else {
            return Err("ttl-overflow");
        };
        let weight = native_cache_entry_weight(&store_key, response, body_len);
        if self.memory_enabled() && weight > self.max_bytes {
            return Err("object-too-large");
        }
        let entry = NativeMemoryCacheEntry {
            status: response.status(),
            reason: response.reason().to_owned(),
            headers: cached_proxy_headers(response, &self.config),
            content_length: response.content_length(),
            body: Arc::from(response.body().to_vec()),
            expires_at,
            stale_while_revalidate_until,
            stale_if_error_until,
            stored_at,
            weight,
        };
        let cache_tags = native_response_cache_tags(response, &self.config);
        let disk_key = NativeDiskCacheStoreKey {
            combined: store_key.clone(),
            primary: key.to_owned(),
            user_tag: self.user_tag(),
            index_path: Some(request.path().to_owned()),
            cache_tags: cache_tags.clone(),
            vary_fields: vary_fields.clone().unwrap_or_default(),
        };
        if self.memory_enabled() {
            let needs_prune = {
                let mut state = lock_native_memory_cache(&self.state, "proxy");
                if let Some(fields) = vary_fields {
                    if let Some(previous) = remove_native_memory_cache_entry(&mut state, key) {
                        state.bytes = state.bytes.saturating_sub(previous.weight);
                    }
                    if let Some(previous) = remove_native_memory_cache_entry(&mut state, &store_key)
                    {
                        state.bytes = state.bytes.saturating_sub(previous.weight);
                    }
                    let variants = state.variants.entry(key.to_owned()).or_default();
                    variants.retain(|variant| variant.key != store_key);
                    variants.push(NativeMemoryCacheVariant {
                        fields,
                        key: store_key.clone(),
                    });
                } else {
                    let removed_bytes = remove_native_memory_cache_variants(&mut state, key);
                    state.bytes = state.bytes.saturating_sub(removed_bytes);
                    if let Some(previous) = remove_native_memory_cache_entry(&mut state, &store_key)
                    {
                        state.bytes = state.bytes.saturating_sub(previous.weight);
                    }
                }
                state.purge_index.insert_with_path_and_tags(
                    store_key.clone(),
                    key.to_owned(),
                    self.user_tag(),
                    Some(request.path().to_owned()),
                    cache_tags,
                );
                if let Some(previous) = state.objects.insert(store_key, entry.clone()) {
                    state.bytes = state.bytes.saturating_sub(previous.weight);
                }
                state.bytes = state.bytes.saturating_add(weight);
                state.bytes > self.max_bytes
            };
            if needs_prune {
                let mut state = lock_native_memory_cache(&self.state, "proxy");
                prune_native_memory_cache(&mut state, self.max_bytes);
            }
        }
        if let Some(disk) = &self.disk {
            let disk = Arc::clone(disk);
            let entry = entry.clone();
            match tokio::task::spawn_blocking(move || disk.store(disk_key, &entry)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "native disk cache store failed: {error}"
                    );
                }
                Err(error) => {
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "native disk cache store task failed: {error}"
                    );
                }
            }
        }
        Ok(())
    }

    fn cache_pass_should_bypass(&self, key: &str) -> bool {
        (self.config.predictor.enabled || self.config.pass_uncacheable_after > 0) && {
            let mut state = lock_native_memory_cache(&self.state, "proxy");
            prune_native_predictor_counters(&mut state.cache_pass, self.config.predictor.capacity);
            native_predictor_counter_uses(&mut state.cache_pass, key).is_some_and(|uses| {
                self.config.predictor.enabled || uses >= self.config.pass_uncacheable_after.max(1)
            })
        }
    }

    fn record_cacheable(&self, key: &str) {
        let mut state = lock_native_memory_cache(&self.state, "proxy");
        state.cache_pass.remove(key);
    }

    fn record_uncacheable(&self, key: &str) {
        if !self.config.predictor.enabled && self.config.pass_uncacheable_after == 0 {
            return;
        }

        let mut state = lock_native_memory_cache(&self.state, "proxy");
        prune_native_predictor_counters(&mut state.cache_pass, self.config.predictor.capacity);
        let threshold = self.config.pass_uncacheable_after.max(1);
        let uses = native_predictor_counter_uses(&mut state.cache_pass, key)
            .unwrap_or(0)
            .saturating_add(1)
            .min(threshold);
        state.cache_pass.insert(
            key.to_owned(),
            NativeMemoryCacheCounter {
                uses,
                seen_at: std::time::Instant::now(),
            },
        );
    }

    fn min_uses_allows_store(&self, key: &str) -> bool {
        if self.config.min_uses <= 1 {
            return true;
        }

        let mut state = lock_native_memory_cache(&self.state, "proxy");
        prune_native_predictor_counters(&mut state.min_uses, self.config.predictor.capacity);
        let uses = native_predictor_counter_uses(&mut state.min_uses, key)
            .unwrap_or(0)
            .saturating_add(1);
        if uses >= self.config.min_uses {
            state.min_uses.remove(key);
            true
        } else {
            state.min_uses.insert(
                key.to_owned(),
                NativeMemoryCacheCounter {
                    uses,
                    seen_at: std::time::Instant::now(),
                },
            );
            false
        }
    }
}

fn prune_native_predictor_counters(
    counters: &mut HashMap<String, NativeMemoryCacheCounter>,
    capacity: usize,
) {
    let capacity = capacity.max(1);
    if counters.len() < capacity {
        return;
    }

    while counters.len() >= capacity {
        let Some(key) = counters.keys().next().cloned() else {
            break;
        };
        counters.remove(&key);
    }
}

fn native_predictor_counter_uses(
    counters: &mut HashMap<String, NativeMemoryCacheCounter>,
    key: &str,
) -> Option<u32> {
    let counter = counters.get(key).copied()?;
    if std::time::Instant::now().saturating_duration_since(counter.seen_at)
        >= NATIVE_CACHE_PREDICTOR_COUNTER_TTL
    {
        counters.remove(key);
        return None;
    }
    Some(counter.uses)
}

fn native_cache_entry_has_stale_window(
    entry: &NativeMemoryCacheEntry,
    now: std::time::Instant,
) -> bool {
    entry
        .stale_while_revalidate_until
        .is_some_and(|until| until > now)
        || entry.stale_if_error_until.is_some_and(|until| until > now)
}

fn native_cache_entry_serve_stale_while_revalidate(
    entry: &NativeMemoryCacheEntry,
    now: std::time::Instant,
) -> bool {
    entry.expires_at <= now
        && entry
            .stale_while_revalidate_until
            .is_some_and(|until| until > now)
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

    async fn fetch_origin_slice(
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
                                CacheStaleEvent::UpstreamError(CacheStaleErrorKind::Connect),
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

fn native_response_write_policy_from_config(
    proxy: &fluxheim_config::ProxyConfig,
) -> NativeHttp1ResponseWritePolicy {
    NativeHttp1ResponseWritePolicy::new(
        proxy.downstream_write_timeout_secs.map(Duration::from_secs),
        proxy
            .downstream_total_response_timeout_secs
            .map(Duration::from_secs),
        proxy.downstream_min_send_rate_bytes_per_sec,
    )
}

fn native_request_is_websocket_upgrade(request: &NativeHttp1Request) -> bool {
    request.method == "GET"
        && native_request_header_values(request, "upgrade")
            .any(|value| value.trim().eq_ignore_ascii_case("websocket"))
        && native_request_header_values(request, "connection").any(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
        && native_request_header_values(request, "sec-websocket-key").count() == 1
        && native_request_header_values(request, "sec-websocket-version")
            .any(|value| value.trim() == "13")
}

fn native_request_header_values<'a>(
    request: &'a NativeHttp1Request,
    name: &'a str,
) -> impl Iterator<Item = &'a str> {
    request
        .headers
        .iter()
        .filter(move |(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn native_proxy_error_is_timeout(error: &crate::NativeHttp1Error) -> bool {
    matches!(
        error,
        crate::NativeHttp1Error::Io(error) if error.kind() == std::io::ErrorKind::TimedOut
    )
}

fn native_cache_stale_event_for_error(error: &crate::NativeHttp1Error) -> CacheStaleEvent {
    CacheStaleEvent::UpstreamError(native_cache_stale_error_kind(error))
}

fn native_cache_stale_error_kind(error: &crate::NativeHttp1Error) -> CacheStaleErrorKind {
    match error {
        crate::NativeHttp1Error::Io(error) => match error.kind() {
            std::io::ErrorKind::TimedOut => CacheStaleErrorKind::Timeout,
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::AddrInUse
            | std::io::ErrorKind::AddrNotAvailable => CacheStaleErrorKind::Connect,
            std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof => CacheStaleErrorKind::ConnectionClosed,
            std::io::ErrorKind::InvalidData => CacheStaleErrorKind::Protocol,
            std::io::ErrorKind::PermissionDenied => CacheStaleErrorKind::Other,
            _ => CacheStaleErrorKind::Other,
        },
        crate::NativeHttp1Error::Parse(_) => CacheStaleErrorKind::Protocol,
    }
}

fn native_cache_expiry_times(
    now: std::time::Instant,
    ttl: Duration,
    stale_while_revalidate_secs: Option<u32>,
    stale_if_error_secs: Option<u32>,
) -> Option<(
    std::time::Instant,
    Option<std::time::Instant>,
    Option<std::time::Instant>,
)> {
    let expires_at = now.checked_add(ttl)?;
    let stale_while_revalidate_until = match stale_while_revalidate_secs {
        Some(stale_secs) => {
            Some(expires_at.checked_add(Duration::from_secs(u64::from(stale_secs)))?)
        }
        None => None,
    };
    let stale_if_error_until = match stale_if_error_secs {
        Some(stale_secs) => {
            Some(expires_at.checked_add(Duration::from_secs(u64::from(stale_secs)))?)
        }
        None => None,
    };
    Some((
        expires_at,
        stale_while_revalidate_until,
        stale_if_error_until,
    ))
}

fn native_request_header<'a>(request: &'a NativeHttp1Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find_map(|(header_name, value)| header_name.eq_ignore_ascii_case(name).then_some(value))
        .map(String::as_str)
}

fn native_cache_entry_revalidatable(
    entry: &NativeMemoryCacheEntry,
    now: std::time::Instant,
) -> bool {
    entry.expires_at <= now
        && (native_entry_first_header(entry, "etag").is_some()
            || native_entry_first_header(entry, "last-modified").is_some())
}

fn native_cache_revalidation_request(
    mut request: NativeHttp1Request,
    entry: &NativeMemoryCacheEntry,
) -> NativeHttp1Request {
    if !request.contains_header("if-none-match")
        && let Some(etag) = native_entry_first_header(entry, "etag")
    {
        request.headers.push(("if-none-match".to_owned(), etag));
        return request;
    }
    if !request.contains_header("if-modified-since")
        && let Some(last_modified) = native_entry_first_header(entry, "last-modified")
    {
        request
            .headers
            .push(("if-modified-since".to_owned(), last_modified));
    }
    request
}

fn native_not_modified_refresh_header_skipped(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("content-range")
        || name.eq_ignore_ascii_case("transfer-encoding")
}

fn native_request_cache_only_if_cached(request: &NativeHttp1Request) -> bool {
    native_request_header_values(request, "cache-control").any(|value| {
        value
            .split(',')
            .any(|directive| directive.trim().eq_ignore_ascii_case("only-if-cached"))
    })
}

fn cached_proxy_headers(
    response: &NativeHttp1Response,
    cache: &CacheConfig,
) -> Vec<(String, String)> {
    response
        .headers()
        .iter()
        .filter(|(name, _)| {
            !name.eq_ignore_ascii_case("age")
                && !cache
                    .hide_response_headers
                    .iter()
                    .any(|hidden| hidden.eq_ignore_ascii_case(name))
        })
        .cloned()
        .collect()
}

fn native_response_cache_tags(response: &NativeHttp1Response, cache: &CacheConfig) -> Vec<String> {
    let mut tags = Vec::new();
    let mut total_bytes = 0_usize;
    for tag_header in &cache.tag_headers {
        for (_, value) in response
            .headers()
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(tag_header))
        {
            collect_cache_tags(value, &mut tags, &mut total_bytes);
        }
    }
    tags
}

fn native_entry_first_header(entry: &NativeMemoryCacheEntry, name: &str) -> Option<String> {
    entry
        .headers
        .iter()
        .find_map(|(header_name, value)| header_name.eq_ignore_ascii_case(name).then_some(value))
        .cloned()
}

fn native_cached_hit_response(
    entry: &NativeMemoryCacheEntry,
    request: &NativeHttp1Request,
    range: Option<CacheRangeRequest>,
) -> NativeHttp1Response {
    if native_cached_conditional_not_modified(entry, request) {
        return native_cached_not_modified_response(entry);
    }
    if entry.status == 206 {
        return entry.to_response();
    }
    if let Some(range) = range.or_else(|| native_cached_full_body_range_request(entry, request)) {
        native_cached_range_response(entry, range)
    } else {
        entry.to_response()
    }
}

fn native_cached_conditional_not_modified(
    entry: &NativeMemoryCacheEntry,
    request: &NativeHttp1Request,
) -> bool {
    if let Some(if_none_match) = native_joined_request_header_values(request, "if-none-match") {
        let Some(etag) = native_cached_header_value(entry, "etag") else {
            return false;
        };
        return native_if_none_match_matches(if_none_match.as_str(), etag);
    }

    let Some(if_modified_since) = native_joined_request_header_values(request, "if-modified-since")
    else {
        return false;
    };
    let Some(last_modified) = native_cached_header_value(entry, "last-modified") else {
        return false;
    };
    let Ok(request_time) = httpdate::parse_http_date(if_modified_since.trim()) else {
        return false;
    };
    let Ok(cached_time) = httpdate::parse_http_date(last_modified.trim()) else {
        return false;
    };
    cached_time <= request_time
}

fn native_cached_header_value<'a>(
    entry: &'a NativeMemoryCacheEntry,
    name: &str,
) -> Option<&'a str> {
    entry
        .headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn native_joined_request_header_values(request: &NativeHttp1Request, name: &str) -> Option<String> {
    fluxheim_headers::join_header_values(
        native_request_header_values(request, name).filter(|value| !value.trim().is_empty()),
    )
}

fn native_if_none_match_matches(if_none_match: &str, etag: &str) -> bool {
    let etag = native_weak_etag_value(etag.trim());
    if_none_match.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*" || native_weak_etag_value(candidate) == etag
    })
}

fn native_weak_etag_value(value: &str) -> &str {
    value.strip_prefix("W/").unwrap_or(value)
}

fn native_cached_not_modified_response(entry: &NativeMemoryCacheEntry) -> NativeHttp1Response {
    let mut response = NativeHttp1Response::new(304, "Not Modified", Vec::new());
    for (name, value) in &entry.headers {
        if native_cached_not_modified_response_header_preserved(name) {
            response.push_header(name.clone(), value.clone());
        }
    }
    response
}

fn native_cached_not_modified_response_header_preserved(name: &str) -> bool {
    !name.eq_ignore_ascii_case("content-length")
        && !name.eq_ignore_ascii_case("content-range")
        && !name.eq_ignore_ascii_case("accept-ranges")
}

fn native_vary_cache_key(
    base_key: &str,
    fields: &[String],
    request: &NativeHttp1Request,
) -> Option<String> {
    let material = vary_request_hash_material(fields.iter().map(|field| {
        VaryRequestHashField {
            name: field.as_str(),
            values: request
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    name.eq_ignore_ascii_case(field).then_some(value.as_bytes())
                })
                .collect(),
        }
    }));
    let variance = base64_ng::URL_SAFE_NO_PAD.encode_string(&material).ok()?;
    Some(format!("{base_key};vary:{variance}"))
}

#[cfg(test)]
mod tests {
    use super::{native_cache_expiry_times, register_native_disk_cache_purge_handle};
    use crate::native_http1_cache::{
        NativeDiskCache, NativeDiskCacheStoreKey, NativeMemoryCacheEntry,
        purge_native_disk_cache_primary,
    };
    use crate::native_http1_proxy_peer_fill::{
        NATIVE_PEER_FILL_MARKER_HEADER, NativePeerFillPeer, native_peer_fill_fetch,
        native_request_is_peer_fill, strip_native_peer_fill_header,
    };
    use crate::native_http1_proxy_peer_fill_auth::{
        NATIVE_PEER_FILL_NONCE_HEADER, NATIVE_PEER_FILL_REQUEST_SIGNATURE_HEADER,
        NATIVE_PEER_FILL_RESPONSE_SIGNATURE_HEADER, NativePeerFillAuth, native_peer_fill_nonce,
        native_peer_fill_request_signature, native_peer_fill_request_signature_matches,
        native_peer_fill_response_signature_matches,
        native_peer_fill_response_without_cache_status, native_peer_fill_sign_response,
        native_response_single_header_value,
    };
    use crate::{NativeHttp1Request, NativeHttp1Response};
    use fluxheim_protocol::Http1Version;
    use sanitization::SecretVec;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    #[test]
    fn native_cache_expiry_times_rejects_unrepresentable_ttl() {
        assert!(native_cache_expiry_times(Instant::now(), Duration::MAX, None, None).is_none());
    }

    #[test]
    fn native_cache_expiry_times_extends_stale_window_from_fresh_expiry() {
        let now = Instant::now();
        let (expires_at, stale_while_revalidate_until, stale_if_error_until) =
            native_cache_expiry_times(now, Duration::from_secs(1), Some(2), Some(3)).unwrap();

        assert!(expires_at > now);
        assert!(
            stale_while_revalidate_until.is_some_and(|stale_while_revalidate_until| {
                stale_while_revalidate_until > expires_at
            })
        );
        assert!(
            stale_if_error_until
                .is_some_and(|stale_if_error_until| stale_if_error_until > expires_at)
        );
    }

    #[test]
    fn strips_client_supplied_peer_fill_marker() {
        let mut request = NativeHttp1Request {
            method: "GET".to_owned(),
            peer_addr: None,
            local_addr: None,
            effective_client_addr: None,
            downstream_tls: false,
            tls_identity: None,
            geo_context: None,
            target: "/asset.png".to_owned(),
            version: Http1Version::Http11,
            headers: vec![
                (NATIVE_PEER_FILL_MARKER_HEADER.to_owned(), "1".to_owned()),
                ("host".to_owned(), "cache.test".to_owned()),
            ],
            body: Zeroizing::new(Vec::new()),
            trailers: Vec::new(),
        };

        assert!(native_request_is_peer_fill(&request));
        strip_native_peer_fill_header(&mut request);

        assert!(!native_request_is_peer_fill(&request));
        assert_eq!(
            request.headers,
            vec![("host".to_owned(), "cache.test".to_owned())]
        );
    }

    #[test]
    fn native_peer_fill_auth_binds_response_body_and_headers() {
        let auth = NativePeerFillAuth {
            secret: Arc::new(SecretVec::from_vec(
                b"0123456789abcdef0123456789abcdef".to_vec(),
            )),
        };
        let nonce = native_peer_fill_nonce();
        let mut request = NativeHttp1Request {
            method: "GET".to_owned(),
            peer_addr: None,
            local_addr: None,
            effective_client_addr: None,
            downstream_tls: false,
            tls_identity: None,
            geo_context: None,
            target: "/asset.css?b=1".to_owned(),
            version: Http1Version::Http11,
            headers: vec![
                ("host".to_owned(), "cache.test".to_owned()),
                (NATIVE_PEER_FILL_MARKER_HEADER.to_owned(), "1".to_owned()),
                ("cache-control".to_owned(), "only-if-cached".to_owned()),
                (NATIVE_PEER_FILL_NONCE_HEADER.to_owned(), nonce.clone()),
            ],
            body: Zeroizing::new(Vec::new()),
            trailers: Vec::new(),
        };
        let signature =
            native_peer_fill_request_signature(&auth, &request.target, &request.headers, &nonce);
        request.headers.push((
            NATIVE_PEER_FILL_REQUEST_SIGNATURE_HEADER.to_owned(),
            signature,
        ));
        assert!(native_peer_fill_request_signature_matches(&auth, &request));

        let mut response = NativeHttp1Response::new(200, "OK", b"safe-body".to_vec())
            .with_header("cache-control", "max-age=60")
            .with_header("content-type", "text/css");
        native_peer_fill_sign_response(&auth, &request, &mut response);

        assert!(native_peer_fill_response_signature_matches(
            &auth, &request, &response
        ));

        let tampered_body = NativeHttp1Response::new(200, "OK", b"evil-body".to_vec())
            .with_header("cache-control", "max-age=60")
            .with_header("content-type", "text/css")
            .with_header(
                NATIVE_PEER_FILL_NONCE_HEADER,
                native_response_single_header_value(&response, NATIVE_PEER_FILL_NONCE_HEADER)
                    .unwrap()
                    .to_owned(),
            )
            .with_header(
                NATIVE_PEER_FILL_RESPONSE_SIGNATURE_HEADER,
                native_response_single_header_value(
                    &response,
                    NATIVE_PEER_FILL_RESPONSE_SIGNATURE_HEADER,
                )
                .unwrap()
                .to_owned(),
            );
        assert!(!native_peer_fill_response_signature_matches(
            &auth,
            &request,
            &tampered_body
        ));

        let unsigned = NativeHttp1Response::new(200, "OK", b"safe-body".to_vec())
            .with_header("cache-control", "max-age=60")
            .with_header("content-type", "text/css");
        assert!(!native_peer_fill_response_signature_matches(
            &auth, &request, &unsigned
        ));
    }

    #[tokio::test]
    async fn native_peer_fill_fetch_discards_unsigned_authenticated_peer_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let peer_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 256];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            assert!(String::from_utf8_lossy(&request).contains("x-fluxheim-peer-fill-nonce: "));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncache-control: max-age=60\r\ncontent-length: 12\r\n\r\npoison-body!",
                )
                .await
                .unwrap();
        });
        let auth = NativePeerFillAuth {
            secret: Arc::new(SecretVec::from_vec(
                b"0123456789abcdef0123456789abcdef".to_vec(),
            )),
        };
        let peer = NativePeerFillPeer {
            name: "forged-peer".to_owned(),
            base_path: String::new(),
            upstream: crate::NativeHttp1Upstream::new(authority),
        };
        let request = NativeHttp1Request {
            method: "GET".to_owned(),
            peer_addr: None,
            local_addr: None,
            effective_client_addr: None,
            downstream_tls: false,
            tls_identity: None,
            geo_context: None,
            target: "/poison.txt".to_owned(),
            version: Http1Version::Http11,
            headers: vec![("host".to_owned(), "cache.test".to_owned())],
            body: Zeroizing::new(Vec::new()),
            trailers: Vec::new(),
        };
        let cache = fluxheim_config::CacheConfig::default();

        let result = native_peer_fill_fetch(&peer, &cache, Some(&auth), &request, 1024)
            .await
            .unwrap();

        assert!(result.is_none());
        peer_task.await.unwrap();
    }

    #[test]
    fn native_peer_fill_response_without_cache_status_strips_internal_auth_headers() {
        let cache = fluxheim_config::CacheConfig::default();
        let response = NativeHttp1Response::new(200, "OK", b"safe-body".to_vec())
            .with_header(NATIVE_PEER_FILL_NONCE_HEADER, "nonce")
            .with_header(NATIVE_PEER_FILL_RESPONSE_SIGNATURE_HEADER, "signature")
            .with_header("content-type", "text/plain");

        let response = native_peer_fill_response_without_cache_status(response, &cache);

        assert!(
            native_response_single_header_value(&response, NATIVE_PEER_FILL_NONCE_HEADER).is_none()
        );
        assert!(
            native_response_single_header_value(
                &response,
                NATIVE_PEER_FILL_RESPONSE_SIGNATURE_HEADER
            )
            .is_none()
        );
        assert_eq!(
            native_response_single_header_value(&response, "content-type"),
            Some("text/plain")
        );
    }

    #[test]
    fn native_storage_bin_disk_purge_uses_live_cache_instance() {
        let root = tempfile::tempdir().unwrap();
        let mut config = fluxheim_config::CacheConfig {
            enabled: true,
            memory: fluxheim_config::CacheMemoryConfig {
                enabled: false,
                ..Default::default()
            },
            disk: fluxheim_config::CacheDiskConfig {
                enabled: true,
                path: Some(root.path().to_path_buf()),
                backend: fluxheim_config::CacheDiskBackend::StorageBin,
                max_size_bytes: fluxheim_config::ByteSize::from_bytes(1024 * 1024),
                ..Default::default()
            },
            ..Default::default()
        };
        config.disk.storage_bin.bin_size_bytes = fluxheim_config::ByteSize::from_bytes(64 * 1024);
        let cache = Arc::new(NativeDiskCache::from_config(&config).unwrap());
        let vhost = Arc::<str>::from("purge.test");
        register_native_disk_cache_purge_handle(vhost.clone(), None, &cache);

        let now = Instant::now();
        let entry = NativeMemoryCacheEntry {
            status: 200,
            reason: "OK".to_owned(),
            headers: vec![
                ("content-type".to_owned(), "image/png".to_owned()),
                ("cache-control".to_owned(), "max-age=60".to_owned()),
                ("content-length".to_owned(), "11".to_owned()),
                ("surrogate-key".to_owned(), "purge-live".to_owned()),
            ],
            content_length: Some(11),
            body: Arc::from(&b"hello-cache"[..]),
            expires_at: now + Duration::from_secs(60),
            stale_while_revalidate_until: None,
            stale_if_error_until: None,
            stored_at: now,
            weight: 128,
        };
        let key = NativeDiskCacheStoreKey {
            combined: "combined-live".to_owned(),
            primary: "primary-live".to_owned(),
            user_tag: vhost.to_string(),
            index_path: Some("/asset.png".to_owned()),
            cache_tags: vec!["purge-live".to_owned()],
            vary_fields: Vec::new(),
        };
        cache.store(key, &entry).unwrap();
        assert!(cache.get("combined-live", |_| None).is_some());
        assert_eq!(cache.stats().purge_index_entries, 1);

        assert!(purge_native_disk_cache_primary(
            "purge.test",
            None,
            "primary-live",
            "combined-live"
        ));
        assert!(cache.get("combined-live", |_| None).is_none());
        assert_eq!(cache.stats().purge_index_entries, 0);
    }
}
