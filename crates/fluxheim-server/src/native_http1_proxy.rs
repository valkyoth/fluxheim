use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

#[cfg(feature = "auth-request")]
use crate::native_http1_proxy_auth::NativeAuthRequest;
pub use crate::native_http1_proxy_config_error::NativeHttp1ProxyConfigError;
use crate::native_http1_proxy_error_page::NativeHttp1ProxyErrorPage;
use crate::native_http1_proxy_memory_cache::NativeProxyMemoryCache;
#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
use crate::native_http1_proxy_mirror::NativeTrafficMirror;
use crate::native_http1_route_request_headers::NativeRouteRequestHeaderPolicy;
use crate::native_http1_route_response_headers::NativeRouteResponseHeaderPolicy;
use crate::{NativeHttp1ResponseWritePolicy, NativeHttp1Upstream};

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
