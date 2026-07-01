use fluxheim_config::{GrpcRouteConfig, HeaderPolicyConfig, HttpsRedirectConfig};

use crate::native_http1_route_action::NativeHttp1RouteAction;
use crate::native_http1_route_limits::{
    NativeConcurrencyLimit, NativeIpAccessPolicy, NativeRateLimit,
};
use crate::native_http1_route_matcher::NativeHttp1RouteMatcher;
#[cfg(feature = "php-fpm")]
use crate::native_http1_route_php::NativePhpFpmRoute;
use crate::native_http1_route_request_headers::NativeRouteRequestHeaderPolicy;
use crate::native_http1_route_response_headers::NativeRouteResponseHeaderPolicy;
#[cfg(feature = "otel-tracing")]
use crate::native_http1_route_trace::NativeTracePropagation;
use crate::{
    DownstreamHttp1Policy, NativeHttp1Proxy, NativeHttp1ProxyConfigError, NativeHttp1StaticWeb,
    ProxyProtocolTrustedSource,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1RouteProxy {
    pub(crate) routes: Vec<NativeHttp1RouteProxyRoute>,
    pub(crate) fallback: Option<NativeHttp1Proxy>,
    pub(crate) fallback_web: Option<NativeHttp1StaticWeb>,
    #[cfg(feature = "php-fpm")]
    pub(crate) fallback_php: Option<NativePhpFpmRoute>,
    pub(crate) fallback_response_headers: NativeRouteResponseHeaderPolicy,
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    pub(crate) fallback_compression: Option<fluxheim_config::CompressionConfig>,
    pub(crate) access: NativeIpAccessPolicy,
    pub(crate) rate_limit: NativeRateLimit,
    pub(crate) concurrency: NativeConcurrencyLimit,
    pub(crate) max_request_body_bytes: Option<u64>,
    pub(crate) https_redirect: HttpsRedirectConfig,
    #[cfg(feature = "otel-tracing")]
    pub(crate) trace_propagation: NativeTracePropagation,
    #[cfg(not(feature = "privacy-mode"))]
    pub(crate) trusted_sources: Vec<ProxyProtocolTrustedSource>,
}

#[derive(Clone, Copy)]
pub(crate) struct NativeRouteProxyBuildContext<'a> {
    pub(crate) base_headers: &'a HeaderPolicyConfig,
    pub(crate) inherited_compression: Option<&'a fluxheim_config::CompressionConfig>,
    pub(crate) policy: DownstreamHttp1Policy,
    pub(crate) pool_max_idle: usize,
    #[cfg_attr(feature = "privacy-mode", allow(dead_code))]
    pub(crate) trusted_sources: &'a [ProxyProtocolTrustedSource],
}

impl<'a> NativeRouteProxyBuildContext<'a> {
    pub(crate) fn new(
        base_headers: &'a HeaderPolicyConfig,
        inherited_compression: Option<&'a fluxheim_config::CompressionConfig>,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
        trusted_sources: &'a [ProxyProtocolTrustedSource],
    ) -> Self {
        Self {
            base_headers,
            inherited_compression,
            policy,
            pool_max_idle,
            trusted_sources,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1RouteProxyRoute {
    pub(crate) methods: Vec<String>,
    pub(crate) matcher: NativeHttp1RouteMatcher,
    pub(crate) strip_prefix: Option<String>,
    pub(crate) rewrite_prefix: Option<String>,
    pub(crate) rewrite_template: Option<String>,
    pub(crate) max_request_body_bytes: Option<u64>,
    pub(crate) https_redirect_exempt: bool,
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    pub(crate) compression: Option<fluxheim_config::CompressionConfig>,
    pub(crate) request_headers: NativeRouteRequestHeaderPolicy,
    pub(crate) response_headers: NativeRouteResponseHeaderPolicy,
    pub(crate) access: NativeIpAccessPolicy,
    pub(crate) rate_limit: NativeRateLimit,
    pub(crate) concurrency: NativeConcurrencyLimit,
    pub(crate) grpc: GrpcRouteConfig,
    pub(crate) action: NativeHttp1RouteAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHttp1RouteProxyConfigError {
    AccessPolicy,
    #[cfg(feature = "acme")]
    AcmeStorage,
    MissingRouteAction,
    Proxy(NativeHttp1ProxyConfigError),
    RegexRoute,
    StaticWeb,
}

impl std::fmt::Display for NativeHttp1RouteProxyConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessPolicy => {
                formatter.write_str("native route proxy access policy configuration error")
            }
            #[cfg(feature = "acme")]
            Self::AcmeStorage => {
                formatter.write_str("native route proxy ACME storage is not configured")
            }
            Self::MissingRouteAction => {
                formatter.write_str("native route proxy requires an action")
            }
            Self::Proxy(error) => write!(formatter, "{error}"),
            Self::RegexRoute => {
                formatter.write_str("native route proxy regex route configuration error")
            }
            Self::StaticWeb => formatter.write_str("native route static web config is invalid"),
        }
    }
}

impl std::error::Error for NativeHttp1RouteProxyConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Proxy(error) => Some(error),
            Self::AccessPolicy | Self::MissingRouteAction | Self::RegexRoute | Self::StaticWeb => {
                None
            }
            #[cfg(feature = "acme")]
            Self::AcmeStorage => None,
        }
    }
}
