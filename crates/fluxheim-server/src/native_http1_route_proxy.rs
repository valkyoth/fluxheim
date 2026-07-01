use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

#[cfg(feature = "acme")]
use fluxheim_config::{AcmeChallenge, Config};
use fluxheim_config::{
    GrpcRouteConfig, HeaderPolicyConfig, HttpsRedirectConfig, ResponseHeaderPolicyOverlayConfig,
};
#[cfg(not(feature = "privacy-mode"))]
use fluxheim_headers::effective_client_ip;
use fluxheim_protocol::route_method_matches;

#[cfg(feature = "acme")]
use crate::NativeHttp1AcmeHttp01Store;
use crate::native_http1_route_action::{NativeHttp1RouteAction, write_takeover_rejection};
use crate::native_http1_route_cache_policy::{
    native_cache_policy_enabled, native_route_cache_policy_blocked,
    native_vhost_cache_policy_blocked, root_native_cache_supported,
};
#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
use crate::native_http1_route_compression::{
    apply_native_response_compression, apply_route_compression,
};
use crate::native_http1_route_grpc::native_grpc_rejection_response;
use crate::native_http1_route_limits::{
    NativeConcurrencyLimit, NativeConcurrencyPermit, NativeIpAccessPolicy, NativeRateLimit,
    NativeRateLimitDecision, decoded_route_policy_path,
};
use crate::native_http1_route_matcher::{NativeHttp1RouteMatcher, NativeRegexRouteMatcher};
#[cfg(feature = "php-fpm")]
use crate::native_http1_route_php::NativePhpFpmRoute;
#[cfg(feature = "load-balancer")]
use crate::native_http1_route_proxy_upstream::NativeLoadBalancerCollectors;
use crate::native_http1_route_proxy_upstream::{
    NativeProxyBuildRequest, native_proxy_from_config_collecting_load_balancer,
};
use crate::native_http1_route_redirect::{NativeHttp1RouteRedirect, https_redirect_response};
#[cfg(not(feature = "privacy-mode"))]
use crate::native_http1_route_request_headers::joined_header_value;
use crate::native_http1_route_request_headers::{
    NativeRequestHeaderTemplateContext, NativeRouteRequestHeaderPolicy,
    default_native_request_header_policy,
};
use crate::native_http1_route_response_headers::NativeRouteResponseHeaderPolicy;
use crate::native_http1_route_rewrite::{
    NativeRouteRewritePolicy, request_path_and_query, rewrite_route_request,
};
#[cfg(feature = "otel-tracing")]
use crate::native_http1_route_trace::{NativeTracePropagation, apply_native_route_traceparent};
use crate::{
    DownstreamHttp1Policy, NativeHttp1ConnectionStream, NativeHttp1Error, NativeHttp1Handler,
    NativeHttp1Proxy, NativeHttp1ProxyConfigError, NativeHttp1Request, NativeHttp1Response,
    NativeHttp1StaticWeb, ProxyProtocolTrustedSource,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1RouteProxy {
    routes: Vec<NativeHttp1RouteProxyRoute>,
    fallback: Option<NativeHttp1Proxy>,
    fallback_web: Option<NativeHttp1StaticWeb>,
    #[cfg(feature = "php-fpm")]
    fallback_php: Option<NativePhpFpmRoute>,
    fallback_response_headers: NativeRouteResponseHeaderPolicy,
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    fallback_compression: Option<fluxheim_config::CompressionConfig>,
    access: NativeIpAccessPolicy,
    rate_limit: NativeRateLimit,
    concurrency: NativeConcurrencyLimit,
    max_request_body_bytes: Option<u64>,
    https_redirect: HttpsRedirectConfig,
    #[cfg(feature = "otel-tracing")]
    trace_propagation: NativeTracePropagation,
    #[cfg(not(feature = "privacy-mode"))]
    trusted_sources: Vec<ProxyProtocolTrustedSource>,
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
    methods: Vec<String>,
    matcher: NativeHttp1RouteMatcher,
    strip_prefix: Option<String>,
    rewrite_prefix: Option<String>,
    rewrite_template: Option<String>,
    max_request_body_bytes: Option<u64>,
    https_redirect_exempt: bool,
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    compression: Option<fluxheim_config::CompressionConfig>,
    request_headers: NativeRouteRequestHeaderPolicy,
    response_headers: NativeRouteResponseHeaderPolicy,
    access: NativeIpAccessPolicy,
    rate_limit: NativeRateLimit,
    concurrency: NativeConcurrencyLimit,
    grpc: GrpcRouteConfig,
    action: NativeHttp1RouteAction,
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

impl NativeHttp1RouteProxy {
    pub fn new(
        routes: Vec<NativeHttp1RouteProxyRoute>,
        fallback: Option<NativeHttp1Proxy>,
    ) -> Self {
        Self {
            routes,
            fallback,
            fallback_web: None,
            #[cfg(feature = "php-fpm")]
            fallback_php: None,
            fallback_response_headers: NativeRouteResponseHeaderPolicy::default(),
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            fallback_compression: None,
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            max_request_body_bytes: None,
            https_redirect: HttpsRedirectConfig::default(),
            #[cfg(feature = "otel-tracing")]
            trace_propagation: NativeTracePropagation::default(),
            #[cfg(not(feature = "privacy-mode"))]
            trusted_sources: Vec::new(),
        }
    }

    pub fn from_root_config(
        config: &fluxheim_config::Config,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        Self::from_root_config_with_load_balancer_services(
            config,
            policy,
            pool_max_idle,
            #[cfg(feature = "load-balancer")]
            None,
            #[cfg(feature = "load-balancer")]
            None,
        )
    }

    pub(crate) fn from_root_config_with_load_balancer_services(
        config: &fluxheim_config::Config,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
        #[cfg(feature = "load-balancer")] load_balancer_services: Option<
            &mut Vec<fluxheim_load_balancer::UpstreamLoadBalancerService>,
        >,
        #[cfg(feature = "load-balancer")] load_balancer_admin_pools: Option<
            &mut Vec<crate::NativeLoadBalancerAdminPool>,
        >,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        if native_cache_policy_enabled(&config.cache) && !root_native_cache_supported(config) {
            return Err(NativeHttp1RouteProxyConfigError::Proxy(
                NativeHttp1ProxyConfigError::CachePolicy,
            ));
        }
        let fallback_web = if config.web.enabled() {
            let cache =
                NativeHttp1StaticWeb::cache_supported(&config.cache).then_some(&config.cache);
            NativeHttp1StaticWeb::from_config_with_cache(&config.web, cache)
                .map_err(|_| NativeHttp1RouteProxyConfigError::StaticWeb)?
        } else {
            None
        };
        let fallback = native_proxy_from_config_collecting_load_balancer(
            NativeProxyBuildRequest {
                name: "root proxy",
                vhost: "root",
                route: None,
                proxy: &config.proxy,
                policy,
                pool_max_idle,
            },
            #[cfg(feature = "load-balancer")]
            NativeLoadBalancerCollectors::new(load_balancer_services, load_balancer_admin_pools),
        )?
        .map(|proxy| {
            let proxy = proxy.with_header_policy(&config.headers);
            if NativeHttp1Proxy::proxy_cache_supported_for_proxy(&config.cache, &config.proxy) {
                proxy.with_proxy_cache_config_for(&config.cache, "root", None)
            } else {
                proxy
            }
        });
        if fallback_web.is_none() && fallback.is_none() {
            return Err(NativeHttp1RouteProxyConfigError::MissingRouteAction);
        }
        let mut proxy = Self::new(Vec::new(), fallback);
        proxy.fallback_web = fallback_web;
        proxy.https_redirect = config.server.https_redirect;
        #[cfg(feature = "otel-tracing")]
        {
            proxy.trace_propagation = NativeTracePropagation::from_config(&config.tracing);
        }
        proxy.fallback_response_headers =
            NativeRouteResponseHeaderPolicy::from_policy(&config.headers.response);
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        if config.compression.enabled {
            proxy.fallback_compression = Some(config.compression.clone());
        }
        Ok(proxy)
    }

    pub fn routes(&self) -> &[NativeHttp1RouteProxyRoute] {
        &self.routes
    }

    pub fn fallback(&self) -> Option<&NativeHttp1Proxy> {
        self.fallback.as_ref()
    }

    pub(crate) fn with_https_redirect(mut self, https_redirect: HttpsRedirectConfig) -> Self {
        self.https_redirect = https_redirect;
        self
    }

    #[cfg(feature = "otel-tracing")]
    pub(crate) const fn with_trace_config(
        mut self,
        tracing: &fluxheim_config::TracingConfig,
    ) -> Self {
        self.trace_propagation = NativeTracePropagation::from_config(tracing);
        self
    }

    #[cfg(feature = "acme")]
    pub fn from_config(
        config: &Config,
        vhost: &fluxheim_config::VhostConfig,
        base_headers: &HeaderPolicyConfig,
        inherited_compression: Option<&fluxheim_config::CompressionConfig>,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        Self::from_config_with_trusted_sources(
            config,
            vhost,
            base_headers,
            inherited_compression,
            policy,
            pool_max_idle,
            &[],
        )
    }

    #[cfg(feature = "acme")]
    pub fn from_config_with_trusted_sources(
        config: &Config,
        vhost: &fluxheim_config::VhostConfig,
        base_headers: &HeaderPolicyConfig,
        inherited_compression: Option<&fluxheim_config::CompressionConfig>,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
        #[cfg_attr(feature = "privacy-mode", allow(unused_variables))]
        trusted_sources: &[ProxyProtocolTrustedSource],
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        Self::from_config_with_build_context(
            config,
            vhost,
            NativeRouteProxyBuildContext::new(
                base_headers,
                inherited_compression,
                policy,
                pool_max_idle,
                trusted_sources,
            ),
            #[cfg(feature = "load-balancer")]
            NativeLoadBalancerCollectors::none(),
        )
    }

    #[cfg(feature = "acme")]
    pub(crate) fn from_config_with_build_context(
        config: &Config,
        vhost: &fluxheim_config::VhostConfig,
        context: NativeRouteProxyBuildContext<'_>,
        #[cfg(feature = "load-balancer")] collectors: NativeLoadBalancerCollectors<'_>,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        let mut proxy = Self::from_vhost_config_with_build_context(
            vhost,
            context,
            #[cfg(feature = "load-balancer")]
            collectors,
        )?;
        proxy.https_redirect = config.server.https_redirect;
        #[cfg(feature = "otel-tracing")]
        {
            proxy.trace_propagation = NativeTracePropagation::from_config(&config.tracing);
        }
        if let Some(route) = native_managed_http_01_route(config, vhost, context.base_headers)? {
            proxy.routes.insert(0, route);
        }
        Ok(proxy)
    }

    pub fn from_vhost_config(
        vhost: &fluxheim_config::VhostConfig,
        base_headers: &HeaderPolicyConfig,
        inherited_compression: Option<&fluxheim_config::CompressionConfig>,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        Self::from_vhost_config_with_trusted_sources(
            vhost,
            base_headers,
            inherited_compression,
            policy,
            pool_max_idle,
            &[],
        )
    }

    pub fn from_vhost_config_with_trusted_sources(
        vhost: &fluxheim_config::VhostConfig,
        base_headers: &HeaderPolicyConfig,
        inherited_compression: Option<&fluxheim_config::CompressionConfig>,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
        #[cfg_attr(feature = "privacy-mode", allow(unused_variables))]
        trusted_sources: &[ProxyProtocolTrustedSource],
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        Self::from_vhost_config_with_trusted_sources_and_load_balancer_services(
            vhost,
            NativeRouteProxyBuildContext::new(
                base_headers,
                inherited_compression,
                policy,
                pool_max_idle,
                trusted_sources,
            ),
            #[cfg(feature = "load-balancer")]
            NativeLoadBalancerCollectors::none(),
        )
    }

    pub(crate) fn from_vhost_config_with_trusted_sources_and_load_balancer_services(
        vhost: &fluxheim_config::VhostConfig,
        context: NativeRouteProxyBuildContext<'_>,
        #[cfg(feature = "load-balancer")] collectors: NativeLoadBalancerCollectors<'_>,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        Self::from_vhost_config_with_build_context(
            vhost,
            context,
            #[cfg(feature = "load-balancer")]
            collectors,
        )
    }

    pub(crate) fn from_vhost_config_with_build_context(
        vhost: &fluxheim_config::VhostConfig,
        context: NativeRouteProxyBuildContext<'_>,
        #[cfg(feature = "load-balancer")] mut collectors: NativeLoadBalancerCollectors<'_>,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        if native_vhost_cache_policy_blocked(vhost) {
            return Err(NativeHttp1RouteProxyConfigError::Proxy(
                NativeHttp1ProxyConfigError::CachePolicy,
            ));
        }
        let headers = context.base_headers.with_vhost_overlay(&vhost.headers);
        let inherited_compression = vhost.compression.as_ref().or(context.inherited_compression);
        let fallback_web = if vhost.web.enabled() {
            let cache = NativeHttp1StaticWeb::cache_supported(&vhost.cache).then_some(&vhost.cache);
            NativeHttp1StaticWeb::from_config_with_cache(&vhost.web, cache)
                .map_err(|_| NativeHttp1RouteProxyConfigError::StaticWeb)?
        } else {
            None
        };
        #[cfg(feature = "php-fpm")]
        let fallback_php = NativePhpFpmRoute::from_config(
            format!("vhost {}", vhost.name),
            &vhost.name,
            "default",
            &vhost.php,
        )?;
        #[cfg(not(feature = "php-fpm"))]
        if vhost.php.enabled {
            return Err(NativeHttp1RouteProxyConfigError::Proxy(
                NativeHttp1ProxyConfigError::PhpFpm,
            ));
        }
        let access = NativeIpAccessPolicy::from_config(&vhost.access)?;
        let rate_limit = NativeRateLimit::from_config(&vhost.rate_limit);
        let concurrency = NativeConcurrencyLimit::from_config(&vhost.concurrency);
        let fallback = native_proxy_from_config_collecting_load_balancer(
            NativeProxyBuildRequest {
                name: &vhost.name,
                vhost: &vhost.name,
                route: None,
                proxy: &vhost.proxy,
                policy: context.policy,
                pool_max_idle: context.pool_max_idle,
            },
            #[cfg(feature = "load-balancer")]
            collectors.reborrow(),
        )?;
        let fallback = fallback.map(|proxy| {
            let proxy = proxy.with_header_policy(&headers);
            if NativeHttp1Proxy::proxy_cache_supported_for_proxy(&vhost.cache, &vhost.proxy) {
                proxy.with_proxy_cache_config_for(&vhost.cache, &vhost.name, None)
            } else {
                proxy
            }
        });
        #[cfg(not(feature = "privacy-mode"))]
        let fallback = fallback.map(|proxy| proxy.with_trusted_sources(context.trusted_sources));
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        let fallback = fallback.map(|proxy| {
            if let Some(compression) = inherited_compression.cloned() {
                proxy.with_compression_config(compression)
            } else {
                proxy
            }
        });

        let mut routes = Vec::new();
        for route in vhost
            .acme_challenge
            .route_config()
            .into_iter()
            .chain(vhost.routes.iter().cloned())
            .chain(vhost.redirect.route_config())
        {
            let proxy = if let Some(proxy_config) = route.proxy.as_ref() {
                let proxy = native_proxy_from_config_collecting_load_balancer(
                    NativeProxyBuildRequest {
                        name: &format!("{} route {}", vhost.name, route.name),
                        vhost: &vhost.name,
                        route: Some(&route.name),
                        proxy: proxy_config,
                        policy: context.policy,
                        pool_max_idle: context.pool_max_idle,
                    },
                    #[cfg(feature = "load-balancer")]
                    collectors.reborrow(),
                )?;
                #[cfg(not(feature = "privacy-mode"))]
                let proxy = proxy.map(|proxy| proxy.with_trusted_sources(context.trusted_sources));
                proxy.map(|proxy| {
                    if let Some(cache) = route.cache.as_ref().filter(|cache| {
                        NativeHttp1Proxy::proxy_cache_supported_for_proxy(cache, proxy_config)
                    }) {
                        proxy.with_proxy_cache_config_for(cache, &vhost.name, Some(&route.name))
                    } else {
                        proxy
                    }
                })
            } else {
                None
            };
            let route = NativeHttp1RouteProxyRoute::from_config_with_inherited(
                &route,
                proxy,
                &headers,
                inherited_compression,
                &vhost.name,
            )?;
            #[cfg(not(feature = "privacy-mode"))]
            let route = route.with_trusted_sources(context.trusted_sources);
            routes.push(route);
        }

        Ok(Self {
            routes,
            fallback,
            fallback_web,
            #[cfg(feature = "php-fpm")]
            fallback_php,
            fallback_response_headers: NativeRouteResponseHeaderPolicy::from_policy(
                &headers.response,
            ),
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            fallback_compression: inherited_compression.cloned(),
            access,
            rate_limit,
            concurrency,
            max_request_body_bytes: vhost.max_request_body_bytes.map(|bytes| bytes.as_u64()),
            https_redirect: HttpsRedirectConfig::default(),
            #[cfg(feature = "otel-tracing")]
            trace_propagation: NativeTracePropagation::default(),
            #[cfg(not(feature = "privacy-mode"))]
            trusted_sources: context.trusted_sources.to_vec(),
        })
    }
}

#[cfg(feature = "acme")]
fn native_managed_http_01_route(
    config: &Config,
    vhost: &fluxheim_config::VhostConfig,
    base_headers: &HeaderPolicyConfig,
) -> Result<Option<NativeHttp1RouteProxyRoute>, NativeHttp1RouteProxyConfigError> {
    if vhost.acme_challenge.enabled
        || !config.tls.acme.enabled
        || config.tls.acme.challenge != AcmeChallenge::Http01
    {
        return Ok(None);
    }

    let Some(storage) = config.tls.acme.storage.as_deref() else {
        return Err(NativeHttp1RouteProxyConfigError::AcmeStorage);
    };
    let Some(owner) = native_managed_http_01_owner_vhost(config, vhost) else {
        return Ok(None);
    };

    Ok(Some(NativeHttp1RouteProxyRoute::acme_http_01(
        owner,
        storage,
        base_headers,
    )))
}

#[cfg(feature = "acme")]
fn native_managed_http_01_owner_vhost<'a>(
    config: &'a Config,
    request_vhost: &'a fluxheim_config::VhostConfig,
) -> Option<&'a str> {
    if request_vhost.tls.enabled && request_vhost.tls.acme.enabled {
        return Some(&request_vhost.name);
    }

    let request_hosts: std::collections::HashSet<String> = request_vhost
        .hosts
        .iter()
        .filter_map(|host| fluxheim_config::config_net::normalize_host(host))
        .collect();
    if request_hosts.is_empty() {
        return None;
    }

    config.vhosts.iter().find_map(|candidate| {
        if !candidate.tls.enabled || !candidate.tls.acme.enabled {
            return None;
        }

        let domains: Box<dyn Iterator<Item = &str> + '_> = if candidate.tls.acme.domains.is_empty()
        {
            Box::new(candidate.hosts.iter().map(String::as_str))
        } else {
            Box::new(candidate.tls.acme.domains.iter().map(String::as_str))
        };

        for domain in domains {
            let Some(domain) = fluxheim_config::config_net::normalize_host(domain) else {
                continue;
            };
            if request_hosts.contains(&domain) {
                return Some(candidate.name.as_str());
            }
        }

        None
    })
}

impl NativeHttp1RouteProxyRoute {
    pub fn exact(path: impl Into<String>, methods: Vec<String>, proxy: NativeHttp1Proxy) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Exact(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::Proxy(Box::new(proxy.without_header_policy())),
        }
    }

    pub fn prefix(path: impl Into<String>, methods: Vec<String>, proxy: NativeHttp1Proxy) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Prefix(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::Proxy(Box::new(proxy.without_header_policy())),
        }
    }

    pub fn fallback(proxy: NativeHttp1Proxy) -> Self {
        Self {
            methods: Vec::new(),
            matcher: NativeHttp1RouteMatcher::Fallback,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::Proxy(Box::new(proxy.without_header_policy())),
        }
    }

    pub fn exact_redirect(
        path: impl Into<String>,
        methods: Vec<String>,
        to: impl Into<String>,
        status: u16,
    ) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Exact(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::Redirect(NativeHttp1RouteRedirect {
                to: to.into(),
                status,
            }),
        }
    }

    pub fn prefix_redirect(
        path: impl Into<String>,
        methods: Vec<String>,
        to: impl Into<String>,
        status: u16,
    ) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Prefix(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::Redirect(NativeHttp1RouteRedirect {
                to: to.into(),
                status,
            }),
        }
    }

    pub fn prefix_static_web(
        path: impl Into<String>,
        methods: Vec<String>,
        web: NativeHttp1StaticWeb,
    ) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Prefix(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::StaticWeb(Box::new(web)),
        }
    }

    #[cfg(feature = "acme")]
    fn acme_http_01(
        vhost_name: &str,
        storage: &std::path::Path,
        base_headers: &HeaderPolicyConfig,
    ) -> Self {
        Self {
            methods: Vec::new(),
            matcher: NativeHttp1RouteMatcher::Prefix("/.well-known/acme-challenge/".to_owned()),
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: true,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: NativeRouteRequestHeaderPolicy::from_policy(&base_headers.request),
            response_headers: NativeRouteResponseHeaderPolicy::from_policy(&base_headers.response),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::AcmeHttp01(NativeHttp1AcmeHttp01Store::new(
                storage, vhost_name,
            )),
        }
    }

    pub fn from_config(
        route: &fluxheim_config::RouteConfig,
        proxy: Option<NativeHttp1Proxy>,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        Self::from_config_with_inherited(route, proxy, &HeaderPolicyConfig::default(), None, "")
    }

    pub fn from_config_with_inherited(
        route: &fluxheim_config::RouteConfig,
        proxy: Option<NativeHttp1Proxy>,
        base_headers: &HeaderPolicyConfig,
        inherited_compression: Option<&fluxheim_config::CompressionConfig>,
        #[cfg_attr(not(feature = "php-fpm"), allow(unused_variables))] vhost_name: &str,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        if native_route_cache_policy_blocked(route) {
            return Err(NativeHttp1RouteProxyConfigError::Proxy(
                NativeHttp1ProxyConfigError::CachePolicy,
            ));
        }
        #[cfg(not(feature = "php-fpm"))]
        if route.php.as_ref().is_some_and(|php| php.enabled) {
            return Err(NativeHttp1RouteProxyConfigError::Proxy(
                NativeHttp1ProxyConfigError::PhpFpm,
            ));
        }
        #[cfg(not(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        )))]
        let _ = inherited_compression;
        let matcher = if let Some(path) = &route.path_exact {
            NativeHttp1RouteMatcher::Exact(path.clone())
        } else if let Some(path) = &route.path_prefix {
            NativeHttp1RouteMatcher::Prefix(path.clone())
        } else if let Some(pattern) = &route.path_regex {
            NativeHttp1RouteMatcher::Regex(
                NativeRegexRouteMatcher::from_pattern(pattern)
                    .map_err(|_| NativeHttp1RouteProxyConfigError::RegexRoute)?,
            )
        } else if route.fallback {
            NativeHttp1RouteMatcher::Fallback
        } else {
            return Err(NativeHttp1RouteProxyConfigError::MissingRouteAction);
        };
        let action = if let Some(redirect) = &route.redirect {
            NativeHttp1RouteAction::Redirect(NativeHttp1RouteRedirect {
                to: redirect.to.clone(),
                status: redirect.status,
            })
        } else if let Some(php) = route.php.as_ref().filter(|php| php.enabled) {
            #[cfg(feature = "php-fpm")]
            {
                NativeHttp1RouteAction::PhpFpm(Box::new(
                    NativePhpFpmRoute::from_config(
                        format!("route {}", route.name),
                        vhost_name,
                        &route.name,
                        php,
                    )?
                    .ok_or(NativeHttp1RouteProxyConfigError::MissingRouteAction)?,
                ))
            }
            #[cfg(not(feature = "php-fpm"))]
            {
                let _ = php;
                return Err(NativeHttp1RouteProxyConfigError::Proxy(
                    NativeHttp1ProxyConfigError::PhpFpm,
                ));
            }
        } else if let Some(web) = route.web.as_ref().filter(|web| web.enabled()) {
            NativeHttp1RouteAction::StaticWeb(Box::new(
                NativeHttp1StaticWeb::from_config_with_cache(web, route.cache.as_ref())
                    .map_err(|_| NativeHttp1RouteProxyConfigError::StaticWeb)?
                    .ok_or(NativeHttp1RouteProxyConfigError::MissingRouteAction)?,
            ))
        } else {
            NativeHttp1RouteAction::Proxy(Box::new(
                proxy
                    .ok_or(NativeHttp1RouteProxyConfigError::MissingRouteAction)?
                    .without_header_policy(),
            ))
        };
        let headers = base_headers.with_vhost_overlay(&route.headers);
        Ok(Self {
            methods: route.methods.clone(),
            matcher,
            strip_prefix: route.strip_prefix.clone(),
            rewrite_prefix: route.rewrite_prefix.clone(),
            rewrite_template: route.rewrite_template.clone(),
            max_request_body_bytes: route.max_request_body_bytes.map(|bytes| bytes.as_u64()),
            https_redirect_exempt: route.https_redirect_exempt,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: route
                .compression
                .clone()
                .or_else(|| inherited_compression.cloned()),
            request_headers: NativeRouteRequestHeaderPolicy::from_policy(&headers.request),
            response_headers: NativeRouteResponseHeaderPolicy::from_policy(&headers.response),
            access: NativeIpAccessPolicy::from_config(&route.access)?,
            rate_limit: NativeRateLimit::from_config(&route.rate_limit),
            concurrency: NativeConcurrencyLimit::from_config(&route.concurrency),
            grpc: route.grpc,
            action,
        })
    }

    pub fn with_strip_prefix(mut self, strip_prefix: impl Into<String>) -> Self {
        self.strip_prefix = Some(strip_prefix.into());
        self
    }

    pub fn with_rewrite_prefix(mut self, rewrite_prefix: impl Into<String>) -> Self {
        self.rewrite_prefix = Some(rewrite_prefix.into());
        self
    }

    pub const fn with_max_request_body_bytes(mut self, max_request_body_bytes: u64) -> Self {
        self.max_request_body_bytes = Some(max_request_body_bytes);
        self
    }

    #[cfg(test)]
    pub const fn with_grpc_policy(mut self, grpc: GrpcRouteConfig) -> Self {
        self.grpc = grpc;
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

    pub fn with_response_header_policy(
        mut self,
        response_headers: &ResponseHeaderPolicyOverlayConfig,
    ) -> Self {
        // Programmatic builders apply overlays over the safe default response
        // policy. Config-built routes should use from_config_with_inherited()
        // when root/vhost policy inheritance is required.
        self.response_headers = NativeRouteResponseHeaderPolicy::from_overlay(response_headers);
        self
    }

    #[cfg(not(feature = "privacy-mode"))]
    pub fn with_trusted_sources(mut self, trusted_sources: &[ProxyProtocolTrustedSource]) -> Self {
        self.request_headers
            .set_trusted_sources(trusted_sources.to_vec());
        self
    }

    pub fn with_request_header_policy(
        mut self,
        request_headers: &fluxheim_config::RequestHeaderPolicyOverlayConfig,
    ) -> Self {
        // Programmatic builders apply overlays over the safe default request
        // policy. Config-built routes should use from_config_with_inherited()
        // when root/vhost policy inheritance is required.
        self.request_headers = NativeRouteRequestHeaderPolicy::from_overlay(request_headers);
        self
    }

    pub fn proxy(&self) -> Option<&NativeHttp1Proxy> {
        self.action.proxy()
    }

    pub fn is_redirect(&self) -> bool {
        self.action.is_redirect()
    }

    fn https_redirect_exempt_or_redirect(&self) -> bool {
        self.https_redirect_exempt || self.is_redirect() || self.action.https_redirect_exempt()
    }

    pub fn is_static_web(&self) -> bool {
        self.action.is_static_web()
    }
}

impl NativeHttp1Handler for NativeHttp1RouteProxy {
    fn handle<'a>(
        &'a self,
        mut request: NativeHttp1Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp1Response> + Send + 'a>> {
        Box::pin(async move {
            let Some((path, query)) = request_path_and_query(&request) else {
                return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                    .close_connection();
            };
            let selected_route = self.select_route(&request.method, &path);
            let decoded_policy_route = self.select_decoded_policy_route(&request.method, &path);
            if selected_route.is_none()
                && self.fallback_web.is_none()
                && self.fallback.is_none()
                && {
                    #[cfg(feature = "php-fpm")]
                    {
                        self.fallback_php.is_none()
                    }
                    #[cfg(not(feature = "php-fpm"))]
                    {
                        true
                    }
                }
            {
                return NativeHttp1Response::new(404, "Not Found", b"not found\n")
                    .close_connection();
            }
            let client_ip = self.access_client_ip(&request);
            let tls_identity = request.tls_identity.as_ref();
            let geo_context = request.geo_context.as_ref();
            if !self.access.allows(client_ip, tls_identity, geo_context)
                || selected_route
                    .is_some_and(|route| !route.access.allows(client_ip, tls_identity, geo_context))
                || decoded_policy_route
                    .is_some_and(|route| !route.access.allows(client_ip, tls_identity, geo_context))
            {
                return NativeHttp1Response::new(403, "Forbidden", b"forbidden\n")
                    .close_connection();
            }
            if !selected_route
                .is_some_and(NativeHttp1RouteProxyRoute::https_redirect_exempt_or_redirect)
                && let Some(response) = https_redirect_response(
                    &request,
                    &self.https_redirect,
                    &self.fallback_response_headers,
                )
            {
                return response;
            }
            let concurrency_route = decoded_policy_route.or(selected_route);
            // Delay-mode rate limiting sleeps are still live downstream work.
            // Count them against concurrency so an attacker cannot park
            // unlimited delayed tasks outside the configured vhost/route cap.
            let _concurrency_permits =
                match self.acquire_concurrency_permits(concurrency_route).await {
                    Ok(permits) => permits,
                    Err(status) => {
                        return NativeHttp1Response::new(
                            status,
                            "Too Many Requests",
                            b"too many requests\n",
                        )
                        .close_connection();
                    }
                };
            match self.check_rate_limits(concurrency_route, client_ip) {
                NativeRateLimitDecision::Allow => {}
                NativeRateLimitDecision::Delay(delay) => {
                    tokio::time::sleep(delay).await;
                }
                NativeRateLimitDecision::Reject(status) => {
                    return NativeHttp1Response::new(
                        status,
                        "Too Many Requests",
                        b"rate limited\n",
                    )
                    .close_connection();
                }
            }
            if let Some(route) = selected_route {
                if let Some(response) = native_grpc_rejection_response(&route.grpc, &request) {
                    return response;
                }
                let rewrite_policy = NativeRouteRewritePolicy::new(
                    &route.matcher,
                    route.strip_prefix.as_deref(),
                    route.rewrite_prefix.as_deref(),
                    route.rewrite_template.as_deref(),
                );
                let mut request =
                    match rewrite_route_request(request, rewrite_policy, &path, query.as_deref()) {
                        Some(request) => request,
                        None => {
                            return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                                .close_connection();
                        }
                    };
                if route
                    .max_request_body_bytes
                    .or(self.max_request_body_bytes)
                    .is_some_and(|limit| (request.body.len() as u64) > limit)
                {
                    return NativeHttp1Response::new(
                        413,
                        "Payload Too Large",
                        b"payload too large\n",
                    )
                    .close_connection();
                }
                let header_context = NativeRequestHeaderTemplateContext::from_captures(
                    route.matcher.header_captures(&path),
                );
                self.apply_traceparent(&mut request);
                route
                    .request_headers
                    .apply(&mut request, Some(&header_context));
                return route.handle(request).await;
            }
            #[cfg(feature = "php-fpm")]
            if let Some(php) = &self.fallback_php
                && let Some(resolved) = php.resolve_for_fallback(&path)
            {
                return php.handle_resolved(request, path, resolved).await;
            }
            if let Some(response) = self.fallback_web_response(&request, &path) {
                return response;
            }
            #[cfg(feature = "php-fpm")]
            if let Some(php) = &self.fallback_php {
                return php.handle(request).await;
            }
            if let Some(proxy) = &self.fallback {
                self.apply_traceparent(&mut request);
                return proxy.handle(request).await;
            }
            NativeHttp1Response::new(404, "Not Found", b"not found\n").close_connection()
        })
    }

    fn request_body_timeout(&self, request: &NativeHttp1Request) -> Option<Duration> {
        let (path, _) = request_path_and_query(request)?;
        if let Some(route) = self.select_route(&request.method, &path) {
            return route.request_body_timeout();
        }
        #[cfg(feature = "php-fpm")]
        if let Some(php) = &self.fallback_php {
            return Some(Duration::from_secs(php.request_timeout_secs()));
        }
        self.fallback
            .as_ref()
            .and_then(NativeHttp1Proxy::request_body_timeout)
    }

    fn handles_connection_takeover(&self, request: &NativeHttp1Request) -> bool {
        let Some((path, _)) = request_path_and_query(request) else {
            return false;
        };
        if let Some(route) = self.select_route(&request.method, &path) {
            return route.handles_connection_takeover(request);
        }
        self.fallback
            .as_ref()
            .is_some_and(|proxy| proxy.handles_connection_takeover(request))
    }

    fn handle_connection_takeover<'a>(
        &'a self,
        request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        stream: NativeHttp1ConnectionStream,
    ) -> Pin<Box<dyn Future<Output = Result<(), NativeHttp1Error>> + Send + 'a>> {
        Box::pin(async move {
            self.handle_connection_takeover_inner(request, prebuffered, stream)
                .await
        })
    }
}

impl NativeHttp1RouteProxy {
    async fn handle_connection_takeover_inner(
        &self,
        request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        mut stream: NativeHttp1ConnectionStream,
    ) -> Result<(), NativeHttp1Error> {
        let Some((path, query)) = request_path_and_query(&request) else {
            return write_takeover_rejection(&mut stream, 400, "Bad Request", b"bad request\n")
                .await;
        };
        let selected_route = self.select_route(&request.method, &path);
        let decoded_policy_route = self.select_decoded_policy_route(&request.method, &path);
        if selected_route.is_none() && self.fallback.is_none() && {
            #[cfg(feature = "php-fpm")]
            {
                self.fallback_php.is_none()
            }
            #[cfg(not(feature = "php-fpm"))]
            {
                true
            }
        } {
            return write_takeover_rejection(&mut stream, 404, "Not Found", b"not found\n").await;
        }
        let client_ip = self.access_client_ip(&request);
        let tls_identity = request.tls_identity.as_ref();
        let geo_context = request.geo_context.as_ref();
        if !self.access.allows(client_ip, tls_identity, geo_context)
            || selected_route
                .is_some_and(|route| !route.access.allows(client_ip, tls_identity, geo_context))
            || decoded_policy_route
                .is_some_and(|route| !route.access.allows(client_ip, tls_identity, geo_context))
        {
            return write_takeover_rejection(&mut stream, 403, "Forbidden", b"forbidden\n").await;
        }
        let concurrency_route = decoded_policy_route.or(selected_route);
        let concurrency_permits = match self.acquire_concurrency_permits(concurrency_route).await {
            Ok(permits) => permits,
            Err(status) => {
                return write_takeover_rejection(
                    &mut stream,
                    status,
                    "Too Many Requests",
                    b"too many requests\n",
                )
                .await;
            }
        };
        match self.check_rate_limits(concurrency_route, client_ip) {
            NativeRateLimitDecision::Allow => {}
            NativeRateLimitDecision::Delay(delay) => tokio::time::sleep(delay).await,
            NativeRateLimitDecision::Reject(status) => {
                return write_takeover_rejection(
                    &mut stream,
                    status,
                    "Too Many Requests",
                    b"rate limited\n",
                )
                .await;
            }
        }
        drop(concurrency_permits);
        if let Some(route) = selected_route {
            let rewrite_policy = NativeRouteRewritePolicy::new(
                &route.matcher,
                route.strip_prefix.as_deref(),
                route.rewrite_prefix.as_deref(),
                route.rewrite_template.as_deref(),
            );
            let mut request =
                match rewrite_route_request(request, rewrite_policy, &path, query.as_deref()) {
                    Some(request) => request,
                    None => {
                        return write_takeover_rejection(
                            &mut stream,
                            400,
                            "Bad Request",
                            b"bad request\n",
                        )
                        .await;
                    }
                };
            if route
                .max_request_body_bytes
                .or(self.max_request_body_bytes)
                .is_some_and(|limit| (request.body.len() as u64) > limit)
            {
                return write_takeover_rejection(
                    &mut stream,
                    413,
                    "Payload Too Large",
                    b"payload too large\n",
                )
                .await;
            }
            let header_context = NativeRequestHeaderTemplateContext::from_captures(
                route.matcher.header_captures(&path),
            );
            route
                .request_headers
                .apply(&mut request, Some(&header_context));
            return route
                .handle_connection_takeover(request, prebuffered, stream)
                .await;
        }
        if let Some(proxy) = &self.fallback {
            return proxy
                .handle_connection_takeover(request, prebuffered, stream)
                .await;
        }
        #[cfg(feature = "php-fpm")]
        if self.fallback_php.is_some() {
            return write_takeover_rejection(
                &mut stream,
                400,
                "Bad Request",
                b"unsupported upgrade target\n",
            )
            .await;
        }
        write_takeover_rejection(&mut stream, 404, "Not Found", b"not found\n").await
    }

    fn fallback_web_response(
        &self,
        request: &NativeHttp1Request,
        path: &str,
    ) -> Option<NativeHttp1Response> {
        let web = self.fallback_web.as_ref()?;
        let mut response = web.handle_optional(request, path)?;
        self.fallback_response_headers.apply(&mut response);
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        if let Some(compression) = &self.fallback_compression {
            apply_native_response_compression(request, &mut response, compression);
        }
        Some(response)
    }
}

impl NativeHttp1RouteProxy {
    fn select_route(&self, method: &str, path: &str) -> Option<&NativeHttp1RouteProxyRoute> {
        self.select_route_with_fallback(method, path, true)
    }

    fn select_decoded_policy_route(
        &self,
        method: &str,
        path: &str,
    ) -> Option<&NativeHttp1RouteProxyRoute> {
        decoded_route_policy_path(path)
            .as_deref()
            .and_then(|decoded_path| self.select_route_with_fallback(method, decoded_path, false))
    }

    fn select_route_with_fallback(
        &self,
        method: &str,
        path: &str,
        include_fallback: bool,
    ) -> Option<&NativeHttp1RouteProxyRoute> {
        let mut fallback = None;
        let mut best_prefix = None;
        let mut first_regex = None;
        for route in &self.routes {
            if !route_method_matches(&route.methods, method) {
                continue;
            }
            match &route.matcher {
                NativeHttp1RouteMatcher::Exact(exact) if path == exact => return Some(route),
                NativeHttp1RouteMatcher::Prefix(_) if route.matcher.is_match(path) => {
                    if best_prefix
                        .map(|best: &NativeHttp1RouteProxyRoute| {
                            route.prefix_len() > best.prefix_len()
                        })
                        .unwrap_or(true)
                    {
                        best_prefix = Some(route);
                    }
                }
                NativeHttp1RouteMatcher::Regex(_)
                    if first_regex.is_none() && route.matcher.is_match(path) =>
                {
                    first_regex = Some(route);
                }
                NativeHttp1RouteMatcher::Fallback if include_fallback => fallback = Some(route),
                _ => {}
            }
        }
        best_prefix.or(first_regex).or(fallback)
    }

    fn access_client_ip(&self, request: &NativeHttp1Request) -> Option<IpAddr> {
        if let Some(addr) = request.effective_client_addr {
            return Some(addr.ip());
        }
        let direct_ip = request.peer_addr.map(|addr| addr.ip());
        #[cfg(not(feature = "privacy-mode"))]
        {
            let original_x_forwarded_for = joined_header_value(request, "x-forwarded-for");
            let trusted_direct_peer = direct_ip.is_some_and(|ip| self.trusted_source_contains(ip));
            let trusted_proxy_matcher = |ip| self.trusted_source_contains(ip);
            direct_ip.map(|ip| {
                effective_client_ip(
                    ip,
                    trusted_direct_peer,
                    original_x_forwarded_for.as_deref(),
                    Some(&trusted_proxy_matcher),
                )
            })
        }
        #[cfg(feature = "privacy-mode")]
        {
            direct_ip
        }
    }

    #[cfg(feature = "otel-tracing")]
    fn apply_traceparent(&self, request: &mut NativeHttp1Request) {
        let trusted_peer = self.trace_trusted_peer(request);
        apply_native_route_traceparent(request, self.trace_propagation, trusted_peer);
    }

    #[cfg(feature = "otel-tracing")]
    fn trace_trusted_peer(&self, request: &NativeHttp1Request) -> bool {
        #[cfg(not(feature = "privacy-mode"))]
        {
            request
                .peer_addr
                .is_some_and(|addr| self.trusted_source_contains(addr.ip()))
        }
        #[cfg(feature = "privacy-mode")]
        {
            let _ = request;
            false
        }
    }

    #[cfg(not(feature = "otel-tracing"))]
    fn apply_traceparent(&self, _request: &mut NativeHttp1Request) {}

    #[cfg(not(feature = "privacy-mode"))]
    fn trusted_source_contains(&self, address: IpAddr) -> bool {
        self.trusted_sources
            .iter()
            .any(|source| source.contains(address))
    }

    fn check_rate_limits(
        &self,
        route: Option<&NativeHttp1RouteProxyRoute>,
        client_ip: Option<IpAddr>,
    ) -> NativeRateLimitDecision {
        let mut delay = None;
        match self.rate_limit.check(client_ip) {
            NativeRateLimitDecision::Allow => {}
            NativeRateLimitDecision::Delay(vhost_delay) => delay = Some(vhost_delay),
            decision => return decision,
        }
        if let Some(route) = route {
            match route.rate_limit.check(client_ip) {
                NativeRateLimitDecision::Allow => {}
                NativeRateLimitDecision::Delay(route_delay) => {
                    delay = Some(
                        delay.map_or(route_delay, |current: Duration| current.max(route_delay)),
                    );
                }
                decision => return decision,
            }
        }

        delay
            .map(NativeRateLimitDecision::Delay)
            .unwrap_or(NativeRateLimitDecision::Allow)
    }

    async fn acquire_concurrency_permits(
        &self,
        route: Option<&NativeHttp1RouteProxyRoute>,
    ) -> Result<Vec<NativeConcurrencyPermit>, u16> {
        let mut permits = Vec::with_capacity(2);
        if let Some(permit) = self.concurrency.acquire().await? {
            permits.push(permit);
        }
        if let Some(route) = route
            && let Some(permit) = route.concurrency.acquire().await?
        {
            permits.push(permit);
        }
        Ok(permits)
    }
}

impl NativeHttp1RouteProxyRoute {
    fn request_body_timeout(&self) -> Option<Duration> {
        self.action.request_body_timeout()
    }

    fn prefix_len(&self) -> usize {
        self.matcher.prefix_len()
    }

    async fn handle(&self, request: NativeHttp1Request) -> NativeHttp1Response {
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        let compression_request = self.compression.as_ref().map(|_| request.clone());
        let mut response = self.action.handle(request).await;
        self.response_headers.apply(&mut response);
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        if let Some(compression) = &self.compression
            && let Some(compression_request) = compression_request.as_ref()
        {
            apply_route_compression(compression_request, &mut response, compression);
        }
        response
    }

    fn handles_connection_takeover(&self, request: &NativeHttp1Request) -> bool {
        self.action.handles_connection_takeover(request)
    }

    async fn handle_connection_takeover(
        &self,
        request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        stream: NativeHttp1ConnectionStream,
    ) -> Result<(), NativeHttp1Error> {
        self.action
            .handle_connection_takeover(request, prebuffered, stream)
            .await
    }
}
