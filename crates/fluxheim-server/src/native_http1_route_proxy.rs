#[cfg(feature = "acme")]
use fluxheim_config::{AcmeChallenge, Config};
use fluxheim_config::{GrpcRouteConfig, HeaderPolicyConfig, HttpsRedirectConfig};

use crate::native_http1_route_action::NativeHttp1RouteAction;
use crate::native_http1_route_cache_policy::{
    native_cache_policy_enabled, native_vhost_cache_policy_blocked, root_native_cache_supported,
};
use crate::native_http1_route_limits::{
    NativeConcurrencyLimit, NativeIpAccessPolicy, NativeRateLimit,
};
use crate::native_http1_route_matcher::NativeHttp1RouteMatcher;
#[cfg(feature = "php-fpm")]
use crate::native_http1_route_php::NativePhpFpmRoute;
#[cfg(feature = "load-balancer")]
use crate::native_http1_route_proxy_upstream::NativeLoadBalancerCollectors;
use crate::native_http1_route_proxy_upstream::{
    NativeProxyBuildRequest, native_proxy_from_config_collecting_load_balancer,
};
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
