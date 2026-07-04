#[cfg(feature = "acme")]
use fluxheim_config::Config;
use fluxheim_config::{HeaderPolicyConfig, HttpsRedirectConfig};

use crate::native_http1_route_cache_policy::{
    native_cache_policy_enabled, native_vhost_cache_policy_blocked, root_native_cache_supported,
};
use crate::native_http1_route_limits::{
    NativeConcurrencyLimit, NativeIpAccessPolicy, NativeRateLimit,
};
#[cfg(feature = "php-fpm")]
use crate::native_http1_route_php::NativePhpFpmRoute;
#[cfg(feature = "acme")]
use crate::native_http1_route_proxy_acme::native_managed_http_01_route;
pub(crate) use crate::native_http1_route_proxy_types::NativeRouteProxyBuildContext;
pub use crate::native_http1_route_proxy_types::{
    NativeHttp1RouteProxy, NativeHttp1RouteProxyConfigError, NativeHttp1RouteProxyRoute,
};
#[cfg(feature = "load-balancer")]
use crate::native_http1_route_proxy_upstream::NativeLoadBalancerCollectors;
use crate::native_http1_route_proxy_upstream::{
    NativeProxyBuildRequest, native_proxy_from_config_collecting_load_balancer,
};
use crate::native_http1_route_response_headers::NativeRouteResponseHeaderPolicy;
#[cfg(feature = "otel-tracing")]
use crate::native_http1_route_trace::NativeTracePropagation;
#[cfg(feature = "wasm")]
use crate::native_http1_route_wasm::NativeWasmHooks;
use crate::{
    DownstreamHttp1Policy, NativeHttp1Proxy, NativeHttp1ProxyConfigError, NativeHttp1StaticWeb,
    ProxyProtocolTrustedSource,
};

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
            #[cfg(feature = "wasm")]
            wasm_hooks: NativeWasmHooks::default(),
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
            context.clone(),
            #[cfg(feature = "load-balancer")]
            collectors,
        )?;
        proxy.https_redirect = config.server.https_redirect;
        #[cfg(feature = "otel-tracing")]
        {
            proxy.trace_propagation = NativeTracePropagation::from_config(&config.tracing);
        }
        #[cfg(feature = "wasm")]
        if let Some(registry) = context.wasm_registry {
            proxy.wasm_hooks = registry.hooks_for(&vhost.name, None);
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
            #[cfg(feature = "wasm")]
            let route = if let Some(registry) = context.wasm_registry {
                let route_name = route.name.clone();
                route.with_wasm_hooks(registry.hooks_for(&vhost.name, Some(&route_name)))
            } else {
                route
            };
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
            #[cfg(feature = "wasm")]
            wasm_hooks: context
                .wasm_registry
                .map(|registry| registry.hooks_for(&vhost.name, None))
                .unwrap_or_default(),
        })
    }
}
