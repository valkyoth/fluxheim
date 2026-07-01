use crate::{NativeHttp1Proxy, NativeHttp1StaticWeb};

pub(crate) fn native_cache_policy_enabled(cache: &fluxheim_config::CacheConfig) -> bool {
    cache.enabled || cache.local_static
}

pub(crate) fn native_vhost_cache_policy_blocked(vhost: &fluxheim_config::VhostConfig) -> bool {
    if !native_cache_policy_enabled(&vhost.cache) {
        return false;
    }
    !vhost_native_cache_supported(vhost)
}

pub(crate) fn native_route_cache_policy_blocked(route: &fluxheim_config::RouteConfig) -> bool {
    route.cache.as_ref().is_some_and(|cache| {
        if !native_cache_policy_enabled(cache) {
            return false;
        }
        !route_native_cache_supported(route, cache)
    })
}

pub(crate) fn root_native_cache_supported(config: &fluxheim_config::Config) -> bool {
    (config.web.enabled() && NativeHttp1StaticWeb::cache_supported(&config.cache))
        || (config.proxy.has_configured_upstream()
            && NativeHttp1Proxy::proxy_cache_supported_for_proxy(&config.cache, &config.proxy))
}

fn vhost_native_cache_supported(vhost: &fluxheim_config::VhostConfig) -> bool {
    (vhost.web.enabled() && NativeHttp1StaticWeb::cache_supported(&vhost.cache))
        || (vhost.proxy.has_configured_upstream()
            && NativeHttp1Proxy::proxy_cache_supported_for_proxy(&vhost.cache, &vhost.proxy))
}

fn route_native_cache_supported(
    route: &fluxheim_config::RouteConfig,
    cache: &fluxheim_config::CacheConfig,
) -> bool {
    route
        .web
        .as_ref()
        .is_some_and(|web| web.enabled() && NativeHttp1StaticWeb::cache_supported(cache))
        || route.proxy.as_ref().is_some_and(|proxy| {
            proxy.has_configured_upstream()
                && NativeHttp1Proxy::proxy_cache_supported_for_proxy(cache, proxy)
        })
}
