use crate::native_http1_cache::native_disk_cache_supported;
use crate::native_http1_proxy::NativeHttp1Proxy;
use crate::native_http1_proxy_memory_cache::NativeProxyMemoryCache;
use crate::native_http1_proxy_peer_fill::native_peer_fill_supported;
use fluxheim_config::CacheConfig;

impl NativeHttp1Proxy {
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
}

fn native_slice_cache_supported_for_proxy(
    cache: &CacheConfig,
    proxy: &fluxheim_config::ProxyConfig,
) -> bool {
    !cache.range.slice.enabled || proxy.configured_primary_upstream().is_some()
}
