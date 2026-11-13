use fluxheim_cache::{CacheKeyPreviewScope, NativeCachePreviewRequest};
use fluxheim_config::{CacheConfig, Config, ProxyConfig, RouteConfig, VhostConfig};

pub(super) struct PreviewSelection<'a> {
    pub vhost: Option<&'a VhostConfig>,
    pub route: Option<&'a RouteConfig>,
    pub cache: Option<&'a CacheConfig>,
    pub proxy: Option<&'a ProxyConfig>,
    pub root: bool,
}

impl<'a> PreviewSelection<'a> {
    pub fn new(config: &'a Config, request: &NativeCachePreviewRequest) -> Self {
        if config.vhosts.is_empty() {
            return Self {
                vhost: None,
                route: None,
                cache: Some(&config.cache),
                proxy: Some(&config.proxy),
                root: true,
            };
        }
        let host = request
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok());
        let vhost = select_vhost(config, host);
        let route = vhost.and_then(|vhost| {
            super::native_cache_preview_route(
                &vhost.routes,
                request.method.as_str(),
                request.uri.path(),
            )
        });
        // A matching route owns its action and does not inherit the fallback cache.
        let (cache, proxy) = if let Some(route) = route {
            (route.cache.as_ref(), route.proxy.as_ref())
        } else {
            (vhost.map(|v| &v.cache), vhost.map(|v| &v.proxy))
        };
        Self {
            vhost,
            route,
            cache,
            proxy,
            root: false,
        }
    }

    pub fn scope(&self) -> CacheKeyPreviewScope {
        if self.root {
            CacheKeyPreviewScope::Root
        } else if self.route.is_some() {
            CacheKeyPreviewScope::Route
        } else {
            CacheKeyPreviewScope::Vhost
        }
    }

    pub fn runtime_identity(&self) -> &str {
        if self.root {
            "root"
        } else {
            self.vhost.map_or("", |v| v.name.as_str())
        }
    }
}

fn select_vhost<'a>(config: &'a Config, host: Option<&str>) -> Option<&'a VhostConfig> {
    let host = host.and_then(|host| fluxheim_config::normalize_host(host.trim()));
    if let Some(host) = host {
        let mut wildcard = None;
        let mut suffix_len = 0;
        for vhost in &config.vhosts {
            for pattern in &vhost.hosts {
                let Some(pattern) = fluxheim_config::normalize_host_pattern(pattern) else {
                    continue;
                };
                if pattern == host {
                    return Some(vhost);
                }
                if let Some(suffix) = pattern.strip_prefix("*.")
                    && host.len() > suffix.len() + 1
                    && host.ends_with(suffix)
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
                    && suffix.len() > suffix_len
                {
                    wildcard = Some(vhost);
                    suffix_len = suffix.len();
                }
            }
        }
        if wildcard.is_some() {
            return wildcard;
        }
    }
    if config.server.host_routing.strict {
        return None;
    }
    match config.server.default_vhost.as_deref() {
        Some(name) => config.vhosts.iter().find(|vhost| vhost.name == name),
        None => config.vhosts.first(),
    }
}
