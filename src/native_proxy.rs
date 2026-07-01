use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(feature = "cache")]
mod cache_purge;
#[cfg(feature = "cache")]
mod cache_snapshot;
#[cfg(feature = "cache")]
mod cache_stats;
#[cfg(feature = "load-balancer")]
mod load_balancer;

#[cfg(feature = "cache")]
pub use cache_snapshot::NativeProxySnapshot;
#[cfg(feature = "cache")]
use cache_stats::{
    native_cache_activity_reset_result_from_config, native_cache_runtime_stats_from_config,
    overlay_native_cache_runtime_totals,
};
#[cfg(feature = "cache")]
use fluxheim_cache::{CacheActivityResetResult, CacheRuntimeStats};

#[derive(Clone)]
pub struct FluxProxy {
    config: Arc<Mutex<crate::config::Config>>,
    #[cfg(feature = "load-balancer")]
    load_balancer_admin_pools: Vec<fluxheim_server::NativeLoadBalancerAdminPool>,
}

impl FluxProxy {
    pub fn from_config(_config: &crate::config::Config) -> io::Result<Self> {
        Ok(Self {
            config: Arc::new(Mutex::new(_config.clone())),
            #[cfg(feature = "load-balancer")]
            load_balancer_admin_pools: Vec::new(),
        })
    }

    pub fn from_config_with_native_load_balancers(
        _config: &crate::config::Config,
        #[cfg(feature = "load-balancer")] load_balancer_admin_pools: Vec<
            fluxheim_server::NativeLoadBalancerAdminPool,
        >,
    ) -> io::Result<Self> {
        Ok(Self {
            config: Arc::new(Mutex::new(_config.clone())),
            #[cfg(feature = "load-balancer")]
            load_balancer_admin_pools,
        })
    }

    pub fn reload_from_config(&self, _config: &crate::config::Config) -> io::Result<()> {
        let mut config = self.lock_config("reload")?;
        *config = _config.clone();
        Ok(())
    }

    fn lock_config(
        &self,
        context: &'static str,
    ) -> io::Result<MutexGuard<'_, crate::config::Config>> {
        self.config.lock().map_err(|_| {
            io::Error::other(format!(
                "native proxy configuration lock poisoned during {context}"
            ))
        })
    }

    fn lock_config_or_abort(&self, context: &'static str) -> MutexGuard<'_, crate::config::Config> {
        self.config.lock().unwrap_or_else(|error| {
            log::error!(
                target: "fluxheim::native_proxy",
                "native proxy configuration mutex poisoned during {context}: {error}"
            );
            std::process::abort();
        })
    }

    pub fn has_health_reporter(&self) -> bool {
        false
    }

    pub fn route_host(&self, host: Option<&str>) -> String {
        let config = self.lock_config_or_abort("route_host");
        let normalized = host
            .and_then(fluxheim_config::config_net::normalize_host)
            .unwrap_or_default();
        config
            .vhosts
            .iter()
            .find(|vhost| {
                vhost
                    .hosts
                    .iter()
                    .filter_map(|host| fluxheim_config::config_net::normalize_host_pattern(host))
                    .any(|candidate| candidate == normalized)
            })
            .or_else(|| {
                config
                    .server
                    .default_vhost
                    .as_deref()
                    .and_then(|name| config.vhosts.iter().find(|vhost| vhost.name == name))
            })
            .or_else(|| config.vhosts.first())
            .map(|vhost| vhost.name.clone())
            .unwrap_or_default()
    }

    #[cfg(feature = "cache")]
    pub fn snapshot(&self) -> NativeProxySnapshot {
        let config = self.lock_config_or_abort("cache snapshot");
        NativeProxySnapshot {
            config: config.clone(),
        }
    }

    #[cfg(feature = "cache")]
    pub fn cache_runtime_stats(&self) -> io::Result<CacheRuntimeStats> {
        let config = self.lock_config("cache runtime stats")?;
        let mut stats = native_cache_runtime_stats_from_config(&config);
        let native = fluxheim_server::native_cache_runtime_totals();
        overlay_native_cache_runtime_totals(&mut stats.totals, &native);
        Ok(stats)
    }

    #[cfg(feature = "cache")]
    pub fn reset_cache_activity(&self) -> CacheActivityResetResult {
        let config = self.lock_config_or_abort("cache activity reset");
        native_cache_activity_reset_result_from_config(&config)
    }
}

#[cfg(feature = "cache")]
fn native_cache_preview_route<'a>(
    routes: &'a [crate::config::RouteConfig],
    method: &str,
    path: &str,
) -> Option<&'a crate::config::RouteConfig> {
    let mut fallback = None;
    let mut best_prefix = None;
    let mut first_regex = None;
    for route in routes {
        if !fluxheim_protocol::route_method_matches(&route.methods, method) {
            continue;
        }
        if route
            .path_exact
            .as_deref()
            .is_some_and(|exact| path == exact)
        {
            return Some(route);
        }
        if let Some(prefix) = route.path_prefix.as_deref()
            && fluxheim_protocol::route_prefix_matches_path(prefix, path)
            && best_prefix
                .map(|best: &crate::config::RouteConfig| {
                    route.path_prefix.as_ref().map_or(0, String::len)
                        > best.path_prefix.as_ref().map_or(0, String::len)
                })
                .unwrap_or(true)
        {
            best_prefix = Some(route);
        }
        if first_regex.is_none()
            && route
                .path_regex
                .as_deref()
                .is_some_and(|pattern| native_route_regex_matches(pattern, path))
        {
            first_regex = Some(route);
        }
        if route.fallback {
            fallback = Some(route);
        }
    }
    best_prefix.or(first_regex).or(fallback)
}

#[cfg(feature = "cache")]
fn native_vhost_matches_host(vhost: &crate::config::VhostConfig, host: &str) -> bool {
    let Some(normalized_host) = fluxheim_config::config_net::normalize_host(host) else {
        return false;
    };
    vhost
        .hosts
        .iter()
        .filter_map(|host| fluxheim_config::config_net::normalize_host_pattern(host))
        .any(|candidate| candidate == normalized_host)
}

#[cfg(feature = "cache")]
fn native_route_regex_matches(pattern: &str, path: &str) -> bool {
    regex::RegexBuilder::new(pattern)
        .size_limit(fluxheim_config::MAX_ROUTE_REGEX_PROGRAM_BYTES)
        .dfa_size_limit(fluxheim_config::MAX_ROUTE_REGEX_PROGRAM_BYTES)
        .build()
        .map(|regex| regex.is_match(path))
        .unwrap_or(false)
}

#[cfg(all(test, feature = "cache"))]
mod tests {
    use super::*;

    fn test_config(toml: &str) -> crate::config::Config {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn route_host_normalizes_candidate_host() {
        let config = test_config(
            r#"
            [server]
            default_vhost = "fallback"

            [[vhosts]]
            name = "fallback"
            hosts = ["fallback.example"]

            [[vhosts]]
            name = "example"
            hosts = ["example.com"]
            "#,
        );
        let proxy = FluxProxy::from_config(&config).unwrap();

        assert_eq!(proxy.route_host(Some("EXAMPLE.COM:80")), "example");
    }

    #[test]
    fn cache_config_for_request_normalizes_host() {
        let config = test_config(
            r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.com"]

            [vhosts.cache]
            enabled = true
            "#,
        );
        let proxy = FluxProxy::from_config(&config).unwrap();

        let selection = proxy
            .cache_config_for_request(None, None, "EXAMPLE.COM:80")
            .unwrap();

        assert_eq!(selection.vhost_name, "example");
        assert_eq!(selection.route_name, None);
    }

    #[test]
    fn reload_updates_route_cache_stats_and_snapshot_config() {
        let initial = test_config(
            r#"
            [server]
            default_vhost = "old"

            [[vhosts]]
            name = "old"
            hosts = ["old.example"]

            [vhosts.cache]
            enabled = true
            "#,
        );
        let reloaded = test_config(
            r#"
            [server]
            default_vhost = "new"

            [[vhosts]]
            name = "new"
            hosts = ["new.example"]

            [vhosts.cache]
            enabled = true
            key_namespace = "new-vhost-cache"

            [[vhosts.routes]]
            name = "images"
            path_regex = "^/images/[0-9]+[.]png$"

            [vhosts.routes.cache]
            enabled = true
            key_namespace = "new-route-cache"
            "#,
        );
        let proxy = FluxProxy::from_config(&initial).unwrap();

        proxy.reload_from_config(&reloaded).unwrap();

        assert_eq!(proxy.route_host(Some("NEW.EXAMPLE:80")), "new");
        let selection = proxy
            .cache_config_for_request(None, None, "NEW.EXAMPLE:80")
            .unwrap();
        assert_eq!(selection.vhost_name, "new");
        assert_eq!(
            selection.cache.key_namespace.as_deref(),
            Some("new-vhost-cache")
        );
        assert!(
            proxy
                .cache_config_for_request(Some("old"), None, "old.example")
                .is_err()
        );

        let stats = proxy.cache_runtime_stats().unwrap();
        assert_eq!(stats.vhosts.len(), 1);
        assert_eq!(stats.vhosts[0].name, "new");
        assert_eq!(stats.vhosts[0].routes[0].name, "images");

        let mut request =
            crate::http_types::NativeCachePreviewRequest::build("GET", b"/images/42.png", None)
                .unwrap();
        request.insert_header("host", "NEW.EXAMPLE:80").unwrap();
        let preview = proxy
            .snapshot()
            .native_image_cache_key_preview_for_request(&request);
        assert_eq!(preview.vhost, "new");
        assert_eq!(preview.route.as_deref(), Some("images"));
    }

    #[test]
    fn cache_key_preview_normalizes_host_and_matches_regex_route() {
        let config = test_config(
            r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.com"]

            [vhosts.cache]
            enabled = true
            key_namespace = "vhost-cache"

            [[vhosts.routes]]
            name = "images"
            path_regex = "^/images/[0-9]+[.]png$"

            [vhosts.routes.cache]
            enabled = true
            key_namespace = "image-route-cache"
            "#,
        );
        let proxy = FluxProxy::from_config(&config).unwrap();
        let mut request =
            crate::http_types::NativeCachePreviewRequest::build("GET", b"/images/42.png", None)
                .unwrap();
        request.insert_header("host", "EXAMPLE.COM:80").unwrap();

        let preview = proxy
            .snapshot()
            .native_image_cache_key_preview_for_request(&request);

        assert_eq!(preview.vhost, "example");
        assert_eq!(preview.route.as_deref(), Some("images"));
        assert_eq!(preview.scope, fluxheim_cache::CacheKeyPreviewScope::Route);
    }
}
