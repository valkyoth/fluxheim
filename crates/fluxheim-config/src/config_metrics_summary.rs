use std::collections::BTreeMap;

use crate::config::Config;
use crate::config_cache::CacheConfig;
use crate::config_proxy::ProxyConfig;

#[derive(Debug, Default, Eq, PartialEq)]
pub struct CacheConfigStats {
    pub vhosts: u64,
    pub enabled_vhosts: u64,
    pub tiered_vhosts: u64,
    pub configured_routes: u64,
    pub policy_routes: u64,
    pub enabled_routes: u64,
    pub tiered_routes: u64,
    pub memory_tiers: u64,
    pub disk_tiers: u64,
    pub lock_enabled_policies: u64,
    pub lock_wait_timeout_max_secs: u64,
    pub peer_fill_enabled_policies: u64,
    pub peer_fill_peers: u64,
    pub peer_fill_max_concurrent_requests: u64,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct LoadBalancerConfigStats {
    pub pools_by_scope_selection: BTreeMap<(&'static str, &'static str), u64>,
}

pub fn cache_config_stats(config: &Config) -> CacheConfigStats {
    let mut stats = CacheConfigStats {
        vhosts: config.vhosts.len() as u64,
        ..CacheConfigStats::default()
    };
    for vhost in &config.vhosts {
        accumulate_cache_policy(&vhost.cache, true, &mut stats);
        stats.configured_routes = stats
            .configured_routes
            .saturating_add(vhost.routes.len() as u64);
        for route in &vhost.routes {
            let Some(cache) = &route.cache else {
                continue;
            };
            stats.policy_routes = stats.policy_routes.saturating_add(1);
            accumulate_cache_policy(cache, false, &mut stats);
        }
    }
    stats
}

pub fn load_balancer_config_stats(config: &Config) -> LoadBalancerConfigStats {
    let mut stats = LoadBalancerConfigStats::default();
    if config.vhosts.is_empty() {
        accumulate_load_balancer_pool(&config.proxy, "vhost", &mut stats);
        return stats;
    }
    for vhost in &config.vhosts {
        accumulate_load_balancer_pool(&vhost.proxy, "vhost", &mut stats);
        for route in &vhost.routes {
            if let Some(proxy) = &route.proxy {
                accumulate_load_balancer_pool(proxy, "route", &mut stats);
            }
        }
    }
    stats
}

fn accumulate_load_balancer_pool(
    proxy: &ProxyConfig,
    scope: &'static str,
    stats: &mut LoadBalancerConfigStats,
) {
    if !load_balancer_pool_configured(proxy) {
        return;
    }
    let selection = proxy.load_balance.selection.metric_label();
    *stats
        .pools_by_scope_selection
        .entry((scope, selection))
        .or_insert(0) += 1;
}

fn load_balancer_pool_configured(proxy: &ProxyConfig) -> bool {
    proxy.upstreams.len() >= 2
        || proxy.upstreams_file.is_some()
        || proxy.upstream_dns_refresh_secs.is_some()
}

fn accumulate_cache_policy(cache: &CacheConfig, vhost_scope: bool, stats: &mut CacheConfigStats) {
    if !cache.enabled {
        return;
    }
    if vhost_scope {
        stats.enabled_vhosts = stats.enabled_vhosts.saturating_add(1);
    } else {
        stats.enabled_routes = stats.enabled_routes.saturating_add(1);
    }
    if cache.memory.enabled {
        stats.memory_tiers = stats.memory_tiers.saturating_add(1);
    }
    if cache.disk.enabled {
        stats.disk_tiers = stats.disk_tiers.saturating_add(1);
    }
    if (cache.memory.enabled || cache.disk.enabled) && cache.lock.enabled {
        stats.lock_enabled_policies = stats.lock_enabled_policies.saturating_add(1);
        stats.lock_wait_timeout_max_secs = stats
            .lock_wait_timeout_max_secs
            .max(cache.lock.wait_timeout_secs);
    }
    if cache.peer_fill.enabled {
        stats.peer_fill_enabled_policies = stats.peer_fill_enabled_policies.saturating_add(1);
        stats.peer_fill_peers = stats
            .peer_fill_peers
            .saturating_add(cache.peer_fill.peers.len() as u64);
        stats.peer_fill_max_concurrent_requests = stats
            .peer_fill_max_concurrent_requests
            .max(cache.peer_fill.max_concurrent_requests as u64);
    }
    if cache.memory.enabled && cache.disk.enabled {
        if vhost_scope {
            stats.tiered_vhosts = stats.tiered_vhosts.saturating_add(1);
        } else {
            stats.tiered_routes = stats.tiered_routes.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{
        CacheConfig, CacheDiskConfig, CacheMemoryConfig, CachePeerConfig, CachePeerFillConfig,
        Config, LoadBalanceConfig, LoadBalanceSelection, ProxyConfig, RouteConfig,
        VhostAcmeChallengeConfig, VhostConfig, VhostHeaderPolicyConfig, VhostRedirectConfig,
        VhostTlsConfig, WebConfig,
    };

    use super::{cache_config_stats, load_balancer_config_stats};

    #[test]
    fn cache_configuration_stats_are_cardinality_safe_aggregates() {
        let stats = cache_config_stats(&cache_metrics_config());
        assert_eq!(stats.vhosts, 1);
        assert_eq!(stats.enabled_vhosts, 1);
        assert_eq!(stats.tiered_vhosts, 1);
        assert_eq!(stats.configured_routes, 2);
        assert_eq!(stats.policy_routes, 1);
        assert_eq!(stats.enabled_routes, 1);
        assert_eq!(stats.tiered_routes, 0);
        assert_eq!(stats.memory_tiers, 2);
        assert_eq!(stats.disk_tiers, 1);
        assert_eq!(stats.lock_enabled_policies, 2);
        assert_eq!(stats.lock_wait_timeout_max_secs, 30);
        assert_eq!(stats.peer_fill_enabled_policies, 2);
        assert_eq!(stats.peer_fill_peers, 3);
        assert_eq!(stats.peer_fill_max_concurrent_requests, 128);
    }

    #[test]
    fn load_balancer_configuration_stats_are_cardinality_safe_aggregates() {
        let stats = load_balancer_config_stats(&load_balancer_metrics_config());

        assert_eq!(
            stats
                .pools_by_scope_selection
                .get(&("vhost", "least_time"))
                .copied(),
            Some(1)
        );
        assert_eq!(
            stats
                .pools_by_scope_selection
                .get(&("route", "consistent_uri_hash"))
                .copied(),
            Some(1)
        );
        assert_eq!(stats.pools_by_scope_selection.values().sum::<u64>(), 2);
    }

    fn cache_metrics_config() -> Config {
        Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                tls: VhostTlsConfig::default(),
                acme_challenge: VhostAcmeChallengeConfig::default(),
                redirect: VhostRedirectConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: CacheMemoryConfig {
                        enabled: true,
                        ..CacheMemoryConfig::default()
                    },
                    disk: CacheDiskConfig {
                        enabled: true,
                        ..CacheDiskConfig::default()
                    },
                    peer_fill: CachePeerFillConfig {
                        enabled: true,
                        peers: vec![
                            CachePeerConfig {
                                name: "cache-a".to_owned(),
                                base_url: "https://cache-a.example:8443".to_owned(),
                            },
                            CachePeerConfig {
                                name: "cache-b".to_owned(),
                                base_url: "https://cache-b.example:8443".to_owned(),
                            },
                        ],
                        max_concurrent_requests: 128,
                        ..CachePeerFillConfig::default()
                    },
                    ..CacheConfig::default()
                },
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: vec![cached_route(), uncached_route()],
            }],
            ..Config::default()
        }
    }

    fn load_balancer_metrics_config() -> Config {
        Config {
            vhosts: vec![VhostConfig {
                name: "lb".to_owned(),
                hosts: vec!["lb.example".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                tls: VhostTlsConfig::default(),
                acme_challenge: VhostAcmeChallengeConfig::default(),
                redirect: VhostRedirectConfig::default(),
                proxy: ProxyConfig {
                    upstreams: vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()],
                    load_balance: LoadBalanceConfig {
                        selection: LoadBalanceSelection::LeastTime,
                        ..LoadBalanceConfig::default()
                    },
                    ..ProxyConfig::default()
                },
                cache: CacheConfig::default(),
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: vec![load_balancer_route(), single_upstream_route()],
            }],
            ..Config::default()
        }
    }

    fn load_balancer_route() -> RouteConfig {
        RouteConfig {
            name: "route-lb".to_owned(),
            path_exact: None,
            path_prefix: Some("/route-lb/".to_owned()),
            path_regex: None,
            methods: Vec::new(),
            fallback: false,
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: Default::default(),
            redirect: None,
            proxy: Some(ProxyConfig {
                upstreams: vec!["127.0.0.1:4001".to_owned(), "127.0.0.1:4002".to_owned()],
                load_balance: LoadBalanceConfig {
                    selection: LoadBalanceSelection::ConsistentUriHash,
                    ..LoadBalanceConfig::default()
                },
                ..ProxyConfig::default()
            }),
            web: None,
            php: None,
            cache: None,
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
        }
    }

    fn single_upstream_route() -> RouteConfig {
        RouteConfig {
            name: "single-upstream".to_owned(),
            path_exact: None,
            path_prefix: Some("/single/".to_owned()),
            path_regex: None,
            methods: Vec::new(),
            fallback: false,
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: Default::default(),
            redirect: None,
            proxy: Some(ProxyConfig {
                upstreams: vec!["127.0.0.1:5001".to_owned()],
                ..ProxyConfig::default()
            }),
            web: None,
            php: None,
            cache: None,
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
        }
    }

    fn cached_route() -> RouteConfig {
        RouteConfig {
            name: "assets".to_owned(),
            path_exact: None,
            path_prefix: Some("/assets/".to_owned()),
            path_regex: None,
            methods: Vec::new(),
            fallback: false,
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: Default::default(),
            redirect: None,
            proxy: Some(ProxyConfig::default()),
            web: None,
            php: None,
            cache: Some(CacheConfig {
                enabled: true,
                memory: CacheMemoryConfig {
                    enabled: true,
                    ..CacheMemoryConfig::default()
                },
                peer_fill: CachePeerFillConfig {
                    enabled: true,
                    peers: vec![CachePeerConfig {
                        name: "route-cache".to_owned(),
                        base_url: "https://route-cache.example:8443".to_owned(),
                    }],
                    ..CachePeerFillConfig::default()
                },
                ..CacheConfig::default()
            }),
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
        }
    }

    fn uncached_route() -> RouteConfig {
        RouteConfig {
            name: "api".to_owned(),
            path_exact: None,
            path_prefix: Some("/api/".to_owned()),
            path_regex: None,
            methods: Vec::new(),
            fallback: false,
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: Default::default(),
            redirect: None,
            proxy: Some(ProxyConfig::default()),
            web: None,
            php: None,
            cache: None,
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
        }
    }
}
