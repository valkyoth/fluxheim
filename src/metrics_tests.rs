use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use fluxheim_common::test_support::unique_temp_path;
use prometheus::Encoder;
use zeroize::Zeroizing;

use crate::config::{
    CacheConfig, CacheDiskConfig, CacheMemoryConfig, CachePeerConfig, CachePeerFillConfig, Config,
    ProxyConfig, RouteConfig, VhostAcmeChallengeConfig, VhostConfig, VhostHeaderPolicyConfig,
    VhostRedirectConfig, VhostTlsConfig, WebConfig,
};

#[cfg(all(feature = "proxy", feature = "cache"))]
use super::record_cache_runtime_totals;
use super::{
    NativeMetricsApp, init, method_bucket, metrics_background_service_from_config,
    native_metrics_app_from_config, native_prometheus_response, record_acme_event,
    record_admin_auth_event, record_cache_activity, record_cache_activity_scope,
    record_cache_operation_duration, record_cache_purge, record_cache_purger_duration,
    record_cache_purger_entries, record_cache_purger_run, record_config, record_edge_policy_event,
    record_host_routing_rejection, record_load_balancer_event, record_load_balancer_queue_wait,
    record_metrics_otlp_export, record_php_fpm_pool_event, record_php_fpm_pool_idle,
    record_php_fpm_retry, record_php_request, record_php_stderr, record_proxy_outcome,
    record_response_compression, record_stream_bytes, record_stream_connection,
    record_udp_datagram, record_udp_drop, set_udp_active_sessions, status_class,
};

#[path = "metrics_tests_config_cache.rs"]
mod config_cache;
#[path = "metrics_tests_core.rs"]
mod core;
#[path = "metrics_tests_labels.rs"]
mod labels;
#[path = "metrics_tests_lb_php.rs"]
mod lb_php;
#[path = "metrics_tests_native_app.rs"]
mod native_app;
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
                load_balance: crate::config::LoadBalanceConfig {
                    selection: crate::config::LoadBalanceSelection::LeastTime,
                    ..crate::config::LoadBalanceConfig::default()
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
            load_balance: crate::config::LoadBalanceConfig {
                selection: crate::config::LoadBalanceSelection::ConsistentUriHash,
                ..crate::config::LoadBalanceConfig::default()
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

fn metrics_test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}
