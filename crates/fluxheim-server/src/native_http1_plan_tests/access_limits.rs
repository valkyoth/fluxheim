use crate::ServerPlan;
use fluxheim_config::{CacheConfig, Config, RouteConfig, VhostConfig};

#[test]
fn disabled_empty_access_policy_does_not_block_native_http1_proxy_candidate() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "native.test".to_owned(),
            hosts: vec!["native.test".to_owned()],
            max_request_body_bytes: None,
            access: fluxheim_config::AccessPolicyConfig {
                enabled: false,
                ..Default::default()
            },
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: Default::default(),
            acme_challenge: Default::default(),
            redirect: Default::default(),
            proxy: fluxheim_config::ProxyConfig {
                upstreams: vec!["127.0.0.1:3001".to_owned()],
                ..Default::default()
            },
            cache: CacheConfig::default(),
            compression: None,
            headers: Default::default(),
            php: Default::default(),
            web: Default::default(),
            routes: Vec::new(),
        }],
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
}

#[test]
fn ip_access_policy_does_not_block_native_http1_proxy_candidate() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "native.test".to_owned(),
            hosts: vec!["native.test".to_owned()],
            max_request_body_bytes: None,
            access: fluxheim_config::AccessPolicyConfig {
                allow: vec!["127.0.0.1".to_owned()],
                deny: vec!["198.51.100.0/24".to_owned()],
                ..Default::default()
            },
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: Default::default(),
            acme_challenge: Default::default(),
            redirect: Default::default(),
            proxy: fluxheim_config::ProxyConfig {
                upstreams: vec!["127.0.0.1:3001".to_owned()],
                ..Default::default()
            },
            cache: CacheConfig::default(),
            compression: None,
            headers: Default::default(),
            php: Default::default(),
            web: Default::default(),
            routes: Vec::new(),
        }],
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
}

#[test]
fn cert_and_geo_access_policy_does_not_block_native_http1_proxy_candidate() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "native.test".to_owned(),
            hosts: vec!["native.test".to_owned()],
            max_request_body_bytes: None,
            access: fluxheim_config::AccessPolicyConfig {
                require_client_cert: true,
                allow_countries: vec!["SE".to_owned()],
                ..Default::default()
            },
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: Default::default(),
            acme_challenge: Default::default(),
            redirect: Default::default(),
            proxy: fluxheim_config::ProxyConfig {
                upstreams: vec!["127.0.0.1:3001".to_owned()],
                ..Default::default()
            },
            cache: CacheConfig::default(),
            compression: None,
            headers: Default::default(),
            php: Default::default(),
            web: Default::default(),
            routes: Vec::new(),
        }],
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
}

#[test]
fn vhost_concurrency_policy_does_not_block_native_http1_proxy_candidate() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "native.test".to_owned(),
            hosts: vec!["native.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: fluxheim_config::ConcurrencyLimitConfig {
                enabled: true,
                max_in_flight: 8,
                ..Default::default()
            },
            tls: Default::default(),
            acme_challenge: Default::default(),
            redirect: Default::default(),
            proxy: fluxheim_config::ProxyConfig {
                upstreams: vec!["127.0.0.1:3001".to_owned()],
                ..Default::default()
            },
            cache: CacheConfig::default(),
            compression: None,
            headers: Default::default(),
            php: Default::default(),
            web: Default::default(),
            routes: Vec::new(),
        }],
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
}

#[test]
fn route_concurrency_policy_does_not_block_native_http1_proxy_candidate() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "native.test".to_owned(),
            hosts: vec!["native.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: Default::default(),
            acme_challenge: Default::default(),
            redirect: Default::default(),
            proxy: fluxheim_config::ProxyConfig::disabled(),
            cache: CacheConfig::default(),
            compression: None,
            headers: Default::default(),
            php: Default::default(),
            web: Default::default(),
            routes: vec![RouteConfig {
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
                concurrency: fluxheim_config::ConcurrencyLimitConfig {
                    enabled: true,
                    max_in_flight: 8,
                    ..Default::default()
                },
                grpc: Default::default(),
                redirect: None,
                proxy: Some(fluxheim_config::ProxyConfig {
                    upstreams: vec!["127.0.0.1:3002".to_owned()],
                    ..Default::default()
                }),
                web: None,
                php: None,
                cache: None,
                compression: None,
                headers: Default::default(),
            }],
        }],
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
}

#[test]
fn vhost_rate_limit_policy_does_not_block_native_http1_proxy_candidate() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "native.test".to_owned(),
            hosts: vec!["native.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: fluxheim_config::RateLimitConfig {
                enabled: true,
                requests_per_second: 10,
                burst: 2,
                ..Default::default()
            },
            concurrency: Default::default(),
            tls: Default::default(),
            acme_challenge: Default::default(),
            redirect: Default::default(),
            proxy: fluxheim_config::ProxyConfig {
                upstreams: vec!["127.0.0.1:3001".to_owned()],
                ..Default::default()
            },
            cache: CacheConfig::default(),
            compression: None,
            headers: Default::default(),
            php: Default::default(),
            web: Default::default(),
            routes: Vec::new(),
        }],
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
}

#[test]
fn route_rate_limit_policy_does_not_block_native_http1_proxy_candidate() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "native.test".to_owned(),
            hosts: vec!["native.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: Default::default(),
            acme_challenge: Default::default(),
            redirect: Default::default(),
            proxy: fluxheim_config::ProxyConfig::disabled(),
            cache: CacheConfig::default(),
            compression: None,
            headers: Default::default(),
            php: Default::default(),
            web: Default::default(),
            routes: vec![RouteConfig {
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
                rate_limit: fluxheim_config::RateLimitConfig {
                    enabled: true,
                    requests_per_second: 10,
                    burst: 2,
                    ..Default::default()
                },
                concurrency: Default::default(),
                grpc: Default::default(),
                redirect: None,
                proxy: Some(fluxheim_config::ProxyConfig {
                    upstreams: vec!["127.0.0.1:3002".to_owned()],
                    ..Default::default()
                }),
                web: None,
                php: None,
                cache: None,
                compression: None,
                headers: Default::default(),
            }],
        }],
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
}
