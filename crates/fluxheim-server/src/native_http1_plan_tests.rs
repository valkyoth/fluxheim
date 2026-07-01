use crate::{NativeHttp1ProxyConfigError, NativeHttp1ProxyCutoverStatus, ServerPlan};
use fluxheim_config::{CacheConfig, Config, RouteConfig, VhostConfig};

#[path = "native_http1_plan_tests/access_limits.rs"]
mod access_limits_tests;
#[path = "native_http1_plan_tests/cache_web_php.rs"]
mod cache_web_php_tests;
#[path = "native_http1_plan_tests/compression.rs"]
mod compression_tests;
#[path = "native_http1_plan_tests/load_balance_summary.rs"]
mod load_balance_summary_tests;
#[path = "native_http1_plan_tests/root_protocol.rs"]
mod root_protocol_tests;
#[path = "native_http1_plan_tests/route_headers.rs"]
mod route_headers_tests;

#[test]
fn server_plan_collects_vhost_and_route_native_http1_proxy_candidates() {
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
            proxy: fluxheim_config::ProxyConfig {
                upstreams: vec!["127.0.0.1:3001".to_owned()],
                ..Default::default()
            },
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
                concurrency: Default::default(),
                grpc: Default::default(),
                redirect: None,
                proxy: Some(fluxheim_config::ProxyConfig {
                    upstreams: vec!["127.0.0.1:3002".to_owned(), "127.0.0.1:3003".to_owned()],
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
    let candidates = plan.native_http1_proxy_candidates();

    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].scope(), "vhost \"native.test\" proxy");
    assert!(candidates[0].is_eligible());
    assert_eq!(
        candidates[1].scope(),
        "vhost \"native.test\" route \"api\" proxy"
    );
    #[cfg(feature = "load-balancer")]
    {
        assert!(candidates[1].is_eligible());
        assert_eq!(candidates[1].unsupported_reason(), None);
    }
    #[cfg(not(feature = "load-balancer"))]
    {
        assert!(!candidates[1].is_eligible());
        assert_eq!(
            candidates[1].unsupported_reason(),
            Some(NativeHttp1ProxyConfigError::LoadBalancing)
        );
    }
}

#[test]
fn server_plan_accepts_native_http1_proxy_candidate_with_root_header_mutation() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config
        .headers
        .request
        .set
        .insert("x-root".to_owned(), "native".to_owned());
    config
        .headers
        .response
        .set
        .insert("x-root-response".to_owned(), "native".to_owned());

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
}

#[test]
fn server_plan_rejects_native_http1_route_proxy_candidate_with_route_policy() {
    let mut config = Config::default();
    let cache = CacheConfig {
        enabled: true,
        ..Default::default()
    };
    config.vhosts = vec![VhostConfig {
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
            concurrency: Default::default(),
            grpc: Default::default(),
            redirect: None,
            proxy: Some(fluxheim_config::ProxyConfig {
                upstreams: vec!["127.0.0.1:3002".to_owned()],
                ..Default::default()
            }),
            web: None,
            php: None,
            cache: Some(cache),
            compression: None,
            headers: Default::default(),
        }],
    }];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::CachePolicy)
    );
}

#[test]
fn server_plan_accepts_native_http1_route_proxy_candidate_with_response_rewrite() {
    let mut response_headers = fluxheim_config::ResponseHeaderPolicyOverlayConfig::default();
    response_headers.rewrite.location = vec![fluxheim_config::ResponseHeaderRewriteRuleConfig {
        from: "https://origin.example/".to_owned(),
        to: "https://edge.example/".to_owned(),
    }];
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
                headers: fluxheim_config::VhostHeaderPolicyConfig {
                    request: Default::default(),
                    response: response_headers,
                },
            }],
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
fn server_plan_skips_route_proxy_candidate_shadowed_by_redirect() {
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
                name: "redirect".to_owned(),
                path_exact: Some("/old".to_owned()),
                path_prefix: None,
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
                redirect: Some(fluxheim_config::RouteRedirectConfig {
                    to: "https://new.example{uri}".to_owned(),
                    status: 308,
                }),
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

    assert!(plan.native_http1_proxy_candidates().is_empty());
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::NoProxy
    );
}

#[test]
fn server_plan_accepts_native_http1_route_proxy_candidate_with_vhost_header_overlay() {
    let mut headers = fluxheim_config::VhostHeaderPolicyConfig::default();
    headers
        .request
        .set
        .insert("x-vhost".to_owned(), "native".to_owned());
    headers
        .response
        .set
        .insert("x-vhost-response".to_owned(), "native".to_owned());
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
            proxy: fluxheim_config::ProxyConfig {
                upstreams: vec!["127.0.0.1:3001".to_owned()],
                ..Default::default()
            },
            cache: CacheConfig::default(),
            compression: None,
            headers,
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

fn native_proxy_vhost() -> VhostConfig {
    VhostConfig {
        name: "native.test".to_owned(),
        hosts: vec!["native.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
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
    }
}

fn native_proxy_route() -> RouteConfig {
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
        proxy: Some(fluxheim_config::ProxyConfig {
            upstreams: vec!["127.0.0.1:3002".to_owned()],
            ..Default::default()
        }),
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: Default::default(),
    }
}
