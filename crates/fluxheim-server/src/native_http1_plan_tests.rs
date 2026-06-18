use crate::{NativeHttp1ProxyConfigError, ServerPlan};
use fluxheim_config::{CacheConfig, Config, RouteConfig, VhostConfig};

#[test]
fn server_plan_collects_native_http1_proxy_candidates() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert_eq!(plan.native_http1_proxy_candidates().len(), 1);
    assert_eq!(plan.native_http1_proxy_candidates()[0].scope(), "proxy");
    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );

    config.proxy.upstream_tls = true;
    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    #[cfg(not(feature = "tls-rustls-backend"))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::UpstreamTls)
    );
    #[cfg(feature = "tls-rustls-backend")]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::UpstreamTlsPolicy)
    );
}

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
    assert_eq!(
        candidates[1].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::LoadBalancing)
    );
}

#[test]
fn server_plan_rejects_native_http1_proxy_candidate_with_root_policy() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.compression.enabled = true;

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::HttpPolicy)
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
        Some(NativeHttp1ProxyConfigError::HttpPolicy)
    );
}

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
