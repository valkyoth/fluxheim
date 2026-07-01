use crate::{NativeHttp1ProxyConfigError, NativeHttp1ProxyCutoverStatus, ServerPlan};
use fluxheim_config::{CacheConfig, Config, RouteConfig, VhostConfig};

#[test]
fn server_plan_accepts_native_http1_proxy_candidate_with_vhost_acme_challenge_route() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "native.test".to_owned(),
            hosts: vec!["native.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: Default::default(),
            acme_challenge: fluxheim_config::VhostAcmeChallengeConfig {
                enabled: true,
                upstream: Some("127.0.0.1:3002".to_owned()),
                ..Default::default()
            },
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
    let candidates = plan.native_http1_proxy_candidates();

    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].scope(), "vhost \"native.test\" proxy");
    assert!(candidates[0].is_eligible());
    assert_eq!(
        candidates[1].scope(),
        "vhost \"native.test\" route \"acme-http-01\" proxy"
    );
    assert!(candidates[1].is_eligible());
}

#[test]
fn server_plan_accepts_native_http1_proxy_candidate_with_vhost_redirect() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "redir.test".to_owned(),
            hosts: vec!["redir.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: Default::default(),
            acme_challenge: Default::default(),
            redirect: fluxheim_config::VhostRedirectConfig {
                enabled: true,
                to: Some("https://target.example{uri}".to_owned()),
                ..Default::default()
            },
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

    assert_eq!(plan.native_http1_proxy_candidates().len(), 1);
    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
}

#[test]
fn server_plan_tracks_native_http1_proxy_candidate_with_advanced_load_balance_policy() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()];
    config.proxy.upstream_priority_groups = vec![0, 1];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    #[cfg(feature = "load-balancer")]
    {
        assert_eq!(
            plan.native_http1_proxy_candidates()[0].unsupported_reason(),
            None
        );
        assert_eq!(
            plan.native_http1_proxy_cutover_summary().status(),
            NativeHttp1ProxyCutoverStatus::NativeReady
        );
    }
    #[cfg(not(feature = "load-balancer"))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::LoadBalancing)
    );
}

#[test]
fn server_plan_accepts_native_http1_proxy_candidate_with_active_load_balance_health_check() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let summary = plan.native_http1_proxy_cutover_summary();

    assert_eq!(plan.native_http1_proxy_candidates().len(), 1);
    #[cfg(feature = "load-balancer")]
    {
        assert_eq!(
            plan.native_http1_proxy_candidates()[0].unsupported_reason(),
            None
        );
        assert_eq!(summary.status(), NativeHttp1ProxyCutoverStatus::NativeReady);
    }
    #[cfg(not(feature = "load-balancer"))]
    {
        assert_eq!(
            plan.native_http1_proxy_candidates()[0].unsupported_reason(),
            Some(NativeHttp1ProxyConfigError::LoadBalancing)
        );
        assert_eq!(
            summary.status(),
            NativeHttp1ProxyCutoverStatus::CompatibilityRequired
        );
    }
}

#[test]
fn server_plan_accepts_native_http1_proxy_candidate_with_static_load_balance_health_disabled() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()];
    config.proxy.load_balance.health_check.enabled = false;

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let summary = plan.native_http1_proxy_cutover_summary();

    assert_eq!(plan.native_http1_proxy_candidates().len(), 1);
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
    assert_eq!(summary.status(), NativeHttp1ProxyCutoverStatus::NativeReady);
}

#[test]
fn server_plan_reports_no_native_http1_proxy_candidates_without_proxy() {
    let config = Config {
        proxy: fluxheim_config::ProxyConfig::disabled(),
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let summary = plan.native_http1_proxy_cutover_summary();

    assert_eq!(summary.status(), NativeHttp1ProxyCutoverStatus::NoProxy);
    assert_eq!(summary.total(), 0);
    assert_eq!(summary.eligible(), 0);
    assert_eq!(summary.unsupported(), 0);
}

#[test]
fn server_plan_reports_mixed_native_http1_proxy_cutover_summary() {
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
                strip_prefix: Some("/api".to_owned()),
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
                cache: Some(CacheConfig {
                    enabled: true,
                    ..Default::default()
                }),
                compression: None,
                headers: Default::default(),
            }],
        }],
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let summary = plan.native_http1_proxy_cutover_summary();

    assert_eq!(summary.status(), NativeHttp1ProxyCutoverStatus::Mixed);
    assert_eq!(summary.total(), 2);
    assert_eq!(summary.eligible(), 1);
    assert_eq!(summary.unsupported(), 1);
    assert_eq!(
        plan.native_http1_proxy_candidates()[1].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::CachePolicy)
    );
}

#[test]
fn server_plan_reports_compatibility_required_native_http1_proxy_summary() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.compression.enabled = true;

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let summary = plan.native_http1_proxy_cutover_summary();

    #[cfg(not(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    )))]
    {
        assert_eq!(
            summary.status(),
            NativeHttp1ProxyCutoverStatus::CompatibilityRequired
        );
        assert_eq!(summary.total(), 1);
        assert_eq!(summary.eligible(), 0);
        assert_eq!(summary.unsupported(), 1);
    }
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    {
        assert_eq!(summary.status(), NativeHttp1ProxyCutoverStatus::NativeReady);
        assert_eq!(summary.total(), 1);
        assert_eq!(summary.eligible(), 1);
        assert_eq!(summary.unsupported(), 0);
    }
}
