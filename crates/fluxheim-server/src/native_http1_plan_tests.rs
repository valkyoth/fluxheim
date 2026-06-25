use crate::{NativeHttp1ProxyConfigError, NativeHttp1ProxyCutoverStatus, ServerPlan};
use fluxheim_config::{CacheConfig, Config, RouteConfig, VhostConfig};
use tempfile::TempDir;

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
    let summary = plan.native_http1_proxy_cutover_summary();
    assert_eq!(summary.status(), NativeHttp1ProxyCutoverStatus::NativeReady);
    assert_eq!(summary.total(), 1);
    assert_eq!(summary.eligible(), 1);
    assert_eq!(summary.unsupported(), 0);

    config.proxy.upstream_tls = true;
    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::UpstreamTls)
    );
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::UpstreamTlsPolicy)
    );
}

#[test]
fn server_plan_accepts_root_response_header_policy_candidate() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config
        .headers
        .response
        .set
        .insert("x-root-response".to_owned(), "native".to_owned());
    config.headers.response.append.insert(
        "x-root-append".to_owned(),
        fluxheim_config::HeaderValues::Many(vec!["one".to_owned()]),
    );

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::NativeReady
    );
}

#[test]
fn server_plan_accepts_plain_upstream_http2_candidate() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.proxy.upstream_http_version = fluxheim_config::UpstreamHttpVersion::Http2;
    config.proxy.upstream_h2_max_streams = Some(64);

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::NativeReady
    );

    config.proxy.upstream_h2_ping_interval_secs = Some(30);
    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );

    config.proxy.upstream_h2_ping_interval_secs = None;
    config.proxy.upstream_http_version = fluxheim_config::UpstreamHttpVersion::Http1AndHttp2;
    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::UpstreamHttp2)
    );

    config.proxy.upstream_tls = true;
    config.proxy.upstream_sni = Some("localhost".to_owned());
    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::UpstreamHttp2)
    );
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
}

#[test]
fn server_plan_accepts_root_websocket_native_http1_proxy() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.proxy.websocket = true;

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::NativeReady
    );
}

#[test]
fn server_plan_accepts_vhost_websocket_native_http1_proxy() {
    let mut config = Config::default();
    let mut vhost = native_proxy_vhost();
    vhost.proxy.websocket = true;
    config.vhosts = vec![vhost];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::NativeReady
    );
}

#[test]
fn server_plan_accepts_route_websocket_native_http1_proxy() {
    let mut config = Config::default();
    let mut vhost = native_proxy_vhost();
    vhost.proxy = fluxheim_config::ProxyConfig::disabled();
    let mut route = native_proxy_route();
    route.proxy.as_mut().unwrap().websocket = true;
    vhost.routes = vec![route];
    config.vhosts = vec![vhost];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(plan.native_http1_proxy_candidates().len(), 1);
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].scope(),
        "vhost \"native.test\" route \"api\" proxy"
    );
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::NativeReady
    );
}

#[test]
fn server_plan_rejects_websocket_http2_upstream_mode() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.proxy.websocket = true;
    config.proxy.upstream_http_version = fluxheim_config::UpstreamHttpVersion::Http2;

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::WebSocket)
    );
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::CompatibilityRequired
    );
}

#[test]
fn server_plan_tracks_auth_request_native_feature_support() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.proxy.auth_request = fluxheim_config::AuthRequestConfig {
        enabled: true,
        url: Some("http://127.0.0.1:3002/auth".to_owned()),
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    #[cfg(not(feature = "auth-request"))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::AuthRequest)
    );
    #[cfg(feature = "auth-request")]
    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
}

#[test]
fn server_plan_tracks_traffic_mirror_native_feature_support() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.proxy.mirror = fluxheim_config::TrafficMirrorConfig {
        enabled: true,
        base_url: Some("http://127.0.0.1:3002/shadow".to_owned()),
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    #[cfg(not(all(feature = "traffic-mirror", not(feature = "privacy-mode"))))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::TrafficMirror)
    );
    #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
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
fn server_plan_tracks_root_compression_native_feature_support() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.compression.enabled = true;

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    #[cfg(not(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    )))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::HttpPolicy)
    );
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
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
fn server_plan_reports_root_cache_native_http1_proxy_blocker() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.cache.enabled = true;

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::CachePolicy)
    );
}

#[test]
fn server_plan_accepts_root_static_web_memory_local_static_cache() {
    let root = TempDir::new().expect("temp web root");
    std::fs::write(root.path().join("asset.png"), b"asset").unwrap();
    let config = Config {
        proxy: fluxheim_config::ProxyConfig::disabled(),
        web: fluxheim_config::WebConfig {
            root: Some(root.path().to_path_buf()),
            ..Default::default()
        },
        cache: CacheConfig {
            enabled: true,
            local_static: true,
            memory: fluxheim_config::CacheMemoryConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(plan.native_http1_proxy_candidates().len(), 1);
    assert_eq!(plan.native_http1_proxy_candidates()[0].scope(), "proxy");
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::NativeReady
    );

    root.close().unwrap();
}

#[test]
fn server_plan_reports_root_static_web_disk_cache_blocker() {
    let root = TempDir::new().expect("temp web root");
    std::fs::write(root.path().join("asset.png"), b"asset").unwrap();
    let config = Config {
        proxy: fluxheim_config::ProxyConfig::disabled(),
        web: fluxheim_config::WebConfig {
            root: Some(root.path().to_path_buf()),
            ..Default::default()
        },
        cache: CacheConfig {
            enabled: true,
            local_static: true,
            memory: fluxheim_config::CacheMemoryConfig {
                enabled: true,
                ..Default::default()
            },
            disk: fluxheim_config::CacheDiskConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(plan.native_http1_proxy_candidates().len(), 1);
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::CachePolicy)
    );

    root.close().unwrap();
}

#[test]
fn server_plan_reports_vhost_cache_native_http1_proxy_blocker() {
    let mut config = Config::default();
    let mut vhost = native_proxy_vhost();
    vhost.cache.enabled = true;
    config.vhosts = vec![vhost];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::CachePolicy)
    );
}

#[test]
fn server_plan_accepts_vhost_static_web_memory_local_static_cache() {
    let root = TempDir::new().unwrap();
    std::fs::write(root.path().join("asset.png"), b"asset").unwrap();
    let mut config = Config::default();
    let mut vhost = native_proxy_vhost();
    vhost.web = fluxheim_config::WebConfig {
        root: Some(root.path().to_path_buf()),
        ..Default::default()
    };
    vhost.cache = CacheConfig {
        enabled: true,
        local_static: true,
        memory: fluxheim_config::CacheMemoryConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };
    config.vhosts = vec![vhost];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::NativeReady
    );

    root.close().unwrap();
}

#[test]
fn server_plan_accepts_vhost_static_web_without_proxy_candidate() {
    let root = TempDir::new().unwrap();
    std::fs::write(root.path().join("asset.png"), b"asset").unwrap();
    let mut config = Config::default();
    let mut vhost = native_proxy_vhost();
    vhost.proxy = fluxheim_config::ProxyConfig::disabled();
    vhost.web = fluxheim_config::WebConfig {
        root: Some(root.path().to_path_buf()),
        ..Default::default()
    };
    config.vhosts = vec![vhost];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(plan.native_http1_proxy_candidates().len(), 1);
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].scope(),
        "vhost \"native.test\""
    );
    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::NativeReady
    );

    root.close().unwrap();
}

#[test]
fn server_plan_reports_vhost_static_web_disk_cache_without_proxy_candidate() {
    let root = TempDir::new().unwrap();
    std::fs::write(root.path().join("asset.png"), b"asset").unwrap();
    let mut config = Config::default();
    let mut vhost = native_proxy_vhost();
    vhost.proxy = fluxheim_config::ProxyConfig::disabled();
    vhost.web = fluxheim_config::WebConfig {
        root: Some(root.path().to_path_buf()),
        ..Default::default()
    };
    vhost.cache = CacheConfig {
        enabled: true,
        local_static: true,
        memory: fluxheim_config::CacheMemoryConfig {
            enabled: true,
            ..Default::default()
        },
        disk: fluxheim_config::CacheDiskConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };
    config.vhosts = vec![vhost];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(plan.native_http1_proxy_candidates().len(), 1);
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].scope(),
        "vhost \"native.test\""
    );
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::CachePolicy)
    );

    root.close().unwrap();
}

#[test]
fn server_plan_reports_vhost_php_native_http1_proxy_blocker() {
    let mut config = Config::default();
    let mut vhost = native_proxy_vhost();
    vhost.php.enabled = true;
    config.vhosts = vec![vhost];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::PhpFpm)
    );
}

#[test]
fn server_plan_reports_vhost_php_without_proxy_candidate() {
    let mut config = Config::default();
    let mut vhost = native_proxy_vhost();
    vhost.proxy = fluxheim_config::ProxyConfig::disabled();
    vhost.php.enabled = true;
    config.vhosts = vec![vhost];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(plan.native_http1_proxy_candidates().len(), 1);
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].scope(),
        "vhost \"native.test\""
    );
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::PhpFpm)
    );
}

#[test]
fn server_plan_reports_route_php_native_http1_proxy_blocker() {
    let mut config = Config::default();
    let mut vhost = native_proxy_vhost();
    vhost.proxy = fluxheim_config::ProxyConfig::disabled();
    let mut route = native_proxy_route();
    route.php = Some(fluxheim_config::PhpConfig {
        enabled: true,
        ..Default::default()
    });
    vhost.routes = vec![route];
    config.vhosts = vec![vhost];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::PhpFpm)
    );
}

#[test]
fn server_plan_accepts_route_static_web_without_proxy_candidate() {
    let root = TempDir::new().expect("temp web root");
    let mut config = Config::default();
    let mut vhost = native_proxy_vhost();
    let mut route = native_proxy_route();
    route.proxy = None;
    route.web = Some(fluxheim_config::WebConfig {
        root: Some(root.path().to_path_buf()),
        ..Default::default()
    });
    vhost.routes = vec![route];
    config.vhosts = vec![vhost];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(plan.native_http1_proxy_candidates().len(), 2);
    assert_eq!(
        plan.native_http1_proxy_candidates()[1].scope(),
        "vhost \"native.test\" route \"api\""
    );
    assert!(plan.native_http1_proxy_candidates()[1].is_eligible());

    root.close().expect("close temp web root");
}

#[test]
fn server_plan_reports_route_static_web_disk_cache_without_proxy_candidate() {
    let root = TempDir::new().expect("temp web root");
    let mut config = Config::default();
    let mut vhost = native_proxy_vhost();
    let mut route = native_proxy_route();
    route.proxy = None;
    route.web = Some(fluxheim_config::WebConfig {
        root: Some(root.path().to_path_buf()),
        ..Default::default()
    });
    route.cache = Some(CacheConfig {
        enabled: true,
        local_static: true,
        memory: fluxheim_config::CacheMemoryConfig {
            enabled: true,
            ..Default::default()
        },
        disk: fluxheim_config::CacheDiskConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    });
    vhost.routes = vec![route];
    config.vhosts = vec![vhost];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(plan.native_http1_proxy_candidates().len(), 2);
    assert_eq!(
        plan.native_http1_proxy_candidates()[1].scope(),
        "vhost \"native.test\" route \"api\""
    );
    assert_eq!(
        plan.native_http1_proxy_candidates()[1].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::CachePolicy)
    );

    root.close().expect("close temp web root");
}

#[test]
fn server_plan_reports_route_php_without_proxy_candidate() {
    let mut config = Config::default();
    let mut vhost = native_proxy_vhost();
    let mut route = native_proxy_route();
    route.proxy = None;
    route.php = Some(fluxheim_config::PhpConfig {
        enabled: true,
        ..Default::default()
    });
    vhost.routes = vec![route];
    config.vhosts = vec![vhost];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(plan.native_http1_proxy_candidates().len(), 2);
    assert_eq!(
        plan.native_http1_proxy_candidates()[1].scope(),
        "vhost \"native.test\" route \"api\""
    );
    assert_eq!(
        plan.native_http1_proxy_candidates()[1].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::PhpFpm)
    );
}

#[test]
fn server_plan_accepts_static_web_route_with_memory_local_static_cache() {
    let root = TempDir::new().expect("temp web root");
    let mut config = Config::default();
    let mut vhost = native_proxy_vhost();
    vhost.routes = vec![RouteConfig {
        name: "static-cache".to_owned(),
        path_exact: None,
        path_prefix: Some("/static/".to_owned()),
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: Some("/static/".to_owned()),
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        grpc: Default::default(),
        redirect: None,
        proxy: None,
        web: Some(fluxheim_config::WebConfig {
            root: Some(root.path().to_path_buf()),
            ..Default::default()
        }),
        php: None,
        cache: Some(CacheConfig {
            enabled: true,
            local_static: true,
            memory: fluxheim_config::CacheMemoryConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        }),
        compression: None,
        headers: Default::default(),
    }];
    config.vhosts = vec![vhost];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(plan.native_http1_proxy_candidates().len(), 2);
    assert_eq!(
        plan.native_http1_proxy_candidates()[1].scope(),
        "vhost \"native.test\" route \"static-cache\""
    );
    assert!(plan.native_http1_proxy_candidates()[1].is_eligible());
    assert_eq!(
        plan.native_http1_proxy_candidates()[1].unsupported_reason(),
        None
    );

    root.close().expect("close temp web root");
}

#[test]
fn server_plan_rejects_native_http1_route_proxy_candidate_with_disabled_request_headers() {
    let mut config = Config::default();
    let mut route_headers = fluxheim_config::VhostHeaderPolicyConfig::default();
    route_headers.request.enabled = Some(false);
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
            cache: None,
            compression: None,
            headers: route_headers,
        }],
    }];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::HttpPolicy)
    );
}

#[test]
fn server_plan_accepts_native_http1_route_proxy_candidate_with_regex_rewrite_template() {
    let mut config = Config::default();
    config.server.regex_enabled = true;
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
            path_prefix: None,
            path_regex: Some(r"^/api/v(?P<version>[0-9]+)/(?P<rest>.*)$".to_owned()),
            methods: Vec::new(),
            fallback: false,
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: Some(
                "/internal/v{route.regex.version}/{route.regex.rest}".to_owned(),
            ),
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
        }],
    }];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
}

#[test]
fn server_plan_accepts_native_http1_route_proxy_candidate_with_prefix_rewrite() {
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
fn server_plan_accepts_native_http1_route_proxy_candidate_with_response_header_overlay() {
    let mut response_headers = fluxheim_config::ResponseHeaderPolicyOverlayConfig::default();
    response_headers
        .set
        .insert("x-route".to_owned(), "native".to_owned());
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
}

#[test]
fn server_plan_accepts_native_http1_route_proxy_candidate_with_request_header_mutation() {
    let mut request_headers = fluxheim_config::RequestHeaderPolicyOverlayConfig {
        unset: vec!["x-remove".to_owned()],
        ..Default::default()
    };
    request_headers
        .set
        .insert("x-route".to_owned(), "native".to_owned());
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
                cache: None,
                compression: None,
                headers: fluxheim_config::VhostHeaderPolicyConfig {
                    request: request_headers,
                    response: Default::default(),
                },
            }],
        }],
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let summary = plan.native_http1_proxy_cutover_summary();

    assert_eq!(summary.status(), NativeHttp1ProxyCutoverStatus::NativeReady);
    assert_eq!(summary.total(), 1);
    assert_eq!(summary.eligible(), 1);
    assert_eq!(summary.unsupported(), 0);
}

#[test]
fn server_plan_accepts_native_http1_route_proxy_candidate_with_forwarded_append_policy() {
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
                cache: None,
                compression: None,
                headers: fluxheim_config::VhostHeaderPolicyConfig {
                    request: fluxheim_config::RequestHeaderPolicyOverlayConfig {
                        x_forwarded_for: Some(fluxheim_config::ForwardedClientIpHeaderMode::Append),
                        ..Default::default()
                    },
                    response: Default::default(),
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
fn server_plan_accepts_native_http1_route_proxy_candidate_with_owned_forwarded_policy() {
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
                cache: None,
                compression: None,
                headers: fluxheim_config::VhostHeaderPolicyConfig {
                    request: fluxheim_config::RequestHeaderPolicyOverlayConfig {
                        x_forwarded_for: Some(fluxheim_config::ForwardedClientIpHeaderMode::Off),
                        x_real_ip: Some(true),
                        x_forwarded_host: Some(true),
                        x_forwarded_proto: Some(true),
                        forwarded: Some(true),
                        ..Default::default()
                    },
                    response: Default::default(),
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

#[test]
fn server_plan_tracks_vhost_compression_native_feature_support() {
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
            compression: Some(fluxheim_config::CompressionConfig {
                enabled: true,
                gzip: true,
                ..Default::default()
            }),
            headers: Default::default(),
            php: Default::default(),
            web: Default::default(),
            routes: Vec::new(),
        }],
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    #[cfg(not(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    )))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::HttpPolicy)
    );
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
}

#[test]
fn server_plan_tracks_route_compression_native_feature_support() {
    let config = route_compression_config();

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    #[cfg(not(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    )))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::HttpPolicy)
    );
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
}

fn route_compression_config() -> Config {
    Config {
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
                compression: Some(fluxheim_config::CompressionConfig {
                    enabled: true,
                    gzip: true,
                    ..Default::default()
                }),
                headers: Default::default(),
            }],
        }],
        ..Default::default()
    }
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
