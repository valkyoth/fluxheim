use crate::{NativeHttp1ProxyConfigError, NativeHttp1ProxyCutoverStatus, ServerPlan};
use fluxheim_config::{CacheConfig, Config, RouteConfig};
use tempfile::TempDir;

use super::{native_proxy_route, native_proxy_vhost};

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

#[cfg(feature = "php-fpm")]
#[test]
fn server_plan_accepts_vhost_php_with_root() {
    let root = TempDir::new().expect("temp php root");
    let mut config = Config::default();
    let mut vhost = native_proxy_vhost();
    vhost.php.enabled = true;
    vhost.php.root = Some(root.path().to_path_buf());
    config.vhosts = vec![vhost];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(plan.native_http1_proxy_candidates().len(), 1);
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
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

#[cfg(feature = "php-fpm")]
#[test]
fn server_plan_accepts_route_php_with_root_without_proxy_candidate() {
    let root = TempDir::new().expect("temp php root");
    let mut config = Config::default();
    let mut vhost = native_proxy_vhost();
    vhost.proxy = fluxheim_config::ProxyConfig::disabled();
    let mut route = native_proxy_route();
    route.proxy = None;
    route.php = Some(fluxheim_config::PhpConfig {
        enabled: true,
        root: Some(root.path().to_path_buf()),
        ..Default::default()
    });
    vhost.routes = vec![route];
    config.vhosts = vec![vhost];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(plan.native_http1_proxy_candidates().len(), 1);
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].scope(),
        "vhost \"native.test\" route \"api\""
    );
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
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
