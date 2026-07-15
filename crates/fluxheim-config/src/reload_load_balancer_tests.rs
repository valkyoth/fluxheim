use crate::config::{Config, ProxyConfig, VhostConfig, WebConfig};
use crate::reload::{ReloadImpact, ReloadReason, classify_reload};

#[test]
fn load_balancer_service_change_requires_process_upgrade() {
    let old = Config::default();
    let new = Config {
        proxy: ProxyConfig {
            upstream: None,
            upstreams: vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()],
            ..ProxyConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::LoadBalancerServicesChanged]
        }
    );
}

#[test]
fn load_balancer_dynamic_discovery_change_requires_process_upgrade() {
    let old = Config {
        proxy: ProxyConfig {
            upstream: None,
            upstreams_file: Some("/run/fluxheim/backends-a.txt".into()),
            upstreams_file_refresh_secs: 5,
            ..ProxyConfig::default()
        },
        ..Config::default()
    };
    let new = Config {
        proxy: ProxyConfig {
            upstream: None,
            upstreams_file: Some("/run/fluxheim/backends-b.txt".into()),
            upstreams_file_refresh_secs: 10,
            ..ProxyConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::LoadBalancerServicesChanged]
        }
    );
}

#[test]
fn load_balancer_http_discovery_change_requires_process_upgrade() {
    let old = Config {
        proxy: ProxyConfig {
            upstream: None,
            upstreams_http_url: Some("https://discovery.example.test/v1/upstreams".to_owned()),
            upstreams_http_refresh_secs: 5,
            upstreams_http_bearer_token_file: Some("/run/secrets/discovery-token-a".into()),
            ..ProxyConfig::default()
        },
        ..Config::default()
    };
    let new = Config {
        proxy: ProxyConfig {
            upstream: None,
            upstreams_http_url: Some("https://discovery.example.test/v2/upstreams".to_owned()),
            upstreams_http_refresh_secs: 15,
            upstreams_http_bearer_token_file: Some("/run/secrets/discovery-token-b".into()),
            ..ProxyConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::LoadBalancerServicesChanged]
        }
    );
}

#[test]
fn load_balancer_dns_refresh_change_requires_process_upgrade() {
    let old = Config {
        proxy: ProxyConfig {
            upstream: None,
            upstreams: vec!["app.service.local:8080".to_owned()],
            upstream_dns_refresh_secs: Some(5),
            ..ProxyConfig::default()
        },
        ..Config::default()
    };
    let new = Config {
        proxy: ProxyConfig {
            upstream: None,
            upstreams: vec!["app.service.local:8080".to_owned()],
            upstream_dns_refresh_secs: Some(30),
            ..ProxyConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::LoadBalancerServicesChanged]
        }
    );
}

#[test]
fn route_load_balancer_service_change_requires_process_upgrade() {
    let mut old = Config {
        vhosts: vec![VhostConfig {
            name: "example".to_owned(),
            hosts: vec!["example.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: crate::config::CacheConfig::default(),
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }],
        ..Config::default()
    };
    let mut new = old.clone();
    new.vhosts[0].routes.push(crate::config::RouteConfig {
        name: "api".to_owned(),
        path_prefix: Some("/api/".to_owned()),
        proxy: Some(ProxyConfig {
            upstream: None,
            upstreams: vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()],
            ..ProxyConfig::default()
        }),
        path_exact: None,
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
        grpc: crate::config::GrpcRouteConfig::default(),
        redirect: None,
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: crate::config::VhostHeaderPolicyConfig::default(),
    });

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::LoadBalancerServicesChanged]
        }
    );
    old.vhosts[0].routes = new.vhosts[0].routes.clone();
    old.vhosts[0].routes[0].proxy.as_mut().unwrap().upstreams[1] = "127.0.0.1:3003".to_owned();
    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::LoadBalancerServicesChanged]
        }
    );
}

#[test]
fn snapshot_change_with_background_health_service_requires_process_upgrade() {
    let mut old = Config {
        proxy: ProxyConfig {
            upstream: None,
            upstreams: vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()],
            ..ProxyConfig::default()
        },
        ..Config::default()
    };
    old.proxy.load_balance.health_check.enabled = true;
    let mut new = old.clone();
    new.web.index_files = vec!["home.html".to_owned()];

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::LoadBalancerServicesChanged]
        }
    );
}

#[test]
fn snapshot_change_with_dynamic_discovery_requires_process_upgrade() {
    let old = Config {
        proxy: ProxyConfig {
            upstream: None,
            upstreams_file: Some("/run/fluxheim/backends.txt".into()),
            ..ProxyConfig::default()
        },
        ..Config::default()
    };
    let mut new = old.clone();
    new.web.index_files = vec!["home.html".to_owned()];

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::LoadBalancerServicesChanged]
        }
    );
}

#[test]
fn snapshot_change_with_static_load_balancer_remains_live_reloadable() {
    let mut old = Config {
        proxy: ProxyConfig {
            upstream: None,
            upstreams: vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()],
            ..ProxyConfig::default()
        },
        ..Config::default()
    };
    old.proxy.load_balance.health_check.enabled = false;
    let mut new = old.clone();
    new.web.index_files = vec!["home.html".to_owned()];

    assert_eq!(classify_reload(&old, &new), ReloadImpact::Snapshot);
}
