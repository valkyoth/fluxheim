#[cfg(feature = "cache")]
use super::*;

#[cfg(feature = "cache")]
#[test]
fn cache_purge_prefix_endpoint_accepts_path_prefix() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "cached".to_owned(),
            hosts: vec!["cached.example".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig {
                enabled: true,
                memory: crate::config::CacheMemoryConfig {
                    enabled: true,
                    max_size_bytes: ByteSize::from_bytes(2048),
                },
                max_object_bytes: ByteSize::from_bytes(512),
                ..CacheConfig::default()
            },
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }],
        ..Config::default()
    };
    let app = app_with_config(config);

    let response = app.handle(
        "POST",
        "/_fluxheim/cache/purge-prefix",
        Some("vhost=cached&path_prefix=/assets/&limit=16"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""path_prefix":"/assets/""#));
    assert!(body.contains(r#""matched":0"#));
    assert!(body.contains(r#""not_purged":0"#));
    assert!(body.contains(r#""purged_ratio_per_mille":0"#));
    assert!(body.contains(r#""not_purged_ratio_per_mille":0"#));
    assert!(body.contains(r#""memory_not_purged":0"#));
    assert!(body.contains(r#""memory_purged_ratio_per_mille":0"#));
    assert!(body.contains(r#""memory_not_purged_ratio_per_mille":0"#));
    assert!(body.contains(r#""disk_not_purged":0"#));
    assert!(body.contains(r#""disk_purged_ratio_per_mille":0"#));
    assert!(body.contains(r#""disk_not_purged_ratio_per_mille":0"#));
    assert!(body.contains(r#""repeat_required":false"#));
    assert!(body.contains(r#""limit":16"#));
    assert!(body.contains(r#""batches":1"#));
    assert!(body.contains(r#""batch_limit":1"#));
    assert!(body.contains(r#""batches_exhausted":false"#));
    assert!(body.contains(r#""scope":"vhost""#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_prefix_endpoint_reports_route_scope() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "cached".to_owned(),
            hosts: vec!["cached.example".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: vec![cached_assets_route()],
        }],
        ..Config::default()
    };
    let app = app_with_config(config);

    let response = app.handle(
        "POST",
        "/_fluxheim/cache/purge-prefix",
        Some("vhost=cached&route=assets&path_prefix=/assets/&limit=16"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""route":"assets""#));
    assert!(body.contains(r#""scope":"route""#));
    assert!(body.contains(r#""path_prefix":"/assets/""#));
    assert!(body.contains(r#""matched":0"#));
    assert!(body.contains(r#""not_purged":0"#));
    assert!(body.contains(r#""repeat_required":false"#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_prefix_endpoint_accepts_header_route_scope() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "cached".to_owned(),
            hosts: vec!["cached.example".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: vec![cached_assets_route()],
        }],
        ..Config::default()
    };
    let app = app_with_config(config);
    let mut headers = auth_headers();
    headers.insert("x-fluxheim-cache-vhost", HeaderValue::from_static("cached"));
    headers.insert("x-fluxheim-cache-route", HeaderValue::from_static("assets"));
    headers.insert(
        "x-fluxheim-cache-path-prefix",
        HeaderValue::from_static("/assets/"),
    );
    headers.insert("x-fluxheim-cache-limit", HeaderValue::from_static("16"));

    let response = app.handle("POST", "/_fluxheim/cache/purge-prefix", None, &headers);

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""route":"assets""#));
    assert!(body.contains(r#""scope":"route""#));
    assert!(body.contains(r#""path_prefix":"/assets/""#));
    assert!(body.contains(r#""limit":16"#));
    assert!(body.contains(r#""matched":0"#));
    assert!(body.contains(r#""not_purged":0"#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_prefix_endpoint_accepts_soft_purge() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "cached".to_owned(),
            hosts: vec!["cached.example".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig {
                enabled: true,
                memory: crate::config::CacheMemoryConfig {
                    enabled: true,
                    max_size_bytes: ByteSize::from_bytes(2048),
                },
                max_object_bytes: ByteSize::from_bytes(512),
                ..CacheConfig::default()
            },
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }],
        ..Config::default()
    };
    let app = app_with_config(config);

    let response = app.handle(
        "POST",
        "/_fluxheim/cache/purge-prefix",
        Some("vhost=cached&path_prefix=/assets/&soft=true"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""soft":true"#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_prefix_endpoint_rejects_root_prefix() {
    let response = app().handle(
        "POST",
        "/_fluxheim/cache/purge-prefix",
        Some("vhost=cached&path_prefix=/"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_tag_endpoint_accepts_cache_tag() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "cached".to_owned(),
            hosts: vec!["cached.example".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig {
                enabled: true,
                memory: crate::config::CacheMemoryConfig {
                    enabled: true,
                    max_size_bytes: ByteSize::from_bytes(2048),
                },
                max_object_bytes: ByteSize::from_bytes(512),
                ..CacheConfig::default()
            },
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }],
        ..Config::default()
    };
    let app = app_with_config(config);

    let response = app.handle(
        "POST",
        "/_fluxheim/cache/purge-tag",
        Some("vhost=cached&cache_tag=article:1&limit=16"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""cache_tag":"article:1""#));
    assert!(body.contains(r#""matched":0"#));
    assert!(body.contains(r#""not_purged":0"#));
    assert!(body.contains(r#""repeat_required":false"#));
    assert!(body.contains(r#""limit":16"#));
    assert!(body.contains(r#""batches":1"#));
    assert!(body.contains(r#""scope":"vhost""#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_tag_endpoint_reports_route_scope() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "cached".to_owned(),
            hosts: vec!["cached.example".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: vec![cached_assets_route()],
        }],
        ..Config::default()
    };
    let app = app_with_config(config);

    let response = app.handle(
        "POST",
        "/_fluxheim/cache/purge-tag",
        Some("vhost=cached&route=assets&cache_tag=article:1&limit=16"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""route":"assets""#));
    assert!(body.contains(r#""scope":"route""#));
    assert!(body.contains(r#""cache_tag":"article:1""#));
    assert!(body.contains(r#""matched":0"#));
    assert!(body.contains(r#""not_purged":0"#));
    assert!(body.contains(r#""repeat_required":false"#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_tag_endpoint_accepts_header_route_scope() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "cached".to_owned(),
            hosts: vec!["cached.example".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: vec![cached_assets_route()],
        }],
        ..Config::default()
    };
    let app = app_with_config(config);
    let mut headers = auth_headers();
    headers.insert("x-fluxheim-cache-vhost", HeaderValue::from_static("cached"));
    headers.insert("x-fluxheim-cache-route", HeaderValue::from_static("assets"));
    headers.insert(
        "x-fluxheim-cache-tag",
        HeaderValue::from_static("article:1"),
    );
    headers.insert("x-fluxheim-cache-limit", HeaderValue::from_static("16"));
    headers.insert("x-fluxheim-cache-batches", HeaderValue::from_static("3"));
    headers.insert("x-fluxheim-cache-soft", HeaderValue::from_static("yes"));

    let response = app.handle("POST", "/_fluxheim/cache/purge-tag", None, &headers);

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""soft":true"#));
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""route":"assets""#));
    assert!(body.contains(r#""scope":"route""#));
    assert!(body.contains(r#""cache_tag":"article:1""#));
    assert!(body.contains(r#""matched":0"#));
    assert!(body.contains(r#""not_purged":0"#));
    assert!(body.contains(r#""limit":16"#));
    assert!(body.contains(r#""batch_limit":3"#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_tag_endpoint_rejects_invalid_tag() {
    let response = app().handle(
        "POST",
        "/_fluxheim/cache/purge-tag",
        Some("vhost=cached&cache_tag=bad%20tag"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}
