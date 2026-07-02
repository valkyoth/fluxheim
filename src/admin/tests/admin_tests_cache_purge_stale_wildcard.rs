#[cfg(feature = "cache")]
use super::*;

#[cfg(feature = "cache")]
#[test]
fn cache_purge_stale_endpoint_accepts_vhost_scope() {
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
        "/_fluxheim/cache/purge-stale",
        Some("vhost=cached&limit=16&dry_run=true"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""dry_run":true"#));
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""scanned":0"#));
    assert!(body.contains(r#""stale":0"#));
    assert!(body.contains(r#""would_purge":0"#));
    assert!(body.contains(r#""purged":0"#));
    assert!(body.contains(r#""not_purged":0"#));
    assert!(body.contains(r#""limit":16"#));
    assert!(body.contains(r#""batches":1"#));
    assert!(body.contains(r#""batch_limit":1"#));
    assert!(body.contains(r#""batches_exhausted":false"#));
    assert!(body.contains(r#""increase_limit_required":false"#));
    assert!(body.contains(r#""scope":"vhost""#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_stale_endpoint_reports_route_scope() {
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
        "/_fluxheim/cache/purge-stale",
        Some("vhost=cached&route=assets&limit=16&dry_run=true"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""dry_run":true"#));
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""route":"assets""#));
    assert!(body.contains(r#""scope":"route""#));
    assert!(body.contains(r#""scanned":0"#));
    assert!(body.contains(r#""stale":0"#));
    assert!(body.contains(r#""would_purge":0"#));
    assert!(body.contains(r#""purged":0"#));
    assert!(body.contains(r#""not_purged":0"#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_stale_endpoint_accepts_header_route_scope() {
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
    headers.insert("x-fluxheim-cache-limit", HeaderValue::from_static("16"));
    headers.insert("x-fluxheim-cache-batches", HeaderValue::from_static("3"));
    headers.insert("x-fluxheim-cache-dry-run", HeaderValue::from_static("true"));

    let response = app.handle("POST", "/_fluxheim/cache/purge-stale", None, &headers);

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""dry_run":true"#));
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""route":"assets""#));
    assert!(body.contains(r#""scope":"route""#));
    assert!(body.contains(r#""scanned":0"#));
    assert!(body.contains(r#""stale":0"#));
    assert!(body.contains(r#""would_purge":0"#));
    assert!(body.contains(r#""purged":0"#));
    assert!(body.contains(r#""not_purged":0"#));
    assert!(body.contains(r#""limit":16"#));
    assert!(body.contains(r#""batch_limit":3"#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_wildcard_endpoint_accepts_path_pattern() {
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
        "/_fluxheim/cache/purge-wildcard",
        Some("vhost=cached&pattern=/assets/*.png&limit=16"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""path_pattern":"/assets/*.png""#));
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
fn cache_purge_wildcard_endpoint_reports_route_scope() {
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
        "/_fluxheim/cache/purge-wildcard",
        Some("vhost=cached&route=assets&pattern=/assets/*.png&limit=16"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""route":"assets""#));
    assert!(body.contains(r#""scope":"route""#));
    assert!(body.contains(r#""path_pattern":"/assets/*.png""#));
    assert!(body.contains(r#""matched":0"#));
    assert!(body.contains(r#""not_purged":0"#));
    assert!(body.contains(r#""repeat_required":false"#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_wildcard_endpoint_accepts_header_route_scope() {
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
        "x-fluxheim-cache-path-pattern",
        HeaderValue::from_static("/assets/*.png"),
    );
    headers.insert("x-fluxheim-cache-limit", HeaderValue::from_static("16"));
    headers.insert("x-fluxheim-cache-batches", HeaderValue::from_static("3"));
    headers.insert("x-fluxheim-cache-soft", HeaderValue::from_static("true"));

    let response = app.handle("POST", "/_fluxheim/cache/purge-wildcard", None, &headers);

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""soft":true"#));
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""route":"assets""#));
    assert!(body.contains(r#""scope":"route""#));
    assert!(body.contains(r#""path_pattern":"/assets/*.png""#));
    assert!(body.contains(r#""matched":0"#));
    assert!(body.contains(r#""not_purged":0"#));
    assert!(body.contains(r#""repeat_required":false"#));
    assert!(body.contains(r#""limit":16"#));
    assert!(body.contains(r#""batch_limit":3"#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_wildcard_endpoint_rejects_root_pattern() {
    for query in [
        Some("vhost=cached&pattern=/*"),
        Some("vhost=cached&pattern=/***"),
    ] {
        let response = app().handle(
            "POST",
            "/_fluxheim/cache/purge-wildcard",
            query,
            &auth_headers(),
        );

        assert_eq!(response.status, StatusCode::BAD_REQUEST);
    }
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_endpoint_rejects_missing_identity() {
    let response = app().handle(
        "POST",
        "/_fluxheim/cache/purge",
        Some("host=example.test"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_endpoint_rejects_unsafe_identity_parts() {
    let cases = [
        Some("host=example.test&path=/../secret.png"),
        Some("host=example.test&path=/img/%2e%2e/secret.png"),
        Some("host=example.test&path=/img/%252e%252e/secret.png"),
        Some("host=example.test&path=/img/%25252e%25252e/secret.png"),
        Some("host=example.test&path=/img\\secret.png"),
        Some("host=example.test&method=GET POST&path=/img/logo.png"),
        Some("host=example.test/evil&path=/img/logo.png"),
        Some("host=example.test&path=/img/logo.png&url_query=ok#fragment"),
    ];

    for query in cases {
        let response = app().handle("POST", "/_fluxheim/cache/purge", query, &auth_headers());

        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{query:?}");
    }
}
