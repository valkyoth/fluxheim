#[cfg(feature = "cache")]
use super::*;

#[cfg(feature = "cache")]
#[test]
fn cache_purge_bulk_endpoint_accepts_repeated_paths() {
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
        "/_fluxheim/cache/purge-bulk",
        Some("host=cached.example&path=/img/one.png&path=/img/two.png"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""requested":2"#));
    assert!(body.contains(r#""purged":0"#));
    assert!(body.contains(r#""not_purged":2"#));
    assert!(body.contains(r#""purged_ratio_per_mille":0"#));
    assert!(body.contains(r#""not_purged_ratio_per_mille":1000"#));
    assert!(body.contains(r#""route":null"#));
    assert!(body.contains(r#""scope":"vhost""#));
    assert!(body.contains(r#""memory_purged":0"#));
    assert!(body.contains(r#""memory_not_purged":2"#));
    assert!(body.contains(r#""memory_purged_ratio_per_mille":0"#));
    assert!(body.contains(r#""memory_not_purged_ratio_per_mille":1000"#));
    assert!(body.contains(r#""disk_purged":0"#));
    assert!(body.contains(r#""disk_not_purged":2"#));
    assert!(body.contains(r#""disk_purged_ratio_per_mille":0"#));
    assert!(body.contains(r#""disk_not_purged_ratio_per_mille":1000"#));
    assert!(body.contains(r#""results":["#));
    assert!(body.contains(r#""not_purged":true"#));
    assert!(body.contains(r#""path":"/img/one.png""#));
    assert!(body.contains(r#""path":"/img/two.png""#));
    assert!(body.contains(r#""memory_not_purged":true"#));
    assert!(body.contains(r#""disk_not_purged":true"#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_bulk_endpoint_reports_route_scope() {
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
            "/_fluxheim/cache/purge-bulk",
            Some("vhost=cached&route=assets&host=cached.example&path=/assets/one.png&path=/assets/two.png"),
            &auth_headers(),
        );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""requested":2"#));
    assert!(body.contains(r#""not_purged":2"#));
    assert!(body.contains(r#""not_purged_ratio_per_mille":1000"#));
    assert!(body.contains(r#""route":"assets""#));
    assert!(body.contains(r#""scope":"route""#));
    assert!(body.contains(r#""memory_purged":0"#));
    assert!(body.contains(r#""disk_purged":0"#));
    assert!(body.contains(r#""path":"/assets/one.png""#));
    assert!(body.contains(r#""path":"/assets/two.png""#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_bulk_endpoint_accepts_header_route_scope() {
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
        "x-fluxheim-cache-host",
        HeaderValue::from_static("cached.example"),
    );
    headers.insert("x-fluxheim-cache-method", HeaderValue::from_static("GET"));
    headers.insert(
        "x-fluxheim-cache-paths",
        HeaderValue::from_static("/assets/one.png,/assets/two.png"),
    );
    headers.insert("x-fluxheim-cache-query", HeaderValue::from_static("v=1"));

    let response = app.handle("POST", "/_fluxheim/cache/purge-bulk", None, &headers);

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""requested":2"#));
    assert!(body.contains(r#""not_purged":2"#));
    assert!(body.contains(r#""not_purged_ratio_per_mille":1000"#));
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""route":"assets""#));
    assert!(body.contains(r#""scope":"route""#));
    assert!(body.contains(r#""host":"cached.example""#));
    assert!(body.contains(r#""query":"v=1""#));
    assert!(body.contains(r#""path":"/assets/one.png""#));
    assert!(body.contains(r#""path":"/assets/two.png""#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_bulk_endpoint_rejects_empty_paths() {
    let response = app().handle(
        "POST",
        "/_fluxheim/cache/purge-bulk",
        Some("host=example.test"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_bulk_endpoint_rejects_too_many_paths() {
    let mut query = "host=example.test".to_owned();
    for index in 0..=super::super::MAX_CACHE_PURGE_BULK_PATHS {
        query.push_str("&path=/img/");
        query.push_str(&index.to_string());
        query.push_str(".png");
    }

    let response = app().handle(
        "POST",
        "/_fluxheim/cache/purge-bulk",
        Some(&query),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}
