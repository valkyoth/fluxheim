#[cfg(feature = "cache")]
use super::*;

#[cfg(feature = "cache")]
#[test]
fn cache_purge_endpoint_requires_auth_and_purges_by_request_identity() {
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
        "/_fluxheim/cache/purge",
        Some("host=cached.example&path=/img/logo.png"),
        &HeaderMap::new(),
    );
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    let response = app.handle(
        "POST",
        "/_fluxheim/cache/purge",
        Some("host=cached.example&path=/img/logo.png&url_query=v=1"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""purged":false"#));
    assert!(body.contains(r#""not_purged":true"#));
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""scope":"vhost""#));
    assert!(body.contains(r#""host":"cached.example""#));
    assert!(body.contains(r#""method":"GET""#));
    assert!(body.contains(r#""path":"/img/logo.png""#));
    assert!(body.contains(r#""query":"v=1""#));
    assert!(body.contains(r#""memory_purged":false"#));
    assert!(body.contains(r#""memory_not_purged":true"#));
    assert!(body.contains(r#""disk_purged":false"#));
    assert!(body.contains(r#""disk_not_purged":true"#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_endpoint_accepts_route_target() {
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
            routes: vec![RouteConfig {
                name: "assets".to_owned(),
                path_exact: None,
                path_prefix: Some("/assets/".to_owned()),
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
                proxy: Some(ProxyConfig {
                    upstream: Some("127.0.0.1:3000".to_owned()),
                    ..ProxyConfig::default()
                }),
                web: None,
                php: None,
                cache: Some(CacheConfig {
                    enabled: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(2048),
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                }),
                compression: None,
                headers: crate::config::VhostHeaderPolicyConfig::default(),
            }],
        }],
        ..Config::default()
    };
    let app = app_with_config(config);

    let response = app.handle(
        "POST",
        "/_fluxheim/cache/purge",
        Some("vhost=cached&route=assets&host=cached.example&path=/assets/logo.png"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""route":"assets""#));
    assert!(body.contains(r#""scope":"route""#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_endpoint_accepts_header_route_target() {
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
    headers.insert("x-fluxheim-cache-method", HeaderValue::from_static("HEAD"));
    headers.insert(
        "x-fluxheim-cache-path",
        HeaderValue::from_static("/assets/logo.png"),
    );
    headers.insert("x-fluxheim-cache-query", HeaderValue::from_static("v=1"));

    let response = app.handle("POST", "/_fluxheim/cache/purge", None, &headers);

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""purged":false"#));
    assert!(body.contains(r#""not_purged":true"#));
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""route":"assets""#));
    assert!(body.contains(r#""scope":"route""#));
    assert!(body.contains(r#""host":"cached.example""#));
    assert!(body.contains(r#""method":"HEAD""#));
    assert!(body.contains(r#""path":"/assets/logo.png""#));
    assert!(body.contains(r#""query":"v=1""#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_index_endpoint_accepts_vhost_scope() {
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
        "/_fluxheim/cache/purge-index",
        Some("vhost=cached&limit=16&batches=3"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""matched":0"#));
    assert!(body.contains(r#""purged":0"#));
    assert!(body.contains(r#""not_purged":0"#));
    assert!(body.contains(r#""purged_ratio_per_mille":0"#));
    assert!(body.contains(r#""not_purged_ratio_per_mille":0"#));
    assert!(body.contains(r#""memory_not_purged":0"#));
    assert!(body.contains(r#""memory_purged_ratio_per_mille":0"#));
    assert!(body.contains(r#""memory_not_purged_ratio_per_mille":0"#));
    assert!(body.contains(r#""disk_not_purged":0"#));
    assert!(body.contains(r#""disk_purged_ratio_per_mille":0"#));
    assert!(body.contains(r#""disk_not_purged_ratio_per_mille":0"#));
    assert!(body.contains(r#""truncated":false"#));
    assert!(body.contains(r#""repeat_required":false"#));
    assert!(body.contains(r#""limit":16"#));
    assert!(body.contains(r#""batches":1"#));
    assert!(body.contains(r#""batch_limit":3"#));
    assert!(body.contains(r#""batches_exhausted":false"#));
    assert!(body.contains(r#""scope":"vhost""#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_index_endpoint_reports_route_scope() {
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
        "/_fluxheim/cache/purge-index",
        Some("vhost=cached&route=assets&limit=16&batches=3"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""route":"assets""#));
    assert!(body.contains(r#""scope":"route""#));
    assert!(body.contains(r#""matched":0"#));
    assert!(body.contains(r#""purged":0"#));
    assert!(body.contains(r#""not_purged":0"#));
    assert!(body.contains(r#""repeat_required":false"#));
    assert!(body.contains(r#""limit":16"#));
    assert!(body.contains(r#""batch_limit":3"#));
}

#[cfg(feature = "cache")]
#[test]
fn cache_purge_index_endpoint_accepts_header_route_scope() {
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
    headers.insert("x-fluxheim-cache-soft", HeaderValue::from_static("true"));

    let response = app.handle("POST", "/_fluxheim/cache/purge-index", None, &headers);

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""soft":true"#));
    assert!(body.contains(r#""vhost":"cached""#));
    assert!(body.contains(r#""route":"assets""#));
    assert!(body.contains(r#""scope":"route""#));
    assert!(body.contains(r#""matched":0"#));
    assert!(body.contains(r#""purged":0"#));
    assert!(body.contains(r#""not_purged":0"#));
    assert!(body.contains(r#""repeat_required":false"#));
    assert!(body.contains(r#""limit":16"#));
    assert!(body.contains(r#""batch_limit":3"#));
}
