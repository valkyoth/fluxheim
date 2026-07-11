use super::*;

#[test]
fn snapshots_endpoint_requires_auth() {
    let response = app().handle("GET", "/_fluxheim/snapshots", None, &HeaderMap::new());
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    let response = app().handle("GET", "/_fluxheim/snapshots", None, &auth_headers());
    assert_eq!(response.status, StatusCode::OK);
    assert!(
        String::from_utf8(response.body)
            .unwrap()
            .contains(r#""snapshots":["#)
    );
}

#[test]
fn snapshot_endpoint_creates_snapshot() {
    let app = app();
    let response = app.handle("POST", "/_fluxheim/snapshot", None, &auth_headers());

    assert_eq!(response.status, StatusCode::CREATED);
    assert_eq!(app.store.list().unwrap().len(), 1);
}

#[test]
fn snapshot_endpoint_rejects_oversized_message() {
    let app = app();
    let mut headers = auth_headers();
    headers.insert(
        "x-fluxheim-message",
        HeaderValue::from_str(&"a".repeat(fluxheim_snapshot::MAX_SNAPSHOT_MESSAGE_BYTES + 1))
            .unwrap(),
    );

    let response = app.handle("POST", "/_fluxheim/snapshot", None, &headers);

    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(app.store.list().unwrap().len(), 0);
}

#[test]
fn admin_from_config_does_not_install_proxy_health_reporter_for_self_healing() {
    let dir = TestDir::new("admin-proxy-health-reporter");
    let token_file = dir.path.join("admin-token");
    std::fs::write(&token_file, "secret-token\n").unwrap();
    let config = Config {
        admin: AdminConfig {
            enabled: true,
            token_file: Some(token_file),
            snapshot_store: Some(dir.path.join("snapshots")),
            self_healing: AdminSelfHealingConfig {
                enabled: true,
                ..AdminSelfHealingConfig::default()
            },
            ..AdminConfig::default()
        },
        ..Config::default()
    };
    let proxy = FluxProxy::from_config(&config).unwrap();

    let app = AdminApp::from_config(&config, proxy).unwrap();

    assert!(!app.proxy.has_health_reporter());
}

#[test]
fn watchdog_interval_is_bounded() {
    let app = app_with_config_and_self_healing(Config::default(), true);

    assert_eq!(app.watchdog_interval_secs(), 5);
}

#[test]
fn rollback_endpoint_moves_pointer_without_live_apply() {
    let app = app();
    let first = app
        .store
        .snapshot_config(&Config::default(), Some("first"))
        .unwrap();
    let second = app
        .store
        .snapshot_config(&Config::default(), Some("second"))
        .unwrap();
    assert_eq!(app.store.current_id().unwrap(), Some(second.id));

    let response = app.handle("POST", "/_fluxheim/rollback", None, &auth_headers());

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(app.store.current_id().unwrap(), Some(first.id));
    assert!(
        String::from_utf8(response.body)
            .unwrap()
            .contains(r#""live_apply":false"#)
    );
}

#[test]
fn rollback_endpoint_rejects_oversized_target_without_reflecting_it() {
    let app = app();
    let target = "a".repeat(129);
    let mut headers = auth_headers();
    headers.insert(
        "x-fluxheim-rollback-to",
        HeaderValue::from_str(&target).unwrap(),
    );

    let response = app.handle("POST", "/_fluxheim/rollback", None, &headers);
    let body = String::from_utf8(response.body).unwrap();

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(body.contains("129 bytes"));
    assert!(body.contains("expected 1..=128"));
    assert!(!body.contains(&target));
}

#[test]
fn rollback_endpoint_can_live_apply_snapshot_safe_target() {
    let live_config = Config {
        vhosts: vec![VhostConfig {
            name: "live".to_owned(),
            hosts: vec!["live.test".to_owned()],
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
    let app = app_with_config(live_config.clone());
    let rollback_config = Config {
        vhosts: vec![VhostConfig {
            name: "rollback".to_owned(),
            hosts: vec!["rollback.test".to_owned()],
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
    let rollback = app
        .store
        .snapshot_config(&rollback_config, Some("rollback"))
        .unwrap();
    let live = app
        .store
        .snapshot_config(&live_config, Some("live"))
        .unwrap();
    assert_eq!(app.store.current_id().unwrap(), Some(live.id));

    let response = app.handle(
        "POST",
        "/_fluxheim/rollback",
        Some("live=true"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(app.store.current_id().unwrap(), Some(rollback.id.clone()));
    assert_eq!(app.proxy.route_host(Some("rollback.test")), "rollback");
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""live_apply":true"#));
    assert!(body.contains(r#""impact":"snapshot""#));
}

#[test]
fn live_rollback_rejects_process_upgrade_target_without_moving_pointer() {
    let app = app();
    let process_upgrade_config = Config {
        server: ServerConfig {
            listen: vec!["127.0.0.1:19081".to_owned()],
            ..ServerConfig::default()
        },
        ..Config::default()
    };
    let process_upgrade = app
        .store
        .snapshot_config(&process_upgrade_config, Some("process upgrade"))
        .unwrap();
    let current = app
        .store
        .snapshot_config(&Config::default(), Some("current"))
        .unwrap();
    assert_eq!(app.store.current_id().unwrap(), Some(current.id.clone()));

    let response = app.handle(
        "POST",
        "/_fluxheim/rollback",
        Some("live=true"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(app.store.current_id().unwrap(), Some(current.id));
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(&process_upgrade.id));
    assert!(body.contains("listener-changed"));
}

#[test]
fn reload_endpoint_requires_current_snapshot() {
    let response = app().handle("POST", "/_fluxheim/reload", None, &auth_headers());

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(
        String::from_utf8(response.body)
            .unwrap()
            .contains("current pointer")
    );
}

#[test]
fn reload_endpoint_applies_snapshot_safe_config() {
    let app = app();
    let new_config = Config {
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
    let snapshot = app
        .store
        .snapshot_config(&new_config, Some("add example vhost"))
        .unwrap();

    let response = app.handle("POST", "/_fluxheim/reload", None, &auth_headers());

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""live_apply":true"#));
    assert!(body.contains(&snapshot.id));
    assert_eq!(app.proxy.route_host(Some("example.test")), "example");
    assert_eq!(app.current_config.load().vhosts[0].name, "example");
}
