use super::*;
use serde_json::Value;

const PATH: &str = "/_fluxheim/operational-status";

fn status(app: &AdminApp) -> Value {
    let response = app.handle("GET", PATH, None, &auth_headers());
    assert_eq!(response.status, StatusCode::OK);
    assert!(response.body.len() <= super::super::operational_status::MAX_RESPONSE);
    serde_json::from_slice(&response.body).unwrap()
}

#[test]
fn operational_auth_methods_queries_and_health_alias_fail_closed() {
    let mut app = app();
    app.health_path = PATH.into();
    app.health_unauthenticated = true;
    assert_eq!(
        app.handle("GET", PATH, None, &HeaderMap::new()).status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.handle("POST", PATH, None, &auth_headers()).status,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        app.handle("GET", PATH, Some("x=1"), &auth_headers()).status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(status(&app)["schema_version"], 1);
}

#[test]
fn operational_certificate_policy_precedes_status_collection() {
    let app = app_with_config(Config {
        admin: AdminConfig {
            client_certificate: AdminClientCertificateConfig {
                required: true,
                allow_sha256: vec!["a".repeat(64)],
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    });
    assert_eq!(
        app.handle("GET", PATH, None, &auth_headers()).status,
        StatusCode::FORBIDDEN
    );
    let mut headers = auth_headers();
    headers.insert(
        "x-client-cert-sha256",
        HeaderValue::from_static(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
    );
    assert_eq!(
        app.handle("GET", PATH, None, &headers).status,
        StatusCode::OK
    );
}

#[test]
fn operational_status_does_not_consult_a_broken_store() {
    let mut app = app();
    let directory = TestDir::new("operational-unreadable-store");
    let file = directory.path.join("not-a-directory");
    std::fs::write(&file, "not a snapshot store").unwrap();
    app.store = SnapshotStore::new(file);
    assert_eq!(status(&app)["health"], "responding");
    assert!(app.status_response().status.is_server_error());
}

#[test]
fn operational_pending_validation_is_not_confirmed_by_polling() {
    let app = app_with_config_and_self_healing(Config::default(), true);
    set_test_runtime_state(
        &app,
        Some("candidate".into()),
        Some("previous".into()),
        Some(PendingValidation {
            target_snapshot: "candidate".into(),
            previous_snapshot: Some("previous".into()),
            impact: "snapshot".into(),
            expires_unix_secs: super::super::unix_secs().saturating_add(3600),
            successful_checks: 0,
            failed_checks: 0,
            rollback_attempts: 0,
            last_rollback_failure: None,
        }),
    );
    let before = app.runtime_state();
    assert_eq!(status(&app)["readiness"], "validating");
    assert_eq!(app.runtime_state(), before);
}

#[test]
fn operational_status_neither_reads_store_nor_enforces_recovery() {
    let app = app_with_config_and_self_healing(Config::default(), true);
    set_test_runtime_state(
        &app,
        Some("secret-snapshot-id".into()),
        None,
        Some(PendingValidation {
            target_snapshot: "secret-snapshot-id".into(),
            previous_snapshot: None,
            impact: "secret-impact".into(),
            expires_unix_secs: 0,
            successful_checks: 0,
            failed_checks: 0,
            rollback_attempts: 0,
            last_rollback_failure: None,
        }),
    );
    let before = app.runtime_state();
    let response = status(&app);
    assert_eq!(response["readiness"], "recovery_required");
    assert!(!response.to_string().contains("secret-"));
    assert_eq!(app.runtime_state(), before);
    // The existing mutation still enforces and records the failed rollback.
    assert_eq!(
        app.handle(
            "POST",
            "/_fluxheim/self-heal/confirm",
            None,
            &auth_headers()
        )
        .status,
        StatusCode::BAD_REQUEST
    );
    let failed = app.runtime_state();
    assert_eq!(
        failed
            .pending_validation
            .as_ref()
            .unwrap()
            .rollback_attempts,
        1
    );
    assert_eq!(status(&app)["readiness"], "recovery_required");
    assert_eq!(app.runtime_state(), failed);
    assert_eq!(
        status(&app)["configuration"]["last_change"]["outcome"],
        "failed"
    );
}

#[test]
fn operational_contention_returns_unavailable_instead_of_waiting() {
    let app = app();
    let _state = app.state.lock().unwrap();
    let start = std::time::Instant::now();
    assert_eq!(
        app.handle("GET", PATH, None, &auth_headers()).status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(start.elapsed() < std::time::Duration::from_secs(1));
    drop(_state);
    let _deadline = app.validation_deadline.lock().unwrap();
    assert_eq!(
        app.handle("GET", PATH, None, &auth_headers()).status,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn operational_restart_generation_and_reload_failure_are_explicit() {
    let app = app();
    let initial = status(&app);
    assert_eq!(initial["configuration"]["generation"], 1);
    assert!(initial["configuration"]["last_change"].is_null());
    assert_eq!(app.reload_response().status, StatusCode::BAD_REQUEST);
    let failed = status(&app);
    assert_eq!(failed["configuration"]["generation"], 1);
    assert_eq!(
        failed["configuration"]["last_change"]["operation"],
        "reload"
    );
    assert_eq!(failed["configuration"]["last_change"]["outcome"], "failed");
    let snapshot = app.store.snapshot_config(&Config::default(), None).unwrap();
    app.apply_snapshot(
        &snapshot,
        Config::default(),
        fluxheim_snapshot::SnapshotApplyMode::Reload,
    )
    .unwrap();
    assert_eq!(status(&app)["configuration"]["generation"], 2);
    let restarted = app_with_config(Config::default());
    assert_ne!(initial["instance_id"], status(&restarted)["instance_id"]);
    assert_eq!(status(&restarted)["configuration"]["generation"], 1);
}

#[test]
fn operational_capabilities_and_platform_limits_match_build() {
    let body = status(&app());
    for (name, enabled) in [
        ("cache", cfg!(feature = "cache")),
        ("php", cfg!(feature = "php-fpm")),
        ("metrics_otlp", cfg!(feature = "metrics-otlp")),
        ("traces_otlp", cfg!(feature = "otel-otlp")),
        ("wasm", cfg!(feature = "wasm")),
        ("load_balancer", cfg!(feature = "load-balancer")),
    ] {
        assert_eq!(body["capabilities"][name], enabled);
    }
    assert_eq!(
        body["platform"]["managed_php"],
        cfg!(all(unix, feature = "php-fpm"))
    );
    assert_eq!(body["platform"]["ops_socket"], cfg!(unix));
    assert_eq!(
        body["telemetry"]["metrics"]["state"],
        if cfg!(feature = "metrics-otlp") {
            "disabled"
        } else {
            "not_compiled"
        }
    );
    assert_eq!(body["readiness"], "ready");
}

#[test]
fn operational_inventory_is_bounded_and_redacted() {
    // Construct directly, bypassing config validation to exercise the hard bound.
    let config: Config = toml::from_str(
        r#"
[[vhosts]]
name = "secret-name"
hosts = ["secret-host.test"]
[vhosts.proxy]
upstreams = ["secret-upstream:8080"]
"#,
    )
    .unwrap();
    let mut huge = config.clone();
    huge.vhosts = vec![config.vhosts[0].clone(); 5000];
    let app = app();
    app.operational.publish(&huge);
    let value = status(&app);
    assert_eq!(value["stale"], true);
    assert_eq!(value["configuration"]["inventory"]["complete"], false);
    assert_eq!(
        value["configuration"]["inventory"]["inspected_scopes"],
        1024
    );
    assert_eq!(value["configuration"]["inventory"]["vhosts"], 5000);
    assert!(!value.to_string().contains("secret-"));
}

#[cfg(unix)]
#[test]
fn operational_ops_socket_still_requires_bearer() {
    let app = app();
    assert_eq!(
        app.handle_ops_socket("GET", PATH, None, None, false).status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.handle_ops_socket("GET", PATH, None, Some(&auth_headers()), false)
            .status,
        StatusCode::OK
    );
}

#[test]
fn operational_concurrent_readers_are_bounded_and_leave_state_unchanged() {
    let app = app();
    let initial = app.runtime_state();
    std::thread::scope(|scope| {
        for _ in 0..16 {
            let app = &app;
            scope.spawn(move || {
                for _ in 0..50 {
                    let reply = app.handle("GET", PATH, None, &auth_headers());
                    assert!(matches!(
                        reply.status,
                        StatusCode::OK | StatusCode::SERVICE_UNAVAILABLE
                    ));
                    assert!(reply.body.len() <= super::super::operational_status::MAX_RESPONSE);
                }
            });
        }
    });
    assert_eq!(app.runtime_state(), initial);
}
