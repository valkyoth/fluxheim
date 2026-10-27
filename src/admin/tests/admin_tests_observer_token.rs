use super::*;

const PATH: &str = "/_fluxheim/operational-status";

fn observer_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer observer-secret"),
    );
    headers
}

fn observer_app() -> AdminApp {
    let mut app = app();
    app.operational_token = Some(AdminToken::new("observer-secret", false));
    app
}

#[test]
fn operational_observer_obeys_certificate_policy_and_auth_throttle() {
    let mut app = observer_app();
    let mut config = AdminConfig::default();
    config.client_certificate.required = true;
    app.client_certificate = super::super::AdminClientCertificatePolicy::from_config(&config);
    assert_eq!(
        app.handle("GET", PATH, None, &observer_headers()).status,
        StatusCode::FORBIDDEN
    );
    app.client_certificate =
        super::super::AdminClientCertificatePolicy::from_config(&AdminConfig::default());
    app.auth_throttle = AdminAuthThrottle::new(AdminAuthThrottleConfig {
        per_source_failures: 1,
        ..Default::default()
    });
    let source = Some("127.0.0.1".parse().unwrap());
    assert_eq!(
        app.handle_with_source("POST", "/_fluxheim/reload", None, &HeaderMap::new(), source)
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        app.handle_with_source("GET", PATH, None, &observer_headers(), source)
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[cfg(windows)]
#[test]
fn operational_observer_rejects_everyone_read_acl() {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::{LocalBox, SecurityDescriptor};
    let dir = TestDir::new("observer-windows-acl");
    let path = dir.path.join("token");
    write_private(&path, b"observer-secret");
    let config = AdminConfig {
        operational_token_file: Some(path.clone()),
        ..Default::default()
    };
    let control = AdminToken::new("secret-token", false);
    assert!(super::super::load_operational_token(&config, &control, false).is_ok());
    let current = windows_permissions::utilities::current_process_sid().unwrap();
    let descriptor: LocalBox<SecurityDescriptor> =
        format!("D:P(A;;FA;;;{current})(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)")
            .parse()
            .unwrap();
    windows_permissions::wrappers::SetNamedSecurityInfo(
        &path,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        descriptor.dacl(),
        None,
    )
    .unwrap();
    assert!(super::super::load_operational_token(&config, &control, false).is_err());
}

#[test]
fn operational_observer_is_limited_to_exact_get_route_before_recovery() {
    let mut app = observer_app();
    app.auth_throttle = AdminAuthThrottle::new(AdminAuthThrottleConfig {
        enabled: false,
        ..Default::default()
    });
    app.self_healing_enabled = true;
    set_test_runtime_state(
        &app,
        Some("candidate".into()),
        None,
        Some(PendingValidation {
            target_snapshot: "candidate".into(),
            previous_snapshot: None,
            impact: "snapshot".into(),
            expires_unix_secs: 0,
            successful_checks: 0,
            failed_checks: 0,
            rollback_attempts: 0,
            last_rollback_failure: None,
        }),
    );
    let before = app.runtime_state();
    for headers in [observer_headers(), auth_headers()] {
        assert_eq!(
            app.handle("GET", PATH, None, &headers).status,
            StatusCode::OK
        );
    }
    for path in [
        "status",
        "snapshots",
        "snapshot",
        "reload",
        "rollback",
        "health",
        "self-heal/confirm",
        "self-heal/fail",
        "self-heal/report",
        "cache/status",
        "cache/activity/reset",
        "cache/purge",
        "cache/purge-bulk",
        "cache/purge-index",
        "cache/purge-prefix",
        "cache/purge-tag",
        "cache/purge-stale",
        "cache/purge-wildcard",
        "load-balancer/status",
        "load-balancer/member-state",
        "load-balancer/member-weight",
        "load-balancer/member-add",
        "load-balancer/member-remove",
        "load-balancer/member-update",
        "load-balancer/persistence/clear",
        "udp/status",
        "operational-status/",
        "%6fperational-status",
    ] {
        for method in ["GET", "POST"] {
            let response = app.handle(
                method,
                &format!("/_fluxheim/{path}"),
                None,
                &observer_headers(),
            );
            assert_eq!(response.status, StatusCode::FORBIDDEN, "{method} {path}");
        }
    }
    for method in ["POST", "PUT", "DELETE", "HEAD"] {
        assert_eq!(
            app.handle(method, PATH, None, &observer_headers()).status,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(app.runtime_state(), before);
    assert!(app.store.list().unwrap().is_empty());
    // Disabled observer credentials never fall back to a working observer secret.
    app.operational_token = None;
    assert_eq!(
        app.handle("GET", PATH, None, &observer_headers()).status,
        StatusCode::UNAUTHORIZED
    );
}

#[cfg(unix)]
#[test]
fn operational_observer_socket_cannot_read_snapshots_or_mutate() {
    let app = observer_app();
    for require in [false, true] {
        assert_eq!(
            app.handle_ops_socket("GET", PATH, None, Some(&observer_headers()), require)
                .status,
            StatusCode::OK
        );
        assert_eq!(
            app.handle_ops_socket(
                "GET",
                "/_fluxheim/snapshots",
                None,
                Some(&observer_headers()),
                require
            )
            .status,
            StatusCode::FORBIDDEN
        );
        assert!(
            !app.handle_ops_socket(
                "POST",
                "/_fluxheim/reload",
                None,
                Some(&observer_headers()),
                require
            )
            .status
            .is_success()
        );
    }
    assert_eq!(
        app.handle_ops_socket(
            "GET",
            "/_fluxheim/status",
            None,
            Some(&observer_headers()),
            true
        )
        .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.handle_ops_socket(
            "GET",
            "/_fluxheim/snapshots",
            None,
            Some(&auth_headers()),
            true
        )
        .status,
        StatusCode::OK
    );
}

fn write_private(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    #[cfg(windows)]
    let mut file = fluxheim_config::fs_trust::create_confidential_file(path).unwrap();
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap()
    };
    file.write_all(bytes).unwrap();
}

#[test]
fn operational_observer_startup_rejects_identical_empty_large_and_missing_secrets() {
    let dir = TestDir::new("observer-secrets");
    let control = dir.path.join("control");
    write_private(&control, b"secret-token");
    for (name, bytes) in [
        ("same", b" secret-token\n".to_vec()),
        ("empty", b" \n".to_vec()),
        ("large", vec![b'x'; MAX_ADMIN_TOKEN_FILE_BYTES as usize + 1]),
        ("distinct", b"observer-secret".to_vec()),
    ] {
        let observer = dir.path.join(name);
        write_private(&observer, &bytes);
        let config = Config {
            admin: AdminConfig {
                token_file: Some(control.clone()),
                operational_token_file: Some(observer),
                snapshot_store: Some(dir.path.join("snapshots")),
                ..Default::default()
            },
            ..Default::default()
        };
        let result = AdminApp::from_config(&config, FluxProxy::from_config(&config).unwrap());
        assert_eq!(result.is_ok(), name == "distinct", "{name}");
        if let Ok(app) = result {
            assert_eq!(
                app.handle("GET", PATH, None, &observer_headers()).status,
                StatusCode::OK
            );
        }
    }
    let config = AdminConfig {
        operational_token_file: Some(dir.path.join("missing")),
        ..Default::default()
    };
    assert!(
        super::super::load_operational_token(
            &config,
            &AdminToken::new("secret-token", false),
            false
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn operational_observer_rejects_public_and_linked_secret_files() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = TestDir::new("observer-permissions");
    let path = dir.path.join("token");
    write_private(&path, b"observer-secret");
    let control = AdminToken::new("secret-token", false);
    let load = |path| {
        super::super::load_operational_token(
            &AdminConfig {
                operational_token_file: Some(path),
                ..Default::default()
            },
            &control,
            false,
        )
    };
    for mode in [0o640, 0o644, 0o660] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(load(path.clone()).is_err());
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load(path.clone()).is_ok());
    let link = dir.path.join("link");
    symlink(&path, &link).unwrap();
    assert!(load(link).is_err());
    assert!(load(dir.path.clone()).is_err());
}
