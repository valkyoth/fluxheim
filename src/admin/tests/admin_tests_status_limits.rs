use super::*;

#[test]
fn status_endpoint_reports_tls_compliance_mode() {
    let config = Config {
        tls: crate::config::TlsConfig {
            iso19790: crate::config::TlsIso19790Config {
                required: true,
                require_disk_cache_encryption: false,
            },
            ..crate::config::TlsConfig::default()
        },
        ..Config::default()
    };
    let response =
        app_with_config(config).handle("GET", "/_fluxheim/status", None, &auth_headers());

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""tls_compliance_mode":"ISO/IEC 19790""#));
    assert!(body.contains(r#""tls_iso19790_required":true"#));
}

#[test]
fn admin_auth_throttle_locks_repeated_failures_by_source() {
    let mut config = Config::default();
    config.admin.auth_throttle = AdminAuthThrottleConfig {
        enabled: true,
        window_secs: 60,
        per_source_failures: 2,
        global_failures: 100,
        base_lockout_secs: 60,
        max_lockout_secs: 60,
        max_sources: 16,
    };
    let app = app_with_config(config);
    let source = Some("192.0.2.10".parse().unwrap());
    let other_source = Some("192.0.2.11".parse().unwrap());

    let response =
        app.handle_with_source("GET", "/_fluxheim/status", None, &HeaderMap::new(), source);
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    let response =
        app.handle_with_source("GET", "/_fluxheim/status", None, &HeaderMap::new(), source);
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.body, br#"{"error":"admin_auth_throttled"}"#);

    let response =
        app.handle_with_source("GET", "/_fluxheim/status", None, &auth_headers(), source);
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);

    let response = app.handle_with_source(
        "GET",
        "/_fluxheim/status",
        None,
        &auth_headers(),
        other_source,
    );
    assert_eq!(response.status, StatusCode::OK);
}

#[test]
fn admin_auth_global_throttle_rejects_invalid_attempts_but_allows_valid_operator() {
    let mut config = Config::default();
    config.admin.auth_throttle = AdminAuthThrottleConfig {
        enabled: true,
        window_secs: 60,
        per_source_failures: 100,
        global_failures: 2,
        base_lockout_secs: 60,
        max_lockout_secs: 60,
        max_sources: 16,
    };
    let app = app_with_config(config);

    for source in ["192.0.2.20", "192.0.2.21"] {
        let response = app.handle_with_source(
            "GET",
            "/_fluxheim/status",
            None,
            &HeaderMap::new(),
            Some(source.parse().unwrap()),
        );
        if source == "192.0.2.20" {
            assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        } else {
            assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
        }
    }

    let response = app.handle_with_source(
        "GET",
        "/_fluxheim/status",
        None,
        &auth_headers(),
        Some("192.0.2.22".parse().unwrap()),
    );
    assert_eq!(response.status, StatusCode::OK);

    let response = app.handle_with_source(
        "GET",
        "/_fluxheim/status",
        None,
        &HeaderMap::new(),
        Some("192.0.2.23".parse().unwrap()),
    );
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
}

#[test]
fn admin_auth_throttle_evicts_stale_source_when_source_table_is_full() {
    let throttle = AdminAuthThrottle::new(AdminAuthThrottleConfig {
        enabled: true,
        window_secs: 60,
        per_source_failures: 100,
        global_failures: 100,
        base_lockout_secs: 60,
        max_lockout_secs: 60,
        max_sources: 1,
    });

    assert_eq!(
        throttle.record_failure(Some("192.0.2.30".parse().unwrap())),
        None
    );
    assert_eq!(
        throttle.record_failure(Some("192.0.2.31".parse().unwrap())),
        None
    );
    assert_eq!(
        throttle.pre_auth_check(Some("192.0.2.30".parse().unwrap())),
        None
    );
    assert_eq!(
        throttle.record_failure(Some("192.0.2.31".parse().unwrap())),
        None
    );
}

#[test]
fn admin_auth_throttle_does_not_source_lock_indeterminate_clients() {
    let throttle = AdminAuthThrottle::new(AdminAuthThrottleConfig {
        enabled: true,
        window_secs: 60,
        per_source_failures: 2,
        global_failures: 100,
        base_lockout_secs: 60,
        max_lockout_secs: 60,
        max_sources: 16,
    });

    assert_eq!(throttle.record_failure(None), None);
    assert_eq!(throttle.record_failure(None), None);
    assert_eq!(throttle.pre_auth_check(None), None);
}

#[test]
fn admin_endpoint_rejects_oversized_query_before_parsing() {
    let query = "x=".to_owned() + &"a".repeat(super::super::MAX_ADMIN_QUERY_BYTES);

    let response = app().handle("GET", "/_fluxheim/status", Some(&query), &auth_headers());

    assert_eq!(response.status, StatusCode::URI_TOO_LONG);
    assert_eq!(response.body, br#"{"error":"query_too_large"}"#);
}

#[test]
fn admin_endpoint_rejects_oversized_path_before_routing() {
    let path = "/".to_owned() + &"a".repeat(super::super::MAX_ADMIN_PATH_BYTES);

    let response = app().handle("GET", &path, None, &auth_headers());

    assert_eq!(response.status, StatusCode::URI_TOO_LONG);
    assert_eq!(response.body, br#"{"error":"path_too_large"}"#);
}
