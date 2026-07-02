use super::*;

#[cfg(feature = "load-balancer")]
#[test]
fn load_balancer_runtime_weight_parser_documents_all_reset_keywords() {
    assert_eq!(
        super::super::parse_load_balancer_runtime_weight("configured"),
        Ok(None)
    );
    assert_eq!(
        super::super::parse_load_balancer_runtime_weight("bogus"),
        Err("load balancer weight must be a number or one of default/reset/clear/configured")
    );
}

#[cfg(all(feature = "load-balancer", not(feature = "privacy-mode")))]
#[test]
fn load_balancer_metric_member_label_falls_back_to_member_outside_privacy_mode() {
    assert_eq!(
        super::super::load_balancer_metric_member_label(None, "127.0.0.1:3000"),
        Some("127.0.0.1:3000")
    );
    assert_eq!(
        super::super::load_balancer_metric_member_label(Some("origin-a"), "127.0.0.1:3000"),
        Some("origin-a")
    );
}

#[cfg(all(feature = "load-balancer", feature = "privacy-mode"))]
#[test]
fn load_balancer_display_member_redacts_unaliased_privacy_member() {
    assert_eq!(
        super::super::load_balancer_metric_member_label(None, "127.0.0.1:3000"),
        None
    );
    assert_eq!(
        super::super::load_balancer_display_member(None, "127.0.0.1:3000"),
        "redacted"
    );
    assert_eq!(
        super::super::load_balancer_display_member(Some("origin-a"), "127.0.0.1:3000"),
        "origin-a"
    );
}

#[cfg(feature = "load-balancer")]
#[test]
fn load_balancer_member_state_endpoint_reports_bad_requests() {
    #[cfg(feature = "tls-rustls-backend")]
    let _ = crate::tls::install_rustls_crypto_provider();

    let app = app_with_config(load_balancer_admin_config());
    let invalid_state = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-state",
        Some("vhost=one&member=app-a&state=evacuate"),
        &auth_headers(),
    );
    assert_eq!(invalid_state.status, StatusCode::BAD_REQUEST);

    let unknown_member = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-state",
        Some("vhost=one&member=missing&state=disable"),
        &auth_headers(),
    );
    assert_eq!(unknown_member.status, StatusCode::NOT_FOUND);

    let missing_member = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-state",
        Some("vhost=one&state=disable"),
        &auth_headers(),
    );
    assert_eq!(missing_member.status, StatusCode::BAD_REQUEST);
}

#[cfg(feature = "load-balancer")]
#[test]
fn load_balancer_member_set_endpoints_report_bad_requests() {
    #[cfg(feature = "tls-rustls-backend")]
    let _ = crate::tls::install_rustls_crypto_provider();

    let app = app_with_config(load_balancer_admin_config());
    let missing_vhost = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-add",
        Some("member=127.0.0.1:3003"),
        &auth_headers(),
    );
    assert_eq!(missing_vhost.status, StatusCode::BAD_REQUEST);

    let missing_member = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-add",
        Some("vhost=one"),
        &auth_headers(),
    );
    assert_eq!(missing_member.status, StatusCode::BAD_REQUEST);

    let invalid_weight = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-add",
        Some("vhost=one&member=127.0.0.1:3003&weight=reset"),
        &auth_headers(),
    );
    assert_eq!(invalid_weight.status, StatusCode::BAD_REQUEST);

    let duplicate = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-add",
        Some("vhost=one&member=127.0.0.1:3001"),
        &auth_headers(),
    );
    assert_eq!(duplicate.status, StatusCode::CONFLICT);

    let unknown_remove = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-remove",
        Some("vhost=one&member=127.0.0.1:3999"),
        &auth_headers(),
    );
    assert_eq!(unknown_remove.status, StatusCode::NOT_FOUND);

    let noop_update = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-update",
        Some("vhost=one&member=127.0.0.1:3001"),
        &auth_headers(),
    );
    assert_eq!(noop_update.status, StatusCode::BAD_REQUEST);
}

#[cfg(feature = "load-balancer")]
#[test]
fn load_balancer_persistence_clear_endpoint_reports_scope() {
    #[cfg(feature = "tls-rustls-backend")]
    let _ = crate::tls::install_rustls_crypto_provider();

    let app = app_with_config(load_balancer_admin_config());
    let response = app.handle(
        "POST",
        "/_fluxheim/load-balancer/persistence/clear",
        Some("vhost=one"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["vhost"], "one");
    assert_eq!(body["route"], Value::Null);
    assert_eq!(body["scope"], "vhost");
    assert_eq!(body["cleared_entries"], 0);
    assert_eq!(body["persistent"], false);

    let missing_vhost = app.handle(
        "POST",
        "/_fluxheim/load-balancer/persistence/clear",
        None,
        &auth_headers(),
    );
    assert_eq!(missing_vhost.status, StatusCode::BAD_REQUEST);

    let unknown_vhost = app.handle(
        "POST",
        "/_fluxheim/load-balancer/persistence/clear",
        Some("vhost=missing"),
        &auth_headers(),
    );
    assert_eq!(unknown_vhost.status, StatusCode::NOT_FOUND);
    let body: Value = serde_json::from_slice(&unknown_vhost.body).unwrap();
    assert_eq!(body["status"], "error");
    assert_eq!(body["error"], "load balancer vhost has no configured pool");

    let unknown_route = app.handle(
        "POST",
        "/_fluxheim/load-balancer/persistence/clear",
        Some("vhost=one&route=missing"),
        &auth_headers(),
    );
    assert_eq!(unknown_route.status, StatusCode::NOT_FOUND);
    let body: Value = serde_json::from_slice(&unknown_route.body).unwrap();
    assert_eq!(body["status"], "error");
    assert_eq!(body["error"], "load balancer route has no configured pool");
}
