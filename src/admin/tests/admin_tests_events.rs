use super::*;
use fluxheim_observability::event_test_support::Capture;

#[test]
fn audit_provenance_does_not_accept_request_assertions_or_secrets() {
    let capture = Capture::start();
    let app = app();
    let mut headers = HeaderMap::new();
    for name in [
        "x-request-id",
        "traceparent",
        "x-fluxheim-actor",
        "x-fluxheim-message",
    ] {
        headers.insert(name, HeaderValue::from_static("SECRET-CANARY"));
    }
    let response = app.handle("POST", "/_fluxheim/snapshot", None, &headers);
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    capture.assert_reason("authentication_rejected", 1);
    assert!(
        capture
            .events()
            .iter()
            .all(|e| e["data"]["kind"] != "audit")
    );
    headers.extend(auth_headers());
    let response = app.handle("POST", "/_fluxheim/snapshot", None, &headers);
    assert_eq!(response.status, StatusCode::CREATED);
    capture.assert_audit("snapshot", "succeeded", "admin_token");
    for event in capture.events() {
        assert!(!event.to_string().contains("SECRET-CANARY"));
        assert_eq!(event["correlation"], serde_json::json!({}));
        assert!(event.get("resource").is_none());
    }
}

#[test]
fn authenticated_rejection_is_audited_but_unknown_routes_are_not_mutations() {
    let capture = Capture::start();
    let app = app();
    let response = app.handle("POST", "/_fluxheim/reload", None, &auth_headers());
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    capture.assert_audit("reload", "rejected", "admin_token");
    let count = capture.events().len();
    assert_eq!(
        app.handle(
            "POST",
            "/_fluxheim/snapshot/SECRET-CANARY",
            None,
            &auth_headers()
        )
        .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(capture.events().len(), count);
}
