use super::*;

const OBSERVER_PATH: &str = "/_fluxheim/operational-status";
const CONTROL_PATH: &str = "/_fluxheim/status";

fn headers(token: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, HeaderValue::from_static(token));
    headers
}

fn observer_app() -> AdminApp {
    let mut app = app();
    app.operational_token = Some(AdminToken::new("observer-secret", false));
    app
}

#[test]
fn observer_success_cannot_erase_control_guesses_on_any_route() {
    for path in [CONTROL_PATH, OBSERVER_PATH] {
        let app = observer_app();
        let source = Some("192.0.2.45".parse().unwrap());
        for _ in 0..9 {
            assert_eq!(
                app.handle_with_source(
                    "GET",
                    path,
                    None,
                    &headers("Bearer guessed-control"),
                    source
                )
                .status,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                app.handle_with_source(
                    "GET",
                    OBSERVER_PATH,
                    None,
                    &headers("Bearer observer-secret"),
                    source
                )
                .status,
                StatusCode::OK
            );
        }
        assert_eq!(
            app.handle_with_source(
                "GET",
                path,
                None,
                &headers("Bearer guessed-control"),
                source
            )
            .status,
            StatusCode::TOO_MANY_REQUESTS
        );
        for credential in [headers("Bearer observer-secret"), auth_headers()] {
            assert_eq!(
                app.handle_with_source("GET", OBSERVER_PATH, None, &credential, source)
                    .status,
                StatusCode::TOO_MANY_REQUESTS
            );
        }
        assert_eq!(
            app.handle_with_source(
                "GET",
                CONTROL_PATH,
                None,
                &auth_headers(),
                Some("192.0.2.46".parse().unwrap())
            )
            .status,
            StatusCode::OK
        );
    }
}

#[test]
fn observer_authorization_denial_does_not_modify_failure_budget() {
    let app = observer_app();
    let source = Some("192.0.2.47".parse().unwrap());
    assert_eq!(
        app.handle_with_source("GET", CONTROL_PATH, None, &HeaderMap::new(), source)
            .status,
        StatusCode::UNAUTHORIZED
    );
    for _ in 0..20 {
        assert_eq!(
            app.handle_with_source(
                "POST",
                "/_fluxheim/reload",
                None,
                &headers("Bearer observer-secret"),
                source
            )
            .status,
            StatusCode::FORBIDDEN
        );
    }
    for _ in 0..8 {
        assert_eq!(
            app.handle_with_source("GET", CONTROL_PATH, None, &HeaderMap::new(), source)
                .status,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        app.handle_with_source("GET", CONTROL_PATH, None, &HeaderMap::new(), source)
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[test]
fn only_control_success_resets_shared_source_failures() {
    let app = observer_app();
    let source = Some("192.0.2.48".parse().unwrap());
    for _ in 0..2 {
        for _ in 0..9 {
            assert_eq!(
                app.handle_with_source("GET", CONTROL_PATH, None, &HeaderMap::new(), source)
                    .status,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            app.handle_with_source("GET", OBSERVER_PATH, None, &auth_headers(), source)
                .status,
            StatusCode::OK
        );
    }
}

#[test]
fn observer_success_does_not_reset_global_invalid_attempt_lockout() {
    let mut app = observer_app();
    app.auth_throttle = AdminAuthThrottle::new(AdminAuthThrottleConfig {
        global_failures: 2,
        ..Default::default()
    });
    for source in [None, Some("192.0.2.49".parse().unwrap())] {
        let response = app.handle_with_source("GET", CONTROL_PATH, None, &HeaderMap::new(), source);
        assert!(matches!(
            response.status,
            StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS
        ));
        assert_eq!(
            app.handle_with_source(
                "GET",
                OBSERVER_PATH,
                None,
                &headers("Bearer observer-secret"),
                source
            )
            .status,
            StatusCode::OK
        );
    }
    assert_eq!(
        app.handle_with_source("GET", CONTROL_PATH, None, &HeaderMap::new(), None)
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Preserve the documented incident-response exception for valid operators.
    assert_eq!(
        app.handle_with_source("GET", CONTROL_PATH, None, &auth_headers(), None)
            .status,
        StatusCode::OK
    );
}
