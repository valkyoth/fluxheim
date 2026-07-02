use super::*;
#[test]
fn admin_json_response_is_size_bounded() {
    let body = vec![b'x'; super::super::MAX_ADMIN_JSON_RESPONSE_BYTES + 1];
    let response = json_response(StatusCode::OK, &body);

    assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        String::from_utf8(response.body)
            .unwrap()
            .contains("exceeded")
    );
}

#[test]
fn admin_error_response_clamps_oversized_messages() {
    let message = "x".repeat(super::super::MAX_ADMIN_ERROR_MESSAGE_CHARS + 128);
    let response = error_response(StatusCode::BAD_REQUEST, &message);
    let body = String::from_utf8(response.body).unwrap();

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(body.len() < message.len());
    assert!(body.contains("..."));
}

#[test]
fn native_admin_target_parts_preserves_absolute_uri_query_without_path() {
    assert_eq!(
        native_admin_target_parts("http://admin.local?reload=true#fragment"),
        ("/", Some("reload=true"))
    );
    assert_eq!(
        native_admin_target_parts("https://admin.local/_fluxheim/health?full=1"),
        ("/_fluxheim/health", Some("full=1"))
    );
    assert_eq!(native_admin_target_parts("http://admin.local"), ("/", None));
}

#[test]
fn health_endpoint_requires_auth_by_default() {
    let response = app().handle("GET", "/_fluxheim/health", None, &HeaderMap::new());
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    let response = app().handle("GET", "/_fluxheim/health", None, &auth_headers());

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, br#"{"status":"ok"}"#);
}

#[tokio::test]
async fn native_admin_http1_preserves_auth_first_health_contract() {
    let app = app();

    let unauthorized = fluxheim_server::NativeHttp1Handler::handle(
        &app,
        native_request("GET", "/_fluxheim/health", Vec::new()),
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED.as_u16());
    assert_eq!(unauthorized.body(), br#"{"error":"unauthorized"}"#);

    let authorized = fluxheim_server::NativeHttp1Handler::handle(
        &app,
        native_request(
            "GET",
            "http://admin.local/_fluxheim/health",
            vec![(
                header::AUTHORIZATION.as_str().to_owned(),
                "Bearer secret-token".to_owned(),
            )],
        ),
    )
    .await;
    assert_eq!(authorized.status(), StatusCode::OK.as_u16());
    assert_eq!(authorized.body(), br#"{"status":"ok"}"#);
    assert!(
        authorized
            .headers()
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("cache-control") && value == "no-store")
    );
}

#[tokio::test]
async fn native_admin_http1_serves_health_through_listener() {
    let app = app();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        fluxheim_server::serve_native_http1_listener(
            listener,
            fluxheim_server::DownstreamHttp1Policy::default(),
            Arc::new(app),
            async {
                let _ = shutdown_rx.await;
            },
        )
        .await
        .unwrap();
    });

    let authorized = native_admin_listener_request(
        addr,
        concat!(
            "GET /_fluxheim/health HTTP/1.1\r\n",
            "Host: admin.test\r\n",
            "Authorization: Bearer secret-token\r\n",
            "Connection: close\r\n",
            "\r\n"
        ),
    )
    .await;
    let _ = shutdown_tx.send(());

    assert!(authorized.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(authorized.contains("cache-control: no-store"));
    assert!(authorized.ends_with(r#"{"status":"ok"}"#));
}

async fn native_admin_listener_request(addr: std::net::SocketAddr, request: &str) -> String {
    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut client, request.as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut client, &mut response)
        .await
        .unwrap();
    String::from_utf8(response).unwrap()
}

#[test]
fn health_endpoint_can_be_explicitly_unauthenticated() {
    let mut config = Config::default();
    config.admin.health.unauthenticated = true;
    let response =
        app_with_config(config).handle("GET", "/_fluxheim/health", None, &HeaderMap::new());

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, br#"{"status":"ok"}"#);
}

#[test]
fn health_endpoint_can_minimize_response() {
    let mut config = Config::default();
    config.admin.health = AdminHealthConfig {
        unauthenticated: true,
        response: AdminHealthResponseMode::Minimal,
    };
    let response =
        app_with_config(config).handle("GET", "/_fluxheim/health", None, &HeaderMap::new());

    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert!(response.body.is_empty());
}

#[cfg(unix)]
#[test]
fn ops_socket_exposes_only_read_only_status_without_bearer_auth() {
    let app = app();

    let response = app.handle_ops_socket("GET", "/_fluxheim/status", None, None, false);
    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""status":"ok""#));

    let response = app.handle_ops_socket("POST", "/_fluxheim/status", None, None, false);
    assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);

    let response = app.handle_ops_socket("POST", "/_fluxheim/reload", None, None, false);
    assert_eq!(response.status, StatusCode::NOT_FOUND);
}

#[cfg(unix)]
#[test]
fn ops_socket_can_require_bearer_auth_for_status() {
    let app = app();

    let response = app.handle_ops_socket("GET", "/_fluxheim/status", None, None, true);
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    let headers = auth_headers();
    let response = app.handle_ops_socket("GET", "/_fluxheim/status", None, Some(&headers), true);
    assert_eq!(response.status, StatusCode::OK);
}

#[cfg(unix)]
#[test]
fn ops_socket_requires_bearer_auth_for_snapshots() {
    let app = app();

    let response = app.handle_ops_socket("GET", "/_fluxheim/snapshots", None, None, false);
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    let headers = auth_headers();
    let response =
        app.handle_ops_socket("GET", "/_fluxheim/snapshots", None, Some(&headers), false);
    assert_eq!(response.status, StatusCode::OK);
}

#[test]
fn status_endpoint_requires_bearer_token() {
    let response = app().handle("GET", "/_fluxheim/status", None, &HeaderMap::new());
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    let response = app().handle("GET", "/_fluxheim/status", None, &auth_headers());
    assert_eq!(response.status, StatusCode::OK);
    assert!(
        String::from_utf8(response.body)
            .unwrap()
            .contains(r#""pending_validation":null"#)
    );
}
