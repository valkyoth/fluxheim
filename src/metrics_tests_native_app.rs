use super::*;
#[test]
fn records_host_routing_rejection_counter() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_host_routing_rejection("missing");
    record_host_routing_rejection("attacker-reason");

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("fluxheim_host_routing_rejections_total"));
    assert!(output.contains(r#"reason="missing""#));
    assert!(output.contains(r#"reason="other""#));
}

#[test]
fn records_admin_auth_event_counter() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_admin_auth_event("failure", "source");
    record_admin_auth_event("throttled", "global");
    record_admin_auth_event("attacker-event", "attacker-scope");

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("fluxheim_admin_auth_events_total"));
    assert!(output.contains(r#"event="failure",scope="source""#));
    assert!(output.contains(r#"event="throttled",scope="global""#));
    assert!(output.contains(r#"event="other",scope="other""#));
}

#[test]
fn native_prometheus_response_exposes_text_metrics() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_admin_auth_event("failure", "source");
    let response = native_prometheus_response().unwrap();
    let output = String::from_utf8(response.body().to_vec()).unwrap();

    assert_eq!(response.status(), 200);
    assert!(
        response
            .headers()
            .iter()
            .any(|(name, value)| name == "content-type" && value.starts_with("text/plain"))
    );
    assert!(output.contains("fluxheim_admin_auth_events_total"));
    assert!(output.contains(r#"event="failure",scope="source""#));
}

#[test]
fn native_metrics_app_serves_prometheus_response() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_admin_auth_event("failure", "source");
    let request = fluxheim_server::NativeHttp1Request {
        method: "GET".to_owned(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: "/metrics".to_owned(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![("host".to_owned(), "metrics.test".to_owned())],
        body: Zeroizing::new(Vec::new()),
        trailers: Vec::new(),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let response = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &NativeMetricsApp::new(),
        request,
    ));
    let output = String::from_utf8(response.body().to_vec()).unwrap();

    assert_eq!(response.status(), 200);
    assert!(
        response
            .headers()
            .iter()
            .any(|(name, value)| name == "content-type" && value.starts_with("text/plain"))
    );
    assert!(output.contains("fluxheim_admin_auth_events_total"));
    assert!(output.contains(r#"event="failure",scope="source""#));
}

#[test]
fn native_metrics_app_restricts_method_and_target() {
    let _guard = metrics_test_lock();
    init().unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let app = NativeMetricsApp::new();

    let head = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &app,
        native_metrics_request("HEAD", "/metrics"),
    ));
    assert_eq!(head.status(), 200);
    assert_eq!(head.body(), b"");
    assert!(head.content_length().is_some_and(|length| length > 0));

    let absolute = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &app,
        native_metrics_request("GET", "http://metrics.test/metrics?format=prometheus"),
    ));
    assert_eq!(absolute.status(), 200);

    let wrong_path = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &app,
        native_metrics_request("GET", "/"),
    ));
    assert_eq!(wrong_path.status(), 404);

    let wrong_method = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &app,
        native_metrics_request("POST", "/metrics"),
    ));
    assert_eq!(wrong_method.status(), 405);
    assert!(
        wrong_method
            .headers()
            .iter()
            .any(|(name, value)| name == "allow" && value == "GET, HEAD")
    );
}

#[test]
fn native_metrics_app_can_require_bearer_token() {
    let _guard = metrics_test_lock();
    init().unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let app = NativeMetricsApp::new().with_bearer_token("metrics-secret");

    let missing = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &app,
        native_metrics_request("GET", "/metrics"),
    ));
    assert_eq!(missing.status(), 401);
    assert!(
        missing
            .headers()
            .iter()
            .any(|(name, value)| name == "www-authenticate" && value == "Bearer realm=\"metrics\"")
    );

    let mut wrong = native_metrics_request("GET", "/metrics");
    wrong
        .headers
        .push(("authorization".to_owned(), "Bearer wrong".to_owned()));
    let wrong = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(&app, wrong));
    assert_eq!(wrong.status(), 401);

    let mut authorized = native_metrics_request("GET", "/metrics");
    authorized.headers.push((
        "authorization".to_owned(),
        "Bearer metrics-secret".to_owned(),
    ));
    let authorized = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &app, authorized,
    ));
    assert_eq!(authorized.status(), 200);
}

#[test]
fn native_metrics_app_loads_bearer_token_from_config_file() {
    let _guard = metrics_test_lock();
    init().unwrap();

    let token_file = unique_temp_path("native-metrics-token-file");
    std::fs::write(&token_file, "metrics-file-secret\n").unwrap();
    let config = crate::config::MetricsConfig {
        token_file: Some(token_file.clone()),
        ..crate::config::MetricsConfig::default()
    };
    let app = native_metrics_app_from_config(&config).unwrap();
    let _ = std::fs::remove_file(&token_file);
    let debug = format!("{app:?}");
    assert!(debug.contains("bearer_token_configured: true"));
    assert!(!debug.contains("metrics-file-secret"));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let missing = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &app,
        native_metrics_request("GET", "/metrics"),
    ));
    assert_eq!(missing.status(), 401);

    let mut authorized = native_metrics_request("GET", "/metrics");
    authorized.headers.push((
        "authorization".to_owned(),
        "Bearer metrics-file-secret".to_owned(),
    ));
    let authorized = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &app, authorized,
    ));
    assert_eq!(authorized.status(), 200);
}

#[test]
fn native_metrics_background_service_binds_and_stops() {
    let _guard = metrics_test_lock();
    init().unwrap();

    let config = crate::config::MetricsConfig {
        enabled: true,
        listen: "127.0.0.1:0".to_owned(),
        ..crate::config::MetricsConfig::default()
    };
    let service = metrics_background_service_from_config(&config)
        .unwrap()
        .expect("metrics service");
    let service = service.into_native();
    assert_eq!(service.name(), "Fluxheim metrics HTTP");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let supervisor = fluxheim_runtime::NativeBackgroundSupervisor::new();
        let (ready_tx, mut ready_rx) = tokio::sync::watch::channel(false);
        let handle = supervisor.spawn_service_with_ready(service, move || {
            let _ = ready_tx.send(true);
        });
        ready_rx.changed().await.unwrap();
        assert!(*ready_rx.borrow());
        assert!(supervisor.shutdown());
        handle.join().await.unwrap();
    });
}

#[test]
fn native_metrics_app_serves_prometheus_response_through_listener() {
    let _guard = metrics_test_lock();
    init().unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let response = runtime.block_on(async {
        record_admin_auth_event("failure", "source");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            fluxheim_server::serve_native_http1_listener(
                listener,
                fluxheim_server::DownstreamHttp1Policy::default(),
                std::sync::Arc::new(NativeMetricsApp::new()),
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
            .unwrap();
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut client,
            b"GET /metrics HTTP/1.1\r\nHost: metrics.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let mut response = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut client, &mut response)
            .await
            .unwrap();
        let _ = shutdown_tx.send(());
        String::from_utf8(response).unwrap()
    });

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: text/plain"));
    assert!(response.contains("fluxheim_admin_auth_events_total"));
    assert!(response.contains(r#"event="failure",scope="source""#));
}

#[test]
fn native_metrics_listener_enforces_bearer_token() {
    let _guard = metrics_test_lock();
    init().unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (missing, authorized) = runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            tokio::spawn(async move {
                fluxheim_server::serve_native_http1_listener(
                    listener,
                    fluxheim_server::DownstreamHttp1Policy::default(),
                    std::sync::Arc::new(
                        NativeMetricsApp::new().with_bearer_token("listener-secret"),
                    ),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
                .unwrap();
            });

            let missing = native_metrics_listener_request(
                addr,
                b"GET /metrics HTTP/1.1\r\nHost: metrics.test\r\nConnection: close\r\n\r\n",
            )
            .await;
            let authorized = native_metrics_listener_request(
                addr,
                b"GET /metrics HTTP/1.1\r\nHost: metrics.test\r\nAuthorization: Bearer listener-secret\r\nConnection: close\r\n\r\n",
            )
            .await;
            let _ = shutdown_tx.send(());
            (missing, authorized)
        });

    assert!(missing.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
    assert!(missing.contains("www-authenticate: Bearer realm=\"metrics\""));
    assert!(authorized.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(authorized.contains("content-type: text/plain"));
}

fn native_metrics_request(method: &str, target: &str) -> fluxheim_server::NativeHttp1Request {
    fluxheim_server::NativeHttp1Request {
        method: method.to_owned(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: target.to_owned(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![("host".to_owned(), "metrics.test".to_owned())],
        body: Zeroizing::new(Vec::new()),
        trailers: Vec::new(),
    }
}

async fn native_metrics_listener_request(addr: std::net::SocketAddr, request: &[u8]) -> String {
    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut client, request)
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut client, &mut response)
        .await
        .unwrap();
    String::from_utf8(response).unwrap()
}
