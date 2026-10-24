use super::*;

const PARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

fn request(headers: &[(&str, &str)]) -> NativeHttp1Request {
    NativeHttp1Request {
        method: "GET".into(),
        peer_addr: Some("127.0.0.1:1234".parse().unwrap()),
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: "/secret?token=secret".into(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: headers
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
        body: crate::NativeHttp1RequestBody::empty(),
        trailers: Vec::new(),
    }
}

fn telemetry(trusted: bool) -> RequestTelemetry {
    let mut config = fluxheim_config::Config::default();
    config.tracing.enabled = true;
    RequestTelemetry::new(
        &config,
        if trusted {
            vec![ProxyProtocolTrustedSource::Ip("127.0.0.1".parse().unwrap())]
        } else {
            Vec::new()
        },
    )
    .unwrap()
}

#[test]
#[cfg(all(feature = "otel-tracing", not(feature = "privacy-mode")))]
fn only_transport_peer_can_authorize_inbound_context() {
    let mut request = request(&[
        ("traceparent", PARENT),
        ("x-request-id", "trusted-id"),
        ("x-forwarded-for", "127.0.0.1"),
    ]);
    let completion = telemetry(false).begin(&mut request);
    let context = &completion.0.context;
    assert_ne!(context.request_id.as_deref(), Some("trusted-id"));
    assert_ne!(context.trace.unwrap().trace_id_hex(), &PARENT[3..35]);
    assert!(!context.trace.unwrap().sampled());
    let mut request =
        super::tests::request(&[("traceparent", PARENT), ("x-request-id", "trusted-id")]);
    let completion = telemetry(true).begin(&mut request);
    assert_eq!(
        completion.0.context.request_id.as_deref(),
        Some("trusted-id")
    );
    assert_eq!(
        completion
            .0
            .context
            .trace
            .unwrap()
            .parent_span_id_hex()
            .as_deref(),
        Some(&PARENT[36..52])
    );
    assert!(completion.0.context.trace.unwrap().sampled());
}

#[test]
#[cfg(not(feature = "privacy-mode"))]
fn duplicate_oversized_and_malformed_ids_are_replaced_without_shortening() {
    let oversized = "a".repeat(4096);
    for values in [
        vec!["one", "two"],
        vec!["same", "same"],
        vec!["bad id"],
        vec![oversized.as_str()],
        vec![""],
    ] {
        let mut headers = values
            .iter()
            .map(|v| ("x-request-id", *v))
            .collect::<Vec<_>>();
        headers.extend([
            ("traceparent", PARENT),
            ("TraceParent", PARENT),
            ("baggage", "secret"),
            ("tracestate", "secret"),
        ]);
        let mut request = request(&headers);
        let completion = telemetry(true).begin(&mut request);
        let id = completion.0.context.request_id.as_deref().unwrap();
        assert!(id.starts_with("fh-"));
        assert!(fluxheim_observability::access_log_request_id_valid(id));
        assert_eq!(unique_header(&request, "x-request-id"), Some(id));
        assert!(unique_header(&request, "baggage").is_none());
        assert!(unique_header(&request, "tracestate").is_none());
        if let Some(trace) = completion.0.context.trace {
            assert_ne!(trace.trace_id_hex(), &PARENT[3..35]);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scopes_are_isolated_and_not_inherited_by_background_tasks() {
    let a = telemetry(true).begin(&mut request(&[("x-request-id", "one")]));
    let b = telemetry(true).begin(&mut request(&[("x-request-id", "two")]));
    let run = |completion: Completion| async move {
        completion
            .scope(async {
                tokio::task::yield_now().await;
                assert!(
                    CURRENT
                        .try_with(|c| Arc::ptr_eq(c, &completion.0.context))
                        .unwrap()
                );
                assert!(
                    tokio::spawn(async { CURRENT.try_with(|_| ()).is_err() })
                        .await
                        .unwrap()
                );
            })
            .await;
    };
    let (a, b) = tokio::join!(tokio::spawn(run(a)), tokio::spawn(run(b)));
    a.unwrap();
    b.unwrap();
    assert!(current_trace().is_none());
}

#[tokio::test]
async fn completion_survives_response_clones_and_writes_once() {
    let completion = telemetry(true).begin(&mut request(&[]));
    let response = completion
        .clone()
        .attach(NativeHttp1Response::new(200, "OK", b"ok"));
    drop(response.clone());
    assert!(!completion.0.finished.load(Ordering::Acquire));
    completion.finish(Some(200), 2, true);
    completion.finish(Some(500), 0, false);
    assert!(completion.0.finished.load(Ordering::Acquire));
    drop(response);
}

#[tokio::test]
#[cfg(all(feature = "otel-tracing", not(feature = "privacy-mode")))]
async fn attempts_and_safe_retries_get_distinct_children() {
    let completion = telemetry(true).begin(&mut request(&[("traceparent", PARENT)]));
    completion
        .scope(async {
            upstream_attempt(async {
                let first = attempt_traceparent().unwrap();
                retry_attempt();
                let second = attempt_traceparent().unwrap();
                assert_eq!(&first[3..35], &second[3..35]);
                assert_ne!(&first[36..52], &second[36..52]);
                assert_ne!(
                    &first[36..52],
                    completion.0.context.trace.unwrap().span_id_hex()
                );
                Ok(NativeHttp1Response::new(200, "OK", b"ok"))
            })
            .await
            .unwrap();
        })
        .await;
    assert_eq!(completion.0.context.attempts.load(Ordering::Relaxed), 2);
    assert!(attempt_traceparent().is_none());
}

#[test]
fn disabled_correlation_has_no_identifiers() {
    let mut telemetry = telemetry(true);
    telemetry.access.request_id = false;
    telemetry.trace = false;
    let completion = telemetry.begin(&mut request(&[("traceparent", PARENT)]));
    assert!(completion.0.context.request_id.is_none());
    assert!(completion.0.context.trace.is_none());
}

#[test]
fn telemetry_rejects_unvalidated_identity_header_configuration() {
    for name in [
        "x-authenticated-user",
        "x-ssl-client-cert",
        "x-client-ip",
        "x-envoy-external-address",
    ] {
        let mut config = fluxheim_config::Config::default();
        config.logging.access.enabled = false;
        config.logging.access.request_id_header = name.into();
        let result = RequestTelemetry::new(&config, Vec::new());
        assert!(result.is_err(), "accepted unsafe request-ID header: {name}");
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }
}

#[test]
#[cfg(not(feature = "privacy-mode"))]
fn correlation_headers_do_not_create_or_replace_identity_headers() {
    for name in ["x-request-id", "X-Correlation-ID"] {
        for trusted in [false, true] {
            let mut telemetry = telemetry(trusted);
            telemetry.access.request_id_header = name.into();
            let mut request = request(&[
                (name, "inbound-id"),
                ("x-authenticated-user", "original-user"),
            ]);
            let completion = telemetry.begin(&mut request);
            assert_eq!(
                unique_header(&request, "x-authenticated-user"),
                Some("original-user")
            );
            assert!(unique_header(&request, "x-ssl-client-cert").is_none());
            assert!(unique_header(&request, "x-client-ip").is_none());
            let id = completion.0.context.request_id.as_deref().unwrap();
            assert_eq!(id == "inbound-id", trusted);
            assert_eq!(unique_header(&request, name), Some(id));
        }
    }
}

#[tokio::test]
#[cfg(all(feature = "otel-tracing", not(feature = "privacy-mode")))]
async fn outbound_header_removal_does_not_remove_local_context_or_reinsert_headers() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
            assert!(head.len() < 4096);
        }
        let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
        assert!(!head.contains("traceparent:"));
        assert!(!head.contains("x-request-id:"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let mut request = request(&[("traceparent", PARENT), ("x-request-id", "local-only")]);
    let completion = telemetry(true).begin(&mut request);
    let policy =
        crate::native_http1_route_request_headers::NativeRouteRequestHeaderPolicy::from_overlay(
            &fluxheim_config::RequestHeaderPolicyOverlayConfig {
                enabled: Some(true),
                unset: vec!["traceparent".into(), "x-request-id".into()],
                ..Default::default()
            },
        );
    policy.apply(&mut request, None);
    let upstream = crate::NativeHttp1Upstream::new(address.to_string());
    let response = completion.scope(upstream.send(&mut request)).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        completion.0.context.request_id.as_deref(),
        Some("local-only")
    );
    assert_eq!(completion.0.context.attempts.load(Ordering::Relaxed), 1);
    origin.await.unwrap();
}

#[test]
#[cfg(feature = "privacy-mode")]
fn privacy_build_never_generates_correlation() {
    let completion = telemetry(true).begin(&mut request(&[
        ("traceparent", PARENT),
        ("x-request-id", "secret"),
    ]));
    assert!(completion.0.context.request_id.is_none());
    assert!(completion.0.context.trace.is_none());
}
