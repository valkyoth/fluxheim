#![allow(unused_imports)]

use std::future::poll_fn;
use std::sync::Arc;
use std::time::Duration;

use super::Backend;
use super::FluxHealthCheck;
use super::HealthDerivedWeights;
#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
use super::transport::{FluxTcpHealthCheck, configured_tcp_health_check_tls_inner};
use super::{
    HealthHttpRequest, HealthHttpResponse, POSTGRES_HEALTH_CHECK_SSL_REQUEST,
    REDIS_HEALTH_CHECK_REQUEST, configured_exec_health_check, configured_health_check,
    configured_http_health_check, configured_mysql_health_check, configured_postgres_health_check,
    configured_redis_health_check, grpc_frame, grpc_health_request_body, record_health_weight,
    validate_grpc_health_response_body, validate_grpc_health_response_header,
    validate_http_health_response, validate_http_health_response_body,
    validate_http_health_response_body_json, validate_mysql_health_handshake,
    validate_postgres_health_response, validate_redis_health_response,
};
use bytes::Bytes;
use fluxheim_config::{
    LoadBalanceConfig, LoadBalanceHealthCheckConfig, LoadBalanceHealthCheckExpectedHeader,
    LoadBalanceHealthCheckExpectedJson, LoadBalanceHealthCheckExpectedStatusRange,
    LoadBalanceHealthCheckProtocol, LoadBalanceHealthCheckRequestHeader, ProxyConfig,
};
use http::{HeaderMap, HeaderValue, StatusCode};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
fn health_response(status: u16, headers: &[(&str, &str)]) -> HealthHttpResponse {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.append(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    HealthHttpResponse {
        status: StatusCode::from_u16(status).unwrap(),
        headers: map,
    }
}
#[test]
fn configures_native_http_health_check() {
    crate::install_test_crypto_provider();
    let health_check = configured_http_health_check(
        &ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            connect_timeout_secs: Some(2),
            read_timeout_secs: Some(4),
            load_balance: LoadBalanceConfig {
                health_check: LoadBalanceHealthCheckConfig {
                    enabled: true,
                    protocol: LoadBalanceHealthCheckProtocol::Http,
                    consecutive_success: 2,
                    consecutive_failure: 3,
                    method: "HEAD".to_owned(),
                    path: "/healthz".to_owned(),
                    host: Some("origin.example.test".to_owned()),
                    request_headers: vec![LoadBalanceHealthCheckRequestHeader {
                        name: "Authorization".to_owned(),
                        value: "Bearer health-token".to_owned(),
                    }],
                    expected_statuses: vec![200, 204],
                    expected_status_ranges: vec![LoadBalanceHealthCheckExpectedStatusRange {
                        start: 300,
                        end: 399,
                    }],
                    expected_headers: vec![LoadBalanceHealthCheckExpectedHeader {
                        name: "x-fluxheim-health".to_owned(),
                        value: "ready".to_owned(),
                    }],
                    expected_body_contains: vec!["ready".to_owned()],
                    expected_body_json: vec![LoadBalanceHealthCheckExpectedJson {
                        path: "status".to_owned(),
                        equals: "ready".to_owned(),
                    }],
                    reuse_connection: true,
                    port_override: Some(8081),
                    connect_timeout_secs: Some(5),
                    read_timeout_secs: Some(6),
                    ..LoadBalanceHealthCheckConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        },
        Arc::new(HealthDerivedWeights::default()),
    )
    .unwrap();

    assert_eq!(health_check.consecutive_success, 2);
    assert_eq!(health_check.consecutive_failure, 3);
    assert_eq!(health_check.req.method.as_str(), "HEAD");
    assert_eq!(
        health_check
            .req
            .headers
            .get("Authorization")
            .map(|value| value.as_bytes()),
        Some("Bearer health-token".as_bytes())
    );
    assert_eq!(health_check.port_override, Some(8081));
    assert_eq!(health_check.connection_timeout, Duration::from_secs(5));
    assert_eq!(health_check.read_timeout, Duration::from_secs(6));
    assert!(!health_check.expected_statuses.is_empty());
    assert!(!health_check.expected_headers.is_empty());
    assert_eq!(
        health_check.expected_body_contains.as_ref(),
        ["ready".to_owned()]
    );
    assert_eq!(health_check.expected_body_json[0].path, "status");
}

#[test]
fn rejects_http_health_check_path_and_host_crlf() {
    let base = ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned()],
        load_balance: LoadBalanceConfig {
            health_check: LoadBalanceHealthCheckConfig {
                enabled: true,
                protocol: LoadBalanceHealthCheckProtocol::Http,
                path: "/healthz".to_owned(),
                host: Some("origin.example.test".to_owned()),
                ..LoadBalanceHealthCheckConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    };

    let mut bad_path = base.clone();
    bad_path.load_balance.health_check.path = "/healthz\r\nX-Injected: yes".to_owned();
    let error =
        match configured_http_health_check(&bad_path, Arc::new(HealthDerivedWeights::default())) {
            Ok(_) => panic!("CRLF path was accepted"),
            Err(error) => error,
        };
    assert!(error.to_string().contains("path must not contain"));

    let mut bad_host = base;
    bad_host.load_balance.health_check.host =
        Some("origin.example.test\r\nX-Injected: yes".to_owned());
    let error =
        match configured_http_health_check(&bad_host, Arc::new(HealthDerivedWeights::default())) {
            Ok(_) => panic!("CRLF host was accepted"),
            Err(error) => error,
        };
    assert!(error.to_string().contains("host must not contain"));
}

#[test]
fn validates_http_health_check_expected_headers() {
    let expected_statuses = [204];
    let expected_status_ranges = [LoadBalanceHealthCheckExpectedStatusRange {
        start: 300,
        end: 399,
    }];
    let expected_headers = [LoadBalanceHealthCheckExpectedHeader {
        name: "x-fluxheim-health".to_owned(),
        value: "ready".to_owned(),
    }];
    let response = health_response(204, &[("x-fluxheim-health", "ready")]);
    assert!(
        validate_http_health_response(
            &response,
            &expected_statuses,
            &expected_status_ranges,
            &expected_headers
        )
        .is_ok()
    );

    let missing = health_response(204, &[]);
    assert!(
        validate_http_health_response(
            &missing,
            &expected_statuses,
            &expected_status_ranges,
            &expected_headers
        )
        .is_err()
    );

    let ranged = health_response(302, &[]);
    assert!(validate_http_health_response(&ranged, &[], &expected_status_ranges, &[]).is_ok());
}

#[test]
fn validates_http_health_check_expected_body_contains() {
    let expected = ["ready".to_owned(), "database=up".to_owned()];
    assert!(validate_http_health_response_body(b"ready database=up", &expected).is_ok());
    assert!(validate_http_health_response_body(b"ready database=down", &expected).is_err());
}

#[test]
fn validates_http_health_check_expected_body_json() {
    let expected = [
        LoadBalanceHealthCheckExpectedJson {
            path: "status".to_owned(),
            equals: "ok".to_owned(),
        },
        LoadBalanceHealthCheckExpectedJson {
            path: "database.connected".to_owned(),
            equals: "true".to_owned(),
        },
        LoadBalanceHealthCheckExpectedJson {
            path: "queue_depth".to_owned(),
            equals: "42".to_owned(),
        },
    ];
    assert!(
        validate_http_health_response_body_json(
            br#"{"status":"ok","database":{"connected":true},"queue_depth":42}"#,
            &expected
        )
        .is_ok()
    );
    assert!(validate_http_health_response_body_json(br#"{"status":"down"}"#, &expected).is_err());
}

#[tokio::test]
async fn http_health_check_uses_native_http1_client() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0);
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /healthz HTTP/1.1\r\n"));
        assert!(request.contains("\r\nHost: origin.example.test\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("\r\nauthorization: bearer health-token\r\n")
        );
        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nx-fluxheim-health: ready\r\nx-health-weight: 40\r\ncontent-length: 18\r\n\r\n{\"status\":\"ready\"}",
                )
                .await
                .unwrap();
    });
    let weights = Arc::new(HealthDerivedWeights::default());
    let health_check = configured_http_health_check(
        &ProxyConfig {
            upstreams: vec![address.to_string()],
            load_balance: LoadBalanceConfig {
                health_check: LoadBalanceHealthCheckConfig {
                    enabled: true,
                    protocol: LoadBalanceHealthCheckProtocol::Http,
                    path: "/healthz".to_owned(),
                    host: Some("origin.example.test".to_owned()),
                    request_headers: vec![LoadBalanceHealthCheckRequestHeader {
                        name: "Authorization".to_owned(),
                        value: "Bearer health-token".to_owned(),
                    }],
                    expected_headers: vec![LoadBalanceHealthCheckExpectedHeader {
                        name: "x-fluxheim-health".to_owned(),
                        value: "ready".to_owned(),
                    }],
                    expected_body_json: vec![LoadBalanceHealthCheckExpectedJson {
                        path: "status".to_owned(),
                        equals: "ready".to_owned(),
                    }],
                    connect_timeout_secs: Some(1),
                    read_timeout_secs: Some(1),
                    ..LoadBalanceHealthCheckConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        },
        weights.clone(),
    )
    .unwrap();
    let backend = Backend::new(&address.to_string()).unwrap();

    health_check.check(&backend).await.unwrap();
    server.await.unwrap();
    assert_eq!(
        weights.weight_percent(super::backend_key(&backend)),
        Some(40)
    );
}

#[test]
fn health_weight_signal_is_clamped_to_configured_floor() {
    let weights = HealthDerivedWeights::default();
    let response = health_response(200, &[("x-health-weight", "1")]);

    assert!(record_health_weight(&response, 42, 25, &weights).is_ok());
    assert_eq!(weights.weight_percent(42), Some(25));

    let recovered = health_response(200, &[("x-health-weight", "100")]);
    assert!(record_health_weight(&recovered, 42, 25, &weights).is_ok());
    assert_eq!(weights.weight_percent(42), None);
}
