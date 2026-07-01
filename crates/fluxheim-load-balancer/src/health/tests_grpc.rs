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
fn configures_grpc_health_check() {
    crate::install_test_crypto_provider();
    let health_check = configured_http_health_check(
        &ProxyConfig {
            upstreams: vec!["127.0.0.1:50051".to_owned()],
            upstream_h2_max_streams: Some(32),
            load_balance: LoadBalanceConfig {
                health_check: LoadBalanceHealthCheckConfig {
                    protocol: LoadBalanceHealthCheckProtocol::Grpc,
                    host: Some("grpc.example.test".to_owned()),
                    grpc_service: Some("example.Health".to_owned()),
                    ..LoadBalanceHealthCheckConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        },
        Arc::new(HealthDerivedWeights::default()),
    )
    .unwrap();

    assert_eq!(health_check.req.method.as_str(), "POST");
    assert_eq!(health_check.req.path, "/grpc.health.v1.Health/Check");
    assert!(health_check.req.grpc);
    assert_eq!(
        health_check
            .req
            .headers
            .get("content-type")
            .map(|value| value.as_bytes()),
        Some("application/grpc".as_bytes())
    );
    assert_eq!(
        health_check.req.body.as_deref(),
        Some(
            grpc_health_request_body(Some("example.Health"))
                .unwrap()
                .as_slice()
        )
    );
}

#[test]
fn rejects_grpc_health_check_host_with_userinfo() {
    assert!(
        configured_http_health_check(
            &ProxyConfig {
                load_balance: LoadBalanceConfig {
                    health_check: LoadBalanceHealthCheckConfig {
                        protocol: LoadBalanceHealthCheckProtocol::Grpc,
                        host: Some("metadata@backend.example.test".to_owned()),
                        ..LoadBalanceHealthCheckConfig::default()
                    },
                    ..LoadBalanceConfig::default()
                },
                ..ProxyConfig::default()
            },
            Arc::new(HealthDerivedWeights::default()),
        )
        .is_err()
    );
}

#[tokio::test]
async fn grpc_health_check_uses_native_h2_client() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let Some(result) = connection.accept().await else {
            panic!("missing gRPC health request");
        };
        let (request, mut respond) = result.unwrap();
        assert_eq!(request.uri().path(), "/grpc.health.v1.Health/Check");
        assert_eq!(
            request.headers().get("content-type").unwrap(),
            "application/grpc"
        );
        let mut body = request.into_body();
        let mut request_body = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            body.flow_control().release_capacity(chunk.len()).unwrap();
            request_body.extend_from_slice(&chunk);
        }
        assert_eq!(
            request_body,
            grpc_health_request_body(Some("example.Health")).unwrap()
        );
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();
        let mut send = respond.send_response(response, false).unwrap();
        send.send_data(Bytes::from(grpc_frame(&[0x08, 0x01]).unwrap()), false)
            .unwrap();
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        send.send_trailers(trailers).unwrap();
        drive_h2_test_server_to_close(connection).await;
    });
    let health_check = configured_http_health_check(
        &ProxyConfig {
            upstreams: vec![address.to_string()],
            load_balance: LoadBalanceConfig {
                health_check: LoadBalanceHealthCheckConfig {
                    enabled: true,
                    protocol: LoadBalanceHealthCheckProtocol::Grpc,
                    host: Some("grpc.example.test".to_owned()),
                    grpc_service: Some("example.Health".to_owned()),
                    connect_timeout_secs: Some(1),
                    read_timeout_secs: Some(1),
                    ..LoadBalanceHealthCheckConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        },
        Arc::new(HealthDerivedWeights::default()),
    )
    .unwrap();
    let backend = Backend::new(&address.to_string()).unwrap();

    health_check.check(&backend).await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn grpc_health_check_rejects_non_ok_trailer_status() {
    let (client, server) = tokio::io::duplex(8192);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server).await.unwrap();
        let Some(result) = connection.accept().await else {
            panic!("missing gRPC health request");
        };
        let (_request, mut respond) = result.unwrap();
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();
        let mut send = respond.send_response(response, false).unwrap();
        send.send_data(Bytes::from(grpc_frame(&[0x08, 0x01]).unwrap()), false)
            .unwrap();
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("14"));
        send.send_trailers(trailers).unwrap();
        drive_h2_test_server_to_close(connection).await;
    });
    let request = HealthHttpRequest {
        method: http::Method::POST,
        path: "/grpc.health.v1.Health/Check".to_owned(),
        host: "grpc.example.test".to_owned(),
        headers: HeaderMap::new(),
        body: Some(Bytes::from(grpc_health_request_body(None).unwrap())),
        grpc: true,
    };

    let result =
        super::execute_grpc_health_check(Box::new(client), &request, Duration::from_secs(1)).await;

    assert!(result.is_err());
    server.await.unwrap();
}

async fn drive_h2_test_server_to_close<T>(mut connection: h2::server::Connection<T, Bytes>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    connection.graceful_shutdown();
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        poll_fn(|context| connection.poll_closed(context)),
    )
    .await;
}

#[test]
fn validates_grpc_health_check_response() {
    let response = health_response(200, &[("content-type", "application/grpc")]);
    let serving = grpc_frame(&[0x08, 0x01]).unwrap();
    assert!(validate_grpc_health_response_header(&response).is_ok());
    assert!(validate_grpc_health_response_body(&serving).is_ok());

    let not_serving = grpc_frame(&[0x08, 0x02]).unwrap();
    assert!(validate_grpc_health_response_body(&not_serving).is_err());

    let wrong_type = health_response(200, &[("content-type", "text/plain")]);
    assert!(validate_grpc_health_response_header(&wrong_type).is_err());
}

#[test]
fn grpc_health_response_skips_unknown_fixed_width_fields() {
    let mut response = vec![0x11];
    response.extend_from_slice(&[0u8; 8]);
    response.push(0x1d);
    response.extend_from_slice(&[0u8; 4]);
    response.extend_from_slice(&[0x08, 0x01]);

    assert!(validate_grpc_health_response_body(&grpc_frame(&response).unwrap()).is_ok());
    let overlarge_varint = grpc_frame(&[
        0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02,
    ])
    .unwrap();
    assert!(validate_grpc_health_response_body(&overlarge_varint).is_err());
}
