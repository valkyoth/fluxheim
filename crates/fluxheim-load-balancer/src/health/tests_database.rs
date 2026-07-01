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
#[tokio::test]
async fn redis_health_check_sends_ping_and_accepts_pong() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; REDIS_HEALTH_CHECK_REQUEST.len()];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, REDIS_HEALTH_CHECK_REQUEST);
        stream.write_all(b"+PONG\r\n").await.unwrap();
    });
    let health_check = configured_redis_health_check(&ProxyConfig {
        load_balance: LoadBalanceConfig {
            health_check: LoadBalanceHealthCheckConfig {
                protocol: LoadBalanceHealthCheckProtocol::Redis,
                consecutive_success: 2,
                consecutive_failure: 4,
                connect_timeout_secs: Some(2),
                read_timeout_secs: Some(2),
                ..LoadBalanceHealthCheckConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap();
    let backend = Backend::new(&address.to_string()).unwrap();

    health_check.check(&backend).await.unwrap();
    server.await.unwrap();
    assert_eq!(health_check.consecutive_success, 2);
    assert_eq!(health_check.consecutive_failure, 4);
    assert_eq!(
        health_check.backend_summary(&backend),
        format!("{address} via redis")
    );
}

#[tokio::test]
async fn redis_health_check_accepts_fragmented_pong() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; REDIS_HEALTH_CHECK_REQUEST.len()];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, REDIS_HEALTH_CHECK_REQUEST);
        stream.write_all(b"+PO").await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        stream.write_all(b"NG\r\n").await.unwrap();
    });
    let health_check = configured_redis_health_check(&ProxyConfig {
        load_balance: LoadBalanceConfig {
            health_check: LoadBalanceHealthCheckConfig {
                protocol: LoadBalanceHealthCheckProtocol::Redis,
                connect_timeout_secs: Some(2),
                read_timeout_secs: Some(2),
                ..LoadBalanceHealthCheckConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap();
    let backend = Backend::new(&address.to_string()).unwrap();

    health_check.check(&backend).await.unwrap();
    server.await.unwrap();
}

#[test]
fn validates_redis_health_response() {
    assert!(validate_redis_health_response(b"+PONG\r\n").is_ok());
    assert!(validate_redis_health_response(b"-NOAUTH Authentication required\r\n").is_err());
    assert!(validate_redis_health_response(b"$4\r\nPONG\r\n").is_err());
}

#[tokio::test]
async fn mysql_health_check_accepts_protocol_handshake() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut payload = Vec::new();
        payload.push(10);
        payload.extend_from_slice(b"8.0.36-fluxheim\0");
        payload.extend_from_slice(&1234u32.to_le_bytes());
        payload.extend_from_slice(b"abcdefgh");
        payload.push(0);
        payload.extend_from_slice(&0xffffu16.to_le_bytes());
        payload.push(45);
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.push(21);
        payload.extend_from_slice(&[0u8; 10]);
        payload.extend_from_slice(b"ijklmnopqrstuv\0");
        payload.extend_from_slice(b"mysql_native_password\0");
        let len = payload.len();
        let header = [
            (len & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            ((len >> 16) & 0xff) as u8,
            0,
        ];
        stream.write_all(&header).await.unwrap();
        stream.write_all(&payload).await.unwrap();
    });
    let health_check = configured_mysql_health_check(&ProxyConfig {
        load_balance: LoadBalanceConfig {
            health_check: LoadBalanceHealthCheckConfig {
                protocol: LoadBalanceHealthCheckProtocol::Mysql,
                consecutive_success: 2,
                consecutive_failure: 4,
                connect_timeout_secs: Some(2),
                read_timeout_secs: Some(2),
                ..LoadBalanceHealthCheckConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap();
    let backend = Backend::new(&address.to_string()).unwrap();

    health_check.check(&backend).await.unwrap();
    server.await.unwrap();
    assert_eq!(health_check.consecutive_success, 2);
    assert_eq!(health_check.consecutive_failure, 4);
    assert_eq!(
        health_check.backend_summary(&backend),
        format!("{address} via mysql")
    );
}

#[test]
fn validates_mysql_health_check_handshake() {
    assert!(validate_mysql_health_handshake(&[22, 0, 0, 0], b"\x0a8.0.36\0rest").is_ok());
    assert!(validate_mysql_health_handshake(&[22, 0, 0, 1], b"\x0a8.0.36\0rest").is_err());
    assert!(validate_mysql_health_handshake(&[22, 0, 0, 0], b"\x09old\0rest").is_err());
    assert!(validate_mysql_health_handshake(&[22, 0, 0, 0], b"\x0aunterminated").is_err());
}

#[tokio::test]
async fn postgres_health_check_sends_ssl_request_and_accepts_response() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; POSTGRES_HEALTH_CHECK_SSL_REQUEST.len()];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, POSTGRES_HEALTH_CHECK_SSL_REQUEST);
        stream.write_all(b"N").await.unwrap();
    });
    let health_check = configured_postgres_health_check(&ProxyConfig {
        load_balance: LoadBalanceConfig {
            health_check: LoadBalanceHealthCheckConfig {
                protocol: LoadBalanceHealthCheckProtocol::Postgres,
                consecutive_success: 2,
                consecutive_failure: 4,
                connect_timeout_secs: Some(2),
                read_timeout_secs: Some(2),
                ..LoadBalanceHealthCheckConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap();
    let backend = Backend::new(&address.to_string()).unwrap();

    health_check.check(&backend).await.unwrap();
    server.await.unwrap();
    assert_eq!(health_check.consecutive_success, 2);
    assert_eq!(health_check.consecutive_failure, 4);
    assert_eq!(
        health_check.backend_summary(&backend),
        format!("{address} via postgres")
    );
}

#[test]
fn validates_postgres_health_check_response() {
    assert!(validate_postgres_health_response(b'S').is_ok());
    assert!(validate_postgres_health_response(b'N').is_ok());
    assert!(validate_postgres_health_response(b'E').is_err());
    assert!(validate_postgres_health_response(0).is_err());
}
