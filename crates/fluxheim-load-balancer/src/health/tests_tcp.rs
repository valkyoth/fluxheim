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
async fn tcp_health_check_uses_fluxheim_plain_connect() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    let health_check = configured_health_check(
        &ProxyConfig {
            upstreams: vec![upstream.to_string(), "127.0.0.1:1".to_owned()],
            load_balance: LoadBalanceConfig {
                health_check: LoadBalanceHealthCheckConfig {
                    enabled: true,
                    protocol: LoadBalanceHealthCheckProtocol::Tcp,
                    consecutive_success: 2,
                    consecutive_failure: 3,
                    connect_timeout_secs: Some(1),
                    ..LoadBalanceHealthCheckConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        },
        Arc::new(HealthDerivedWeights::default()),
    )
    .unwrap();
    let backend = Backend::new(&upstream.to_string()).unwrap();

    health_check.check(&backend).await.unwrap();
    assert_eq!(health_check.health_threshold(true), 2);
    assert_eq!(health_check.health_threshold(false), 3);
    accept.await.unwrap();
}

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
#[tokio::test]
async fn tcp_tls_health_check_times_out_stalled_handshake() {
    crate::install_test_crypto_provider();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let Ok((_stream, _peer)) = listener.accept().await else {
            return;
        };
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    let tls = configured_tcp_health_check_tls_inner(
        &ProxyConfig {
            upstream_tls: true,
            upstream_sni: Some("localhost".to_owned()),
            ..ProxyConfig::default()
        },
        super::HealthTlsAlpn::None,
    )
    .unwrap();
    let health_check = FluxTcpHealthCheck {
        consecutive_success: 1,
        consecutive_failure: 1,
        connect_timeout: Duration::from_millis(50),
        tls: Some(tls),
    };
    let backend = Backend::new(&upstream.to_string()).unwrap();

    let error = health_check.check(&backend).await.unwrap_err();

    assert!(error.to_string().contains("TLS TCP health check handshake"));
    accept.abort();
}
