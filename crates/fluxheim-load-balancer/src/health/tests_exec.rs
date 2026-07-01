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
#[test]
fn configures_exec_health_check() {
    let health_check = configured_exec_health_check(&ProxyConfig {
        load_balance: LoadBalanceConfig {
            health_check: LoadBalanceHealthCheckConfig {
                protocol: LoadBalanceHealthCheckProtocol::Exec,
                consecutive_success: 2,
                consecutive_failure: 4,
                exec_command: Some("/usr/local/libexec/fluxheim-health".to_owned()),
                exec_args: vec!["--probe".to_owned()],
                exec_allowed_commands: vec!["/usr/local/libexec/fluxheim-health".to_owned()],
                exec_timeout_secs: Some(3),
                ..LoadBalanceHealthCheckConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap();

    assert_eq!(health_check.consecutive_success, 2);
    assert_eq!(health_check.consecutive_failure, 4);
    assert_eq!(health_check.command, "/usr/local/libexec/fluxheim-health");
    assert_eq!(health_check.args.as_ref(), ["--probe".to_owned()]);
    assert_eq!(health_check.timeout, Duration::from_secs(3));
    let backend = Backend::new("127.0.0.1:8080").unwrap();
    assert_eq!(
        health_check.backend_summary(&backend),
        "127.0.0.1:8080 via exec"
    );
}

#[test]
fn rejects_exec_health_check_without_runtime_allowlist_match() {
    assert!(
        configured_exec_health_check(&ProxyConfig {
            load_balance: LoadBalanceConfig {
                health_check: LoadBalanceHealthCheckConfig {
                    protocol: LoadBalanceHealthCheckProtocol::Exec,
                    exec_command: Some("/usr/local/libexec/fluxheim-health".to_owned()),
                    exec_allowed_commands: vec!["/usr/local/libexec/other-health".to_owned()],
                    ..LoadBalanceHealthCheckConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .is_err()
    );
}

#[tokio::test]
async fn exec_health_check_runs_command_and_reports_status() {
    let command = std::env::current_exe()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let backend = Backend::new("127.0.0.1:8080").unwrap();
    let success = configured_exec_health_check(&ProxyConfig {
        load_balance: LoadBalanceConfig {
            health_check: LoadBalanceHealthCheckConfig {
                protocol: LoadBalanceHealthCheckProtocol::Exec,
                exec_command: Some(command.clone()),
                exec_args: vec!["--help".to_owned()],
                exec_allowed_commands: vec![command.clone()],
                exec_timeout_secs: Some(2),
                ..LoadBalanceHealthCheckConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap();
    success.check(&backend).await.unwrap();

    let failure = configured_exec_health_check(&ProxyConfig {
        load_balance: LoadBalanceConfig {
            health_check: LoadBalanceHealthCheckConfig {
                protocol: LoadBalanceHealthCheckProtocol::Exec,
                exec_command: Some(command.clone()),
                exec_args: vec!["--fluxheim-invalid-test-harness-flag".to_owned()],
                exec_allowed_commands: vec![command],
                exec_timeout_secs: Some(2),
                ..LoadBalanceHealthCheckConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap();
    assert!(failure.check(&backend).await.is_err());
}
