use std::io;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::connectors::http::Connector as HttpConnector;
use pingora::lb::health_check::{HealthCheck as PingoraHealthCheck, TcpHealthCheck};
use pingora::protocols::http::client::HttpSession;
use pingora::upstreams::peer::{HttpPeer, Peer};
use pingora::{Error, ErrorType};
use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use fluxheim_common::{FluxError, FluxResult};
use fluxheim_config::{
    LoadBalanceHealthCheckExpectedHeader, LoadBalanceHealthCheckExpectedJson,
    LoadBalanceHealthCheckExpectedStatusRange, LoadBalanceHealthCheckProtocol, ProxyConfig,
};
use pingora::http::{RequestHeader, ResponseHeader};

use super::backend::{FluxHealthCheck, RuntimeBackend as Backend};
use super::key::backend_key;
use super::policy::HealthDerivedWeights;

const HTTP_HEALTH_CHECK_MAX_BODY_BYTES: usize = 64 * 1024;
const GRPC_HEALTH_CHECK_PATH: &[u8] = b"/grpc.health.v1.Health/Check";
const GRPC_SERVING_STATUS: u64 = 1;
const HEALTH_WEIGHT_HEADER: &str = "x-health-weight";
const REDIS_HEALTH_CHECK_REQUEST: &[u8] = b"*1\r\n$4\r\nPING\r\n";
const REDIS_HEALTH_CHECK_MAX_RESPONSE_BYTES: usize = 64;
const MYSQL_HEALTH_CHECK_MAX_HANDSHAKE_BYTES: usize = 1024;
const POSTGRES_HEALTH_CHECK_SSL_REQUEST: &[u8; 8] = b"\x00\x00\x00\x08\x04\xd2\x16/";

pub(super) fn configured_health_check(
    config: &ProxyConfig,
    health_weights: Arc<HealthDerivedWeights>,
) -> io::Result<Box<dyn FluxHealthCheck>> {
    #[cfg(test)]
    crate::install_test_crypto_provider();

    match config.load_balance.health_check.protocol {
        LoadBalanceHealthCheckProtocol::Tcp => {
            let mut health_check = if config.upstream_tls {
                TcpHealthCheck::new_tls(&config.upstream_sni())
            } else {
                TcpHealthCheck::new()
            };
            health_check.consecutive_success = config.load_balance.health_check.consecutive_success;
            health_check.consecutive_failure = config.load_balance.health_check.consecutive_failure;
            apply_health_check_peer_timeouts(
                &mut health_check.peer_template.options.connection_timeout,
                None,
                config,
            );
            Ok(Box::new(FluxTcpHealthCheck {
                inner: health_check,
            }))
        }
        LoadBalanceHealthCheckProtocol::Http | LoadBalanceHealthCheckProtocol::Grpc => {
            configured_http_health_check(config, health_weights)
                .map_err(FluxError::into_io)
                .map(|check| check as Box<dyn FluxHealthCheck>)
        }
        LoadBalanceHealthCheckProtocol::Exec => configured_exec_health_check(config)
            .map_err(FluxError::into_io)
            .map(|check| check as Box<dyn FluxHealthCheck>),
        LoadBalanceHealthCheckProtocol::Redis => configured_redis_health_check(config)
            .map_err(FluxError::into_io)
            .map(|check| check as Box<dyn FluxHealthCheck>),
        LoadBalanceHealthCheckProtocol::Mysql => configured_mysql_health_check(config)
            .map_err(FluxError::into_io)
            .map(|check| check as Box<dyn FluxHealthCheck>),
        LoadBalanceHealthCheckProtocol::Postgres => configured_postgres_health_check(config)
            .map_err(FluxError::into_io)
            .map(|check| check as Box<dyn FluxHealthCheck>),
    }
}

struct FluxTcpHealthCheck {
    inner: Box<TcpHealthCheck>,
}

#[async_trait]
impl FluxHealthCheck for FluxTcpHealthCheck {
    async fn check(&self, target: &Backend) -> FluxResult<()> {
        self.inner
            .check(target)
            .await
            .map_err(pingora_health_error("TCP health check failed"))
    }

    fn health_threshold(&self, success: bool) -> usize {
        self.inner.health_threshold(success)
    }

    async fn health_status_change(&self, target: &Backend, healthy: bool) {
        self.inner.health_status_change(target, healthy).await;
    }

    fn backend_summary(&self, target: &Backend) -> String {
        self.inner.backend_summary(target)
    }
}

struct FluxExecHealthCheck {
    consecutive_success: usize,
    consecutive_failure: usize,
    command: String,
    args: Arc<[String]>,
    timeout: Duration,
}

#[async_trait]
impl FluxHealthCheck for FluxExecHealthCheck {
    async fn check(&self, target: &Backend) -> FluxResult<()> {
        let mut command = tokio::process::Command::new(&self.command);
        let backend_addr = target.addr.to_string();
        let backend_inet = target.addr.as_inet();
        command
            .args(self.args.iter().map(String::as_str))
            .env_clear()
            .env("FLUXHEIM_HEALTH_BACKEND_ADDR", backend_addr)
            .env(
                "FLUXHEIM_HEALTH_BACKEND_HOST",
                backend_inet
                    .map(|addr| addr.ip().to_string())
                    .unwrap_or_default(),
            )
            .env(
                "FLUXHEIM_HEALTH_BACKEND_PORT",
                backend_inet
                    .map(|addr| addr.port().to_string())
                    .unwrap_or_default(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|error| FluxError::io("spawn exec health check command", error))?;
        match tokio::time::timeout(self.timeout, child.wait()).await {
            Ok(Ok(status)) if status.success() => Ok(()),
            Ok(Ok(status)) => Err(FluxError::io(
                "exec health check failed",
                io::Error::other(match status.code() {
                    Some(code) => format!("command exited with status {code}"),
                    None => "command terminated by signal".to_owned(),
                }),
            )),
            Ok(Err(error)) => Err(FluxError::io("wait for exec health check command", error)),
            Err(_) => {
                let _ = child.kill().await;
                Err(FluxError::timeout(
                    "exec health check timed out",
                    format!("timeout after {}s", self.timeout.as_secs()),
                ))
            }
        }
    }

    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }

    fn backend_summary(&self, target: &Backend) -> String {
        format!("{} via exec", target.addr)
    }
}

fn configured_exec_health_check(config: &ProxyConfig) -> FluxResult<Box<FluxExecHealthCheck>> {
    let Some(command) = config.load_balance.health_check.exec_command.clone() else {
        return Err(FluxError::InvalidInput(
            "exec health check command is required",
        ));
    };
    Ok(Box::new(FluxExecHealthCheck {
        consecutive_success: config.load_balance.health_check.consecutive_success,
        consecutive_failure: config.load_balance.health_check.consecutive_failure,
        command,
        args: config.load_balance.health_check.exec_args.clone().into(),
        timeout: Duration::from_secs(
            config
                .load_balance
                .health_check
                .exec_timeout_secs
                .unwrap_or(1),
        ),
    }))
}

struct FluxRedisHealthCheck {
    consecutive_success: usize,
    consecutive_failure: usize,
    connect_timeout: Duration,
    read_timeout: Duration,
}

#[async_trait]
impl FluxHealthCheck for FluxRedisHealthCheck {
    async fn check(&self, target: &Backend) -> FluxResult<()> {
        let authority = target.addr.to_string();
        let connect = tokio::net::TcpStream::connect(authority.as_str());
        let mut stream = tokio::time::timeout(self.connect_timeout, connect)
            .await
            .map_err(|_| {
                FluxError::timeout(
                    "connect Redis health check upstream",
                    format!("timeout after {}s", self.connect_timeout.as_secs()),
                )
            })?
            .map_err(|error| FluxError::io("connect Redis health check upstream", error))?;
        tokio::time::timeout(
            self.read_timeout,
            stream.write_all(REDIS_HEALTH_CHECK_REQUEST),
        )
        .await
        .map_err(|_| {
            FluxError::timeout(
                "write Redis health check request",
                format!("timeout after {}s", self.read_timeout.as_secs()),
            )
        })?
        .map_err(|error| FluxError::io("write Redis health check request", error))?;

        let response =
            tokio::time::timeout(self.read_timeout, read_redis_health_response(&mut stream))
                .await
                .map_err(|_| {
                    FluxError::timeout(
                        "read Redis health check response",
                        format!("timeout after {}s", self.read_timeout.as_secs()),
                    )
                })?
                .map_err(|error| FluxError::io("read Redis health check response", error))?;
        validate_redis_health_response(&response)
    }

    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }

    fn backend_summary(&self, target: &Backend) -> String {
        format!("{} via redis", target.addr)
    }
}

fn configured_redis_health_check(config: &ProxyConfig) -> FluxResult<Box<FluxRedisHealthCheck>> {
    if config.upstream_tls {
        return Err(FluxError::InvalidInput(
            "redis health checks do not support upstream TLS yet",
        ));
    }
    Ok(Box::new(FluxRedisHealthCheck {
        consecutive_success: config.load_balance.health_check.consecutive_success,
        consecutive_failure: config.load_balance.health_check.consecutive_failure,
        connect_timeout: Duration::from_secs(
            config
                .load_balance
                .health_check
                .connect_timeout_secs
                .or(config.connect_timeout_secs)
                .unwrap_or(1),
        ),
        read_timeout: Duration::from_secs(
            config
                .load_balance
                .health_check
                .read_timeout_secs
                .or(config.read_timeout_secs)
                .unwrap_or(1),
        ),
    }))
}

async fn read_redis_health_response(stream: &mut tokio::net::TcpStream) -> io::Result<Vec<u8>> {
    let mut response = Vec::with_capacity(REDIS_HEALTH_CHECK_MAX_RESPONSE_BYTES);
    let mut byte = [0u8; 1];
    while response.len() < REDIS_HEALTH_CHECK_MAX_RESPONSE_BYTES {
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            break;
        }
        response.push(byte[0]);
        if response.ends_with(b"\r\n") {
            break;
        }
    }
    Ok(response)
}

struct FluxMysqlHealthCheck {
    consecutive_success: usize,
    consecutive_failure: usize,
    connect_timeout: Duration,
    read_timeout: Duration,
}

#[async_trait]
impl FluxHealthCheck for FluxMysqlHealthCheck {
    async fn check(&self, target: &Backend) -> FluxResult<()> {
        let authority = target.addr.to_string();
        let connect = tokio::net::TcpStream::connect(authority.as_str());
        let mut stream = tokio::time::timeout(self.connect_timeout, connect)
            .await
            .map_err(|_| {
                FluxError::timeout(
                    "connect MySQL health check upstream",
                    format!("timeout after {}s", self.connect_timeout.as_secs()),
                )
            })?
            .map_err(|error| FluxError::io("connect MySQL health check upstream", error))?;

        let mut header = [0u8; 4];
        tokio::time::timeout(self.read_timeout, stream.read_exact(&mut header))
            .await
            .map_err(|_| {
                FluxError::timeout(
                    "read MySQL health check packet header",
                    format!("timeout after {}s", self.read_timeout.as_secs()),
                )
            })?
            .map_err(|error| FluxError::io("read MySQL health check packet header", error))?;
        let payload_len =
            usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
        if payload_len == 0 || payload_len > MYSQL_HEALTH_CHECK_MAX_HANDSHAKE_BYTES {
            return Err(FluxError::InvalidInput(
                "MySQL health check handshake packet is outside allowed size",
            ));
        }
        let mut payload = vec![0u8; payload_len];
        tokio::time::timeout(self.read_timeout, stream.read_exact(&mut payload))
            .await
            .map_err(|_| {
                FluxError::timeout(
                    "read MySQL health check handshake",
                    format!("timeout after {}s", self.read_timeout.as_secs()),
                )
            })?
            .map_err(|error| FluxError::io("read MySQL health check handshake", error))?;
        validate_mysql_health_handshake(&header, &payload)
    }

    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }

    fn backend_summary(&self, target: &Backend) -> String {
        format!("{} via mysql", target.addr)
    }
}

fn configured_mysql_health_check(config: &ProxyConfig) -> FluxResult<Box<FluxMysqlHealthCheck>> {
    if config.upstream_tls {
        return Err(FluxError::InvalidInput(
            "mysql health checks do not support upstream TLS yet",
        ));
    }
    Ok(Box::new(FluxMysqlHealthCheck {
        consecutive_success: config.load_balance.health_check.consecutive_success,
        consecutive_failure: config.load_balance.health_check.consecutive_failure,
        connect_timeout: Duration::from_secs(
            config
                .load_balance
                .health_check
                .connect_timeout_secs
                .or(config.connect_timeout_secs)
                .unwrap_or(1),
        ),
        read_timeout: Duration::from_secs(
            config
                .load_balance
                .health_check
                .read_timeout_secs
                .or(config.read_timeout_secs)
                .unwrap_or(1),
        ),
    }))
}

struct FluxPostgresHealthCheck {
    consecutive_success: usize,
    consecutive_failure: usize,
    connect_timeout: Duration,
    read_timeout: Duration,
}

#[async_trait]
impl FluxHealthCheck for FluxPostgresHealthCheck {
    async fn check(&self, target: &Backend) -> FluxResult<()> {
        let authority = target.addr.to_string();
        let connect = tokio::net::TcpStream::connect(authority.as_str());
        let mut stream = tokio::time::timeout(self.connect_timeout, connect)
            .await
            .map_err(|_| {
                FluxError::timeout(
                    "connect PostgreSQL health check upstream",
                    format!("timeout after {}s", self.connect_timeout.as_secs()),
                )
            })?
            .map_err(|error| FluxError::io("connect PostgreSQL health check upstream", error))?;
        tokio::time::timeout(
            self.read_timeout,
            stream.write_all(POSTGRES_HEALTH_CHECK_SSL_REQUEST),
        )
        .await
        .map_err(|_| {
            FluxError::timeout(
                "write PostgreSQL health check SSLRequest",
                format!("timeout after {}s", self.read_timeout.as_secs()),
            )
        })?
        .map_err(|error| FluxError::io("write PostgreSQL health check SSLRequest", error))?;

        let mut response = [0u8; 1];
        tokio::time::timeout(self.read_timeout, stream.read_exact(&mut response))
            .await
            .map_err(|_| {
                FluxError::timeout(
                    "read PostgreSQL health check SSLResponse",
                    format!("timeout after {}s", self.read_timeout.as_secs()),
                )
            })?
            .map_err(|error| FluxError::io("read PostgreSQL health check SSLResponse", error))?;
        validate_postgres_health_response(response[0])
    }

    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }

    fn backend_summary(&self, target: &Backend) -> String {
        format!("{} via postgres", target.addr)
    }
}

fn configured_postgres_health_check(
    config: &ProxyConfig,
) -> FluxResult<Box<FluxPostgresHealthCheck>> {
    if config.upstream_tls {
        return Err(FluxError::InvalidInput(
            "postgres health checks do not support upstream TLS yet",
        ));
    }
    Ok(Box::new(FluxPostgresHealthCheck {
        consecutive_success: config.load_balance.health_check.consecutive_success,
        consecutive_failure: config.load_balance.health_check.consecutive_failure,
        connect_timeout: Duration::from_secs(
            config
                .load_balance
                .health_check
                .connect_timeout_secs
                .or(config.connect_timeout_secs)
                .unwrap_or(1),
        ),
        read_timeout: Duration::from_secs(
            config
                .load_balance
                .health_check
                .read_timeout_secs
                .or(config.read_timeout_secs)
                .unwrap_or(1),
        ),
    }))
}

struct FluxHttpHealthCheck {
    consecutive_success: usize,
    consecutive_failure: usize,
    peer_template: HttpPeer,
    reuse_connection: bool,
    req: RequestHeader,
    connector: HttpConnector,
    port_override: Option<u16>,
    expected_statuses: Arc<[u16]>,
    expected_status_ranges: Arc<[LoadBalanceHealthCheckExpectedStatusRange]>,
    expected_headers: Arc<[LoadBalanceHealthCheckExpectedHeader]>,
    expected_body_contains: Arc<[String]>,
    expected_body_json: Arc<[LoadBalanceHealthCheckExpectedJson]>,
    request_body: Option<Bytes>,
    grpc_response: bool,
    health_weight_min_percent: u8,
    health_weights: Arc<HealthDerivedWeights>,
}

#[async_trait]
impl FluxHealthCheck for FluxHttpHealthCheck {
    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }

    async fn check(&self, target: &Backend) -> FluxResult<()> {
        let mut peer = self.peer_template.clone();
        peer._address = target.addr.clone();
        if let Some(port) = self.port_override {
            peer._address.set_port(port);
        }

        let (mut session, _) = self
            .connector
            .get_http_session(&peer)
            .await
            .map_err(pingora_health_error("connect HTTP health check upstream"))?;
        session
            .write_request_header(Box::new(self.req.clone()))
            .await
            .map_err(pingora_health_error(
                "write HTTP health check request header",
            ))?;
        if let Some(body) = &self.request_body {
            session
                .write_request_body(body.clone(), true)
                .await
                .map_err(pingora_health_error("write HTTP health check request body"))?;
        } else {
            session
                .finish_request_body()
                .await
                .map_err(pingora_health_error(
                    "finish HTTP health check request body",
                ))?;
        }

        if let Some(read_timeout) = peer.options.read_timeout {
            session.set_read_timeout(Some(read_timeout));
        }

        session
            .read_response_header()
            .await
            .map_err(pingora_health_error(
                "read HTTP health check response header",
            ))?;
        let Some(response) = session.response_header() else {
            return Err(HttpHealthCheckError::new(
                ErrorType::ReadError,
                "missing HTTP health check response header",
            )
            .into_flux());
        };
        validate_http_health_response(
            response,
            &self.expected_statuses,
            &self.expected_status_ranges,
            &self.expected_headers,
        )
        .map_err(HttpHealthCheckError::into_flux)?;
        record_health_weight(
            response,
            backend_key(target),
            self.health_weight_min_percent,
            &self.health_weights,
        )
        .map_err(HttpHealthCheckError::into_flux)?;

        if self.grpc_response {
            validate_grpc_health_response_header(response)
                .map_err(HttpHealthCheckError::into_flux)?;
            let body = read_http_health_response_body(&mut session).await?;
            validate_grpc_health_response_body(&body).map_err(HttpHealthCheckError::into_flux)?;
        } else if self.expected_body_contains.is_empty() && self.expected_body_json.is_empty() {
            drain_http_health_response_body(&mut session).await?;
        } else {
            let body = read_http_health_response_body(&mut session).await?;
            validate_http_health_response_body(&body, &self.expected_body_contains)
                .map_err(HttpHealthCheckError::into_flux)?;
            validate_http_health_response_body_json(&body, &self.expected_body_json)
                .map_err(HttpHealthCheckError::into_flux)?;
        }

        if self.reuse_connection {
            let idle_timeout = peer.idle_timeout();
            self.connector
                .release_http_session(session, &peer, idle_timeout)
                .await;
        }

        Ok(())
    }
}

fn configured_http_health_check(
    config: &ProxyConfig,
    health_weights: Arc<HealthDerivedWeights>,
) -> FluxResult<Box<FluxHttpHealthCheck>> {
    #[cfg(test)]
    crate::install_test_crypto_provider();

    let grpc = config.load_balance.health_check.protocol == LoadBalanceHealthCheckProtocol::Grpc;
    let host = config
        .load_balance
        .health_check
        .host
        .clone()
        .unwrap_or_else(|| config.upstream_sni());
    let method = if grpc {
        "POST"
    } else {
        config.load_balance.health_check.method.as_str()
    };
    let path = if grpc {
        GRPC_HEALTH_CHECK_PATH
    } else {
        config.load_balance.health_check.path.as_bytes()
    };
    let mut request = RequestHeader::build(method, path, None).map_err(|error| {
        FluxError::io(
            "build HTTP health check request header",
            io::Error::other(error.to_string()),
        )
    })?;
    request.append_header("Host", &host).map_err(|error| {
        FluxError::io(
            "append HTTP health check Host header",
            io::Error::other(error.to_string()),
        )
    })?;
    for header in &config.load_balance.health_check.request_headers {
        request
            .append_header(header.name.clone(), header.value.clone())
            .map_err(|error| {
                FluxError::io(
                    "append HTTP health check request header",
                    io::Error::other(error.to_string()),
                )
            })?;
    }
    if grpc {
        request
            .append_header("Content-Type", "application/grpc")
            .map_err(|error| {
                FluxError::io(
                    "append gRPC health check content type",
                    io::Error::other(error.to_string()),
                )
            })?;
        request.append_header("TE", "trailers").map_err(|error| {
            FluxError::io(
                "append gRPC health check trailers header",
                io::Error::other(error.to_string()),
            )
        })?;
    }

    let sni = if config.upstream_tls {
        host.clone()
    } else {
        String::new()
    };
    let mut peer_template = HttpPeer::new("0.0.0.0:1", config.upstream_tls, sni);
    if grpc {
        peer_template.options.set_http_version(2, 2);
        peer_template.options.max_h2_streams = config.upstream_h2_max_streams.unwrap_or(64);
        peer_template.options.h2_ping_interval = config
            .upstream_h2_ping_interval_secs
            .map(Duration::from_secs);
    }
    peer_template.options.connection_timeout = Some(Duration::from_secs(1));
    peer_template.options.read_timeout = Some(Duration::from_secs(1));
    apply_health_check_peer_timeouts(
        &mut peer_template.options.connection_timeout,
        Some(&mut peer_template.options.read_timeout),
        config,
    );

    Ok(Box::new(FluxHttpHealthCheck {
        consecutive_success: config.load_balance.health_check.consecutive_success,
        consecutive_failure: config.load_balance.health_check.consecutive_failure,
        peer_template,
        reuse_connection: config.load_balance.health_check.reuse_connection,
        req: request,
        connector: HttpConnector::new(None),
        port_override: config.load_balance.health_check.port_override,
        expected_statuses: config
            .load_balance
            .health_check
            .expected_statuses
            .clone()
            .into(),
        expected_status_ranges: config
            .load_balance
            .health_check
            .expected_status_ranges
            .clone()
            .into(),
        expected_headers: config
            .load_balance
            .health_check
            .expected_headers
            .clone()
            .into(),
        expected_body_contains: config
            .load_balance
            .health_check
            .expected_body_contains
            .clone()
            .into(),
        expected_body_json: config
            .load_balance
            .health_check
            .expected_body_json
            .clone()
            .into(),
        request_body: grpc.then(|| {
            Bytes::from(grpc_health_request_body(
                config.load_balance.health_check.grpc_service.as_deref(),
            ))
        }),
        grpc_response: grpc,
        health_weight_min_percent: config.load_balance.health_check.health_weight_min_percent,
        health_weights,
    }))
}

fn apply_health_check_peer_timeouts(
    connection_timeout: &mut Option<Duration>,
    read_timeout: Option<&mut Option<Duration>>,
    config: &ProxyConfig,
) {
    if let Some(timeout) = config
        .load_balance
        .health_check
        .connect_timeout_secs
        .or(config.connect_timeout_secs)
    {
        *connection_timeout = Some(Duration::from_secs(timeout));
    }
    if let Some(read_timeout) = read_timeout
        && let Some(timeout) = config
            .load_balance
            .health_check
            .read_timeout_secs
            .or(config.read_timeout_secs)
    {
        *read_timeout = Some(Duration::from_secs(timeout));
    }
}

fn validate_redis_health_response(response: &[u8]) -> FluxResult<()> {
    if response.starts_with(b"+PONG\r\n") {
        return Ok(());
    }
    Err(FluxError::InvalidInput(
        "Redis health check did not receive PONG",
    ))
}

fn validate_mysql_health_handshake(header: &[u8; 4], payload: &[u8]) -> FluxResult<()> {
    if header[3] != 0 {
        return Err(FluxError::InvalidInput(
            "MySQL health check handshake packet has unexpected sequence id",
        ));
    }
    if payload.first().copied() != Some(10) {
        return Err(FluxError::InvalidInput(
            "MySQL health check did not receive protocol 10 handshake",
        ));
    }
    if !payload[1..].contains(&0) {
        return Err(FluxError::InvalidInput(
            "MySQL health check handshake is missing server version terminator",
        ));
    }
    Ok(())
}

fn validate_postgres_health_response(response: u8) -> FluxResult<()> {
    if matches!(response, b'S' | b'N') {
        return Ok(());
    }
    Err(FluxError::InvalidInput(
        "PostgreSQL health check did not receive SSLResponse",
    ))
}

fn validate_http_health_response(
    response: &ResponseHeader,
    expected_statuses: &[u16],
    expected_status_ranges: &[LoadBalanceHealthCheckExpectedStatusRange],
    expected_headers: &[LoadBalanceHealthCheckExpectedHeader],
) -> Result<(), HttpHealthCheckError> {
    let status = response.status.as_u16();
    if expected_statuses.is_empty() && expected_status_ranges.is_empty() {
        if status != 200 {
            return Err(HttpHealthCheckError::new(
                ErrorType::HTTPStatus(status),
                "unexpected HTTP health check status",
            ));
        }
    } else if !expected_statuses.contains(&status)
        && !expected_status_ranges
            .iter()
            .any(|range| (range.start..=range.end).contains(&status))
    {
        return Err(HttpHealthCheckError::new(
            ErrorType::HTTPStatus(status),
            "unexpected HTTP health check status",
        ));
    }

    for expected in expected_headers {
        let mut matched = false;
        for value in response.headers.get_all(expected.name.as_str()) {
            if value.as_bytes() == expected.value.as_bytes() {
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(HttpHealthCheckError::new(
                ErrorType::InvalidHTTPHeader,
                "missing expected HTTP health check header",
            ));
        }
    }
    Ok(())
}

async fn drain_http_health_response_body(session: &mut HttpSession) -> FluxResult<()> {
    let mut drained = 0usize;
    while let Some(chunk) = session
        .read_response_body()
        .await
        .map_err(pingora_health_error("read HTTP health check response body"))?
    {
        drained = drained.saturating_add(chunk.len());
        if drained > HTTP_HEALTH_CHECK_MAX_BODY_BYTES {
            return Err(HttpHealthCheckError::new(
                ErrorType::ReadError,
                "HTTP health check response body exceeded maximum size",
            )
            .into_flux());
        }
    }
    Ok(())
}

async fn read_http_health_response_body(session: &mut HttpSession) -> FluxResult<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = session
        .read_response_body()
        .await
        .map_err(pingora_health_error("read HTTP health check response body"))?
    {
        if body.len().saturating_add(chunk.len()) > HTTP_HEALTH_CHECK_MAX_BODY_BYTES {
            return Err(HttpHealthCheckError::new(
                ErrorType::ReadError,
                "HTTP health check response body exceeded maximum size",
            )
            .into_flux());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn validate_http_health_response_body(
    body: &[u8],
    expected_body_contains: &[String],
) -> Result<(), HttpHealthCheckError> {
    for expected in expected_body_contains {
        if !body
            .windows(expected.len())
            .any(|window| window == expected.as_bytes())
        {
            return Err(HttpHealthCheckError::new(
                ErrorType::ReadError,
                "missing expected HTTP health check response body substring",
            ));
        }
    }
    Ok(())
}

fn validate_http_health_response_body_json(
    body: &[u8],
    expected_body_json: &[LoadBalanceHealthCheckExpectedJson],
) -> Result<(), HttpHealthCheckError> {
    if expected_body_json.is_empty() {
        return Ok(());
    }
    let json: Value = serde_json::from_slice(body).map_err(|_| {
        HttpHealthCheckError::new(
            ErrorType::ReadError,
            "invalid HTTP health check JSON response body",
        )
    })?;
    for expected in expected_body_json {
        let Some(value) = json_path_value(&json, &expected.path) else {
            return Err(HttpHealthCheckError::new(
                ErrorType::ReadError,
                "missing expected HTTP health check JSON field",
            ));
        };
        if json_scalar_string(value).as_deref() != Some(expected.equals.as_str()) {
            return Err(HttpHealthCheckError::new(
                ErrorType::ReadError,
                "unexpected HTTP health check JSON field value",
            ));
        }
    }
    Ok(())
}

fn json_path_value<'a>(json: &'a Value, path: &str) -> Option<&'a Value> {
    let mut value = json;
    for segment in path.split('.') {
        value = value.as_object()?.get(segment)?;
    }
    Some(value)
}

fn record_health_weight(
    response: &ResponseHeader,
    key: u64,
    min_percent: u8,
    health_weights: &HealthDerivedWeights,
) -> Result<(), HttpHealthCheckError> {
    let Some(value) = response.headers.get(HEALTH_WEIGHT_HEADER) else {
        health_weights.set_percent(key, None);
        return Ok(());
    };
    let value = value.to_str().map_err(|_| {
        HttpHealthCheckError::new(
            ErrorType::InvalidHTTPHeader,
            "invalid HTTP health check degraded weight header",
        )
    })?;
    let percent = value.trim().parse::<u8>().map_err(|_| {
        HttpHealthCheckError::new(
            ErrorType::InvalidHTTPHeader,
            "invalid HTTP health check degraded weight header",
        )
    })?;
    if percent == 0 || percent > 100 {
        return Err(HttpHealthCheckError::new(
            ErrorType::InvalidHTTPHeader,
            "invalid HTTP health check degraded weight header",
        ));
    }
    let percent = percent.max(min_percent);
    health_weights.set_percent(key, (percent < 100).then_some(percent));
    Ok(())
}

fn json_scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null => Some("null".to_owned()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

fn grpc_health_request_body(service: Option<&str>) -> Vec<u8> {
    let mut message = Vec::new();
    if let Some(service) = service
        && !service.is_empty()
    {
        message.push(0x0a);
        encode_grpc_varint(service.len() as u64, &mut message);
        message.extend_from_slice(service.as_bytes());
    }
    grpc_frame(&message)
}

fn grpc_frame(message: &[u8]) -> Vec<u8> {
    let len = message.len() as u32;
    let mut frame = Vec::with_capacity(5 + message.len());
    frame.push(0);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(message);
    frame
}

fn encode_grpc_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn validate_grpc_health_response_header(
    response: &ResponseHeader,
) -> Result<(), HttpHealthCheckError> {
    if response.status.as_u16() != 200 {
        return Err(HttpHealthCheckError::new(
            ErrorType::HTTPStatus(response.status.as_u16()),
            "unexpected gRPC health check HTTP status",
        ));
    }
    let content_type = response
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !content_type
        .to_ascii_lowercase()
        .starts_with("application/grpc")
    {
        return Err(HttpHealthCheckError::new(
            ErrorType::InvalidHTTPHeader,
            "unexpected gRPC health check content type",
        ));
    }
    Ok(())
}

fn validate_grpc_health_response_body(body: &[u8]) -> Result<(), HttpHealthCheckError> {
    if body.len() < 5 || body[0] != 0 {
        return Err(HttpHealthCheckError::new(
            ErrorType::ReadError,
            "invalid gRPC health check response frame",
        ));
    }
    let len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    if body.len() != 5 + len {
        return Err(HttpHealthCheckError::new(
            ErrorType::ReadError,
            "invalid gRPC health check response length",
        ));
    }
    let status = decode_grpc_health_status(&body[5..])?;
    if status != GRPC_SERVING_STATUS {
        return Err(HttpHealthCheckError::new(
            ErrorType::ReadError,
            "gRPC health check response is not SERVING",
        ));
    }
    Ok(())
}

fn decode_grpc_health_status(message: &[u8]) -> Result<u64, HttpHealthCheckError> {
    let mut offset = 0usize;
    while offset < message.len() {
        let key = decode_grpc_varint(message, &mut offset)?;
        let field = key >> 3;
        let wire_type = key & 0x07;
        match (field, wire_type) {
            (1, 0) => return decode_grpc_varint(message, &mut offset),
            (_, 0) => {
                let _ = decode_grpc_varint(message, &mut offset)?;
            }
            (_, 2) => {
                let len = decode_grpc_varint(message, &mut offset)? as usize;
                offset = offset.checked_add(len).ok_or_else(invalid_grpc_response)?;
                if offset > message.len() {
                    return Err(invalid_grpc_response());
                }
            }
            (_, 1) => {
                offset = offset.checked_add(8).ok_or_else(invalid_grpc_response)?;
                if offset > message.len() {
                    return Err(invalid_grpc_response());
                }
            }
            (_, 5) => {
                offset = offset.checked_add(4).ok_or_else(invalid_grpc_response)?;
                if offset > message.len() {
                    return Err(invalid_grpc_response());
                }
            }
            _ => return Err(invalid_grpc_response()),
        }
    }
    Err(invalid_grpc_response())
}

fn decode_grpc_varint(message: &[u8], offset: &mut usize) -> Result<u64, HttpHealthCheckError> {
    let mut value = 0u64;
    let mut shift = 0u32;
    while *offset < message.len() && shift < 64 {
        let byte = message[*offset];
        *offset += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err(invalid_grpc_response())
}

fn invalid_grpc_response() -> HttpHealthCheckError {
    HttpHealthCheckError::new(
        ErrorType::ReadError,
        "invalid gRPC health check response message",
    )
}

struct HttpHealthCheckError {
    kind: ErrorType,
    error: FluxError,
}

impl HttpHealthCheckError {
    fn new(kind: ErrorType, detail: &'static str) -> Self {
        Self {
            kind,
            error: FluxError::InvalidInput(detail),
        }
    }

    fn into_flux(self) -> FluxError {
        FluxError::io(
            "HTTP health check failed",
            io::Error::other(format!("{:?}: {}", self.kind, self.error)),
        )
    }
}

fn pingora_health_error(context: &'static str) -> impl FnOnce(Box<Error>) -> FluxError {
    move |error| FluxError::io(context, io::Error::other(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::Backend;
    use super::FluxHealthCheck;
    use super::HealthDerivedWeights;
    use super::{
        POSTGRES_HEALTH_CHECK_SSL_REQUEST, REDIS_HEALTH_CHECK_REQUEST,
        configured_exec_health_check, configured_http_health_check, configured_mysql_health_check,
        configured_postgres_health_check, configured_redis_health_check, grpc_frame,
        grpc_health_request_body, record_health_weight, validate_grpc_health_response_body,
        validate_grpc_health_response_header, validate_http_health_response,
        validate_http_health_response_body, validate_http_health_response_body_json,
        validate_mysql_health_handshake, validate_postgres_health_response,
        validate_redis_health_response,
    };
    use fluxheim_config::{
        LoadBalanceConfig, LoadBalanceHealthCheckConfig, LoadBalanceHealthCheckExpectedHeader,
        LoadBalanceHealthCheckExpectedJson, LoadBalanceHealthCheckExpectedStatusRange,
        LoadBalanceHealthCheckProtocol, LoadBalanceHealthCheckRequestHeader, ProxyConfig,
    };
    use pingora::http::ResponseHeader;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn install_test_crypto_provider() {
        #[cfg(feature = "tls-rustls-backend")]
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn configures_pingora_http_health_check() {
        install_test_crypto_provider();
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
        assert!(health_check.reuse_connection);
        assert_eq!(health_check.port_override, Some(8081));
        assert_eq!(
            health_check.peer_template.options.connection_timeout,
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            health_check.peer_template.options.read_timeout,
            Some(Duration::from_secs(6))
        );
        assert!(!health_check.expected_statuses.is_empty());
        assert!(!health_check.expected_headers.is_empty());
        assert_eq!(
            health_check.expected_body_contains.as_ref(),
            ["ready".to_owned()]
        );
        assert_eq!(health_check.expected_body_json[0].path, "status");
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
        let mut response = ResponseHeader::build(204, None).unwrap();
        response
            .append_header("x-fluxheim-health", "ready")
            .unwrap();
        assert!(
            validate_http_health_response(
                &response,
                &expected_statuses,
                &expected_status_ranges,
                &expected_headers
            )
            .is_ok()
        );

        let missing = ResponseHeader::build(204, None).unwrap();
        assert!(
            validate_http_health_response(
                &missing,
                &expected_statuses,
                &expected_status_ranges,
                &expected_headers
            )
            .is_err()
        );

        let ranged = ResponseHeader::build(302, None).unwrap();
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
        assert!(
            validate_http_health_response_body_json(br#"{"status":"down"}"#, &expected).is_err()
        );
    }

    #[test]
    fn configures_grpc_health_check() {
        install_test_crypto_provider();
        let health_check = configured_http_health_check(
            &ProxyConfig {
                upstreams: vec!["127.0.0.1:50051".to_owned()],
                upstream_tls: true,
                upstream_sni: Some("grpc.example.test".to_owned()),
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
        assert_eq!(health_check.req.uri.path(), "/grpc.health.v1.Health/Check");
        assert!(health_check.grpc_response);
        assert_eq!(health_check.peer_template.options.max_h2_streams, 32);
        assert_eq!(
            health_check
                .req
                .headers
                .get("content-type")
                .map(|value| value.as_bytes()),
            Some("application/grpc".as_bytes())
        );
        assert_eq!(
            health_check.request_body.as_deref(),
            Some(grpc_health_request_body(Some("example.Health")).as_slice())
        );
    }

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

    #[test]
    fn validates_grpc_health_check_response() {
        let mut response = ResponseHeader::build(200, None).unwrap();
        response
            .append_header("content-type", "application/grpc")
            .unwrap();
        let serving = grpc_frame(&[0x08, 0x01]);
        assert!(validate_grpc_health_response_header(&response).is_ok());
        assert!(validate_grpc_health_response_body(&serving).is_ok());

        let not_serving = grpc_frame(&[0x08, 0x02]);
        assert!(validate_grpc_health_response_body(&not_serving).is_err());

        let mut wrong_type = ResponseHeader::build(200, None).unwrap();
        wrong_type
            .append_header("content-type", "text/plain")
            .unwrap();
        assert!(validate_grpc_health_response_header(&wrong_type).is_err());
    }

    #[test]
    fn grpc_health_response_skips_unknown_fixed_width_fields() {
        let mut response = vec![0x11];
        response.extend_from_slice(&[0u8; 8]);
        response.push(0x1d);
        response.extend_from_slice(&[0u8; 4]);
        response.extend_from_slice(&[0x08, 0x01]);

        assert!(validate_grpc_health_response_body(&grpc_frame(&response)).is_ok());
    }

    #[test]
    fn health_weight_signal_is_clamped_to_configured_floor() {
        let weights = HealthDerivedWeights::default();
        let mut response = ResponseHeader::build(200, None).unwrap();
        response.append_header("x-health-weight", "1").unwrap();

        assert!(record_health_weight(&response, 42, 25, &weights).is_ok());
        assert_eq!(weights.weight_percent(42), Some(25));

        let mut recovered = ResponseHeader::build(200, None).unwrap();
        recovered.append_header("x-health-weight", "100").unwrap();
        assert!(record_health_weight(&recovered, 42, 25, &weights).is_ok());
        assert_eq!(weights.weight_percent(42), None);
    }
}
