use std::io;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use fluxheim_common::{FluxError, FluxResult};
use fluxheim_config::{
    LoadBalanceHealthCheckExpectedHeader, LoadBalanceHealthCheckExpectedJson,
    LoadBalanceHealthCheckExpectedStatusRange, LoadBalanceHealthCheckProtocol, ProxyConfig,
};

use super::backend::{FluxHealthCheck, RuntimeBackend as Backend};
use super::key::backend_key;
use super::policy::HealthDerivedWeights;

mod grpc;
mod http1;

#[cfg(test)]
use self::grpc::grpc_frame;
use self::grpc::{
    execute_grpc_health_check, grpc_health_request_body, validate_grpc_health_response_body,
    validate_grpc_health_response_header,
};
use self::http1::execute_http1_health_check;

const HTTP_HEALTH_CHECK_MAX_BODY_BYTES: usize = 64 * 1024;
const GRPC_HEALTH_CHECK_PATH: &[u8] = b"/grpc.health.v1.Health/Check";
const HEALTH_WEIGHT_HEADER: &str = "x-health-weight";
const REDIS_HEALTH_CHECK_REQUEST: &[u8] = b"*1\r\n$4\r\nPING\r\n";
const REDIS_HEALTH_CHECK_MAX_RESPONSE_BYTES: usize = 64;
const MYSQL_HEALTH_CHECK_MAX_HANDSHAKE_BYTES: usize = 1024;
const POSTGRES_HEALTH_CHECK_SSL_REQUEST: &[u8; 8] = b"\x00\x00\x00\x08\x04\xd2\x16/";

trait HealthIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> HealthIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

type BoxedHealthIo = Box<dyn HealthIo>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HealthTlsAlpn {
    None,
    Http1,
    Http2,
}

pub(super) fn configured_health_check(
    config: &ProxyConfig,
    health_weights: Arc<HealthDerivedWeights>,
) -> io::Result<Box<dyn FluxHealthCheck>> {
    #[cfg(test)]
    crate::install_test_crypto_provider();

    match config.load_balance.health_check.protocol {
        LoadBalanceHealthCheckProtocol::Tcp => {
            let consecutive_success = config.load_balance.health_check.consecutive_success;
            let consecutive_failure = config.load_balance.health_check.consecutive_failure;
            let connect_timeout = Duration::from_secs(
                config
                    .load_balance
                    .health_check
                    .connect_timeout_secs
                    .or(config.connect_timeout_secs)
                    .unwrap_or(1),
            );
            let tls = configured_tcp_health_check_tls(config, HealthTlsAlpn::None)
                .map_err(FluxError::into_io)?;
            Ok(Box::new(FluxTcpHealthCheck {
                consecutive_success,
                consecutive_failure,
                connect_timeout,
                tls,
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
    consecutive_success: usize,
    consecutive_failure: usize,
    connect_timeout: Duration,
    tls: Option<FluxTcpHealthCheckTls>,
}

#[cfg(feature = "tls-rustls-backend")]
struct FluxTcpHealthCheckTls {
    server_name: rustls::pki_types::ServerName<'static>,
    config: Arc<rustls::ClientConfig>,
}

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
struct FluxTcpHealthCheckTls {
    domain: String,
    connector: openssl::ssl::SslConnector,
}

#[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
struct FluxTcpHealthCheckTls;

#[async_trait]
impl FluxHealthCheck for FluxTcpHealthCheck {
    async fn check(&self, target: &Backend) -> FluxResult<()> {
        let authority = target.addr.to_string();
        let stream = tokio::time::timeout(
            self.connect_timeout,
            tokio::net::TcpStream::connect(authority.as_str()),
        )
        .await
        .map_err(|_| {
            FluxError::timeout(
                "connect TCP health check upstream",
                format!("timeout after {}s", self.connect_timeout.as_secs()),
            )
        })?
        .map_err(|error| FluxError::io("connect TCP health check upstream", error))?;
        if let Some(tls) = &self.tls {
            let _stream = tokio::time::timeout(self.connect_timeout, tls.handshake(stream))
                .await
                .map_err(|_| {
                    FluxError::timeout(
                        "TLS TCP health check handshake",
                        format!("timeout after {}s", self.connect_timeout.as_secs()),
                    )
                })??;
            return Ok(());
        }
        Ok(())
    }

    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }

    async fn health_status_change(&self, _target: &Backend, _healthy: bool) {}

    fn backend_summary(&self, target: &Backend) -> String {
        format!("{target:?}")
    }
}

impl FluxTcpHealthCheckTls {
    #[cfg(feature = "tls-rustls-backend")]
    async fn handshake(&self, stream: tokio::net::TcpStream) -> FluxResult<BoxedHealthIo> {
        let connector = tokio_rustls::TlsConnector::from(self.config.clone());
        let stream = connector
            .connect(self.server_name.clone(), stream)
            .await
            .map_err(|error| FluxError::io("TLS TCP health check handshake failed", error))?;
        Ok(Box::new(stream))
    }

    #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
    async fn handshake(&self, stream: tokio::net::TcpStream) -> FluxResult<BoxedHealthIo> {
        let ssl = self
            .connector
            .configure()
            .and_then(|config| config.into_ssl(self.domain.as_str()))
            .map_err(|error| {
                FluxError::io(
                    "build OpenSSL TCP health check session",
                    io::Error::other(error.to_string()),
                )
            })?;
        let mut stream = tokio_openssl::SslStream::new(ssl, stream).map_err(|error| {
            FluxError::io(
                "build OpenSSL TCP health check stream",
                io::Error::other(error.to_string()),
            )
        })?;
        std::pin::Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|error| {
                FluxError::io(
                    "TLS TCP health check handshake failed",
                    io::Error::other(error.to_string()),
                )
            })?;
        Ok(Box::new(stream))
    }

    #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
    async fn handshake(&self, _stream: tokio::net::TcpStream) -> FluxResult<BoxedHealthIo> {
        Err(FluxError::InvalidInput(
            "TLS TCP health checks require a TLS backend feature",
        ))
    }
}

fn configured_tcp_health_check_tls(
    config: &ProxyConfig,
    alpn: HealthTlsAlpn,
) -> FluxResult<Option<FluxTcpHealthCheckTls>> {
    if !config.upstream_tls {
        return Ok(None);
    }
    configured_tcp_health_check_tls_inner(config, alpn).map(Some)
}

#[cfg(feature = "tls-rustls-backend")]
fn configured_tcp_health_check_tls_inner(
    config: &ProxyConfig,
    alpn: HealthTlsAlpn,
) -> FluxResult<FluxTcpHealthCheckTls> {
    let server_name =
        rustls::pki_types::ServerName::try_from(config.upstream_sni()).map_err(|error| {
            FluxError::io(
                "build TCP health check TLS server name",
                io::Error::new(io::ErrorKind::InvalidInput, error),
            )
        })?;
    let native_certs = rustls_native_certs::load_native_certs();
    if !native_certs.errors.is_empty() {
        log::warn!(
            target: "fluxheim::security",
            "TCP health check TLS trust store loaded with {} certificate errors",
            native_certs.errors.len()
        );
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in native_certs.certs {
        roots.add(cert).map_err(|error| {
            FluxError::io(
                "load TCP health check TLS root certificate",
                io::Error::new(io::ErrorKind::InvalidData, error),
            )
        })?;
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    match alpn {
        HealthTlsAlpn::None => {}
        HealthTlsAlpn::Http1 => config.alpn_protocols = vec![b"http/1.1".to_vec()],
        HealthTlsAlpn::Http2 => config.alpn_protocols = vec![b"h2".to_vec()],
    }
    Ok(FluxTcpHealthCheckTls {
        server_name,
        config: Arc::new(config),
    })
}

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
fn configured_tcp_health_check_tls_inner(
    config: &ProxyConfig,
    alpn: HealthTlsAlpn,
) -> FluxResult<FluxTcpHealthCheckTls> {
    let domain = config.upstream_sni();
    if domain.is_empty() {
        return Err(FluxError::InvalidInput(
            "TCP health check TLS SNI is required for OpenSSL",
        ));
    }
    let mut builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client())
        .map_err(|error| {
            FluxError::io(
                "build OpenSSL TCP health check connector",
                io::Error::other(error.to_string()),
            )
        })?;
    builder.set_default_verify_paths().map_err(|error| {
        FluxError::io(
            "load OpenSSL TCP health check trust store",
            io::Error::other(error.to_string()),
        )
    })?;
    match alpn {
        HealthTlsAlpn::None => {}
        HealthTlsAlpn::Http1 => builder.set_alpn_protos(b"\x08http/1.1").map_err(|error| {
            FluxError::io(
                "configure OpenSSL TCP health check ALPN",
                io::Error::other(error.to_string()),
            )
        })?,
        HealthTlsAlpn::Http2 => builder.set_alpn_protos(b"\x02h2").map_err(|error| {
            FluxError::io(
                "configure OpenSSL TCP health check ALPN",
                io::Error::other(error.to_string()),
            )
        })?,
    }
    Ok(FluxTcpHealthCheckTls {
        domain,
        connector: builder.build(),
    })
}

#[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
fn configured_tcp_health_check_tls_inner(
    _config: &ProxyConfig,
    _alpn: HealthTlsAlpn,
) -> FluxResult<FluxTcpHealthCheckTls> {
    Err(FluxError::InvalidInput(
        "TLS TCP health checks require a TLS backend feature",
    ))
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
        let backend_inet = target.addr;
        command
            .args(self.args.iter().map(String::as_str))
            .env_clear()
            .env("FLUXHEIM_HEALTH_BACKEND_ADDR", backend_addr)
            .env(
                "FLUXHEIM_HEALTH_BACKEND_HOST",
                backend_inet.ip().to_string(),
            )
            .env(
                "FLUXHEIM_HEALTH_BACKEND_PORT",
                backend_inet.port().to_string(),
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct HealthHttpRequest {
    method: Method,
    path: String,
    host: String,
    headers: HeaderMap,
    body: Option<Bytes>,
    grpc: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HealthHttpResponse {
    status: StatusCode,
    headers: HeaderMap,
}

struct FluxHttpHealthCheck {
    consecutive_success: usize,
    consecutive_failure: usize,
    upstream_tls: bool,
    tls: Option<FluxTcpHealthCheckTls>,
    connection_timeout: Duration,
    read_timeout: Duration,
    reuse_connection: bool,
    req: HealthHttpRequest,
    port_override: Option<u16>,
    expected_statuses: Arc<[u16]>,
    expected_status_ranges: Arc<[LoadBalanceHealthCheckExpectedStatusRange]>,
    expected_headers: Arc<[LoadBalanceHealthCheckExpectedHeader]>,
    expected_body_contains: Arc<[String]>,
    expected_body_json: Arc<[LoadBalanceHealthCheckExpectedJson]>,
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
        let mut address = target.addr;
        if let Some(port) = self.port_override {
            address.set_port(port);
        }
        let stream = connect_health_stream(
            address,
            self.upstream_tls,
            self.tls.as_ref(),
            self.connection_timeout,
        )
        .await?;

        let (response, body) = if self.req.grpc {
            execute_grpc_health_check(stream, &self.req, self.read_timeout).await?
        } else {
            execute_http1_health_check(stream, &self.req, self.read_timeout).await?
        };
        validate_http_health_response(
            &response,
            &self.expected_statuses,
            &self.expected_status_ranges,
            &self.expected_headers,
        )
        .map_err(HttpHealthCheckError::into_flux)?;
        record_health_weight(
            &response,
            backend_key(target),
            self.health_weight_min_percent,
            &self.health_weights,
        )
        .map_err(HttpHealthCheckError::into_flux)?;

        if self.req.grpc {
            validate_grpc_health_response_header(&response)
                .map_err(HttpHealthCheckError::into_flux)?;
            validate_grpc_health_response_body(&body).map_err(HttpHealthCheckError::into_flux)?;
        } else if self.expected_body_contains.is_empty() && self.expected_body_json.is_empty() {
            let _ = body;
        } else {
            validate_http_health_response_body(&body, &self.expected_body_contains)
                .map_err(HttpHealthCheckError::into_flux)?;
            validate_http_health_response_body_json(&body, &self.expected_body_json)
                .map_err(HttpHealthCheckError::into_flux)?;
        }
        let _ = self.reuse_connection;

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
        std::str::from_utf8(GRPC_HEALTH_CHECK_PATH).unwrap_or("/grpc.health.v1.Health/Check")
    } else {
        config.load_balance.health_check.path.as_str()
    };
    reject_http1_health_request_crlf(path, "health check path must not contain CR or LF")?;
    reject_http1_health_request_crlf(&host, "health check host must not contain CR or LF")?;
    let method = Method::from_bytes(method.as_bytes()).map_err(|error| {
        FluxError::io(
            "build HTTP health check request method",
            io::Error::other(error.to_string()),
        )
    })?;
    let mut headers = HeaderMap::new();
    for header in &config.load_balance.health_check.request_headers {
        let name = HeaderName::from_bytes(header.name.as_bytes()).map_err(|error| {
            FluxError::io(
                "append HTTP health check request header",
                io::Error::other(error.to_string()),
            )
        })?;
        let value = HeaderValue::from_str(&header.value).map_err(|error| {
            FluxError::io(
                "append HTTP health check request header",
                io::Error::other(error.to_string()),
            )
        })?;
        headers.append(name, value);
    }
    if grpc {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/grpc"),
        );
        headers.insert("te", HeaderValue::from_static("trailers"));
    }

    let mut connection_timeout = Some(Duration::from_secs(1));
    let mut read_timeout = Some(Duration::from_secs(1));
    apply_health_check_peer_timeouts(&mut connection_timeout, Some(&mut read_timeout), config);
    let connection_timeout = connection_timeout.unwrap_or_else(|| Duration::from_secs(1));
    let read_timeout = read_timeout.unwrap_or_else(|| Duration::from_secs(1));
    let tls = configured_tcp_health_check_tls(
        config,
        if grpc {
            HealthTlsAlpn::Http2
        } else {
            HealthTlsAlpn::Http1
        },
    )?;

    Ok(Box::new(FluxHttpHealthCheck {
        consecutive_success: config.load_balance.health_check.consecutive_success,
        consecutive_failure: config.load_balance.health_check.consecutive_failure,
        upstream_tls: config.upstream_tls,
        tls,
        connection_timeout,
        read_timeout,
        reuse_connection: config.load_balance.health_check.reuse_connection,
        req: HealthHttpRequest {
            method,
            path: path.to_owned(),
            host,
            headers,
            body: grpc.then(|| {
                Bytes::from(grpc_health_request_body(
                    config.load_balance.health_check.grpc_service.as_deref(),
                ))
            }),
            grpc,
        },
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
        health_weight_min_percent: config.load_balance.health_check.health_weight_min_percent,
        health_weights,
    }))
}

fn reject_http1_health_request_crlf(value: &str, message: &'static str) -> FluxResult<()> {
    if value.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(FluxError::InvalidInput(message));
    }
    Ok(())
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

async fn connect_health_stream(
    address: std::net::SocketAddr,
    upstream_tls: bool,
    tls: Option<&FluxTcpHealthCheckTls>,
    connection_timeout: Duration,
) -> FluxResult<BoxedHealthIo> {
    let stream = tokio::time::timeout(connection_timeout, tokio::net::TcpStream::connect(address))
        .await
        .map_err(|_| {
            FluxError::timeout(
                "connect HTTP health check upstream",
                format!("timeout after {}s", connection_timeout.as_secs()),
            )
        })?
        .map_err(|error| FluxError::io("connect HTTP health check upstream", error))?;
    if !upstream_tls {
        return Ok(Box::new(stream));
    }
    let Some(tls) = tls else {
        return Err(FluxError::InvalidInput(
            "HTTP health check TLS requires a TLS backend feature",
        ));
    };
    tokio::time::timeout(connection_timeout, tls.handshake(stream))
        .await
        .map_err(|_| {
            FluxError::timeout(
                "TLS HTTP health check handshake",
                format!("timeout after {}s", connection_timeout.as_secs()),
            )
        })?
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
    response: &HealthHttpResponse,
    expected_statuses: &[u16],
    expected_status_ranges: &[LoadBalanceHealthCheckExpectedStatusRange],
    expected_headers: &[LoadBalanceHealthCheckExpectedHeader],
) -> Result<(), HttpHealthCheckError> {
    let status = response.status.as_u16();
    if expected_statuses.is_empty() && expected_status_ranges.is_empty() {
        if status != 200 {
            return Err(HttpHealthCheckError::new(
                HealthErrorKind::HttpStatus(status),
                "unexpected HTTP health check status",
            ));
        }
    } else if !expected_statuses.contains(&status)
        && !expected_status_ranges
            .iter()
            .any(|range| (range.start..=range.end).contains(&status))
    {
        return Err(HttpHealthCheckError::new(
            HealthErrorKind::HttpStatus(status),
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
                HealthErrorKind::InvalidHttpHeader,
                "missing expected HTTP health check header",
            ));
        }
    }
    Ok(())
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
                HealthErrorKind::ReadError,
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
            HealthErrorKind::ReadError,
            "invalid HTTP health check JSON response body",
        )
    })?;
    for expected in expected_body_json {
        let Some(value) = json_path_value(&json, &expected.path) else {
            return Err(HttpHealthCheckError::new(
                HealthErrorKind::ReadError,
                "missing expected HTTP health check JSON field",
            ));
        };
        if json_scalar_string(value).as_deref() != Some(expected.equals.as_str()) {
            return Err(HttpHealthCheckError::new(
                HealthErrorKind::ReadError,
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
    response: &HealthHttpResponse,
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
            HealthErrorKind::InvalidHttpHeader,
            "invalid HTTP health check degraded weight header",
        )
    })?;
    let percent = value.trim().parse::<u8>().map_err(|_| {
        HttpHealthCheckError::new(
            HealthErrorKind::InvalidHttpHeader,
            "invalid HTTP health check degraded weight header",
        )
    })?;
    if percent == 0 || percent > 100 {
        return Err(HttpHealthCheckError::new(
            HealthErrorKind::InvalidHttpHeader,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HealthErrorKind {
    ReadError,
    InvalidHttpHeader,
    HttpStatus(u16),
}

struct HttpHealthCheckError {
    kind: HealthErrorKind,
    error: FluxError,
}

impl HttpHealthCheckError {
    fn new(kind: HealthErrorKind, detail: &'static str) -> Self {
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

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::sync::Arc;
    use std::time::Duration;

    use super::Backend;
    use super::FluxHealthCheck;
    use super::HealthDerivedWeights;
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
    use super::{FluxTcpHealthCheck, configured_tcp_health_check_tls_inner};
    use super::{
        HealthHttpResponse, POSTGRES_HEALTH_CHECK_SSL_REQUEST, REDIS_HEALTH_CHECK_REQUEST,
        configured_exec_health_check, configured_health_check, configured_http_health_check,
        configured_mysql_health_check, configured_postgres_health_check,
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

    fn install_test_crypto_provider() {
        #[cfg(feature = "tls-rustls-backend")]
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

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
        install_test_crypto_provider();
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

    #[test]
    fn configures_native_http_health_check() {
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
        let error = match configured_http_health_check(
            &bad_path,
            Arc::new(HealthDerivedWeights::default()),
        ) {
            Ok(_) => panic!("CRLF path was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("path must not contain"));

        let mut bad_host = base;
        bad_host.load_balance.health_check.host =
            Some("origin.example.test\r\nX-Injected: yes".to_owned());
        let error = match configured_http_health_check(
            &bad_host,
            Arc::new(HealthDerivedWeights::default()),
        ) {
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
            Some(grpc_health_request_body(Some("example.Health")).as_slice())
        );
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
                grpc_health_request_body(Some("example.Health"))
            );
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(Bytes::from(grpc_frame(&[0x08, 0x01])), true)
                .unwrap();
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
        let response = health_response(200, &[("content-type", "application/grpc")]);
        let serving = grpc_frame(&[0x08, 0x01]);
        assert!(validate_grpc_health_response_header(&response).is_ok());
        assert!(validate_grpc_health_response_body(&serving).is_ok());

        let not_serving = grpc_frame(&[0x08, 0x02]);
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

        assert!(validate_grpc_health_response_body(&grpc_frame(&response)).is_ok());
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
}
