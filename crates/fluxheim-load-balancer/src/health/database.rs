use std::io;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use fluxheim_common::{FluxError, FluxResult};
use fluxheim_config::ProxyConfig;

use crate::backend::{FluxHealthCheck, RuntimeBackend as Backend};

pub(super) const REDIS_HEALTH_CHECK_REQUEST: &[u8] = b"*1\r\n$4\r\nPING\r\n";
const REDIS_HEALTH_CHECK_MAX_RESPONSE_BYTES: usize = 64;
const MYSQL_HEALTH_CHECK_MAX_HANDSHAKE_BYTES: usize = 1024;
pub(super) const POSTGRES_HEALTH_CHECK_SSL_REQUEST: &[u8; 8] = b"\x00\x00\x00\x08\x04\xd2\x16/";

pub(super) struct FluxRedisHealthCheck {
    pub(super) consecutive_success: usize,
    pub(super) consecutive_failure: usize,
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

pub(super) fn configured_redis_health_check(
    config: &ProxyConfig,
) -> FluxResult<Box<FluxRedisHealthCheck>> {
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

pub(super) struct FluxMysqlHealthCheck {
    pub(super) consecutive_success: usize,
    pub(super) consecutive_failure: usize,
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

pub(super) fn configured_mysql_health_check(
    config: &ProxyConfig,
) -> FluxResult<Box<FluxMysqlHealthCheck>> {
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

pub(super) struct FluxPostgresHealthCheck {
    pub(super) consecutive_success: usize,
    pub(super) consecutive_failure: usize,
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

pub(super) fn configured_postgres_health_check(
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

pub(super) fn validate_redis_health_response(response: &[u8]) -> FluxResult<()> {
    if response.starts_with(b"+PONG\r\n") {
        return Ok(());
    }
    Err(FluxError::InvalidInput(
        "Redis health check did not receive PONG",
    ))
}

pub(super) fn validate_mysql_health_handshake(header: &[u8; 4], payload: &[u8]) -> FluxResult<()> {
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

pub(super) fn validate_postgres_health_response(response: u8) -> FluxResult<()> {
    if matches!(response, b'S' | b'N') {
        return Ok(());
    }
    Err(FluxError::InvalidInput(
        "PostgreSQL health check did not receive SSLResponse",
    ))
}
