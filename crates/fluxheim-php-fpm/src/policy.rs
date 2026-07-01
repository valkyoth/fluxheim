use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fluxheim_config::PhpFpmConfig;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PhpFpmEndpoint {
    Tcp(String),
    #[cfg(unix)]
    Unix(PathBuf),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PhpFpmTimeoutKind {
    Connect,
    Request,
}

impl std::fmt::Display for PhpFpmTimeoutKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect => write!(formatter, "php-fpm connect timed out"),
            Self::Request => write!(formatter, "php-fpm request timed out"),
        }
    }
}

impl std::error::Error for PhpFpmTimeoutKind {}

pub fn php_fpm_timeout_error(kind: PhpFpmTimeoutKind) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, kind)
}

pub fn php_fpm_timeout_kind(error: &io::Error) -> Option<PhpFpmTimeoutKind> {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<PhpFpmTimeoutKind>())
        .copied()
}

pub fn php_fpm_error_outcome(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::TimedOut => match php_fpm_timeout_kind(error) {
            Some(PhpFpmTimeoutKind::Connect) => "connect_timeout",
            Some(PhpFpmTimeoutKind::Request) | None => "request_timeout",
        },
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::NotConnected
        | io::ErrorKind::AddrInUse
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::NotFound
        | io::ErrorKind::UnexpectedEof => "connection_error",
        io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported => "configuration_error",
        io::ErrorKind::InvalidData => "invalid_response",
        _ => "fpm_error",
    }
}

pub fn php_fpm_endpoints_from_config(config: &PhpFpmConfig) -> Vec<PhpFpmEndpoint> {
    if !config.tcp_upstreams.is_empty() {
        return config
            .tcp_upstreams
            .iter()
            .cloned()
            .map(PhpFpmEndpoint::Tcp)
            .collect();
    }
    if let Some(address) = config.tcp.as_deref() {
        return vec![PhpFpmEndpoint::Tcp(address.to_owned())];
    }
    if let Some(socket) = config.socket.as_deref() {
        #[cfg(unix)]
        {
            return vec![PhpFpmEndpoint::Unix(socket.to_path_buf())];
        }
        #[cfg(not(unix))]
        {
            let _ = socket;
            return Vec::new();
        }
    }
    Vec::new()
}

pub fn php_fpm_effective_connect_timeout(
    fpm: &PhpFpmConfig,
    request_timeout: Duration,
) -> Duration {
    fpm.connect_timeout_secs
        .map(Duration::from_secs)
        .map(|connect_timeout| connect_timeout.min(request_timeout))
        .unwrap_or(request_timeout)
}

pub fn php_fpm_effective_request_timeout(
    fpm: &PhpFpmConfig,
    request_timeout: Duration,
) -> Duration {
    [fpm.read_timeout_secs, fpm.write_timeout_secs]
        .into_iter()
        .flatten()
        .map(Duration::from_secs)
        .fold(request_timeout, Duration::min)
}

fn php_fpm_retry_method_allowed(fpm: &PhpFpmConfig, method: &str) -> bool {
    fpm.retry_methods
        .iter()
        .any(|retry_method| retry_method.eq_ignore_ascii_case(method))
}

pub fn php_fpm_retry_attempts(fpm: &PhpFpmConfig, method: &str) -> u8 {
    php_fpm_retry_attempts_for_endpoint_count(fpm, method, 1)
}

pub fn php_fpm_retry_attempts_for_endpoint_count(
    fpm: &PhpFpmConfig,
    method: &str,
    endpoint_count: usize,
) -> u8 {
    if !php_fpm_retry_method_allowed(fpm, method) {
        return 0;
    }
    let failover_retries = endpoint_count.saturating_sub(1).min(usize::from(u8::MAX)) as u8;
    fpm.max_retries.max(failover_retries)
}

pub fn php_fpm_retry_deadline(retry_timeout_secs: Option<u64>) -> Option<Instant> {
    retry_timeout_secs.and_then(|secs| Instant::now().checked_add(Duration::from_secs(secs)))
}

pub fn php_fpm_retry_deadline_allows(deadline: Option<Instant>) -> bool {
    match deadline {
        Some(deadline) => Instant::now() < deadline,
        None => true,
    }
}

pub fn php_fpm_retryable_status(fpm: &PhpFpmConfig, status: u16) -> bool {
    fpm.retry_statuses.contains(&status)
}

pub fn php_fpm_retryable_error(error: &io::Error) -> bool {
    match error.kind() {
        io::ErrorKind::TimedOut => php_fpm_timeout_kind(error) == Some(PhpFpmTimeoutKind::Connect),
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::NotConnected
        | io::ErrorKind::AddrInUse
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::NotFound
        | io::ErrorKind::UnexpectedEof => true,
        _ => false,
    }
}
