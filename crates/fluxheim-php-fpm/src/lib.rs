#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::io;

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

#[cfg(test)]
mod tests {
    use std::io;

    use super::{PhpFpmTimeoutKind, php_fpm_error_outcome, php_fpm_timeout_error};

    #[test]
    fn php_fpm_error_outcomes_are_bounded() {
        assert_eq!(
            php_fpm_error_outcome(&php_fpm_timeout_error(PhpFpmTimeoutKind::Connect)),
            "connect_timeout"
        );
        assert_eq!(
            php_fpm_error_outcome(&php_fpm_timeout_error(PhpFpmTimeoutKind::Request)),
            "request_timeout"
        );
        assert_eq!(
            php_fpm_error_outcome(&io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "connection refused",
            )),
            "connection_error"
        );
        assert_eq!(
            php_fpm_error_outcome(&io::Error::new(io::ErrorKind::InvalidInput, "missing fpm")),
            "configuration_error"
        );
        assert_eq!(
            php_fpm_error_outcome(&io::Error::new(io::ErrorKind::InvalidData, "bad response")),
            "invalid_response"
        );
        assert_eq!(
            php_fpm_error_outcome(&io::Error::other("backend failed")),
            "fpm_error"
        );
    }
}
