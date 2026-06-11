//! Fluxheim-owned internal error boundary.
//!
//! This module gives non-boundary code a typed error surface. Adapter crates
//! can convert this error into framework-specific errors at their boundaries.

use std::io;

pub type FluxResult<T> = Result<T, FluxError>;

#[derive(Debug, thiserror::Error)]
pub enum FluxError {
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },

    #[error("{0}")]
    InvalidInput(&'static str),

    #[error("{0}")]
    InvalidInputMessage(String),

    #[error("{context}: {detail}")]
    Timeout {
        context: &'static str,
        detail: String,
    },

    #[error("write PROXY protocol header: {0}")]
    WriteProxyHeader(#[source] io::Error),
}

impl FluxError {
    pub fn io(context: &'static str, source: io::Error) -> Self {
        Self::Io { context, source }
    }

    pub fn invalid_input(detail: impl Into<String>) -> Self {
        Self::InvalidInputMessage(detail.into())
    }

    pub fn timeout(context: &'static str, detail: impl Into<String>) -> Self {
        Self::Timeout {
            context,
            detail: detail.into(),
        }
    }

    pub fn write_proxy_header(source: io::Error) -> Self {
        Self::WriteProxyHeader(source)
    }

    pub fn into_io(self) -> io::Error {
        match self {
            Self::Io { context, source } => {
                let kind = source.kind();
                io::Error::new(kind, Self::Io { context, source })
            }
            Self::InvalidInput(_) | Self::InvalidInputMessage(_) => {
                io::Error::new(io::ErrorKind::InvalidInput, self)
            }
            Self::Timeout { .. } => io::Error::new(io::ErrorKind::TimedOut, self),
            Self::WriteProxyHeader(source) => {
                let kind = source.kind();
                io::Error::new(kind, Self::WriteProxyHeader(source))
            }
        }
    }

    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Io { source, .. } => Some(source.kind()),
            Self::WriteProxyHeader(source) => Some(source.kind()),
            Self::InvalidInput(_) | Self::InvalidInputMessage(_) | Self::Timeout { .. } => None,
        }
    }
}
