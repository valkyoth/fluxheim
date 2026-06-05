//! Fluxheim-owned internal error boundary.
//!
//! This module gives non-boundary code a typed error surface. Pingora errors
//! are still produced at Pingora adapter boundaries.

use std::io;

pub(crate) type FluxResult<T> = Result<T, FluxError>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum FluxError {
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
}

impl FluxError {
    pub(crate) fn io(context: &'static str, source: io::Error) -> Self {
        Self::Io { context, source }
    }

    pub(crate) fn invalid_input(detail: impl Into<String>) -> Self {
        Self::InvalidInputMessage(detail.into())
    }

    pub(crate) fn timeout(context: &'static str, detail: impl Into<String>) -> Self {
        Self::Timeout {
            context,
            detail: detail.into(),
        }
    }

    pub(crate) fn into_io(self) -> io::Error {
        match self {
            Self::Io { context, source } => {
                let kind = source.kind();
                io::Error::new(kind, Self::Io { context, source })
            }
            Self::InvalidInput(_) | Self::InvalidInputMessage(_) => {
                io::Error::new(io::ErrorKind::InvalidInput, self)
            }
            Self::Timeout { .. } => io::Error::new(io::ErrorKind::TimedOut, self),
        }
    }

    #[cfg(test)]
    pub(crate) fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Io { source, .. } => Some(source.kind()),
            Self::InvalidInput(_) | Self::InvalidInputMessage(_) | Self::Timeout { .. } => None,
        }
    }

    #[cfg(feature = "ingress")]
    pub(crate) fn into_pingora(self, kind: pingora::ErrorType) -> Box<pingora::Error> {
        pingora::Error::because(kind, "Fluxheim internal error", self)
    }
}
