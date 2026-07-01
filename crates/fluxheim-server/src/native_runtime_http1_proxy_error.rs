use std::error::Error;
use std::fmt;

use super::NativeHttp1ProxyRuntimeError;

impl fmt::Display for NativeHttp1ProxyRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind { addr, source } => {
                write!(
                    formatter,
                    "failed to bind native HTTP/1 proxy listener {addr}: {source}"
                )
            }
            Self::LaunchPlan(error) => {
                write!(formatter, "native HTTP/1 proxy launch plan: {error}")
            }
            Self::MissingProxyHttpListener => {
                formatter.write_str("native HTTP/1 proxy runtime requires a proxy HTTP listener")
            }
            Self::Router(error) => write!(formatter, "native HTTP/1 host router: {error}"),
            #[cfg(feature = "tls-rustls-backend")]
            Self::RustlsCertificate(error) => {
                write!(
                    formatter,
                    "native HTTP/1 rustls certificate resolver: {error}"
                )
            }
            #[cfg(feature = "tls-rustls-backend")]
            Self::RustlsServerConfig(error) => {
                write!(formatter, "native HTTP/1 rustls server config: {error}")
            }
            #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
            Self::OpenSslAcceptor(error) => {
                write!(formatter, "native HTTP/1 OpenSSL acceptor: {error}")
            }
            #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
            Self::OpenSslCertificateStore(error) => {
                write!(
                    formatter,
                    "native HTTP/1 OpenSSL certificate store: {error}"
                )
            }
            #[cfg(any(
                feature = "tls-rustls-backend",
                all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
            ))]
            Self::TlsPlan(error) => write!(formatter, "native HTTP/1 TLS listener plan: {error}"),
            Self::UnsupportedTlsAlpn { policy } => write!(
                formatter,
                "native HTTP/1 proxy HTTPS listener requires tls.alpn = \"http1\", got {policy:?}"
            ),
            Self::UnsupportedListener { protocol, addr } => write!(
                formatter,
                "native HTTP/1 proxy listener {addr} uses unsupported protocol {protocol:?}"
            ),
        }
    }
}

impl Error for NativeHttp1ProxyRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Bind { source, .. } => Some(source),
            Self::LaunchPlan(error) => Some(error),
            Self::Router(error) => Some(error),
            #[cfg(feature = "tls-rustls-backend")]
            Self::RustlsCertificate(error) => Some(error),
            #[cfg(feature = "tls-rustls-backend")]
            Self::RustlsServerConfig(error) => Some(error),
            #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
            Self::OpenSslAcceptor(error) => Some(error),
            #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
            Self::OpenSslCertificateStore(error) => Some(error),
            #[cfg(any(
                feature = "tls-rustls-backend",
                all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
            ))]
            Self::TlsPlan(error) => Some(error),
            Self::MissingProxyHttpListener
            | Self::UnsupportedTlsAlpn { .. }
            | Self::UnsupportedListener { .. } => None,
        }
    }
}
