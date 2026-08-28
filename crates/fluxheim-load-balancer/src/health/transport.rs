#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
use std::io;
#[cfg(feature = "tls-rustls-backend")]
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use fluxheim_common::{FluxError, FluxResult};
use fluxheim_config::ProxyConfig;

use crate::backend::{FluxHealthCheck, RuntimeBackend as Backend};

pub(super) trait HealthIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> HealthIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(super) type BoxedHealthIo = Box<dyn HealthIo>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HealthTlsAlpn {
    None,
    Http1,
    Http2,
}

pub(super) struct FluxTcpHealthCheck {
    pub(super) consecutive_success: usize,
    pub(super) consecutive_failure: usize,
    pub(super) connect_timeout: Duration,
    pub(super) tls: Option<FluxTcpHealthCheckTls>,
}

#[cfg(feature = "tls-rustls-backend")]
pub(super) struct FluxTcpHealthCheckTls {
    server_name: rustls::pki_types::ServerName<'static>,
    config: Arc<rustls::ClientConfig>,
}

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
pub(super) struct FluxTcpHealthCheckTls {
    domain: String,
    connector: openssl::ssl::SslConnector,
}

#[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
pub(super) struct FluxTcpHealthCheckTls;

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

pub(super) fn configured_tcp_health_check_tls(
    config: &ProxyConfig,
    alpn: HealthTlsAlpn,
) -> FluxResult<Option<FluxTcpHealthCheckTls>> {
    if !config.upstream_tls {
        return Ok(None);
    }
    configured_tcp_health_check_tls_inner(config, alpn).map(Some)
}

#[cfg(feature = "tls-rustls-backend")]
pub(super) fn configured_tcp_health_check_tls_inner(
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
            "one or more native trust roots could not be loaded for TCP health-check TLS"
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
pub(super) fn configured_tcp_health_check_tls_inner(
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
pub(super) fn configured_tcp_health_check_tls_inner(
    _config: &ProxyConfig,
    _alpn: HealthTlsAlpn,
) -> FluxResult<FluxTcpHealthCheckTls> {
    Err(FluxError::InvalidInput(
        "TLS TCP health checks require a TLS backend feature",
    ))
}

pub(super) async fn connect_health_stream(
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
