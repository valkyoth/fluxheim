use std::fmt;
#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::StreamRouteConfig;
use crate::stream_proxy::FluxStream;
#[cfg(feature = "tls-openssl")]
use crate::stream_tls_openssl::{build_openssl_connector, stream_upstream_tls_sni};
#[cfg(feature = "tls-rustls-backend")]
use crate::stream_tls_rustls::{build_rustls_connector, stream_upstream_tls_server_name};
use fluxheim_common::{FluxError, FluxResult};
#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
use fluxheim_config::config_net::upstream_host;

#[cfg(feature = "tls-rustls-backend")]
use tokio_rustls::TlsConnector as RustlsTlsConnector;

#[cfg(feature = "tls-openssl")]
use openssl::ssl::{SslConnector, SslVerifyMode};
#[cfg(feature = "tls-openssl")]
use tokio_openssl::SslStream;

#[derive(Clone)]
pub(crate) struct StreamUpstreamTlsConnector {
    sni: Option<Arc<str>>,
    verify_cert: bool,
    verify_hostname: bool,
    alternative_cn: Option<Arc<str>>,
    #[cfg(feature = "tls-rustls-backend")]
    rustls: RustlsTlsConnector,
    #[cfg(feature = "tls-openssl")]
    openssl: Arc<SslConnector>,
}

impl StreamUpstreamTlsConnector {
    pub(crate) fn from_route(route: &StreamRouteConfig) -> FluxResult<Option<Self>> {
        if !route.upstream_tls {
            return Ok(None);
        }
        warn_if_ip_upstream_tls_verification_skips_hostname(route);

        Ok(Some(Self {
            sni: route.upstream_sni.as_deref().map(Arc::from),
            verify_cert: route.upstream_verify_cert,
            verify_hostname: route.upstream_verify_hostname,
            alternative_cn: route.upstream_alternative_cn.as_deref().map(Arc::from),
            #[cfg(feature = "tls-rustls-backend")]
            rustls: build_rustls_connector(route)?,
            #[cfg(feature = "tls-openssl")]
            openssl: Arc::new(build_openssl_connector(route)?),
        }))
    }

    pub(crate) async fn connect(
        &self,
        upstream_authority: &str,
        socket_addr: SocketAddr,
    ) -> FluxResult<FluxStream> {
        #[cfg(feature = "tls-rustls-backend")]
        {
            self.connect_rustls(upstream_authority, socket_addr).await
        }
        #[cfg(all(feature = "tls-openssl", not(feature = "tls-rustls-backend")))]
        {
            self.connect_openssl(upstream_authority, socket_addr).await
        }
    }

    #[cfg(feature = "tls-rustls-backend")]
    async fn connect_rustls(
        &self,
        upstream_authority: &str,
        socket_addr: SocketAddr,
    ) -> FluxResult<FluxStream> {
        let stream = tokio::net::TcpStream::connect(socket_addr)
            .await
            .map_err(|error| FluxError::io("connect stream TLS upstream", error))?;
        let server_name =
            stream_upstream_tls_server_name(self.sni.as_deref(), upstream_authority, socket_addr)?;
        let stream = self
            .rustls
            .connect(server_name, stream)
            .await
            .map_err(|error| {
                FluxError::invalid_input(format!("stream upstream TLS connect failed: {error}"))
            })?;
        Ok(Box::new(stream) as FluxStream)
    }

    #[cfg(feature = "tls-openssl")]
    async fn connect_openssl(
        &self,
        upstream_authority: &str,
        socket_addr: SocketAddr,
    ) -> FluxResult<FluxStream> {
        let stream = tokio::net::TcpStream::connect(socket_addr)
            .await
            .map_err(|error| FluxError::io("connect stream TLS upstream", error))?;
        let sni = stream_upstream_tls_sni(self.sni.as_deref(), upstream_authority);
        let mut config = self.openssl.configure().map_err(|error| {
            FluxError::invalid_input(format!("stream upstream TLS configure failed: {error}"))
        })?;

        if sni.is_empty() {
            config.set_use_server_name_indication(false);
            config.set_verify(SslVerifyMode::NONE);
        } else if self.verify_cert {
            if self.verify_hostname {
                // OpenSSL's set_host() replaces the previous hostname list; an
                // alternative CN is an explicit verification override, not an
                // additional host checked alongside SNI.
                let check_host = self.alternative_cn.as_deref().unwrap_or(&sni);
                config.param_mut().set_host(check_host).map_err(|error| {
                    FluxError::invalid_input(format!(
                        "stream upstream TLS hostname policy failed: {error}"
                    ))
                })?;
            }
            config.set_verify(SslVerifyMode::PEER);
        } else {
            config.set_verify(SslVerifyMode::NONE);
        }
        config.set_verify_hostname(false);

        let ssl = config.into_ssl(&sni).map_err(|error| {
            FluxError::invalid_input(format!("stream upstream TLS configure failed: {error}"))
        })?;
        let mut stream = SslStream::new(ssl, stream).map_err(|error| {
            FluxError::invalid_input(format!("stream upstream TLS stream setup failed: {error}"))
        })?;
        std::pin::Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|error| {
                FluxError::invalid_input(format!("stream upstream TLS connect failed: {error}"))
            })?;
        Ok(Box::new(stream) as FluxStream)
    }
}

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
fn warn_if_ip_upstream_tls_verification_skips_hostname(route: &StreamRouteConfig) {
    if !stream_route_tls_cert_verification_skips_for_ip_upstreams(route) {
        return;
    }
    log::warn!(
        target: "fluxheim::security",
        "stream route '{}' enables upstream TLS certificate verification for one or more IP upstreams without upstream_sni; hostname verification is skipped for those IP connections",
        route.name
    );
}

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
fn stream_route_tls_cert_verification_skips_for_ip_upstreams(route: &StreamRouteConfig) -> bool {
    if !route.upstream_tls || !route.upstream_verify_cert || route.upstream_sni.is_some() {
        return false;
    }

    route.upstreams().any(|upstream| {
        upstream_host(upstream)
            .map(|host| host.parse::<IpAddr>().is_ok())
            .unwrap_or(false)
    })
}

impl fmt::Debug for StreamUpstreamTlsConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamUpstreamTlsConnector")
            .field("sni", &self.sni)
            .field("verify_cert", &self.verify_cert)
            .field("verify_hostname", &self.verify_hostname)
            .field("alternative_cn", &self.alternative_cn)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
    use super::stream_route_tls_cert_verification_skips_for_ip_upstreams;
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
    use crate::config::StreamRouteConfig;

    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
    fn tls_ip_route() -> StreamRouteConfig {
        StreamRouteConfig {
            name: "stream".to_owned(),
            listen: vec!["127.0.0.1:8443".to_owned()],
            upstreams: vec!["127.0.0.1:9443".to_owned()],
            upstream_tls: true,
            ..StreamRouteConfig::default()
        }
    }

    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
    #[test]
    fn ip_only_verified_stream_tls_without_sni_is_warnable() {
        let mut route = tls_ip_route();
        assert!(stream_route_tls_cert_verification_skips_for_ip_upstreams(
            &route
        ));

        route.upstream_sni = Some("backend.example.test".to_owned());
        assert!(!stream_route_tls_cert_verification_skips_for_ip_upstreams(
            &route
        ));

        route.upstream_sni = None;
        route.upstream = Some("backend.example.test:9443".to_owned());
        route.upstreams.clear();
        assert!(!stream_route_tls_cert_verification_skips_for_ip_upstreams(
            &route
        ));

        route.upstream = None;
        route.upstreams = vec![
            "192.168.1.100:9443".to_owned(),
            "backend.example.test:9443".to_owned(),
        ];
        assert!(stream_route_tls_cert_verification_skips_for_ip_upstreams(
            &route
        ));
    }
}
