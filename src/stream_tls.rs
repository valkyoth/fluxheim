use std::fmt;
#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
use std::net::IpAddr;
use std::net::SocketAddr;
#[cfg(feature = "tls-rustls-backend")]
use std::path::Path;
use std::sync::Arc;

use crate::config::StreamRouteConfig;
#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
use crate::config_net::upstream_host;
use crate::flux_error::{FluxError, FluxResult};
use crate::stream_proxy::FluxStream;
use crate::upstream_tls::read_upstream_tls_file;

#[cfg(feature = "tls-rustls-backend")]
use rustls::client::WebPkiServerVerifier;
#[cfg(feature = "tls-rustls-backend")]
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
#[cfg(feature = "tls-rustls-backend")]
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject};
#[cfg(feature = "tls-rustls-backend")]
use rustls::{
    CertificateError, ClientConfig as RustlsClientConfig, DigitallySignedStruct,
    Error as RustlsError, RootCertStore, SignatureScheme,
};
#[cfg(feature = "tls-rustls-backend")]
use tokio_rustls::TlsConnector as RustlsTlsConnector;

#[cfg(feature = "tls-openssl")]
use openssl::pkey::PKey;
#[cfg(feature = "tls-openssl")]
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
#[cfg(feature = "tls-openssl")]
use openssl::x509::{X509, store::X509StoreBuilder};
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
        "stream route '{}' enables upstream TLS certificate verification for IP-only upstreams without upstream_sni; hostname verification is skipped for those connections",
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

#[cfg(feature = "tls-rustls-backend")]
fn build_rustls_connector(route: &StreamRouteConfig) -> FluxResult<RustlsTlsConnector> {
    let roots = Arc::new(rustls_root_store(route.upstream_ca_path.as_deref())?);
    let builder = RustlsClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS12,
        &rustls::version::TLS13,
    ])
    .with_root_certificates(Arc::clone(&roots));

    let mut config = match (
        route.upstream_client_cert_path.as_deref(),
        route.upstream_client_key_path.as_deref(),
    ) {
        (Some(cert_path), Some(key_path)) => {
            let (certs, key) = rustls_client_cert_key(cert_path, key_path)?;
            builder.with_client_auth_cert(certs, key).map_err(|error| {
                FluxError::invalid_input(format!(
                    "stream upstream TLS client certificate policy failed: {error}"
                ))
            })?
        }
        _ => builder.with_no_client_auth(),
    };

    let mode = rustls_verification_mode(route);
    if mode != RustlsVerificationMode::Full {
        let delegate = WebPkiServerVerifier::builder(roots)
            .build()
            .map_err(|error| {
                FluxError::invalid_input(format!(
                    "stream upstream TLS verifier setup failed: {error}"
                ))
            })?;
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(StreamRustlsVerifier::new(delegate, mode)));
    }

    Ok(RustlsTlsConnector::from(Arc::new(config)))
}

#[cfg(feature = "tls-rustls-backend")]
fn rustls_root_store(ca_path: Option<&Path>) -> FluxResult<RootCertStore> {
    let mut roots = RootCertStore::empty();
    if let Some(path) = ca_path {
        for cert in rustls_certificates_from_file(path, "upstream CA bundle")? {
            roots.add(cert).map_err(|error| {
                FluxError::invalid_input(format!(
                    "failed to add upstream CA bundle {}: {error}",
                    path.display()
                ))
            })?;
        }
    } else {
        let native = rustls_native_certs::load_native_certs();
        for error in native.errors {
            log::warn!(
                target: "fluxheim::stream",
                "failed to load one native trust root for stream upstream TLS: {error}"
            );
        }
        for cert in native.certs {
            roots.add(cert).map_err(|error| {
                FluxError::invalid_input(format!(
                    "failed to add native stream upstream TLS trust root: {error}"
                ))
            })?;
        }
    }

    if roots.is_empty() {
        return Err(FluxError::InvalidInput(
            "stream upstream TLS trust store contains no certificates",
        ));
    }
    Ok(roots)
}

#[cfg(feature = "tls-rustls-backend")]
fn rustls_certificates_from_file(
    path: &Path,
    label: &str,
) -> FluxResult<Vec<CertificateDer<'static>>> {
    let contents = read_upstream_tls_file(path)
        .map_err(|error| FluxError::io("read stream upstream TLS file", error))?;
    let certs = CertificateDer::pem_slice_iter(&contents)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| {
            FluxError::invalid_input(format!(
                "failed to parse {label} {}: {error}",
                path.display()
            ))
        })?;
    if certs.is_empty() {
        return Err(FluxError::invalid_input(format!(
            "{label} {} contains no certificates",
            path.display()
        )));
    }
    Ok(certs)
}

#[cfg(feature = "tls-rustls-backend")]
fn rustls_client_cert_key(
    cert_path: &Path,
    key_path: &Path,
) -> FluxResult<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs = rustls_certificates_from_file(cert_path, "upstream client certificate")?;
    let key_contents = zeroize::Zeroizing::new(
        read_upstream_tls_file(key_path)
            .map_err(|error| FluxError::io("read stream upstream TLS private key", error))?,
    );
    let key = PrivateKeyDer::from_pem_slice(&key_contents).map_err(|error| {
        FluxError::invalid_input(format!(
            "failed to parse upstream client private key {}: {error}",
            key_path.display()
        ))
    })?;
    Ok((certs, key))
}

#[cfg(feature = "tls-rustls-backend")]
fn rustls_verification_mode(route: &StreamRouteConfig) -> RustlsVerificationMode {
    if !route.upstream_verify_cert {
        RustlsVerificationMode::SkipAll
    } else if !route.upstream_verify_hostname {
        RustlsVerificationMode::SkipHostname
    } else if route.upstream_sni.is_none() {
        RustlsVerificationMode::FullOrSkipAllForIp
    } else {
        RustlsVerificationMode::Full
    }
}

#[cfg(feature = "tls-rustls-backend")]
fn stream_upstream_tls_server_name(
    configured: Option<&str>,
    upstream_authority: &str,
    socket_addr: SocketAddr,
) -> FluxResult<ServerName<'static>> {
    if let Some(configured) = configured {
        return ServerName::try_from(configured.to_owned()).map_err(|error| {
            FluxError::invalid_input(format!("stream upstream TLS SNI is invalid: {error}"))
        });
    }
    if let Some(host) = upstream_host(upstream_authority) {
        return ServerName::try_from(host).map_err(|error| {
            FluxError::invalid_input(format!("stream upstream TLS host is invalid: {error}"))
        });
    }
    Ok(ServerName::IpAddress(socket_addr.ip().into()))
}

#[cfg(feature = "tls-rustls-backend")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RustlsVerificationMode {
    Full,
    FullOrSkipAllForIp,
    SkipHostname,
    SkipAll,
}

#[cfg(feature = "tls-rustls-backend")]
#[derive(Debug)]
struct StreamRustlsVerifier {
    delegate: Arc<WebPkiServerVerifier>,
    mode: RustlsVerificationMode,
}

#[cfg(feature = "tls-rustls-backend")]
impl StreamRustlsVerifier {
    fn new(delegate: Arc<WebPkiServerVerifier>, mode: RustlsVerificationMode) -> Self {
        Self { delegate, mode }
    }
}

#[cfg(feature = "tls-rustls-backend")]
impl ServerCertVerifier for StreamRustlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        match self.mode {
            RustlsVerificationMode::Full => self.delegate.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ),
            RustlsVerificationMode::FullOrSkipAllForIp
                if matches!(server_name, ServerName::IpAddress(_)) =>
            {
                Ok(ServerCertVerified::assertion())
            }
            RustlsVerificationMode::FullOrSkipAllForIp => self.delegate.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ),
            RustlsVerificationMode::SkipAll => Ok(ServerCertVerified::assertion()),
            RustlsVerificationMode::SkipHostname => {
                match self.delegate.verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                ) {
                    Ok(verified) => Ok(verified),
                    Err(RustlsError::InvalidCertificate(
                        CertificateError::NotValidForName
                        | CertificateError::NotValidForNameContext { .. },
                    )) => Ok(ServerCertVerified::assertion()),
                    Err(error) => Err(error),
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.delegate.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.delegate.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.delegate.supported_verify_schemes()
    }
}

#[cfg(feature = "tls-openssl")]
fn build_openssl_connector(route: &StreamRouteConfig) -> FluxResult<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|error| {
        FluxError::invalid_input(format!(
            "stream upstream TLS connector setup failed: {error}"
        ))
    })?;
    if let Some(ca_path) = route.upstream_ca_path.as_deref() {
        let contents = read_upstream_tls_file(ca_path)
            .map_err(|error| FluxError::io("read stream upstream TLS CA bundle", error))?;
        let certs = X509::stack_from_pem(&contents).map_err(|error| {
            FluxError::invalid_input(format!(
                "failed to parse upstream CA bundle {}: {error}",
                ca_path.display()
            ))
        })?;
        if certs.is_empty() {
            return Err(FluxError::invalid_input(format!(
                "upstream CA bundle {} contains no certificates",
                ca_path.display()
            )));
        }
        let mut store = X509StoreBuilder::new().map_err(|error| {
            FluxError::invalid_input(format!(
                "stream upstream TLS trust store setup failed: {error}"
            ))
        })?;
        for cert in certs {
            store.add_cert(cert).map_err(|error| {
                FluxError::invalid_input(format!(
                    "failed to add upstream CA bundle {}: {error}",
                    ca_path.display()
                ))
            })?;
        }
        builder.set_cert_store(store.build());
    } else {
        builder.set_default_verify_paths().map_err(|error| {
            FluxError::invalid_input(format!(
                "failed to load default stream upstream TLS trust roots: {error}"
            ))
        })?;
    }

    if let (Some(cert_path), Some(key_path)) = (
        route.upstream_client_cert_path.as_deref(),
        route.upstream_client_key_path.as_deref(),
    ) {
        let cert_contents = read_upstream_tls_file(cert_path)
            .map_err(|error| FluxError::io("read stream upstream TLS client certificate", error))?;
        let key_contents = zeroize::Zeroizing::new(
            read_upstream_tls_file(key_path)
                .map_err(|error| FluxError::io("read stream upstream TLS private key", error))?,
        );
        let certs = X509::stack_from_pem(&cert_contents).map_err(|error| {
            FluxError::invalid_input(format!(
                "failed to parse upstream client certificate {}: {error}",
                cert_path.display()
            ))
        })?;
        let Some((leaf, intermediates)) = certs.split_first() else {
            return Err(FluxError::invalid_input(format!(
                "upstream client certificate {} contains no certificates",
                cert_path.display()
            )));
        };
        let key = PKey::private_key_from_pem(&key_contents).map_err(|error| {
            FluxError::invalid_input(format!(
                "failed to parse upstream client private key {}: {error}",
                key_path.display()
            ))
        })?;
        builder.set_certificate(leaf).map_err(|error| {
            FluxError::invalid_input(format!(
                "failed to configure upstream client certificate {}: {error}",
                cert_path.display()
            ))
        })?;
        for cert in intermediates {
            builder
                .add_extra_chain_cert(cert.clone())
                .map_err(|error| {
                    FluxError::invalid_input(format!(
                        "failed to configure upstream client certificate chain {}: {error}",
                        cert_path.display()
                    ))
                })?;
        }
        builder.set_private_key(&key).map_err(|error| {
            FluxError::invalid_input(format!(
                "failed to configure upstream client private key {}: {error}",
                key_path.display()
            ))
        })?;
    }

    Ok(builder.build())
}

#[cfg(feature = "tls-openssl")]
fn stream_upstream_tls_sni(configured: Option<&str>, upstream_authority: &str) -> String {
    configured
        .map(str::to_owned)
        .or_else(|| {
            let host = upstream_host(upstream_authority)?;
            host.parse::<IpAddr>().is_err().then_some(host)
        })
        .unwrap_or_default()
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
    #[cfg(feature = "tls-openssl")]
    use super::stream_upstream_tls_sni;
    #[cfg(feature = "tls-rustls-backend")]
    use super::{RustlsVerificationMode, rustls_verification_mode};
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

    #[cfg(feature = "tls-rustls-backend")]
    #[test]
    fn rustls_without_explicit_sni_decides_ip_skip_per_connection() {
        let route = tls_ip_route();
        assert_eq!(
            rustls_verification_mode(&route),
            RustlsVerificationMode::FullOrSkipAllForIp
        );
    }

    #[cfg(feature = "tls-rustls-backend")]
    #[test]
    fn rustls_explicit_sni_uses_full_verification() {
        let mut route = tls_ip_route();
        route.upstream_sni = Some("backend.example.test".to_owned());
        assert_eq!(
            rustls_verification_mode(&route),
            RustlsVerificationMode::Full
        );
    }

    #[cfg(feature = "tls-rustls-backend")]
    #[test]
    fn rustls_verification_flags_override_sni_policy() {
        let mut route = tls_ip_route();
        route.upstream_sni = Some("backend.example.test".to_owned());
        route.upstream_verify_hostname = false;
        assert_eq!(
            rustls_verification_mode(&route),
            RustlsVerificationMode::SkipHostname
        );

        route.upstream_verify_cert = false;
        assert_eq!(
            rustls_verification_mode(&route),
            RustlsVerificationMode::SkipAll
        );
    }

    #[cfg(feature = "tls-openssl")]
    #[test]
    fn openssl_sni_derives_only_dns_hosts() {
        assert_eq!(
            stream_upstream_tls_sni(None, "backend.example.test:443"),
            "backend.example.test"
        );
        assert_eq!(stream_upstream_tls_sni(None, "127.0.0.1:443"), "");
        assert_eq!(
            stream_upstream_tls_sni(Some("configured.example.test"), "127.0.0.1:443"),
            "configured.example.test"
        );
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
