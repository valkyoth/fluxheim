use std::path::Path;
use std::sync::Arc;

use fluxheim_common::{FluxError, FluxResult};
use fluxheim_config::config_net::upstream_host;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject};
use rustls::{
    CertificateError, ClientConfig as RustlsClientConfig, DigitallySignedStruct,
    Error as RustlsError, RootCertStore, SignatureScheme,
};
use sanitization::SecretVec;
use tokio_rustls::TlsConnector as RustlsTlsConnector;

use crate::config::StreamRouteConfig;
use crate::upstream_tls::read_upstream_tls_file;

pub(super) fn build_rustls_connector(route: &StreamRouteConfig) -> FluxResult<RustlsTlsConnector> {
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

fn rustls_client_cert_key(
    cert_path: &Path,
    key_path: &Path,
) -> FluxResult<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs = rustls_certificates_from_file(cert_path, "upstream client certificate")?;
    let key_contents = SecretVec::from_vec(
        read_upstream_tls_file(key_path)
            .map_err(|error| FluxError::io("read stream upstream TLS private key", error))?,
    );
    let key = key_contents
        .with_secret(PrivateKeyDer::from_pem_slice)
        .map_err(|error| {
            FluxError::invalid_input(format!(
                "failed to parse upstream client private key {}: {error}",
                key_path.display()
            ))
        })?;
    Ok((certs, key))
}

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

pub(super) fn stream_upstream_tls_server_name(
    configured: Option<&str>,
    upstream_authority: &str,
    socket_addr: std::net::SocketAddr,
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RustlsVerificationMode {
    Full,
    FullOrSkipAllForIp,
    SkipHostname,
    SkipAll,
}

#[derive(Debug)]
struct StreamRustlsVerifier {
    delegate: Arc<WebPkiServerVerifier>,
    mode: RustlsVerificationMode,
}

impl StreamRustlsVerifier {
    fn new(delegate: Arc<WebPkiServerVerifier>, mode: RustlsVerificationMode) -> Self {
        Self { delegate, mode }
    }
}

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

#[cfg(test)]
mod tests {
    use super::{RustlsVerificationMode, rustls_verification_mode};
    use crate::config::StreamRouteConfig;

    fn tls_ip_route() -> StreamRouteConfig {
        StreamRouteConfig {
            name: "stream".to_owned(),
            listen: vec!["127.0.0.1:8443".to_owned()],
            upstreams: vec!["127.0.0.1:9443".to_owned()],
            upstream_tls: true,
            ..StreamRouteConfig::default()
        }
    }

    #[test]
    fn rustls_without_explicit_sni_decides_ip_skip_per_connection() {
        let route = tls_ip_route();
        assert_eq!(
            rustls_verification_mode(&route),
            RustlsVerificationMode::FullOrSkipAllForIp
        );
    }

    #[test]
    fn rustls_explicit_sni_uses_full_verification() {
        let mut route = tls_ip_route();
        route.upstream_sni = Some("backend.example.test".to_owned());
        assert_eq!(
            rustls_verification_mode(&route),
            RustlsVerificationMode::Full
        );
    }

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
}
