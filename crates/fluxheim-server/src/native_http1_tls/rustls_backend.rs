use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore,
    SignatureScheme,
};
use sanitization::SecretVec;
use tokio_rustls::TlsConnector;

use super::file::{read_upstream_tls_file, read_upstream_tls_secret_file};
use crate::NativeHttp1Error;

pub(super) fn build_rustls_connector(
    proxy: &fluxheim_config::ProxyConfig,
) -> Result<TlsConnector, NativeHttp1Error> {
    ensure_rustls_provider_installed()?;
    let roots = Arc::new(root_store(proxy.upstream_ca_path.as_deref())?);
    let builder = ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS12,
        &rustls::version::TLS13,
    ])
    .with_root_certificates(Arc::clone(&roots));

    let mut config = match (
        proxy.upstream_client_cert_path.as_deref(),
        proxy.upstream_client_key_path.as_deref(),
    ) {
        (Some(cert_path), Some(key_path)) => {
            let (certs, key) = client_cert_key(cert_path, key_path)?;
            builder.with_client_auth_cert(certs, key).map_err(|error| {
                NativeHttp1Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("native HTTP/1 upstream TLS client certificate failed: {error}"),
                ))
            })?
        }
        _ => builder.with_no_client_auth(),
    };

    let mode = verification_mode(proxy);
    let alternative_name = proxy
        .upstream_alternative_cn
        .as_deref()
        .map(|name| {
            ServerName::try_from(name.to_owned()).map_err(|error| {
                NativeHttp1Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("native HTTP/1 upstream TLS alternative name is invalid: {error}"),
                ))
            })
        })
        .transpose()?;
    if mode != RustlsVerificationMode::Full || alternative_name.is_some() {
        let delegate = WebPkiServerVerifier::builder(roots)
            .build()
            .map_err(|error| {
                NativeHttp1Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("native HTTP/1 upstream TLS verifier setup failed: {error}"),
                ))
            })?;
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NativeRustlsVerifier {
                delegate,
                mode,
                alternative_name,
            }));
    }
    config.alpn_protocols = upstream_tls_alpn_protocols(proxy);

    Ok(TlsConnector::from(Arc::new(config)))
}

fn ensure_rustls_provider_installed() -> Result<(), NativeHttp1Error> {
    let provider = {
        #[cfg(feature = "tls-rustls-fips")]
        {
            rustls::crypto::default_fips_provider()
        }
        #[cfg(not(feature = "tls-rustls-fips"))]
        {
            rustls::crypto::ring::default_provider()
        }
    };
    match provider.install_default() {
        Ok(()) => Ok(()),
        Err(_) if rustls::crypto::CryptoProvider::get_default().is_some() => Ok(()),
        Err(_) => Err(NativeHttp1Error::Io(io::Error::other(
            "native HTTP/1 upstream TLS crypto provider is not installed",
        ))),
    }
}

fn root_store(ca_path: Option<&Path>) -> Result<RootCertStore, NativeHttp1Error> {
    let mut roots = RootCertStore::empty();
    if let Some(path) = ca_path {
        for cert in certificates_from_file(path, "upstream CA bundle")? {
            roots.add(cert).map_err(|error| {
                NativeHttp1Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "failed to add upstream CA bundle {}: {error}",
                        path.display()
                    ),
                ))
            })?;
        }
    } else {
        let native = rustls_native_certs::load_native_certs();
        if !native.errors.is_empty() {
            log::warn!(
                target: "fluxheim::native_http1",
                "one or more native trust roots could not be loaded for native HTTP/1 upstream TLS"
            );
        }
        for cert in native.certs {
            roots.add(cert).map_err(|error| {
                NativeHttp1Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to add native upstream TLS trust root: {error}"),
                ))
            })?;
        }
    }

    if roots.is_empty() {
        return Err(NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "native HTTP/1 upstream TLS trust store contains no certificates",
        )));
    }
    Ok(roots)
}

fn certificates_from_file(
    path: &Path,
    label: &str,
) -> Result<Vec<CertificateDer<'static>>, NativeHttp1Error> {
    let contents = read_upstream_tls_file(path)?;
    let certs = CertificateDer::pem_slice_iter(&contents)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| {
            NativeHttp1Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse {label} {}: {error}", path.display()),
            ))
        })?;
    if certs.is_empty() {
        return Err(NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} {} contains no certificates", path.display()),
        )));
    }
    Ok(certs)
}

fn client_cert_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), NativeHttp1Error> {
    let certs = certificates_from_file(cert_path, "upstream client certificate")?;
    let key_contents = SecretVec::from_vec(read_upstream_tls_secret_file(key_path)?);
    let key = key_contents
        .with_secret(PrivateKeyDer::from_pem_slice)
        .map_err(|error| {
            NativeHttp1Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse upstream client private key {}: {error}",
                    key_path.display()
                ),
            ))
        })?;
    Ok((certs, key))
}

fn upstream_tls_alpn_protocols(proxy: &fluxheim_config::ProxyConfig) -> Vec<Vec<u8>> {
    match proxy.upstream_http_version {
        fluxheim_config::UpstreamHttpVersion::Http2 => vec![b"h2".to_vec()],
        fluxheim_config::UpstreamHttpVersion::Http1AndHttp2 => {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        }
        fluxheim_config::UpstreamHttpVersion::Http1 => vec![b"http/1.1".to_vec()],
    }
}

fn verification_mode(proxy: &fluxheim_config::ProxyConfig) -> RustlsVerificationMode {
    if !proxy.upstream_verify_cert {
        RustlsVerificationMode::SkipAll
    } else if !proxy.upstream_verify_hostname {
        RustlsVerificationMode::SkipHostname
    } else {
        RustlsVerificationMode::Full
    }
}

pub(super) fn upstream_tls_server_name(
    configured: Option<&str>,
    upstream_authority: &str,
) -> Result<ServerName<'static>, NativeHttp1Error> {
    if let Some(configured) = configured {
        return ServerName::try_from(configured.to_owned()).map_err(|error| {
            NativeHttp1Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("native HTTP/1 upstream TLS SNI is invalid: {error}"),
            ))
        });
    }
    if let Some(host) = fluxheim_config::config_net::upstream_host(upstream_authority) {
        return ServerName::try_from(host).map_err(|error| {
            NativeHttp1Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("native HTTP/1 upstream TLS host is invalid: {error}"),
            ))
        });
    }
    Err(NativeHttp1Error::Io(io::Error::new(
        io::ErrorKind::InvalidInput,
        "native HTTP/1 upstream TLS requires a DNS SNI name",
    )))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RustlsVerificationMode {
    Full,
    SkipHostname,
    SkipAll,
}

#[derive(Debug)]
struct NativeRustlsVerifier {
    delegate: Arc<WebPkiServerVerifier>,
    mode: RustlsVerificationMode,
    alternative_name: Option<ServerName<'static>>,
}

impl ServerCertVerifier for NativeRustlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let verification_name = self.alternative_name.as_ref().unwrap_or(server_name);
        match self.mode {
            RustlsVerificationMode::Full => self.delegate.verify_server_cert(
                end_entity,
                intermediates,
                verification_name,
                ocsp_response,
                now,
            ),
            RustlsVerificationMode::SkipAll => Ok(ServerCertVerified::assertion()),
            RustlsVerificationMode::SkipHostname => {
                match self.delegate.verify_server_cert(
                    end_entity,
                    intermediates,
                    verification_name,
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
