use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use fluxheim_config::{TlsClientAuthMode, TlsConfig, TlsProtocolVersion};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use rustls::server::{ResolvesServerCert, VerifierBuilderError};
use rustls::{RootCertStore, SupportedProtocolVersion};
use thiserror::Error;

use crate::rustls_kx_group;
use crate::tls_input::{MAX_CA_BUNDLE_BYTES, MAX_CA_CERTIFICATES, read_bounded_file};
use crate::{TlsRuntimeError, rustls_alpn_protocols, rustls_cipher_suite, rustls_crypto_provider};

static TLS12_AND_13: [&SupportedProtocolVersion; 2] =
    [&rustls::version::TLS12, &rustls::version::TLS13];
static TLS13_ONLY: [&SupportedProtocolVersion; 1] = [&rustls::version::TLS13];

#[derive(Debug, Error)]
pub enum RustlsDownstreamServerConfigError {
    #[error(transparent)]
    TlsRuntime(#[from] TlsRuntimeError),
    #[error("rustls rejected downstream TLS protocol/cipher/group policy: {0}")]
    InvalidPolicy(#[source] rustls::Error),
    #[error("tls.client_auth.ca_path is required when client auth is enabled")]
    MissingClientAuthCa,
    #[error("failed to open TLS client-auth CA bundle {path}: {source}")]
    OpenClientAuthCa {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse TLS client-auth CA bundle {path}: {source}")]
    ParseClientAuthCa {
        path: PathBuf,
        #[source]
        source: rustls::pki_types::pem::Error,
    },
    #[error("failed to add certificate from TLS client-auth CA bundle {path}: {source}")]
    AddClientAuthCa {
        path: PathBuf,
        #[source]
        source: rustls::Error,
    },
    #[error("TLS client-auth CA bundle {path} does not contain any certificates")]
    EmptyClientAuthCa { path: PathBuf },
    #[error("TLS client-auth CA bundle {path} contains {count} certificates; maximum is {maximum}")]
    TooManyClientAuthCa {
        path: PathBuf,
        count: usize,
        maximum: usize,
    },
    #[error("failed to build TLS client certificate verifier from {path}: {source}")]
    BuildClientAuthVerifier {
        path: PathBuf,
        #[source]
        source: VerifierBuilderError,
    },
    #[error("rustls downstream listener configuration does not report FIPS mode")]
    FipsNotReported,
}

pub fn build_rustls_downstream_server_config(
    tls: &TlsConfig,
    cert_resolver: Arc<dyn ResolvesServerCert>,
    acme_tls_alpn_protocol: Option<&[u8]>,
) -> Result<rustls::ServerConfig, RustlsDownstreamServerConfigError> {
    let fips_required = tls.compliance_mode().required();
    let mut provider = rustls_crypto_provider();
    provider.cipher_suites = tls
        .effective_cipher_suites()
        .into_iter()
        .map(|cipher| rustls_cipher_suite(cipher, fips_required))
        .collect::<Result<Vec<_>, _>>()?;
    provider.kx_groups = tls
        .effective_curve_preferences()
        .into_iter()
        .map(|curve| rustls_kx_group(curve, fips_required))
        .collect::<Result<Vec<_>, _>>()?;

    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(protocol_versions(tls.effective_min_protocol()))
        .map_err(RustlsDownstreamServerConfigError::InvalidPolicy)?;
    let builder = if let Some(verifier) = rustls_client_cert_verifier(tls)? {
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let mut config = builder.with_cert_resolver(cert_resolver);
    config.alpn_protocols = rustls_alpn_protocols(tls, acme_tls_alpn_protocol);

    if fips_required && !config.fips() {
        return Err(RustlsDownstreamServerConfigError::FipsNotReported);
    }

    Ok(config)
}

fn protocol_versions(
    min_protocol: TlsProtocolVersion,
) -> &'static [&'static SupportedProtocolVersion] {
    match min_protocol {
        TlsProtocolVersion::Tls12 => &TLS12_AND_13,
        TlsProtocolVersion::Tls13 => &TLS13_ONLY,
    }
}

fn rustls_client_cert_verifier(
    tls: &TlsConfig,
) -> Result<
    Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
    RustlsDownstreamServerConfigError,
> {
    if tls.client_auth.mode == TlsClientAuthMode::Off {
        return Ok(None);
    }

    let ca_path = tls
        .client_auth
        .ca_path
        .as_deref()
        .ok_or(RustlsDownstreamServerConfigError::MissingClientAuthCa)?;
    let contents = read_bounded_file(ca_path, MAX_CA_BUNDLE_BYTES).map_err(|source| {
        RustlsDownstreamServerConfigError::OpenClientAuthCa {
            path: ca_path.to_path_buf(),
            source,
        }
    })?;
    let mut roots = RootCertStore::empty();
    let mut loaded = 0usize;
    for certificate in CertificateDer::pem_slice_iter(&contents) {
        let certificate =
            certificate.map_err(
                |source| RustlsDownstreamServerConfigError::ParseClientAuthCa {
                    path: ca_path.to_path_buf(),
                    source,
                },
            )?;
        if loaded >= MAX_CA_CERTIFICATES {
            return Err(RustlsDownstreamServerConfigError::TooManyClientAuthCa {
                path: ca_path.to_path_buf(),
                count: loaded + 1,
                maximum: MAX_CA_CERTIFICATES,
            });
        }
        roots.add(certificate).map_err(|source| {
            RustlsDownstreamServerConfigError::AddClientAuthCa {
                path: ca_path.to_path_buf(),
                source,
            }
        })?;
        loaded += 1;
    }
    if loaded == 0 {
        return Err(RustlsDownstreamServerConfigError::EmptyClientAuthCa {
            path: ca_path.to_path_buf(),
        });
    }

    let builder = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls_crypto_provider()),
    );
    let builder = match tls.client_auth.mode {
        TlsClientAuthMode::Off => return Ok(None),
        TlsClientAuthMode::Required => builder,
        TlsClientAuthMode::Optional => builder.allow_unauthenticated(),
    };
    builder.build().map(Some).map_err(|source| {
        RustlsDownstreamServerConfigError::BuildClientAuthVerifier {
            path: ca_path.to_path_buf(),
            source,
        }
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::path::PathBuf;

    use fluxheim_config::{
        Config, StaticCertificateConfig, TlsAlpnPolicy, TlsClientAuthConfig, TlsConfig,
    };

    use super::*;
    use crate::DownstreamCertificateSelector;
    use crate::RustlsDownstreamCertificateResolver;

    #[test]
    fn native_server_config_builds_with_sni_resolver_and_alpn()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let certificate = StaticCertificateConfig {
            cert_path: PathBuf::from("../../tests/fixtures/tls/localhost-cert.pem"),
            key_path: PathBuf::from("../../tests/fixtures/tls/localhost-key.pem"),
        };
        let config = Config {
            tls: TlsConfig {
                enabled: true,
                alpn: TlsAlpnPolicy::Http1AndHttp2,
                certificates: vec![certificate],
                ..TlsConfig::default()
            },
            ..Config::default()
        };
        let selector = DownstreamCertificateSelector::from_config(&config)
            .ok_or("expected downstream certificate selector")?;
        let resolver = Arc::new(RustlsDownstreamCertificateResolver::new(&selector)?);

        let server_config =
            build_rustls_downstream_server_config(&config.tls, resolver, Some(b"acme-tls/1"))?;

        assert_eq!(
            server_config.alpn_protocols,
            vec![b"acme-tls/1".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        Ok(())
    }

    #[test]
    fn client_auth_ca_certificate_count_is_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let ca_path = directory.path().join("ca.pem");
        let certificate = std::fs::read("../../tests/fixtures/tls/localhost-cert.pem").unwrap();
        let mut file = std::fs::File::create(&ca_path).unwrap();
        for _ in 0..=MAX_CA_CERTIFICATES {
            file.write_all(&certificate).unwrap();
        }
        let tls = TlsConfig {
            client_auth: TlsClientAuthConfig {
                mode: TlsClientAuthMode::Required,
                ca_path: Some(ca_path.clone()),
            },
            ..TlsConfig::default()
        };

        assert!(matches!(
            rustls_client_cert_verifier(&tls),
            Err(RustlsDownstreamServerConfigError::TooManyClientAuthCa { path, .. })
                if path == ca_path
        ));
    }
}
