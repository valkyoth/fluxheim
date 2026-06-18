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
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use crate::native_http1_client::NativeHttp1Stream;
use crate::{NativeHttp1Error, NativeHttp1ProxyConfigError};

#[derive(Clone)]
pub struct NativeHttp1UpstreamTls {
    sni: Option<Arc<str>>,
    verify_cert: bool,
    verify_hostname: bool,
    alternative_cn: Option<Arc<str>>,
    connector: TlsConnector,
}

impl NativeHttp1UpstreamTls {
    pub fn from_proxy_config(
        proxy: &fluxheim_config::ProxyConfig,
    ) -> Result<Option<Self>, NativeHttp1ProxyConfigError> {
        if !proxy.upstream_tls {
            return Ok(None);
        }
        if proxy.upstream_verify_cert
            && proxy.upstream_sni.is_none()
            && configured_upstreams_contain_ip_literal(proxy)
        {
            return Err(NativeHttp1ProxyConfigError::UpstreamTlsPolicy);
        }

        let connector =
            build_connector(proxy).map_err(|_| NativeHttp1ProxyConfigError::UpstreamTlsPolicy)?;
        Ok(Some(Self {
            sni: proxy.upstream_sni.as_deref().map(Arc::from),
            verify_cert: proxy.upstream_verify_cert,
            verify_hostname: proxy.upstream_verify_hostname,
            alternative_cn: proxy.upstream_alternative_cn.as_deref().map(Arc::from),
            connector,
        }))
    }

    pub(crate) async fn connect(
        &self,
        stream: TcpStream,
        upstream_authority: &str,
    ) -> Result<NativeHttp1Stream, NativeHttp1Error> {
        let server_name = upstream_tls_server_name(self.sni.as_deref(), upstream_authority)?;
        let stream = self
            .connector
            .connect(server_name, stream)
            .await
            .map_err(|error| {
                NativeHttp1Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("native HTTP/1 upstream TLS handshake failed: {error}"),
                ))
            })?;
        Ok(Box::new(stream) as NativeHttp1Stream)
    }
}

fn configured_upstreams_contain_ip_literal(proxy: &fluxheim_config::ProxyConfig) -> bool {
    if !proxy.upstreams.is_empty() {
        return proxy
            .upstreams
            .iter()
            .filter_map(|upstream| fluxheim_config::config_net::upstream_host(upstream))
            .any(|host| host.parse::<std::net::IpAddr>().is_ok());
    }
    proxy
        .configured_primary_upstream()
        .and_then(fluxheim_config::config_net::upstream_host)
        .is_some_and(|host| host.parse::<std::net::IpAddr>().is_ok())
}

impl std::fmt::Debug for NativeHttp1UpstreamTls {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeHttp1UpstreamTls")
            .field("sni", &self.sni)
            .field("verify_cert", &self.verify_cert)
            .field("verify_hostname", &self.verify_hostname)
            .field("alternative_cn", &self.alternative_cn)
            .finish_non_exhaustive()
    }
}

impl PartialEq for NativeHttp1UpstreamTls {
    fn eq(&self, other: &Self) -> bool {
        self.sni == other.sni
            && self.verify_cert == other.verify_cert
            && self.verify_hostname == other.verify_hostname
            && self.alternative_cn == other.alternative_cn
    }
}

impl Eq for NativeHttp1UpstreamTls {}

fn build_connector(proxy: &fluxheim_config::ProxyConfig) -> Result<TlsConnector, NativeHttp1Error> {
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

    Ok(TlsConnector::from(Arc::new(config)))
}

fn ensure_rustls_provider_installed() -> Result<(), NativeHttp1Error> {
    let provider = {
        #[cfg(feature = "tls-rustls-fips")]
        {
            rustls::crypto::aws_lc_rs::default_fips_provider()
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
        for error in native.errors {
            log::warn!(
                target: "fluxheim::native_http1",
                "failed to load one native trust root for native HTTP/1 upstream TLS: {error}"
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
    let key_contents = Zeroizing::new(read_upstream_tls_file(key_path)?);
    let key = PrivateKeyDer::from_pem_slice(&key_contents).map_err(|error| {
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

fn verification_mode(proxy: &fluxheim_config::ProxyConfig) -> RustlsVerificationMode {
    if !proxy.upstream_verify_cert {
        RustlsVerificationMode::SkipAll
    } else if !proxy.upstream_verify_hostname {
        RustlsVerificationMode::SkipHostname
    } else {
        RustlsVerificationMode::Full
    }
}

fn upstream_tls_server_name(
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

const MAX_UPSTREAM_TLS_FILE_BYTES: u64 = 1024 * 1024;

#[cfg(target_os = "linux")]
const UPSTREAM_TLS_O_NOFOLLOW: i32 = 0o400000;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const UPSTREAM_TLS_O_NOFOLLOW: i32 = 0x0100;

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!(
    "O_NOFOLLOW is unknown on this Unix platform; audit native upstream TLS file opening before building Fluxheim"
);

fn read_upstream_tls_file(path: &Path) -> Result<Vec<u8>, NativeHttp1Error> {
    let metadata = std::fs::symlink_metadata(path).map_err(NativeHttp1Error::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "upstream TLS path is not a regular file: {}",
                path.display()
            ),
        )));
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(UPSTREAM_TLS_O_NOFOLLOW);
    }

    let file = options.open(path).map_err(NativeHttp1Error::Io)?;
    let metadata = file.metadata().map_err(NativeHttp1Error::Io)?;
    if !metadata.is_file() {
        return Err(NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "upstream TLS path is not a regular file: {}",
                path.display()
            ),
        )));
    }
    if metadata.len() > MAX_UPSTREAM_TLS_FILE_BYTES {
        return Err(NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream TLS file {} exceeds {} bytes",
                path.display(),
                MAX_UPSTREAM_TLS_FILE_BYTES
            ),
        )));
    }

    let mut contents = Vec::new();
    let mut limited = std::io::Read::take(file, MAX_UPSTREAM_TLS_FILE_BYTES.saturating_add(1));
    std::io::Read::read_to_end(&mut limited, &mut contents).map_err(NativeHttp1Error::Io)?;
    if contents.len() as u64 > MAX_UPSTREAM_TLS_FILE_BYTES {
        return Err(NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream TLS file {} exceeds {} bytes",
                path.display(),
                MAX_UPSTREAM_TLS_FILE_BYTES
            ),
        )));
    }
    Ok(contents)
}
