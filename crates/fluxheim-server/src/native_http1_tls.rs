use std::io;
use std::path::Path;
use std::sync::Arc;

#[cfg(feature = "tls-rustls-backend")]
use rustls::client::WebPkiServerVerifier;
#[cfg(feature = "tls-rustls-backend")]
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
#[cfg(feature = "tls-rustls-backend")]
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject};
#[cfg(feature = "tls-rustls-backend")]
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore,
    SignatureScheme,
};
use tokio::net::TcpStream;
#[cfg(feature = "tls-rustls-backend")]
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
use openssl::pkey::PKey;
#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
use openssl::x509::{X509, store::X509StoreBuilder};
#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
use tokio_openssl::SslStream;

use crate::native_http1_client::{NativeHttp1Stream, NativeNegotiatedHttpProtocol};
use crate::{NativeHttp1Error, NativeHttp1ProxyConfigError};

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
const OPENSSL_UPSTREAM_TLS12_CIPHERS: &str = concat!(
    "ECDHE-ECDSA-AES256-GCM-SHA384:",
    "ECDHE-RSA-AES256-GCM-SHA384:",
    "ECDHE-ECDSA-CHACHA20-POLY1305:",
    "ECDHE-RSA-CHACHA20-POLY1305:",
    "ECDHE-ECDSA-AES128-GCM-SHA256:",
    "ECDHE-RSA-AES128-GCM-SHA256",
);

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
const OPENSSL_UPSTREAM_TLS13_CIPHERS: &str =
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";

#[derive(Clone)]
pub struct NativeHttp1UpstreamTls {
    sni: Option<Arc<str>>,
    verify_cert: bool,
    verify_hostname: bool,
    alternative_cn: Option<Arc<str>>,
    #[cfg(feature = "tls-rustls-backend")]
    rustls: TlsConnector,
    #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
    openssl: Arc<SslConnector>,
}

impl NativeHttp1UpstreamTls {
    pub fn from_proxy_config(
        proxy: &fluxheim_config::ProxyConfig,
    ) -> Result<Option<Self>, NativeHttp1ProxyConfigError> {
        if !proxy.upstream_tls {
            return Ok(None);
        }
        if !proxy.upstream_verify_cert && proxy.upstream_verify_hostname {
            return Err(NativeHttp1ProxyConfigError::UpstreamTlsPolicy);
        }
        if !proxy.upstream_verify_cert && proxy.upstream_ca_path.is_some() {
            return Err(NativeHttp1ProxyConfigError::UpstreamTlsPolicy);
        }
        match (
            &proxy.upstream_client_cert_path,
            &proxy.upstream_client_key_path,
        ) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => return Err(NativeHttp1ProxyConfigError::UpstreamTlsPolicy),
        }
        if proxy.upstream_verify_cert
            && proxy.upstream_sni.is_none()
            && configured_upstreams_contain_ip_literal(proxy)
        {
            return Err(NativeHttp1ProxyConfigError::UpstreamTlsPolicy);
        }

        Ok(Some(Self {
            sni: proxy.upstream_sni.as_deref().map(Arc::from),
            verify_cert: proxy.upstream_verify_cert,
            verify_hostname: proxy.upstream_verify_hostname,
            alternative_cn: proxy.upstream_alternative_cn.as_deref().map(Arc::from),
            #[cfg(feature = "tls-rustls-backend")]
            rustls: build_rustls_connector(proxy)
                .map_err(|_| NativeHttp1ProxyConfigError::UpstreamTlsPolicy)?,
            #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
            openssl: Arc::new(
                build_openssl_connector(proxy)
                    .map_err(|_| NativeHttp1ProxyConfigError::UpstreamTlsPolicy)?,
            ),
        }))
    }

    pub(crate) async fn connect(
        &self,
        stream: TcpStream,
        upstream_authority: &str,
    ) -> Result<NativeHttp1Stream, NativeHttp1Error> {
        self.connect_with_negotiated_protocol(stream, upstream_authority)
            .await
            .map(|(stream, _protocol)| stream)
    }

    pub(crate) async fn connect_with_negotiated_protocol(
        &self,
        stream: TcpStream,
        upstream_authority: &str,
    ) -> Result<(NativeHttp1Stream, NativeNegotiatedHttpProtocol), NativeHttp1Error> {
        #[cfg(feature = "tls-rustls-backend")]
        {
            return self.connect_rustls(stream, upstream_authority).await;
        }
        #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
        {
            self.connect_openssl(stream, upstream_authority).await
        }
    }

    #[cfg(feature = "tls-rustls-backend")]
    async fn connect_rustls(
        &self,
        stream: TcpStream,
        upstream_authority: &str,
    ) -> Result<(NativeHttp1Stream, NativeNegotiatedHttpProtocol), NativeHttp1Error> {
        let server_name = upstream_tls_server_name(self.sni.as_deref(), upstream_authority)?;
        let stream = self
            .rustls
            .connect(server_name, stream)
            .await
            .map_err(|error| {
                NativeHttp1Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("native HTTP/1 upstream TLS handshake failed: {error}"),
                ))
            })?;
        let protocol = match stream.get_ref().1.alpn_protocol() {
            Some(b"h2") => NativeNegotiatedHttpProtocol::Http2,
            _ => NativeNegotiatedHttpProtocol::Http1,
        };
        Ok((Box::new(stream) as NativeHttp1Stream, protocol))
    }

    #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
    async fn connect_openssl(
        &self,
        stream: TcpStream,
        upstream_authority: &str,
    ) -> Result<(NativeHttp1Stream, NativeNegotiatedHttpProtocol), NativeHttp1Error> {
        let sni = upstream_tls_openssl_sni(self.sni.as_deref(), upstream_authority);
        let mut config = self.openssl.configure().map_err(|error| {
            NativeHttp1Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("native HTTP/1 upstream TLS configure failed: {error}"),
            ))
        })?;

        if sni.is_empty() {
            config.set_use_server_name_indication(false);
            config.set_verify(SslVerifyMode::NONE);
        } else if self.verify_cert {
            if self.verify_hostname {
                let check_host = self.alternative_cn.as_deref().unwrap_or(&sni);
                config.param_mut().set_host(check_host).map_err(|error| {
                    NativeHttp1Error::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("native HTTP/1 upstream TLS hostname policy failed: {error}"),
                    ))
                })?;
            }
            config.set_verify(SslVerifyMode::PEER);
        } else {
            config.set_verify(SslVerifyMode::NONE);
        }
        config.set_verify_hostname(false);

        let ssl = config.into_ssl(&sni).map_err(|error| {
            NativeHttp1Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("native HTTP/1 upstream TLS configure failed: {error}"),
            ))
        })?;
        let mut stream = SslStream::new(ssl, stream).map_err(|error| {
            NativeHttp1Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("native HTTP/1 upstream TLS stream setup failed: {error}"),
            ))
        })?;
        std::pin::Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|error| {
                NativeHttp1Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("native HTTP/1 upstream TLS handshake failed: {error}"),
                ))
            })?;
        let protocol = match stream.ssl().selected_alpn_protocol() {
            Some(b"h2") => NativeNegotiatedHttpProtocol::Http2,
            _ => NativeNegotiatedHttpProtocol::Http1,
        };
        Ok((Box::new(stream) as NativeHttp1Stream, protocol))
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

#[cfg(feature = "tls-rustls-backend")]
fn build_rustls_connector(
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

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
fn build_openssl_connector(
    proxy: &fluxheim_config::ProxyConfig,
) -> Result<SslConnector, NativeHttp1Error> {
    let mut builder = SslConnector::builder(SslMethod::tls_client()).map_err(|error| {
        NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("native HTTP/1 upstream TLS connector setup failed: {error}"),
        ))
    })?;
    configure_openssl_tls_baseline(&mut builder)?;
    if let Some(ca_path) = proxy.upstream_ca_path.as_deref() {
        let certs = X509::stack_from_pem(&read_upstream_tls_file(ca_path)?).map_err(|error| {
            NativeHttp1Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse upstream CA bundle {}: {error}",
                    ca_path.display()
                ),
            ))
        })?;
        if certs.is_empty() {
            return Err(NativeHttp1Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "upstream CA bundle {} contains no certificates",
                    ca_path.display()
                ),
            )));
        }
        let mut store = X509StoreBuilder::new().map_err(|error| {
            NativeHttp1Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("native HTTP/1 upstream TLS trust store setup failed: {error}"),
            ))
        })?;
        for cert in certs {
            store.add_cert(cert).map_err(|error| {
                NativeHttp1Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "failed to add upstream CA bundle {}: {error}",
                        ca_path.display()
                    ),
                ))
            })?;
        }
        builder.set_cert_store(store.build());
    } else {
        builder.set_default_verify_paths().map_err(|error| {
            NativeHttp1Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to load native upstream TLS trust roots: {error}"),
            ))
        })?;
    }

    if let (Some(cert_path), Some(key_path)) = (
        proxy.upstream_client_cert_path.as_deref(),
        proxy.upstream_client_key_path.as_deref(),
    ) {
        configure_openssl_client_cert(&mut builder, cert_path, key_path)?;
    }
    builder
        .set_alpn_protos(&upstream_tls_alpn_protocol_wire(proxy))
        .map_err(|error| {
            NativeHttp1Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to configure upstream TLS ALPN protocols: {error}"),
            ))
        })?;

    Ok(builder.build())
}

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
fn configure_openssl_tls_baseline(
    builder: &mut openssl::ssl::SslConnectorBuilder,
) -> Result<(), NativeHttp1Error> {
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|error| {
            NativeHttp1Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to set minimum upstream TLS version: {error}"),
            ))
        })?;
    builder
        .set_cipher_list(OPENSSL_UPSTREAM_TLS12_CIPHERS)
        .map_err(|error| {
            NativeHttp1Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to configure upstream TLS cipher list: {error}"),
            ))
        })?;
    builder
        .set_ciphersuites(OPENSSL_UPSTREAM_TLS13_CIPHERS)
        .map_err(|error| {
            NativeHttp1Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to configure upstream TLS 1.3 ciphersuites: {error}"),
            ))
        })?;
    Ok(())
}

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
fn configure_openssl_client_cert(
    builder: &mut openssl::ssl::SslConnectorBuilder,
    cert_path: &Path,
    key_path: &Path,
) -> Result<(), NativeHttp1Error> {
    let certs = X509::stack_from_pem(&read_upstream_tls_file(cert_path)?).map_err(|error| {
        NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to parse upstream client certificate {}: {error}",
                cert_path.display()
            ),
        ))
    })?;
    let Some((leaf, intermediates)) = certs.split_first() else {
        return Err(NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream client certificate {} contains no certificates",
                cert_path.display()
            ),
        )));
    };
    let key_contents = Zeroizing::new(read_upstream_tls_file(key_path)?);
    let key = PKey::private_key_from_pem(&key_contents).map_err(|error| {
        NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to parse upstream client private key {}: {error}",
                key_path.display()
            ),
        ))
    })?;
    builder.set_certificate(leaf).map_err(|error| {
        NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to configure upstream client certificate {}: {error}",
                cert_path.display()
            ),
        ))
    })?;
    for cert in intermediates {
        builder
            .add_extra_chain_cert(cert.clone())
            .map_err(|error| {
                NativeHttp1Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "failed to configure upstream client certificate chain {}: {error}",
                        cert_path.display()
                    ),
                ))
            })?;
    }
    builder.set_private_key(&key).map_err(|error| {
        NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to configure upstream client private key {}: {error}",
                key_path.display()
            ),
        ))
    })?;
    Ok(())
}

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
fn upstream_tls_openssl_sni(configured: Option<&str>, upstream_authority: &str) -> String {
    configured
        .map(str::to_owned)
        .or_else(|| {
            let host = fluxheim_config::config_net::upstream_host(upstream_authority)?;
            host.parse::<std::net::IpAddr>().is_err().then_some(host)
        })
        .unwrap_or_default()
}

#[cfg(feature = "tls-rustls-backend")]
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

#[cfg(feature = "tls-rustls-backend")]
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

#[cfg(feature = "tls-rustls-backend")]
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

#[cfg(feature = "tls-rustls-backend")]
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

#[cfg(feature = "tls-rustls-backend")]
fn upstream_tls_alpn_protocols(proxy: &fluxheim_config::ProxyConfig) -> Vec<Vec<u8>> {
    match proxy.upstream_http_version {
        fluxheim_config::UpstreamHttpVersion::Http2 => vec![b"h2".to_vec()],
        fluxheim_config::UpstreamHttpVersion::Http1AndHttp2 => {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        }
        fluxheim_config::UpstreamHttpVersion::Http1 => vec![b"http/1.1".to_vec()],
    }
}

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
fn upstream_tls_alpn_protocol_wire(proxy: &fluxheim_config::ProxyConfig) -> Vec<u8> {
    match proxy.upstream_http_version {
        fluxheim_config::UpstreamHttpVersion::Http2 => b"\x02h2".to_vec(),
        fluxheim_config::UpstreamHttpVersion::Http1AndHttp2 => b"\x02h2\x08http/1.1".to_vec(),
        fluxheim_config::UpstreamHttpVersion::Http1 => b"\x08http/1.1".to_vec(),
    }
}

#[cfg(feature = "tls-rustls-backend")]
fn verification_mode(proxy: &fluxheim_config::ProxyConfig) -> RustlsVerificationMode {
    if !proxy.upstream_verify_cert {
        RustlsVerificationMode::SkipAll
    } else if !proxy.upstream_verify_hostname {
        RustlsVerificationMode::SkipHostname
    } else {
        RustlsVerificationMode::Full
    }
}

#[cfg(feature = "tls-rustls-backend")]
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

#[cfg(feature = "tls-rustls-backend")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RustlsVerificationMode {
    Full,
    SkipHostname,
    SkipAll,
}

#[cfg(feature = "tls-rustls-backend")]
#[derive(Debug)]
struct NativeRustlsVerifier {
    delegate: Arc<WebPkiServerVerifier>,
    mode: RustlsVerificationMode,
    alternative_name: Option<ServerName<'static>>,
}

#[cfg(feature = "tls-rustls-backend")]
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
    let safe_path = canonical_upstream_tls_file_path(path)?;
    let metadata = std::fs::symlink_metadata(&safe_path).map_err(NativeHttp1Error::Io)?;
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

    let file = options.open(&safe_path).map_err(NativeHttp1Error::Io)?;
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

fn canonical_upstream_tls_file_path(path: &Path) -> Result<std::path::PathBuf, NativeHttp1Error> {
    let file_name = path.file_name().ok_or_else(|| {
        NativeHttp1Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("upstream TLS path has no file name: {}", path.display()),
        ))
    })?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let canonical_parent = std::fs::canonicalize(parent).map_err(NativeHttp1Error::Io)?;
    Ok(canonical_parent.join(file_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NATIVE_HTTP1_TLS_TEST_DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_temp_dir(label: &str) -> std::path::PathBuf {
        let sequence = NATIVE_HTTP1_TLS_TEST_DIR_COUNTER.fetch_add(1, Ordering::AcqRel);
        let base = std::path::PathBuf::from("target/fluxheim-native-http1-tls-tests");
        std::fs::create_dir_all(&base).unwrap();
        let path = base.join(format!(
            "fluxheim-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn upstream_tls_file_reader_rejects_oversized_files() {
        let directory = unique_temp_dir("native-upstream-tls-large");
        let path = directory.join("ca.pem");
        std::fs::write(
            &path,
            vec![b'a'; MAX_UPSTREAM_TLS_FILE_BYTES.saturating_add(1) as usize],
        )
        .unwrap();

        let error = read_upstream_tls_file(&path).unwrap_err();

        assert!(
            matches!(&error, NativeHttp1Error::Io(error) if error.kind() == io::ErrorKind::InvalidData),
            "unexpected error: {error:?}"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn upstream_tls_file_reader_rejects_final_symlink() {
        use std::os::unix::fs::symlink;

        let directory = unique_temp_dir("native-upstream-tls-symlink");
        let target = directory.join("target.pem");
        let link = directory.join("linked.pem");
        std::fs::write(&target, b"not a real certificate").unwrap();
        symlink(&target, &link).unwrap();

        let error = read_upstream_tls_file(&link).unwrap_err();

        assert!(
            matches!(&error, NativeHttp1Error::Io(error) if error.kind() == io::ErrorKind::InvalidInput),
            "unexpected error: {error:?}"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
    #[test]
    fn openssl_upstream_tls_baseline_uses_modern_cipher_suites() {
        assert_eq!(
            OPENSSL_UPSTREAM_TLS12_CIPHERS,
            concat!(
                "ECDHE-ECDSA-AES256-GCM-SHA384:",
                "ECDHE-RSA-AES256-GCM-SHA384:",
                "ECDHE-ECDSA-CHACHA20-POLY1305:",
                "ECDHE-RSA-CHACHA20-POLY1305:",
                "ECDHE-ECDSA-AES128-GCM-SHA256:",
                "ECDHE-RSA-AES128-GCM-SHA256",
            )
        );
        assert_eq!(
            OPENSSL_UPSTREAM_TLS13_CIPHERS,
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
        );
    }
}
