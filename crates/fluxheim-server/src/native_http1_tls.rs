use std::io;
#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
use std::path::Path;
use std::sync::Arc;

use tokio::net::TcpStream;
#[cfg(feature = "tls-rustls-backend")]
use tokio_rustls::TlsConnector;

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
use openssl::pkey::PKey;
#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
use openssl::x509::{X509, store::X509StoreBuilder};
#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
use sanitization::SecretVec;
#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
use tokio_openssl::SslStream;

use crate::native_http1_client::{NativeHttp1Stream, NativeNegotiatedHttpProtocol};
use crate::{NativeHttp1Error, NativeHttp1ProxyConfigError};

mod file;
#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
use file::{read_upstream_tls_file, read_upstream_tls_secret_file};
#[cfg(feature = "tls-rustls-backend")]
mod rustls_backend;
#[cfg(feature = "tls-rustls-backend")]
use rustls_backend::{build_rustls_connector, upstream_tls_server_name};

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
    let key_contents = SecretVec::from_vec(read_upstream_tls_secret_file(key_path)?);
    let key = key_contents
        .with_secret(PKey::private_key_from_pem)
        .map_err(|error| {
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

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
fn upstream_tls_alpn_protocol_wire(proxy: &fluxheim_config::ProxyConfig) -> Vec<u8> {
    match proxy.upstream_http_version {
        fluxheim_config::UpstreamHttpVersion::Http2 => b"\x02h2".to_vec(),
        fluxheim_config::UpstreamHttpVersion::Http1AndHttp2 => b"\x02h2\x08http/1.1".to_vec(),
        fluxheim_config::UpstreamHttpVersion::Http1 => b"\x08http/1.1".to_vec(),
    }
}

#[cfg(all(
    test,
    not(feature = "tls-rustls-backend"),
    feature = "tls-openssl-backend"
))]
mod tests {
    use super::*;

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
