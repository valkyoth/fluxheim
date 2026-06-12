#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
use std::io;
#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
use std::sync::Arc;

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
use crate::config::ProxyConfig;
#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
use zeroize::Zeroizing;

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
#[derive(Debug, Clone, Default)]
pub(crate) struct RuntimeUpstreamTls {
    pub(crate) ca: Option<Arc<pingora::protocols::tls::CaType>>,
    pub(crate) ca_pool_key: Option<u64>,
    pub(crate) client_cert_key: Option<Arc<pingora::utils::tls::CertKey>>,
}

#[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl")))]
pub(crate) struct RuntimeUpstreamTls;

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
impl RuntimeUpstreamTls {
    pub(crate) fn from_config(config: &ProxyConfig) -> io::Result<Self> {
        Self::from_paths(
            config.upstream_ca_path.as_deref(),
            config.upstream_client_cert_path.as_deref(),
            config.upstream_client_key_path.as_deref(),
        )
    }

    pub(crate) fn from_paths(
        ca_path: Option<&std::path::Path>,
        client_cert_path: Option<&std::path::Path>,
        client_key_path: Option<&std::path::Path>,
    ) -> io::Result<Self> {
        let ca_bundle = ca_path.map(load_upstream_ca_bundle).transpose()?;
        Ok(Self {
            ca: ca_bundle.as_ref().map(|bundle| bundle.ca.clone()),
            ca_pool_key: ca_bundle.map(|bundle| bundle.pool_key),
            client_cert_key: match (client_cert_path, client_key_path) {
                (Some(cert), Some(key)) => Some(load_upstream_client_cert_key(cert, key)?),
                _ => None,
            },
        })
    }
}

#[cfg(all(
    any(feature = "tls-rustls-backend", feature = "tls-openssl"),
    target_os = "linux"
))]
const UPSTREAM_TLS_O_NOFOLLOW: i32 = 0o400000;

#[cfg(all(
    any(feature = "tls-rustls-backend", feature = "tls-openssl"),
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )
))]
const UPSTREAM_TLS_O_NOFOLLOW: i32 = 0x0100;

#[cfg(all(
    unix,
    any(feature = "tls-rustls-backend", feature = "tls-openssl"),
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
    "O_NOFOLLOW is unknown on this Unix platform; audit upstream TLS file opening before building Fluxheim"
);

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
const MAX_UPSTREAM_TLS_FILE_BYTES: u64 = 1024 * 1024;

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
struct LoadedUpstreamCaBundle {
    ca: Arc<pingora::protocols::tls::CaType>,
    pool_key: u64,
}

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
fn upstream_tls_ca_pool_key(contents: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in b"fluxheim-upstream-ca\0"
        .iter()
        .copied()
        .chain(contents.iter().copied())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
pub(crate) fn read_upstream_tls_file(path: &std::path::Path) -> io::Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "upstream TLS path is not a regular file: {}",
                path.display()
            ),
        ));
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(UPSTREAM_TLS_O_NOFOLLOW);
    }

    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "upstream TLS path is not a regular file: {}",
                path.display()
            ),
        ));
    }
    if metadata.len() > MAX_UPSTREAM_TLS_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream TLS file {} exceeds {} bytes",
                path.display(),
                MAX_UPSTREAM_TLS_FILE_BYTES
            ),
        ));
    }

    let mut contents = Vec::new();
    let mut limited = std::io::Read::take(file, MAX_UPSTREAM_TLS_FILE_BYTES.saturating_add(1));
    std::io::Read::read_to_end(&mut limited, &mut contents)?;
    if contents.len() as u64 > MAX_UPSTREAM_TLS_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream TLS file {} exceeds {} bytes",
                path.display(),
                MAX_UPSTREAM_TLS_FILE_BYTES
            ),
        ));
    }
    Ok(contents)
}

#[cfg(all(feature = "tls-rustls-backend", not(feature = "tls-openssl")))]
fn load_upstream_ca_bundle(path: &std::path::Path) -> io::Result<LoadedUpstreamCaBundle> {
    let contents = read_upstream_tls_file(path)?;
    let pool_key = upstream_tls_ca_pool_key(&contents);
    use rustls::pki_types::{CertificateDer, pem::PemObject};

    let certs = CertificateDer::pem_slice_iter(&contents)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse upstream CA bundle {}: {error}",
                    path.display()
                ),
            )
        })?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream CA bundle {} contains no certificates",
                path.display()
            ),
        ));
    }
    let wrapped = certs
        .into_iter()
        .map(|cert| pingora::utils::tls::WrappedX509::try_from_der(cert.as_ref().to_vec()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse upstream CA bundle {}: {error}",
                    path.display()
                ),
            )
        })?;
    Ok(LoadedUpstreamCaBundle {
        ca: Arc::from(wrapped.into_boxed_slice()),
        pool_key,
    })
}

#[cfg(all(feature = "tls-openssl", not(feature = "tls-rustls-backend")))]
fn load_upstream_ca_bundle(path: &std::path::Path) -> io::Result<LoadedUpstreamCaBundle> {
    let contents = read_upstream_tls_file(path)?;
    let pool_key = upstream_tls_ca_pool_key(&contents);
    let certs = pingora::tls::x509::X509::stack_from_pem(&contents).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to parse upstream CA bundle {}: {error}",
                path.display()
            ),
        )
    })?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream CA bundle {} contains no certificates",
                path.display()
            ),
        ));
    }
    Ok(LoadedUpstreamCaBundle {
        ca: Arc::from(certs.into_boxed_slice()),
        pool_key,
    })
}

#[cfg(all(feature = "tls-rustls-backend", not(feature = "tls-openssl")))]
fn load_upstream_client_cert_key(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> io::Result<Arc<pingora::utils::tls::CertKey>> {
    let cert_contents = read_upstream_tls_file(cert_path)?;
    let key_contents = Zeroizing::new(read_upstream_tls_file(key_path)?);

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    let certs = CertificateDer::pem_slice_iter(&cert_contents)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse upstream client certificate {}: {error}",
                    cert_path.display()
                ),
            )
        })?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream client certificate {} contains no certificates",
                cert_path.display()
            ),
        ));
    }

    let key = PrivateKeyDer::from_pem_slice(&key_contents).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to parse upstream client private key {}: {error}",
                key_path.display()
            ),
        )
    })?;

    let key_der = Zeroizing::new(key.secret_der().to_vec());
    let cert_key = pingora::utils::tls::CertKey::try_new(
        certs
            .into_iter()
            .map(|cert| cert.as_ref().to_vec())
            .collect(),
        key_der.to_vec(),
    )
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to parse upstream client certificate {}: {error}",
                cert_path.display()
            ),
        )
    })?;
    Ok(Arc::new(cert_key))
}

#[cfg(all(feature = "tls-openssl", not(feature = "tls-rustls-backend")))]
fn load_upstream_client_cert_key(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> io::Result<Arc<pingora::utils::tls::CertKey>> {
    let cert_contents = read_upstream_tls_file(cert_path)?;
    let key_contents = Zeroizing::new(read_upstream_tls_file(key_path)?);
    let certs = pingora::tls::x509::X509::stack_from_pem(&cert_contents).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to parse upstream client certificate {}: {error}",
                cert_path.display()
            ),
        )
    })?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream client certificate {} contains no certificates",
                cert_path.display()
            ),
        ));
    }
    let key = pingora::tls::pkey::PKey::private_key_from_pem(&key_contents).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to parse upstream client private key {}: {error}",
                key_path.display()
            ),
        )
    })?;
    Ok(Arc::new(pingora::utils::tls::CertKey::new(certs, key)))
}
