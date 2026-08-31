use std::fs::OpenOptions;
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "android"))]
const O_NOFOLLOW: i32 = 0o400000;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const O_NOFOLLOW: i32 = 0x0100;

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!(
    "O_NOFOLLOW is unknown on this Unix platform; audit symlink-safe OTLP CA loading before building Fluxheim"
);

const MAX_OTLP_CA_CERT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OtlpHttpEndpoint {
    pub url: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl OtlpHttpEndpoint {
    pub fn parse(endpoint: &str) -> Option<Self> {
        let (rest, default_port) = if let Some(rest) = endpoint.strip_prefix("http://") {
            (rest, 80)
        } else {
            (endpoint.strip_prefix("https://")?, 443)
        };
        let (authority, path) = rest.split_once('/')?;
        if authority.is_empty() || path.is_empty() {
            return None;
        }
        let (host, port) = parse_authority(authority, default_port)?;
        Some(Self {
            url: endpoint.to_owned(),
            host,
            port,
            path: format!("/{path}"),
        })
    }
}

fn parse_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(stripped) = authority.strip_prefix('[') {
        let (host, tail) = stripped.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        let port = if tail.is_empty() {
            default_port
        } else {
            tail.strip_prefix(':')?.parse::<u16>().ok()?
        };
        return (port != 0).then(|| (host.to_owned(), port));
    }

    let Some((host, port)) = authority.rsplit_once(':') else {
        return Some((authority.to_owned(), default_port));
    };
    if host.is_empty() {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    (port != 0).then(|| (host.to_owned(), port))
}

pub fn agent(timeout: Duration, tls_ca_cert_path: Option<&Path>) -> io::Result<ureq::Agent> {
    let mut builder = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .http_status_as_error(false);

    if let Some(path) = tls_ca_cert_path {
        let certs = load_ca_certificates(path)?;
        builder = builder.tls_config(
            ureq::tls::TlsConfig::builder()
                .root_certs(ureq::tls::RootCerts::new_with_certs(&certs))
                .build(),
        );
    }

    Ok(builder.build().into())
}

fn load_ca_certificates(path: &Path) -> io::Result<Vec<ureq::tls::Certificate<'static>>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(O_NOFOLLOW);
    let file = options.open(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to read OTLP TLS CA certificate {}: {error}",
                path.display()
            ),
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to inspect OTLP TLS CA certificate {}: {error}",
                path.display()
            ),
        )
    })?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "OTLP TLS CA certificate {} is not a regular file",
                path.display()
            ),
        ));
    }

    let mut contents = Vec::new();
    let mut limited = file.take(MAX_OTLP_CA_CERT_BYTES.saturating_add(1));
    limited.read_to_end(&mut contents).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to read OTLP TLS CA certificate {}: {error}",
                path.display()
            ),
        )
    })?;
    if contents.len() as u64 > MAX_OTLP_CA_CERT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "OTLP TLS CA certificate {} exceeds {} bytes",
                path.display(),
                MAX_OTLP_CA_CERT_BYTES
            ),
        ));
    }
    let mut certificates = Vec::new();
    for item in ureq::tls::parse_pem(&contents) {
        match item {
            Ok(ureq::tls::PemItem::Certificate(certificate)) => {
                certificates.push(certificate);
            }
            Ok(_) => {}
            Err(error) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "failed to parse OTLP TLS CA certificate {}: {error}",
                        path.display()
                    ),
                ));
            }
        }
    }
    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "OTLP TLS CA certificate {} did not contain any PEM certificates",
                path.display()
            ),
        ));
    }
    Ok(certificates)
}

#[cfg(test)]
mod tests {
    use super::OtlpHttpEndpoint;
    #[cfg(unix)]
    use super::load_ca_certificates;

    #[test]
    fn parses_prometheus_otlp_endpoint() {
        let endpoint = OtlpHttpEndpoint::parse("http://127.0.0.1:9090/api/v1/otlp/v1/metrics")
            .expect("valid endpoint");

        assert_eq!(endpoint.host, "127.0.0.1");
        assert_eq!(endpoint.port, 9090);
        assert_eq!(endpoint.path, "/api/v1/otlp/v1/metrics");
    }

    #[test]
    fn parses_https_prometheus_otlp_endpoint() {
        let endpoint =
            OtlpHttpEndpoint::parse("https://collector.example.test/api/v1/otlp/v1/metrics")
                .expect("valid endpoint");

        assert_eq!(endpoint.host, "collector.example.test");
        assert_eq!(endpoint.port, 443);
        assert_eq!(endpoint.path, "/api/v1/otlp/v1/metrics");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_ca_certificate() {
        let target = fluxheim_common::test_support::unique_temp_path("otlp-ca-target");
        let link = fluxheim_common::test_support::unique_temp_path("otlp-ca-link");
        std::fs::write(&target, b"not a certificate\n").expect("write target");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let error = load_ca_certificates(&link).expect_err("symlink must be rejected");

        assert_ne!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("failed to read"));
        let _ = std::fs::remove_file(target);
        let _ = std::fs::remove_file(link);
    }
}
