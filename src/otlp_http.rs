use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::Path;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

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

pub(crate) fn agent(timeout: Duration, tls_ca_cert_path: Option<&Path>) -> io::Result<ureq::Agent> {
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
            Ok(ureq::tls::PemItem::Certificate(certificate)) => certificates.push(certificate),
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

pub(crate) fn plaintext_non_loopback_endpoint(endpoint: &str) -> bool {
    let Some(rest) = endpoint.strip_prefix("http://") else {
        return false;
    };
    let Some((authority, _)) = rest.split_once('/') else {
        return false;
    };
    let host = endpoint_host(authority);
    !host.eq_ignore_ascii_case("localhost")
        && !host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn endpoint_host(authority: &str) -> &str {
    if let Some(stripped) = authority.strip_prefix('[')
        && let Some((host, _)) = stripped.split_once(']')
    {
        return host;
    }
    authority
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(authority)
}

#[cfg(test)]
mod tests {
    use super::{load_ca_certificates, plaintext_non_loopback_endpoint};

    #[test]
    fn detects_plaintext_non_loopback_otlp_endpoint() {
        assert!(!plaintext_non_loopback_endpoint(
            "https://collector.example.test/v1/traces"
        ));
        assert!(!plaintext_non_loopback_endpoint(
            "http://127.0.0.1:4318/v1/traces"
        ));
        assert!(!plaintext_non_loopback_endpoint(
            "http://[::1]:4318/v1/traces"
        ));
        assert!(!plaintext_non_loopback_endpoint(
            "http://localhost:4318/v1/traces"
        ));
        assert!(plaintext_non_loopback_endpoint(
            "http://collector.example.test/v1/traces"
        ));
        assert!(plaintext_non_loopback_endpoint(
            "http://10.0.0.10:4318/v1/traces"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_ca_certificate() {
        let target = crate::test_support::unique_temp_path("otlp-ca-target");
        let link = crate::test_support::unique_temp_path("otlp-ca-link");
        std::fs::write(&target, b"not a certificate\n").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let error = load_ca_certificates(&link).unwrap_err();

        assert_ne!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("failed to read"));
        let _ = std::fs::remove_file(target);
        let _ = std::fs::remove_file(link);
    }
}
