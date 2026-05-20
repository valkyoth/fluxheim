use std::io;
use std::path::Path;
use std::time::Duration;

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
    let contents = std::fs::read(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to read OTLP TLS CA certificate {}: {error}",
                path.display()
            ),
        )
    })?;
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
    use super::plaintext_non_loopback_endpoint;

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
}
