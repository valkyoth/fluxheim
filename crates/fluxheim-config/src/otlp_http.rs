/// No DNS-based plaintext exceptions: names can resolve outside the local host.
pub fn endpoint_transport_is_secure(endpoint: &str) -> bool {
    if endpoint.len() > 2048
        || endpoint.contains('\\')
        || !crate::config_http::valid_http_endpoint_url(endpoint)
    {
        return false;
    }
    if endpoint.starts_with("https://") {
        return true;
    }
    let Some(rest) = endpoint.strip_prefix("http://") else {
        return false;
    };
    let Some((authority, _)) = rest.split_once('/') else {
        return false;
    };
    let host = endpoint_host(authority);
    host.parse::<std::net::IpAddr>()
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
    use super::endpoint_transport_is_secure;

    #[test]
    fn otlp_transport_requires_https_except_numeric_loopback() {
        for endpoint in [
            "https://collector.example.test/v1/traces",
            "https://10.0.0.10/v1/metrics",
            "https://[fd00::1]/v1/metrics",
            "http://127.0.0.1:4318/v1/traces",
            "http://127.12.34.56/v1/metrics",
            "http://[::1]:4318/v1/traces",
            "http://[0:0:0:0:0:0:0:1]/v1/traces",
        ] {
            assert!(endpoint_transport_is_secure(endpoint), "{endpoint}");
        }
        for endpoint in [
            "http://localhost:4318/v1/traces",
            "http://LOCALHOST/v1/metrics",
            "http://localhost./v1/traces",
            "http://collector.example.test/v1/traces",
            "http://10.0.0.10:4318/v1/traces",
            "http://192.168.0.10/v1/metrics",
            "http://169.254.169.254/v1/traces",
            "http://[fd00::1]/v1/traces",
            "http://[::ffff:127.0.0.1]/v1/traces",
            "http://0.0.0.0/v1/traces",
            "http://[::]/v1/traces",
            "http://127.1/v1/traces",
            "http://2130706433/v1/traces",
            "http://127.0.0.1.example.test/v1/traces",
            "http://127.0.0.1@collector.example.test/v1/traces",
            "http://127.0.0.1:0/v1/traces",
            "http://127.0.0.1/v1/traces?secret=x",
            "http://127.0.0.1/v1/traces#secret",
            "http://127.0.0.1/\\evil",
            "http://127.0.0.1/v1/traces\n",
            "http://127.0.0.1",
            "https://collector.example.test/",
            "file:///v1/traces",
        ] {
            assert!(!endpoint_transport_is_secure(endpoint), "{endpoint:?}");
        }
        assert!(!endpoint_transport_is_secure(&format!(
            "https://collector.example.test/{}",
            "x".repeat(2048)
        )));
    }
}
