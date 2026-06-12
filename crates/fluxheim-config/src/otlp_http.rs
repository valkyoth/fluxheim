pub fn plaintext_non_loopback_endpoint(endpoint: &str) -> bool {
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
