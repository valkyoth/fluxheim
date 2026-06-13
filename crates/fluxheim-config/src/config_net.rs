use std::net::{IpAddr, SocketAddr};

pub fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty()
        || host.contains('*')
        || host.contains('/')
        || host.contains('\\')
        || host.contains('?')
        || host.contains('#')
        || host.contains('@')
        || host.chars().any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return None;
    }

    if let Some(stripped) = host.strip_prefix('[') {
        let (addr, rest) = stripped.split_once(']')?;
        if !rest.is_empty() && !valid_port_suffix(rest) {
            return None;
        }
        return Some(addr.to_ascii_lowercase());
    }

    let host = if let Some((candidate, port)) = host.rsplit_once(':') {
        if !candidate.contains(':') && !candidate.is_empty() && port.parse::<u16>().is_ok() {
            candidate.trim_end_matches('.')
        } else {
            host
        }
    } else {
        host
    };

    if host.is_empty() || host.starts_with('.') {
        return None;
    }
    if host.parse::<IpAddr>().is_err() && !valid_dns_hostname(host) {
        return None;
    }

    Some(host.to_ascii_lowercase())
}

pub fn normalize_host_pattern(host: &str) -> Option<String> {
    let host = host.trim();
    if let Some(suffix) = host.strip_prefix("*.") {
        let suffix = normalize_host(suffix)?;
        if suffix.contains(':') {
            return None;
        }
        Some(format!("*.{suffix}"))
    } else {
        normalize_host(host)
    }
}

pub fn upstream_host(authority: &str) -> Option<String> {
    if let Ok(socket) = authority.parse::<SocketAddr>() {
        return Some(socket.ip().to_string());
    }

    split_host_port(authority).map(|(host, _port)| host.to_owned())
}

pub fn valid_authority(authority: &str) -> bool {
    if authority.parse::<SocketAddr>().is_ok() {
        return true;
    }
    split_host_port(authority)
        .is_some_and(|(host, _)| host.parse::<IpAddr>().is_ok() || normalize_host(host).is_some())
}

pub fn valid_ip_matcher(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return false;
    }

    let Some((address, prefix)) = value.split_once('/') else {
        return value.parse::<IpAddr>().is_ok();
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match address {
        IpAddr::V4(_) => prefix <= 32,
        IpAddr::V6(_) => prefix <= 128,
    }
}

pub fn valid_trusted_proxy(value: &str) -> bool {
    valid_ip_matcher(value) && trusted_proxy_has_safe_scope(value)
}

fn trusted_proxy_has_safe_scope(value: &str) -> bool {
    let value = value.trim();
    let Some((address, prefix)) = value.split_once('/') else {
        return value
            .parse::<IpAddr>()
            .is_ok_and(|address| !address.is_unspecified());
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    if address.is_unspecified() {
        return false;
    }
    match address {
        IpAddr::V4(_) => prefix >= 8,
        // Large edge providers can publish IPv6 allocations broader than /32
        // (Cloudflare uses 2a06:98c0::/29). Keep rejecting catch-all and
        // near-global ranges while allowing real provider trust lists.
        IpAddr::V6(_) => prefix >= 29,
    }
}

pub fn valid_upstream_alias(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= 64
        && alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

pub fn http_authority_is_loopback(authority: &str) -> bool {
    let Some(host) = http_authority_host(authority) else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

pub fn http_authority_is_numeric_loopback(authority: &str) -> bool {
    http_authority_host(authority).is_some_and(|host| host == "127.0.0.1" || host == "::1")
}

pub fn valid_http_authority(authority: &str) -> bool {
    if authority.starts_with('[') {
        let Some(end) = authority.find(']') else {
            return false;
        };
        if end <= 1 {
            return false;
        }
        let tail = &authority[end + 1..];
        return tail.is_empty() || valid_http_authority_port_tail(tail);
    }

    let Some((host, port)) = authority.rsplit_once(':') else {
        return valid_http_host(authority);
    };
    valid_http_host(host) && valid_u16_port(port)
}

fn valid_port_suffix(rest: &str) -> bool {
    rest.strip_prefix(':')
        .is_some_and(|port| !port.is_empty() && port.parse::<u16>().is_ok())
}

fn http_authority_host(authority: &str) -> Option<&str> {
    if authority.contains('@') {
        return None;
    }
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let tail = &authority[end + 1..];
        if !tail.is_empty() && !valid_http_authority_port_tail(tail) {
            return None;
        }
        return Some(&authority[1..end]);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            if host.contains(':') || !valid_u16_port(port) {
                return None;
            }
            Some(host)
        }
        None => Some(authority),
    }
}

fn valid_http_authority_port_tail(tail: &str) -> bool {
    tail.strip_prefix(':').is_some_and(valid_u16_port)
}

fn valid_u16_port(port: &str) -> bool {
    port.parse::<u16>().is_ok_and(|port| port != 0)
}

fn valid_http_host(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok() || valid_dns_hostname(host)
}

fn split_host_port(authority: &str) -> Option<(&str, u16)> {
    let (host, port) = authority.rsplit_once(':')?;
    if host.trim().is_empty() || port.trim().is_empty() {
        return None;
    }

    let port = port.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }

    let host = host.trim_matches(['[', ']']);
    if host.trim().is_empty() || host.contains('/') {
        return None;
    }

    Some((host, port))
}

fn valid_dns_hostname(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.len() > 253 || host.as_bytes().contains(&b'%') {
        return false;
    }

    let mut last_label = "";
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return false;
        }
        last_label = label;
    }

    !last_label.bytes().all(|byte| byte.is_ascii_digit())
}
