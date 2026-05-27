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

pub(crate) fn upstream_host(authority: &str) -> Option<String> {
    if let Ok(socket) = authority.parse::<SocketAddr>() {
        return Some(socket.ip().to_string());
    }

    split_host_port(authority).map(|(host, _port)| host.to_owned())
}

pub(crate) fn valid_authority(authority: &str) -> bool {
    authority.parse::<SocketAddr>().is_ok() || split_host_port(authority).is_some()
}

pub(crate) fn valid_ip_matcher(value: &str) -> bool {
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

pub(crate) fn valid_trusted_proxy(value: &str) -> bool {
    valid_ip_matcher(value)
}

pub(crate) fn valid_upstream_alias(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= 64
        && alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn valid_port_suffix(rest: &str) -> bool {
    rest.strip_prefix(':')
        .is_some_and(|port| !port.is_empty() && port.parse::<u16>().is_ok())
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
