use std::error::Error;
use std::io::{Read, Write};

use crate::config::Config;

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct CacheWarmTarget {
    pub(super) host: String,
    pub(super) path: String,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct CacheWarmResult {
    pub(super) status: u16,
    pub(super) bytes_read: u64,
    pub(super) cache_status: Option<String>,
}

#[cfg(feature = "cache")]
pub(super) const CACHE_WARM_INPUT_MAX_BYTES: usize = 1024 * 1024;

#[cfg(feature = "cache")]
pub(super) fn cache_warm_listen_addr(
    config: &Config,
    listen: Option<&str>,
) -> Result<std::net::SocketAddr, Box<dyn Error + Send + Sync>> {
    let candidate = listen
        .or_else(|| config.server.listen.first().map(String::as_str))
        .ok_or("cache-warm requires a server.listen address or --listen")?;
    let mut address: std::net::SocketAddr = candidate.parse()?;
    address.set_ip(match address.ip() {
        std::net::IpAddr::V4(ip) if ip.is_unspecified() => {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        }
        std::net::IpAddr::V6(ip) if ip.is_unspecified() => {
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        }
        ip => ip,
    });
    Ok(address)
}

#[cfg(feature = "cache")]
pub(super) fn cache_warm_default_host(config: &Config) -> Option<String> {
    config
        .server
        .default_vhost
        .as_deref()
        .and_then(|name| config.vhosts.iter().find(|vhost| vhost.name == name))
        .and_then(|vhost| vhost.hosts.first())
        .cloned()
        .or_else(|| {
            config
                .vhosts
                .iter()
                .find_map(|vhost| vhost.hosts.first().cloned())
        })
}

#[cfg(feature = "cache")]
pub(super) fn cache_warm_targets(
    default_host: Option<&str>,
    paths: &[String],
    input: Option<&std::path::Path>,
    max_targets: usize,
) -> Result<Vec<CacheWarmTarget>, Box<dyn Error + Send + Sync>> {
    let mut targets = Vec::new();
    for path in paths {
        let host = default_host.ok_or("cache-warm --host is required when warming --path")?;
        targets.push(cache_warm_target(host, path)?);
    }

    if let Some(input) = input {
        let content = read_cache_warm_input(input)?;
        for (line_number, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let target = cache_warm_target_from_line(default_host, line).map_err(|error| {
                format!(
                    "invalid cache-warm input at {}:{}: {error}",
                    input.display(),
                    line_number + 1
                )
            })?;
            targets.push(target);
        }
    }

    if targets.is_empty() {
        return Err("cache-warm requires at least one --path or --input target".into());
    }
    if targets.len() > max_targets {
        return Err(format!(
            "cache-warm target count {} exceeds --max-targets {}",
            targets.len(),
            max_targets
        )
        .into());
    }
    Ok(targets)
}

#[cfg(feature = "cache")]
pub(super) fn read_cache_warm_input(
    input: &std::path::Path,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let file = std::fs::File::open(input)?;
    let mut content = String::new();
    file.take((CACHE_WARM_INPUT_MAX_BYTES as u64) + 1)
        .read_to_string(&mut content)?;
    if content.len() > CACHE_WARM_INPUT_MAX_BYTES {
        return Err(format!(
            "cache-warm input file must be at most {} bytes",
            CACHE_WARM_INPUT_MAX_BYTES
        )
        .into());
    }
    Ok(content)
}

#[cfg(feature = "cache")]
pub(super) fn cache_warm_target_from_line(
    default_host: Option<&str>,
    line: &str,
) -> Result<CacheWarmTarget, Box<dyn Error + Send + Sync>> {
    if line.starts_with('/') {
        let host = default_host.ok_or("host is required for path-only input lines")?;
        return cache_warm_target(host, line);
    }

    let mut parts = line.split_whitespace();
    let host = parts.next().ok_or("missing host")?;
    let path = parts.next().ok_or("missing path")?;
    if parts.next().is_some() {
        return Err("expected either /path or host /path".into());
    }
    cache_warm_target(host, path)
}

#[cfg(feature = "cache")]
pub(super) fn cache_warm_target(
    host: &str,
    path: &str,
) -> Result<CacheWarmTarget, Box<dyn Error + Send + Sync>> {
    validate_cache_warm_host(host)?;
    validate_cache_warm_path(path)?;
    Ok(CacheWarmTarget {
        host: host.to_owned(),
        path: path.to_owned(),
    })
}

#[cfg(feature = "cache")]
pub(super) fn validate_cache_warm_host(host: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    if host.is_empty() || host.len() > 253 {
        return Err("host must be 1-253 bytes".into());
    }
    if host.bytes().any(|byte| {
        byte.is_ascii_control()
            || byte.is_ascii_whitespace()
            || matches!(byte, b'/' | b'\\' | b'?' | b'#')
    }) {
        return Err("host contains characters that cannot be used in an HTTP Host header".into());
    }
    Ok(())
}

#[cfg(feature = "cache")]
pub(super) fn validate_cache_warm_path(path: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    if !path.starts_with('/') {
        return Err("path must start with /".into());
    }
    if path.len() > 8192 {
        return Err("path must be at most 8192 bytes".into());
    }
    if path
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err("path contains control or whitespace bytes".into());
    }
    Ok(())
}

#[cfg(feature = "cache")]
pub(super) fn validate_cache_warm_allow_statuses(
    statuses: &[u16],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    for status in statuses {
        if !(100..=599).contains(status) {
            return Err(format!(
                "cache-warm --allow-status must be an HTTP status code, got {status}"
            )
            .into());
        }
    }
    Ok(())
}

#[cfg(feature = "cache")]
pub(super) fn validate_cache_warm_header_name(
    name: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if name.is_empty() || name.len() > 64 {
        return Err("cache-warm --cache-status-header must be 1-64 bytes".into());
    }
    if !fluxheim_protocol::http_token_valid(name) {
        return Err("cache-warm --cache-status-header must be a valid HTTP header name".into());
    }
    Ok(())
}

#[cfg(feature = "cache")]
pub(super) fn validate_cache_warm_expected_statuses(
    statuses: &[String],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if statuses.len() > 16 {
        return Err("cache-warm accepts at most 16 --expect-cache-status values".into());
    }
    for status in statuses {
        if status.is_empty() || status.len() > 64 {
            return Err("cache-warm --expect-cache-status values must be 1-64 bytes".into());
        }
        if status
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(
                "cache-warm --expect-cache-status values must not contain control or whitespace bytes"
                    .into(),
            );
        }
    }
    Ok(())
}

#[cfg(feature = "cache")]
pub(super) fn validate_cache_warm_expected_sequence(
    allowed_statuses: &[String],
    sequence: &[String],
    repeat: usize,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if !allowed_statuses.is_empty() && !sequence.is_empty() {
        return Err(
            "cache-warm cannot combine --expect-cache-status and --expect-cache-status-sequence"
                .into(),
        );
    }
    validate_cache_warm_expected_statuses(sequence)?;
    if !sequence.is_empty() && sequence.len() != repeat {
        return Err("cache-warm --expect-cache-status-sequence length must match --repeat".into());
    }
    Ok(())
}

#[cfg(feature = "cache")]
pub(super) fn cache_warm_status_is_success(status: u16, allowed_extra: &[u16]) -> bool {
    (200..400).contains(&status) || allowed_extra.contains(&status)
}

#[cfg(feature = "cache")]
pub(super) fn cache_warm_expected_statuses_for_attempt<'a>(
    allowed_statuses: &'a [String],
    sequence: &'a [String],
    attempt: usize,
) -> &'a [String] {
    if sequence.is_empty() {
        allowed_statuses
    } else {
        let index = attempt.saturating_sub(1);
        &sequence[index..=index]
    }
}

#[cfg(feature = "cache")]
pub(super) fn cache_warm_expected_status_matches(
    actual: Option<&str>,
    expected: &[String],
) -> Result<(), String> {
    if expected.is_empty() {
        return Ok(());
    }
    let Some(actual) = actual else {
        return Err("missing expected cache status header".to_owned());
    };
    if expected
        .iter()
        .any(|expected| expected.eq_ignore_ascii_case(actual))
    {
        Ok(())
    } else {
        Err(format!("unexpected cache status {actual}"))
    }
}

#[cfg(feature = "cache")]
pub(super) fn cache_warm_request(
    listen: &std::net::SocketAddr,
    target: &CacheWarmTarget,
    timeout: std::time::Duration,
    cache_status_header: &str,
    headers: &[(String, String)],
) -> Result<CacheWarmResult, Box<dyn Error + Send + Sync>> {
    let mut stream = std::net::TcpStream::connect_timeout(listen, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: fluxheim-cache-warm/{}\r\nAccept: */*\r\n",
        target.path,
        target.host,
        env!("CARGO_PKG_VERSION")
    )?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "Connection: close\r\n\r\n")?;
    stream.flush()?;

    let mut bytes_read = 0_u64;
    let mut header_prefix = Vec::with_capacity(1024);
    let mut headers_complete = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read.saturating_add(read as u64);
        if !headers_complete && header_prefix.len() < 64 * 1024 {
            let remaining = (64 * 1024) - header_prefix.len();
            header_prefix.extend_from_slice(&buffer[..read.min(remaining)]);
            headers_complete = header_prefix.windows(4).any(|window| window == b"\r\n\r\n");
        }
    }

    let status = cache_warm_status_from_prefix(&header_prefix)?;
    let cache_status = cache_warm_header_value_from_prefix(&header_prefix, cache_status_header)?;
    Ok(CacheWarmResult {
        status,
        bytes_read,
        cache_status,
    })
}

#[cfg(feature = "cache")]
pub(super) fn cache_warm_status_from_prefix(
    prefix: &[u8],
) -> Result<u16, Box<dyn Error + Send + Sync>> {
    let line_end = prefix
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or("response did not include a complete HTTP status line")?;
    let status_line = std::str::from_utf8(&prefix[..line_end])?;
    let mut parts = status_line.split_whitespace();
    let protocol = parts.next().ok_or("missing HTTP protocol in status line")?;
    if !protocol.starts_with("HTTP/") {
        return Err("response status line does not start with HTTP/".into());
    }
    let status = parts
        .next()
        .ok_or("missing HTTP status code")?
        .parse::<u16>()?;
    Ok(status)
}

#[cfg(feature = "cache")]
pub(super) fn cache_warm_header_value_from_prefix(
    prefix: &[u8],
    name: &str,
) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    let Some(header_end) = prefix.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(None);
    };
    let headers = std::str::from_utf8(&prefix[..header_end])?;
    for line in headers.split("\r\n").skip(1) {
        let Some((candidate, value)) = line.split_once(':') else {
            continue;
        };
        if candidate.eq_ignore_ascii_case(name) {
            return Ok(Some(value.trim().to_owned()));
        }
    }
    Ok(None)
}
