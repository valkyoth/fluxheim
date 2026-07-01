use std::io;
use std::path::{Path, PathBuf};

use super::{PHP_HOP_BY_HOP_RESPONSE_HEADERS, safe_php_header_name, safe_php_header_value};

pub fn split_php_response(stdout: &[u8]) -> io::Result<(&[u8], &[u8])> {
    if let Some(index) = stdout.windows(4).position(|window| window == b"\r\n\r\n") {
        return Ok((&stdout[..index], &stdout[index + 4..]));
    }
    if let Some(index) = stdout.windows(2).position(|window| window == b"\n\n") {
        return Ok((&stdout[..index], &stdout[index + 2..]));
    }
    Err(php_response_parse_error(
        "php-fpm response is missing header terminator",
    ))
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedPhpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub fn php_static_offload_uri_target(target: &str) -> io::Result<&str> {
    if target.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "php X-Accel-Redirect target contains control characters",
        ));
    }
    Ok(target)
}

pub fn php_static_offload_x_sendfile_local_path(
    root: &Path,
    fpm_root: &Path,
    target: &str,
) -> io::Result<PathBuf> {
    if target.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "php X-Sendfile target contains control characters",
        ));
    }
    let target_path = Path::new(target);
    let relative = target_path.strip_prefix(fpm_root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "php X-Sendfile target is outside php.fpm_root",
        )
    })?;
    if relative
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "php X-Sendfile target escapes php root",
        ));
    }
    Ok(root.join(relative))
}

pub fn php_static_offload_file_allowed(local_path: &Path, allowed_extensions: &[String]) -> bool {
    local_path
        .extension()
        .and_then(|extension| extension.to_str())
        .filter(|extension| !extension.is_empty())
        .is_some_and(|extension| {
            !allowed_extensions
                .iter()
                .any(|allowed| extension.eq_ignore_ascii_case(allowed))
        })
}

pub fn php_x_accel_expires_ttl_secs(value: &str) -> Option<u64> {
    if let Some(epoch) = value.strip_prefix('@') {
        let epoch = epoch.parse::<u64>().ok()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .ok()?
            .as_secs();
        return Some(epoch.saturating_sub(now));
    }
    let ttl = value.parse::<i64>().ok()?;
    Some(u64::try_from(ttl).unwrap_or(0))
}

pub fn php_origin_cache_policy_is_restrictive<'a, C, P>(
    cache_control_values: C,
    pragma_values: P,
) -> bool
where
    C: IntoIterator<Item = &'a str>,
    P: IntoIterator<Item = &'a str>,
{
    cache_control_values
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(|directive| {
            directive
                .trim()
                .split_once('=')
                .map_or_else(|| directive.trim(), |(name, _)| name.trim())
        })
        .any(|directive| {
            directive.eq_ignore_ascii_case("private")
                || directive.eq_ignore_ascii_case("no-store")
                || directive.eq_ignore_ascii_case("no-cache")
        })
        || pragma_values
            .into_iter()
            .flat_map(|value| value.split(','))
            .any(|directive| directive.trim().eq_ignore_ascii_case("no-cache"))
}

pub fn php_response_headers_to_strip<'a, I>(
    connection_values: I,
    hide_response_headers: &[String],
) -> Vec<String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut headers = PHP_HOP_BY_HOP_RESPONSE_HEADERS
        .iter()
        .map(|header| (*header).to_owned())
        .collect::<Vec<_>>();
    headers.extend(
        connection_values
            .into_iter()
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .filter(|value| fluxheim_protocol::http_token_valid(value))
            .map(str::to_owned),
    );
    headers.extend(hide_response_headers.iter().cloned());
    headers
}

pub fn php_should_intercept_error_status<I>(
    status: u16,
    error_page_statuses: I,
    intercept_error_statuses: &[u16],
) -> bool
where
    I: IntoIterator<Item = u16>,
{
    error_page_statuses.into_iter().any(|page| page == status)
        || intercept_error_statuses.contains(&status)
}

pub fn parse_php_response(
    stdout: &[u8],
    max_response_bytes: u64,
    max_response_header_bytes: u64,
) -> io::Result<ParsedPhpResponse> {
    if stdout.len() as u64 > max_response_bytes {
        return Err(php_response_parse_error(
            "php-fpm response exceeds maximum buffered size",
        ));
    }
    let (header_bytes, body) = split_php_response(stdout)?;
    if header_bytes.len() as u64 > max_response_header_bytes {
        return Err(php_response_parse_error(
            "php-fpm response headers exceed maximum size",
        ));
    }

    let mut status = 200;
    let mut headers = Vec::new();
    for line in header_bytes.split(|byte| *byte == b'\n') {
        let line = trim_ascii_cr(line);
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = split_first_colon(line) else {
            return Err(php_response_parse_error(
                "php-fpm response header is malformed",
            ));
        };
        let name = trim_ascii(name);
        let value = trim_ascii(value);
        if !safe_php_header_name(name) || !safe_php_header_value(value) {
            return Err(php_response_parse_error(
                "php-fpm response header contains unsafe bytes",
            ));
        }
        if name.eq_ignore_ascii_case(b"status") {
            status = parse_php_status(value)?;
            continue;
        }
        headers.push((ascii_bytes_to_string(name), ascii_bytes_to_string(value)));
    }

    Ok(ParsedPhpResponse {
        status,
        headers,
        body: body.to_vec(),
    })
}

fn ascii_bytes_to_string(value: &[u8]) -> String {
    debug_assert!(
        value.iter().all(u8::is_ascii),
        "ascii_bytes_to_string called with non-ASCII bytes"
    );
    value.iter().map(|byte| char::from(*byte)).collect()
}

pub fn parse_php_status(value: &[u8]) -> io::Result<u16> {
    let text = std::str::from_utf8(value).map_err(|error| {
        php_response_parse_error(format!("PHP Status header is not valid UTF-8: {error}"))
    })?;
    let status = text
        .split_whitespace()
        .next()
        .ok_or_else(|| php_response_parse_error("empty PHP Status header"))?
        .parse::<u16>()
        .map_err(|error| php_response_parse_error(error.to_string()))?;
    if !(100..=599).contains(&status) {
        return Err(php_response_parse_error(
            "PHP Status header is outside HTTP status range",
        ));
    }
    Ok(status)
}

pub fn trim_ascii_cr(value: &[u8]) -> &[u8] {
    value.strip_suffix(b"\r").unwrap_or(value)
}

pub fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

pub fn split_first_colon(value: &[u8]) -> Option<(&[u8], &[u8])> {
    value
        .iter()
        .position(|byte| *byte == b':')
        .map(|index| (&value[..index], &value[index + 1..]))
}

fn php_response_parse_error(detail: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail.into())
}
