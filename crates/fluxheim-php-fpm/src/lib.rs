#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fluxheim_config::{PhpFpmConfig, PhpFpmProcessManager};

static MANAGED_PHP_FPM_INSTANCE_COUNTER: AtomicUsize = AtomicUsize::new(0);
pub const MAX_PHP_PARAM_VALUE_BYTES: usize = 16 * 1024;
pub const PHP_HOP_BY_HOP_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];
pub const PHP_STATIC_OFFLOAD_RESPONSE_HEADERS: &[&str] = &["x-accel-redirect", "x-sendfile"];

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PhpFpmEndpoint {
    Tcp(String),
    #[cfg(unix)]
    Unix(PathBuf),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PhpFpmTimeoutKind {
    Connect,
    Request,
}

impl std::fmt::Display for PhpFpmTimeoutKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect => write!(formatter, "php-fpm connect timed out"),
            Self::Request => write!(formatter, "php-fpm request timed out"),
        }
    }
}

impl std::error::Error for PhpFpmTimeoutKind {}

pub fn php_fpm_timeout_error(kind: PhpFpmTimeoutKind) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, kind)
}

pub fn php_fpm_timeout_kind(error: &io::Error) -> Option<PhpFpmTimeoutKind> {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<PhpFpmTimeoutKind>())
        .copied()
}

pub fn php_fpm_error_outcome(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::TimedOut => match php_fpm_timeout_kind(error) {
            Some(PhpFpmTimeoutKind::Connect) => "connect_timeout",
            Some(PhpFpmTimeoutKind::Request) | None => "request_timeout",
        },
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::NotConnected
        | io::ErrorKind::AddrInUse
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::NotFound
        | io::ErrorKind::UnexpectedEof => "connection_error",
        io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported => "configuration_error",
        io::ErrorKind::InvalidData => "invalid_response",
        _ => "fpm_error",
    }
}

pub fn php_fpm_endpoints_from_config(config: &PhpFpmConfig) -> Vec<PhpFpmEndpoint> {
    if !config.tcp_upstreams.is_empty() {
        return config
            .tcp_upstreams
            .iter()
            .cloned()
            .map(PhpFpmEndpoint::Tcp)
            .collect();
    }
    if let Some(address) = config.tcp.as_deref() {
        return vec![PhpFpmEndpoint::Tcp(address.to_owned())];
    }
    if let Some(socket) = config.socket.as_deref() {
        #[cfg(unix)]
        {
            return vec![PhpFpmEndpoint::Unix(socket.to_path_buf())];
        }
        #[cfg(not(unix))]
        {
            let _ = socket;
            return Vec::new();
        }
    }
    Vec::new()
}

pub fn php_fpm_effective_connect_timeout(
    fpm: &PhpFpmConfig,
    request_timeout: Duration,
) -> Duration {
    fpm.connect_timeout_secs
        .map(Duration::from_secs)
        .map(|connect_timeout| connect_timeout.min(request_timeout))
        .unwrap_or(request_timeout)
}

pub fn php_fpm_effective_request_timeout(
    fpm: &PhpFpmConfig,
    request_timeout: Duration,
) -> Duration {
    [fpm.read_timeout_secs, fpm.write_timeout_secs]
        .into_iter()
        .flatten()
        .map(Duration::from_secs)
        .fold(request_timeout, Duration::min)
}

fn php_fpm_retry_method_allowed(fpm: &PhpFpmConfig, method: &str) -> bool {
    fpm.retry_methods
        .iter()
        .any(|retry_method| retry_method.eq_ignore_ascii_case(method))
}

pub fn php_fpm_retry_attempts(fpm: &PhpFpmConfig, method: &str) -> u8 {
    php_fpm_retry_attempts_for_endpoint_count(fpm, method, 1)
}

pub fn php_fpm_retry_attempts_for_endpoint_count(
    fpm: &PhpFpmConfig,
    method: &str,
    endpoint_count: usize,
) -> u8 {
    if !php_fpm_retry_method_allowed(fpm, method) {
        return 0;
    }
    let failover_retries = endpoint_count.saturating_sub(1).min(usize::from(u8::MAX)) as u8;
    fpm.max_retries.max(failover_retries)
}

pub fn php_fpm_retry_deadline(retry_timeout_secs: Option<u64>) -> Option<Instant> {
    retry_timeout_secs.and_then(|secs| Instant::now().checked_add(Duration::from_secs(secs)))
}

pub fn php_fpm_retry_deadline_allows(deadline: Option<Instant>) -> bool {
    match deadline {
        Some(deadline) => Instant::now() < deadline,
        None => true,
    }
}

pub fn php_fpm_retryable_status(fpm: &PhpFpmConfig, status: u16) -> bool {
    fpm.retry_statuses.contains(&status)
}

pub fn php_fpm_retryable_error(error: &io::Error) -> bool {
    match error.kind() {
        io::ErrorKind::TimedOut => php_fpm_timeout_kind(error) == Some(PhpFpmTimeoutKind::Connect),
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::NotConnected
        | io::ErrorKind::AddrInUse
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::NotFound
        | io::ErrorKind::UnexpectedEof => true,
        _ => false,
    }
}

pub fn safe_php_header_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

pub fn safe_php_header_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|byte| matches!(byte, b' ' | b'\t' | 0x21..=0x7E))
}

pub fn safe_php_param_value(value: &str) -> bool {
    value.len() <= MAX_PHP_PARAM_VALUE_BYTES
        && value.bytes().all(|byte| !matches!(byte, 0..=31 | 127))
}

pub fn php_header_param_name(name: &str) -> Option<String> {
    if name.eq_ignore_ascii_case("proxy")
        || name.eq_ignore_ascii_case("content-type")
        || name.eq_ignore_ascii_case("content-length")
    {
        return None;
    }
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return None;
    }

    let mut param = String::with_capacity("HTTP_".len() + name.len());
    param.push_str("HTTP_");
    for byte in name.bytes() {
        if byte == b'-' {
            param.push('_');
        } else {
            param.push((byte as char).to_ascii_uppercase());
        }
    }
    Some(param)
}

pub fn php_server_name_param(host: &str, fallback: &str) -> String {
    if safe_php_param_value(host) && !host.is_empty() {
        return host.to_owned();
    }
    if safe_php_param_value(fallback) && !fallback.is_empty() {
        return fallback.to_owned();
    }
    "localhost".to_owned()
}

pub fn php_request_header_params<'a, I>(headers: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut translated = std::collections::BTreeMap::<String, String>::new();
    for (name, value) in headers {
        let Some(param_name) = php_header_param_name(name) else {
            continue;
        };
        if !safe_php_param_value(value) {
            continue;
        }
        translated
            .entry(param_name)
            .and_modify(|existing| {
                let separator = if name.eq_ignore_ascii_case("cookie") {
                    "; "
                } else {
                    ", "
                };
                if existing
                    .len()
                    .saturating_add(separator.len())
                    .saturating_add(value.len())
                    <= MAX_PHP_PARAM_VALUE_BYTES
                {
                    existing.push_str(separator);
                    existing.push_str(value);
                }
            })
            .or_insert_with(|| value.to_owned());
    }
    translated.into_iter().collect()
}

pub fn php_host_param(host: &str) -> Option<(String, String)> {
    safe_php_param_value(host).then(|| ("HTTP_HOST".to_owned(), host.to_owned()))
}

pub fn php_content_type_param_value<'a, I>(values: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    let mut result = String::new();
    for value in values {
        if !safe_php_param_value(value) {
            return String::new();
        }
        let next_len = if result.is_empty() {
            value.len()
        } else {
            result
                .len()
                .saturating_add(", ".len())
                .saturating_add(value.len())
        };
        if next_len > MAX_PHP_PARAM_VALUE_BYTES {
            return String::new();
        }
        if result.capacity() < next_len {
            result.reserve(next_len.saturating_sub(result.len()));
        }
        if !result.is_empty() {
            result.push_str(", ");
        }
        result.push_str(value);
    }
    result
}

pub fn php_custom_params<'a, I>(custom: I) -> (Vec<(String, String)>, Vec<String>)
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut accepted = Vec::new();
    let mut dropped = Vec::new();
    for (name, value) in custom {
        if fluxheim_config::protected_php_param_name(name) || !safe_php_param_value(value) {
            dropped.push(name.to_owned());
            continue;
        }
        accepted.push((name.to_owned(), value.to_owned()));
    }
    (accepted, dropped)
}

pub fn php_fpm_script_filename(root: &Path, fpm_root: &Path, local_path: &Path) -> Option<String> {
    let relative = local_path.strip_prefix(root).ok()?;
    fpm_root.join(relative).to_str().map(str::to_owned)
}

pub fn php_fpm_path_translated(fpm_root: &Path, path_info: &str) -> Option<String> {
    let mut translated = fpm_root.to_path_buf();
    for segment in path_info.trim_start_matches('/').split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.starts_with('.')
            || segment.contains('\\')
            || segment.chars().any(char::is_control)
        {
            return None;
        }
        translated.push(segment);
    }
    translated.to_str().map(str::to_owned)
}

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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PhpScriptName {
    pub script_name: String,
    pub path_info: String,
    pub explicit_php: bool,
}

pub fn php_script_name_for_request(
    request_path: &str,
    index: &str,
    path_info: fluxheim_config::PhpPathInfoMode,
    allowed_extensions: &[String],
) -> Option<PhpScriptName> {
    let decoded = percent_encoding::percent_decode_str(request_path)
        .decode_utf8()
        .ok()?;
    if !decoded.starts_with('/') || decoded.chars().any(char::is_control) {
        return None;
    }

    let mut segments = Vec::new();
    for segment in decoded.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." || segment.contains('\\') || segment.starts_with('.') {
            return None;
        }
        segments.push(segment.to_owned());
    }

    if let Some((index, _)) = segments
        .iter()
        .enumerate()
        .find(|(_, segment)| php_segment_has_allowed_extension(segment, allowed_extensions))
    {
        let script_name = format!("/{}", segments[..=index].join("/"));
        let trailing = &segments[index + 1..];
        if !trailing.is_empty() && path_info == fluxheim_config::PhpPathInfoMode::Disabled {
            return None;
        }
        let path_info = if trailing.is_empty() {
            String::new()
        } else {
            format!("/{}", trailing.join("/"))
        };
        return Some(PhpScriptName {
            script_name,
            path_info,
            explicit_php: true,
        });
    }

    Some(PhpScriptName {
        script_name: format!("/{index}"),
        path_info: String::new(),
        explicit_php: false,
    })
}

pub fn php_script_name_denied(deny_path_prefixes: &[String], script_name: &str) -> bool {
    deny_path_prefixes.iter().any(|prefix| {
        script_name == prefix
            || script_name
                .strip_prefix(prefix)
                .is_some_and(|rest| prefix.ends_with('/') || rest.starts_with('/'))
    })
}

pub fn php_should_redirect_directory_index(
    request_path: &str,
    script_name: &str,
    index: &str,
) -> bool {
    if request_path.ends_with('/') || request_path.contains('\\') {
        return false;
    }
    let Some(parent) = script_name.strip_suffix(&format!("/{index}")) else {
        return false;
    };
    !parent.is_empty() && parent == request_path
}

pub fn php_static_file_script_name(
    root: &Path,
    local_path: &Path,
    allowed_extensions: &[String],
) -> Option<String> {
    let relative = local_path.strip_prefix(root).ok()?;
    let mut script_name = String::new();
    for component in relative.components() {
        let std::path::Component::Normal(segment) = component else {
            return None;
        };
        let segment = segment.to_str()?;
        if segment.is_empty() || segment == "." || segment == ".." || segment.starts_with('.') {
            return None;
        }
        script_name.push('/');
        script_name.push_str(segment);
    }
    if script_name.is_empty()
        || !php_segment_has_allowed_extension(&script_name, allowed_extensions)
    {
        return None;
    }
    Some(script_name)
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

pub fn php_segment_has_allowed_extension(segment: &str, allowed_extensions: &[String]) -> bool {
    segment.rsplit_once('.').is_some_and(|(_, extension)| {
        allowed_extensions
            .iter()
            .any(|allowed| extension.eq_ignore_ascii_case(allowed))
    })
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

pub fn managed_php_fpm_restart_backoff_secs(restart_failures: usize) -> u64 {
    2_u64.saturating_pow(restart_failures.min(5) as u32).min(30)
}

pub fn managed_php_fpm_path_env_from(value: Option<String>) -> String {
    const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

    value
        .filter(|value| {
            !value.is_empty() && value.bytes().all(|byte| !matches!(byte, 0..=31 | 127))
        })
        .unwrap_or_else(|| DEFAULT_PATH.to_owned())
}

pub fn managed_php_fpm_instance_name(metric_pool: &str) -> io::Result<String> {
    let counter = MANAGED_PHP_FPM_INSTANCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    managed_php_fpm_instance_name_from_parts(
        metric_pool,
        std::process::id(),
        counter,
        managed_php_fpm_instance_random()?,
    )
}

fn managed_php_fpm_instance_random() -> io::Result<u64> {
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|error| {
        io::Error::other(format!(
            "failed to generate managed php-fpm instance entropy: {error}"
        ))
    })?;
    Ok(u64::from_le_bytes(random))
}

fn managed_php_fpm_instance_name_from_parts(
    metric_pool: &str,
    pid: u32,
    counter: usize,
    random: u64,
) -> io::Result<String> {
    let sanitized = metric_pool
        .bytes()
        .map(|byte| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' => byte as char,
            _ => '-',
        })
        .take(48)
        .collect::<String>();
    let sanitized = if sanitized.is_empty() {
        "php".to_owned()
    } else {
        sanitized
    };
    Ok(format!(
        "fluxheim-php-fpm-{sanitized}-{pid}-{counter}-{random:016x}"
    ))
}

pub fn managed_php_fpm_config(
    socket: &Path,
    pid_path: &Path,
    error_log: &Path,
    slow_log: Option<&Path>,
    fpm: &PhpFpmConfig,
) -> io::Result<String> {
    let socket = php_fpm_config_path_value(socket)?;
    let pid_path = php_fpm_config_path_value(pid_path)?;
    let error_log = php_fpm_config_path_value(error_log)?;
    let slow_log = slow_log.map(php_fpm_config_path_value).transpose()?;
    let session_save_path = fpm
        .session_save_path
        .as_deref()
        .map(php_fpm_config_path_value)
        .transpose()?;
    let upload_tmp_dir = fpm
        .upload_tmp_dir
        .as_deref()
        .map(php_fpm_config_path_value)
        .transpose()?;

    let mut config = String::new();
    config.push_str("[global]\n");
    config.push_str("daemonize = no\n");
    config.push_str(&format!("pid = {pid_path}\n"));
    config.push_str(&format!("error_log = {error_log}\n"));
    config.push('\n');
    config.push_str("[fluxheim]\n");
    config.push_str(&format!("listen = {socket}\n"));
    let listen_mode = match fpm.listen_mode.as_deref() {
        Some(value) => php_fpm_config_listen_mode_value(value)?,
        None => "0600",
    };
    config.push_str(&format!("listen.mode = {listen_mode}\n"));
    if let (Some(listen_owner), Some(listen_group)) = (&fpm.listen_owner, &fpm.listen_group) {
        let listen_owner = php_fpm_config_identity_value(listen_owner)?;
        let listen_group = php_fpm_config_identity_value(listen_group)?;
        config.push_str(&format!("listen.owner = {listen_owner}\n"));
        config.push_str(&format!("listen.group = {listen_group}\n"));
    }
    if let Some(listen_backlog) = fpm.listen_backlog {
        config.push_str(&format!("listen.backlog = {listen_backlog}\n"));
    }
    config.push_str(&managed_php_fpm_identity_config(
        fpm.user.as_deref(),
        fpm.group.as_deref(),
    )?);
    config.push_str(&managed_php_fpm_pool_config(fpm));
    if let Some(request_terminate_timeout_secs) = fpm.request_terminate_timeout_secs {
        config.push_str(&format!(
            "request_terminate_timeout = {request_terminate_timeout_secs}s\n"
        ));
    }
    if fpm.request_terminate_timeout_track_finished {
        config.push_str("request_terminate_timeout_track_finished = yes\n");
    }
    if let Some(request_slowlog_timeout_secs) = fpm.request_slowlog_timeout_secs {
        if let Some(slow_log) = slow_log {
            config.push_str(&format!("slowlog = {slow_log}\n"));
        }
        config.push_str(&format!(
            "request_slowlog_timeout = {request_slowlog_timeout_secs}s\n"
        ));
        config.push_str(&format!(
            "request_slowlog_trace_depth = {}\n",
            fpm.request_slowlog_trace_depth
        ));
    }
    config.push_str(&format!(
        "clear_env = {}\n",
        managed_php_fpm_bool(fpm.clear_env)
    ));
    config.push_str(&format!(
        "catch_workers_output = {}\n",
        managed_php_fpm_bool(fpm.catch_workers_output)
    ));
    config.push_str(&format!(
        "decorate_workers_output = {}\n",
        managed_php_fpm_bool(fpm.decorate_workers_output)
    ));
    config.push_str("chdir = /\n");
    config.push_str("security.limit_extensions = .php\n");
    if let Some(session_save_path) = session_save_path {
        config.push_str(&format!(
            "php_value[session.save_path] = {session_save_path}\n"
        ));
    }
    if let Some(upload_tmp_dir) = upload_tmp_dir {
        config.push_str(&format!(
            "php_admin_value[upload_tmp_dir] = {upload_tmp_dir}\n"
        ));
    }
    Ok(config)
}

fn managed_php_fpm_pool_config(fpm: &PhpFpmConfig) -> String {
    let mut config = String::new();
    match fpm.process_manager {
        PhpFpmProcessManager::Static => {
            config.push_str("pm = static\n");
            config.push_str(&format!("pm.max_children = {}\n", fpm.workers));
        }
        PhpFpmProcessManager::Dynamic => {
            let min_spare = fpm.min_spare_servers.unwrap_or(1);
            let max_spare = fpm.max_spare_servers.unwrap_or(fpm.workers.max(min_spare));
            let start_servers = fpm
                .start_servers
                .unwrap_or_else(|| (min_spare.saturating_add(max_spare) / 2).max(1));
            config.push_str("pm = dynamic\n");
            config.push_str(&format!("pm.max_children = {}\n", fpm.workers));
            config.push_str(&format!("pm.start_servers = {start_servers}\n"));
            config.push_str(&format!("pm.min_spare_servers = {min_spare}\n"));
            config.push_str(&format!("pm.max_spare_servers = {max_spare}\n"));
            if let Some(max_spawn_rate) = fpm.max_spawn_rate {
                config.push_str(&format!("pm.max_spawn_rate = {max_spawn_rate}\n"));
            }
        }
        PhpFpmProcessManager::Ondemand => {
            config.push_str("pm = ondemand\n");
            config.push_str(&format!("pm.max_children = {}\n", fpm.workers));
            if let Some(process_idle_timeout_secs) = fpm.process_idle_timeout_secs {
                config.push_str(&format!(
                    "pm.process_idle_timeout = {process_idle_timeout_secs}s\n"
                ));
            }
        }
    }
    config.push_str(&format!(
        "pm.max_requests = {}\n",
        fpm.max_requests_per_worker
    ));
    config
}

fn managed_php_fpm_bool(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn managed_php_fpm_identity_config(user: Option<&str>, group: Option<&str>) -> io::Result<String> {
    match (user, group) {
        (Some(user), Some(group)) => {
            let user = php_fpm_config_identity_value(user)?;
            let group = php_fpm_config_identity_value(group)?;
            Ok(format!("user = {user}\ngroup = {group}\n"))
        }
        _ => Ok(String::new()),
    }
}

fn php_fpm_config_identity_value(value: &str) -> io::Result<&str> {
    if value.is_empty()
        || value.len() > 64
        || value.starts_with('-')
        || !value.bytes().all(
            |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'.' | b'-'),
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed php-fpm identity contains bytes unsafe for php-fpm config",
        ));
    }
    Ok(value)
}

fn php_fpm_config_listen_mode_value(value: &str) -> io::Result<&str> {
    match value {
        "0600" | "0660" => Ok(value),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed php-fpm listen mode must be 0600 or 0660",
        )),
    }
}

fn php_fpm_config_path_value(path: &Path) -> io::Result<&str> {
    let value = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed php-fpm path is not valid UTF-8",
        )
    })?;
    if value
        .bytes()
        .any(|byte| matches!(byte, 0..=31 | 127 | b'\'' | b'"'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed php-fpm path contains bytes unsafe for php-fpm config",
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::Path;

    use super::{
        MAX_PHP_PARAM_VALUE_BYTES, PhpFpmEndpoint, PhpFpmTimeoutKind, managed_php_fpm_config,
        managed_php_fpm_instance_name_from_parts, managed_php_fpm_path_env_from,
        managed_php_fpm_restart_backoff_secs, parse_php_status, php_content_type_param_value,
        php_custom_params, php_fpm_effective_connect_timeout, php_fpm_effective_request_timeout,
        php_fpm_endpoints_from_config, php_fpm_error_outcome, php_fpm_path_translated,
        php_fpm_retry_attempts, php_fpm_retry_attempts_for_endpoint_count, php_fpm_retryable_error,
        php_fpm_retryable_status, php_fpm_script_filename, php_fpm_timeout_error,
        php_header_param_name, php_host_param, php_request_header_params, php_script_name_denied,
        php_script_name_for_request, php_segment_has_allowed_extension, php_server_name_param,
        php_should_redirect_directory_index, php_static_file_script_name, safe_php_header_name,
        safe_php_header_value, safe_php_param_value, split_first_colon, split_php_response,
        trim_ascii, trim_ascii_cr,
    };
    use fluxheim_config::{PhpFpmConfig, PhpFpmProcessManager, PhpPathInfoMode};

    #[test]
    fn php_fpm_error_outcomes_are_bounded() {
        assert_eq!(
            php_fpm_error_outcome(&php_fpm_timeout_error(PhpFpmTimeoutKind::Connect)),
            "connect_timeout"
        );
        assert_eq!(
            php_fpm_error_outcome(&php_fpm_timeout_error(PhpFpmTimeoutKind::Request)),
            "request_timeout"
        );
        assert_eq!(
            php_fpm_error_outcome(&io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "connection refused",
            )),
            "connection_error"
        );
        assert_eq!(
            php_fpm_error_outcome(&io::Error::new(io::ErrorKind::InvalidInput, "missing fpm")),
            "configuration_error"
        );
        assert_eq!(
            php_fpm_error_outcome(&io::Error::new(io::ErrorKind::InvalidData, "bad response")),
            "invalid_response"
        );
        assert_eq!(
            php_fpm_error_outcome(&io::Error::other("backend failed")),
            "fpm_error"
        );
    }

    #[test]
    fn managed_php_fpm_path_env_falls_back_for_control_bytes() {
        assert_eq!(
            managed_php_fpm_path_env_from(Some("/usr/bin\n/tmp".to_owned())),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        );
    }

    #[test]
    fn managed_php_fpm_restart_backoff_is_bounded() {
        assert_eq!(managed_php_fpm_restart_backoff_secs(0), 1);
        assert_eq!(managed_php_fpm_restart_backoff_secs(1), 2);
        assert_eq!(managed_php_fpm_restart_backoff_secs(4), 16);
        assert_eq!(managed_php_fpm_restart_backoff_secs(64), 30);
    }

    #[test]
    fn managed_php_fpm_instance_names_are_sanitized_and_bounded() {
        assert_eq!(
            managed_php_fpm_instance_name_from_parts("pool/main:php", 42, 7, 0xfeed).unwrap(),
            "fluxheim-php-fpm-pool-main-php-42-7-000000000000feed"
        );
        assert_eq!(
            managed_php_fpm_instance_name_from_parts("", 42, 7, 0xfeed).unwrap(),
            "fluxheim-php-fpm-php-42-7-000000000000feed"
        );

        let long_name =
            managed_php_fpm_instance_name_from_parts(&"a".repeat(96), 42, 7, 0xfeed).unwrap();
        assert!(long_name.contains(&"a".repeat(48)));
        assert!(!long_name.contains(&"a".repeat(49)));
    }

    #[test]
    fn php_fpm_endpoints_include_tcp_upstreams() {
        let fpm = PhpFpmConfig {
            tcp: Some("127.0.0.1:9000".to_owned()),
            tcp_upstreams: vec!["127.0.0.1:9000".to_owned(), "127.0.0.1:9001".to_owned()],
            ..PhpFpmConfig::default()
        };

        assert_eq!(
            php_fpm_endpoints_from_config(&fpm),
            vec![
                PhpFpmEndpoint::Tcp("127.0.0.1:9000".to_owned()),
                PhpFpmEndpoint::Tcp("127.0.0.1:9001".to_owned()),
            ]
        );
    }

    #[test]
    fn php_fpm_retry_attempts_respect_method_allowlist_and_failover() {
        let mut fpm = PhpFpmConfig {
            max_retries: 2,
            retry_methods: vec!["GET".to_owned()],
            ..PhpFpmConfig::default()
        };

        assert_eq!(php_fpm_retry_attempts(&fpm, "GET"), 2);
        assert_eq!(php_fpm_retry_attempts(&fpm, "POST"), 0);
        assert_eq!(php_fpm_retry_attempts_for_endpoint_count(&fpm, "GET", 4), 3);

        fpm.retry_methods.clear();
        assert_eq!(php_fpm_retry_attempts_for_endpoint_count(&fpm, "GET", 4), 0);
    }

    #[test]
    fn php_fpm_effective_timeouts_are_capped_by_request_timeout() {
        let request_timeout = std::time::Duration::from_secs(10);
        let mut fpm = PhpFpmConfig {
            connect_timeout_secs: Some(20),
            read_timeout_secs: Some(7),
            write_timeout_secs: Some(4),
            ..PhpFpmConfig::default()
        };

        assert_eq!(
            php_fpm_effective_connect_timeout(&fpm, request_timeout),
            request_timeout
        );
        assert_eq!(
            php_fpm_effective_request_timeout(&fpm, request_timeout),
            std::time::Duration::from_secs(4)
        );

        fpm.connect_timeout_secs = Some(3);
        assert_eq!(
            php_fpm_effective_connect_timeout(&fpm, request_timeout),
            std::time::Duration::from_secs(3)
        );
    }

    #[test]
    fn php_fpm_retryable_statuses_and_errors_are_explicit() {
        let fpm = PhpFpmConfig {
            retry_statuses: vec![502, 503],
            ..PhpFpmConfig::default()
        };

        assert!(php_fpm_retryable_status(&fpm, 502));
        assert!(php_fpm_retryable_status(&fpm, 503));
        assert!(!php_fpm_retryable_status(&fpm, 404));
        assert!(php_fpm_retryable_error(&io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "refused"
        )));
        assert!(!php_fpm_retryable_error(&php_fpm_timeout_error(
            PhpFpmTimeoutKind::Request
        )));
    }

    #[test]
    fn php_header_guards_reject_injection_bytes() {
        assert!(safe_php_header_name(b"X-PHP-Header"));
        assert!(safe_php_header_name(b"X_PHP.Token"));
        assert!(!safe_php_header_name(b""));
        assert!(!safe_php_header_name(b"bad:name"));
        assert!(!safe_php_header_name(b"bad name"));

        assert!(safe_php_header_value(b"session=ok; Path=/"));
        assert!(safe_php_header_value(b"tab\tallowed"));
        assert!(!safe_php_header_value(b"bad\x0binject"));
        assert!(!safe_php_header_value(b"bad\x7fdelete"));
        assert!(!safe_php_header_value(b"bad\r\ninject"));
        assert!(!safe_php_header_value("bad-é".as_bytes()));
    }

    #[test]
    fn php_param_values_are_bounded_and_control_free() {
        assert!(safe_php_param_value("content-type-value"));
        assert!(safe_php_param_value(&"a".repeat(MAX_PHP_PARAM_VALUE_BYTES)));
        assert!(!safe_php_param_value(
            &"a".repeat(MAX_PHP_PARAM_VALUE_BYTES + 1)
        ));
        assert!(!safe_php_param_value("bad\nvalue"));
        assert!(!safe_php_param_value("bad\x7fvalue"));
    }

    #[test]
    fn php_header_param_names_are_bounded_and_predictable() {
        assert_eq!(
            php_header_param_name("x-request-id").as_deref(),
            Some("HTTP_X_REQUEST_ID")
        );
        assert_eq!(php_header_param_name("proxy"), None);
        assert_eq!(php_header_param_name("content-type"), None);
        assert_eq!(php_header_param_name("content-length"), None);
        assert_eq!(php_header_param_name("bad name"), None);
        assert_eq!(php_header_param_name("bad_name"), None);
    }

    #[test]
    fn php_server_name_prefers_safe_host_then_safe_fallback() {
        assert_eq!(
            php_server_name_param("example.test", "fallback.test"),
            "example.test"
        );
        assert_eq!(
            php_server_name_param("bad\nhost", "fallback.test"),
            "fallback.test"
        );
        assert_eq!(
            php_server_name_param("bad\nhost", "bad\rfallback"),
            "localhost"
        );
    }

    #[test]
    fn php_request_header_params_join_duplicate_headers_and_block_proxy() {
        let params = php_request_header_params([
            ("cookie", "wordpress_logged_in=abc"),
            ("cookie", "wordpress_sec=def"),
            ("proxy", "http://attacker.invalid"),
            ("x-request-id", "req-1"),
            ("x-request-id", "req-2"),
        ]);

        assert_eq!(
            params,
            vec![
                (
                    "HTTP_COOKIE".to_owned(),
                    "wordpress_logged_in=abc; wordpress_sec=def".to_owned()
                ),
                ("HTTP_X_REQUEST_ID".to_owned(), "req-1, req-2".to_owned())
            ]
        );
    }

    #[test]
    fn php_request_header_params_cap_joined_values() {
        let cookie = "a".repeat(MAX_PHP_PARAM_VALUE_BYTES / 2);
        let params = php_request_header_params([
            ("cookie", cookie.as_str()),
            ("cookie", cookie.as_str()),
            ("cookie", cookie.as_str()),
        ]);
        let (_, value) = params
            .iter()
            .find(|(name, _)| name == "HTTP_COOKIE")
            .expect("cookie param should be present");
        assert!(value.len() <= MAX_PHP_PARAM_VALUE_BYTES);
    }

    #[test]
    fn php_host_content_type_and_custom_params_share_runtime_policy() {
        assert_eq!(
            php_host_param("example.test"),
            Some(("HTTP_HOST".to_owned(), "example.test".to_owned()))
        );
        assert_eq!(php_host_param("bad\nhost"), None);
        assert_eq!(
            php_content_type_param_value(["text/plain", "charset=utf-8"]),
            "text/plain, charset=utf-8"
        );
        assert_eq!(php_content_type_param_value(["text/plain\nbad"]), "");
        assert_eq!(
            php_content_type_param_value(["a".repeat(MAX_PHP_PARAM_VALUE_BYTES + 1).as_str()]),
            ""
        );
        let half = "a".repeat(MAX_PHP_PARAM_VALUE_BYTES / 2);
        assert_eq!(
            php_content_type_param_value([half.as_str(), half.as_str(), half.as_str()]),
            ""
        );

        let (accepted, dropped) = php_custom_params([
            ("SAFE_PARAM", "ok"),
            ("SCRIPT_FILENAME", "/tmp/bypass.php"),
            ("PHP_VALUE", "memory_limit=256M"),
            ("BAD_VALUE", "bad\nvalue"),
        ]);
        assert_eq!(accepted, vec![("SAFE_PARAM".to_owned(), "ok".to_owned())]);
        assert_eq!(
            dropped,
            vec![
                "SCRIPT_FILENAME".to_owned(),
                "PHP_VALUE".to_owned(),
                "BAD_VALUE".to_owned()
            ]
        );
    }

    #[test]
    fn php_fpm_path_mapping_supports_split_container_roots_and_rejects_unsafe_path_info() {
        let root = Path::new("site/root");
        let fpm_root = Path::new("container/root");
        let local_script = Path::new("site/root/public/index.php");

        assert_eq!(
            php_fpm_script_filename(root, fpm_root, local_script).as_deref(),
            Some("container/root/public/index.php")
        );
        assert_eq!(
            php_fpm_script_filename(Path::new("other/root"), fpm_root, local_script),
            None
        );
        assert_eq!(
            php_fpm_path_translated(fpm_root, "/uploads/file.txt").as_deref(),
            Some("container/root/uploads/file.txt")
        );
        assert!(php_fpm_path_translated(fpm_root, "/uploads/../wp-config.php").is_none());
        assert!(php_fpm_path_translated(fpm_root, "/uploads/.secret").is_none());
        assert!(php_fpm_path_translated(fpm_root, "/uploads\\wp-config.php").is_none());
        assert!(php_fpm_path_translated(fpm_root, "/uploads/file\x01.txt").is_none());
    }

    #[test]
    fn php_script_name_parser_accepts_direct_script_and_front_controller() {
        let allowed = vec!["php".to_owned()];

        let direct = php_script_name_for_request(
            "/app.php",
            "index.php",
            PhpPathInfoMode::Disabled,
            &allowed,
        )
        .expect("direct PHP script should parse");
        assert_eq!(direct.script_name, "/app.php");
        assert_eq!(direct.path_info, "");
        assert!(direct.explicit_php);

        let front = php_script_name_for_request(
            "/missing/page",
            "index.php",
            PhpPathInfoMode::Disabled,
            &allowed,
        )
        .expect("front controller fallback should parse");
        assert_eq!(front.script_name, "/index.php");
        assert_eq!(front.path_info, "");
        assert!(!front.explicit_php);
    }

    #[test]
    fn php_script_name_parser_rejects_unsafe_segments_and_controls() {
        let allowed = vec!["php".to_owned()];

        assert!(
            php_script_name_for_request(
                "/../app.php",
                "index.php",
                PhpPathInfoMode::Disabled,
                &allowed
            )
            .is_none()
        );
        assert!(
            php_script_name_for_request(
                "/app.php/.hidden",
                "index.php",
                PhpPathInfoMode::Split,
                &allowed
            )
            .is_none()
        );
        assert!(
            php_script_name_for_request(
                "/app.php/user%01admin",
                "index.php",
                PhpPathInfoMode::Split,
                &allowed
            )
            .is_none()
        );
        assert!(
            php_script_name_for_request(
                "/app.php/user%7Fadmin",
                "index.php",
                PhpPathInfoMode::Split,
                &allowed
            )
            .is_none()
        );
    }

    #[test]
    fn php_script_name_parser_respects_path_info_and_deny_prefixes() {
        let allowed = vec!["php".to_owned()];

        assert!(
            php_script_name_for_request(
                "/app.php/user/1",
                "index.php",
                PhpPathInfoMode::Disabled,
                &allowed
            )
            .is_none()
        );
        let split = php_script_name_for_request(
            "/app.php/user/1",
            "index.php",
            PhpPathInfoMode::Split,
            &allowed,
        )
        .expect("split PATH_INFO should parse");
        assert_eq!(split.script_name, "/app.php");
        assert_eq!(split.path_info, "/user/1");
        assert!(split.explicit_php);

        let deny = vec!["/wp-content/uploads/".to_owned()];
        assert!(php_script_name_denied(
            &deny,
            "/wp-content/uploads/shell.php"
        ));
        assert!(!php_script_name_denied(
            &deny,
            "/wp-content/uploads2/app.php"
        ));
        assert!(php_segment_has_allowed_extension("index.PHP", &allowed));
        assert!(!php_segment_has_allowed_extension("style.css", &allowed));
    }

    #[test]
    fn php_static_file_script_names_are_rooted_and_hidden_safe() {
        let allowed = vec!["php".to_owned()];
        let root = Path::new("/srv/www");

        assert_eq!(
            php_static_file_script_name(root, Path::new("/srv/www/blog/index.php"), &allowed),
            Some("/blog/index.php".to_owned())
        );
        assert_eq!(
            php_static_file_script_name(root, Path::new("/srv/www/admin.PHP"), &allowed),
            Some("/admin.PHP".to_owned())
        );
        assert!(
            php_static_file_script_name(root, Path::new("/srv/www/assets/style.css"), &allowed)
                .is_none()
        );
        assert!(
            php_static_file_script_name(root, Path::new("/srv/www/.hidden/index.php"), &allowed)
                .is_none()
        );
        assert!(
            php_static_file_script_name(root, Path::new("/srv/other/index.php"), &allowed)
                .is_none()
        );
    }

    #[test]
    fn php_directory_index_redirect_policy_matches_runtime() {
        assert!(php_should_redirect_directory_index(
            "/blog",
            "/blog/index.php",
            "index.php"
        ));
        assert!(!php_should_redirect_directory_index(
            "/blog/",
            "/blog/index.php",
            "index.php"
        ));
        assert!(!php_should_redirect_directory_index(
            "/blog\\",
            "/blog/index.php",
            "index.php"
        ));
        assert!(!php_should_redirect_directory_index(
            "/blog",
            "/blog/admin.php",
            "index.php"
        ));
    }

    #[test]
    fn php_static_offload_policy_rejects_controls_and_script_targets() {
        let allowed = vec!["php".to_owned()];

        assert_eq!(
            super::php_static_offload_uri_target("/style.css").unwrap(),
            "/style.css"
        );
        assert!(super::php_static_offload_uri_target("/style.css\nbad").is_err());
        assert!(super::php_static_offload_file_allowed(
            Path::new("/srv/www/style.css"),
            &allowed
        ));
        assert!(!super::php_static_offload_file_allowed(
            Path::new("/srv/www/app.PHP"),
            &allowed
        ));
        assert!(!super::php_static_offload_file_allowed(
            Path::new("/srv/www/wp-config"),
            &allowed
        ));
        assert!(!super::php_static_offload_file_allowed(
            Path::new("/srv/www/file."),
            &allowed
        ));
    }

    #[test]
    fn php_x_sendfile_targets_map_from_fpm_root_to_local_root() {
        let root = Path::new("/srv/www");
        let fpm_root = Path::new("/app/public");

        assert_eq!(
            super::php_static_offload_x_sendfile_local_path(
                root,
                fpm_root,
                "/app/public/assets/style.css"
            )
            .unwrap(),
            Path::new("/srv/www/assets/style.css")
        );
        assert_eq!(
            super::php_static_offload_x_sendfile_local_path(
                root,
                fpm_root,
                "/app/public/../secret.txt"
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            super::php_static_offload_x_sendfile_local_path(root, fpm_root, "/other/style.css")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            super::php_static_offload_x_sendfile_local_path(
                root,
                fpm_root,
                "/app/public/style.css\nbad"
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn php_x_accel_expires_ttl_parser_is_bounded() {
        let future = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        let ttl = super::php_x_accel_expires_ttl_secs(&format!("@{future}")).unwrap();

        assert!(ttl <= 60);
        assert!(ttl > 0);
        assert_eq!(super::php_x_accel_expires_ttl_secs("120"), Some(120));
        assert_eq!(super::php_x_accel_expires_ttl_secs("0"), Some(0));
        assert_eq!(super::php_x_accel_expires_ttl_secs("-1"), Some(0));
        assert_eq!(super::php_x_accel_expires_ttl_secs("bad"), None);
    }

    #[test]
    fn php_origin_cache_policy_detects_restrictive_directives() {
        assert!(super::php_origin_cache_policy_is_restrictive(
            ["public, private=max-age=1"],
            []
        ));
        assert!(super::php_origin_cache_policy_is_restrictive(
            ["public, no-store"],
            []
        ));
        assert!(super::php_origin_cache_policy_is_restrictive(
            ["public"],
            ["no-cache"]
        ));
        assert!(!super::php_origin_cache_policy_is_restrictive(
            ["public, max-age=60"],
            []
        ));
    }

    #[test]
    fn php_response_header_strip_policy_includes_connection_tokens_and_hidden_names() {
        let hidden = vec!["x-powered-by".to_owned()];
        let headers =
            super::php_response_headers_to_strip(["x-hop, keep-alive, bad token"], &hidden);

        assert!(headers.iter().any(|header| header == "connection"));
        assert!(headers.iter().any(|header| header == "transfer-encoding"));
        assert!(headers.iter().any(|header| header == "x-hop"));
        assert!(headers.iter().any(|header| header == "keep-alive"));
        assert!(!headers.iter().any(|header| header == "bad token"));
        assert!(headers.iter().any(|header| header == "x-powered-by"));
    }

    #[test]
    fn php_static_offload_header_names_are_shared_policy() {
        assert_eq!(
            super::PHP_STATIC_OFFLOAD_RESPONSE_HEADERS,
            &["x-accel-redirect", "x-sendfile"]
        );
    }

    #[test]
    fn php_error_page_or_intercept_status_enables_interception() {
        assert!(super::php_should_intercept_error_status(502, [502], &[]));
        assert!(super::php_should_intercept_error_status(503, [], &[503]));
        assert!(!super::php_should_intercept_error_status(
            404,
            [502],
            &[503]
        ));
    }

    #[test]
    fn php_response_primitives_parse_headers_status_and_body() {
        let (headers, body) = split_php_response(b"Status: 201 Created\r\nX-Test: ok\r\n\r\nbody")
            .expect("response should split");
        assert_eq!(headers, b"Status: 201 Created\r\nX-Test: ok");
        assert_eq!(body, b"body");
        assert_eq!(parse_php_status(b"201 Created").unwrap(), 201);
        assert_eq!(trim_ascii_cr(b"value\r"), b"value");
        assert_eq!(trim_ascii(b" \tvalue\t "), b"value");
        assert_eq!(
            split_first_colon(b"x-test: value"),
            Some((&b"x-test"[..], &b" value"[..]))
        );
    }

    #[test]
    fn php_response_primitives_reject_invalid_status() {
        assert!(split_php_response(b"missing terminator").is_err());
        assert!(parse_php_status(b"99").is_err());
        assert!(parse_php_status(b"600").is_err());
        assert!(parse_php_status(b"not-a-status").is_err());
        assert!(parse_php_status(&[0xff]).is_err());
    }

    #[test]
    fn php_response_parser_returns_plain_status_headers_and_body() {
        let response = super::parse_php_response(
            b"X-Before: yes\r\nStatus: 201 Created\r\nX-After: ok\r\n\r\nbody",
            64 * 1024,
            64 * 1024,
        )
        .expect("PHP response should parse");

        assert_eq!(response.status, 201);
        assert_eq!(response.body, b"body");
        assert_eq!(
            response.headers,
            vec![
                ("X-Before".to_owned(), "yes".to_owned()),
                ("X-After".to_owned(), "ok".to_owned())
            ]
        );
    }

    #[test]
    fn php_response_parser_rejects_unsafe_headers_and_size_overflow() {
        let error = super::parse_php_response(b"X-Test: ok\rbad\r\n\r\nbody", 64 * 1024, 64 * 1024)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let error =
            super::parse_php_response(b"Content-Type: text/plain\r\n\r\nbody", 8, 64 * 1024)
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let error = super::parse_php_response(
            b"X-Very-Long-Header: abc\r\n\r\nbody",
            64 * 1024,
            "X-Very-Long-Header: abc".len() as u64 - 1,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn managed_php_fpm_config_contains_private_pool_settings() {
        let fpm = PhpFpmConfig {
            process_manager: PhpFpmProcessManager::Dynamic,
            workers: 8,
            min_spare_servers: Some(2),
            max_spare_servers: Some(6),
            start_servers: Some(4),
            max_spawn_rate: Some(16),
            listen_backlog: Some(128),
            listen_owner: Some("fluxheim".to_owned()),
            listen_group: Some("www-data".to_owned()),
            listen_mode: Some("0660".to_owned()),
            user: Some("fluxheim".to_owned()),
            group: Some("www-data".to_owned()),
            request_terminate_timeout_secs: Some(30),
            request_terminate_timeout_track_finished: true,
            request_slowlog_timeout_secs: Some(5),
            session_save_path: Some(Path::new("/run/fluxheim/php/session").to_path_buf()),
            upload_tmp_dir: Some(Path::new("/run/fluxheim/php/upload").to_path_buf()),
            clear_env: false,
            ..PhpFpmConfig::default()
        };

        let config = managed_php_fpm_config(
            Path::new("/run/fluxheim/php/php-fpm.sock"),
            Path::new("/run/fluxheim/php/php-fpm.pid"),
            Path::new("/run/fluxheim/php/php-fpm.log"),
            Some(Path::new("/run/fluxheim/php/php-fpm.slow.log")),
            &fpm,
        )
        .expect("managed php-fpm config should render");

        assert!(config.contains("listen.mode = 0660\n"));
        assert!(config.contains("listen.owner = fluxheim\n"));
        assert!(config.contains("listen.group = www-data\n"));
        assert!(config.contains("listen.backlog = 128\n"));
        assert!(config.contains("user = fluxheim\n"));
        assert!(config.contains("group = www-data\n"));
        assert!(config.contains("pm = dynamic\n"));
        assert!(config.contains("pm.max_children = 8\n"));
        assert!(config.contains("pm.start_servers = 4\n"));
        assert!(config.contains("pm.min_spare_servers = 2\n"));
        assert!(config.contains("pm.max_spare_servers = 6\n"));
        assert!(config.contains("pm.max_spawn_rate = 16\n"));
        assert!(config.contains("request_terminate_timeout = 30s\n"));
        assert!(config.contains("request_terminate_timeout_track_finished = yes\n"));
        assert!(config.contains("request_slowlog_timeout = 5s\n"));
        assert!(config.contains("slowlog = /run/fluxheim/php/php-fpm.slow.log\n"));
        assert!(config.contains("clear_env = no\n"));
        assert!(config.contains("catch_workers_output = yes\n"));
        assert!(config.contains("decorate_workers_output = yes\n"));
        assert!(config.contains("security.limit_extensions = .php\n"));
        assert!(config.contains("php_value[session.save_path] = /run/fluxheim/php/session\n"));
        assert!(config.contains("php_admin_value[upload_tmp_dir] = /run/fluxheim/php/upload\n"));
    }

    #[test]
    fn managed_php_fpm_config_rejects_unsafe_path_bytes() {
        let error = managed_php_fpm_config(
            Path::new("/run/fluxheim/php/php-fpm.sock"),
            Path::new("/run/fluxheim/php/php-fpm.pid"),
            Path::new("/run/fluxheim/php/php-fpm\".log"),
            None,
            &PhpFpmConfig::default(),
        )
        .expect_err("unsafe config paths should be rejected");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
