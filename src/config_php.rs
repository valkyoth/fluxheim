use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::{Path, PathBuf};

use crate::config::ConfigError;
#[cfg(unix)]
use crate::config::{PhpFpmConfig, PhpFpmProcessManager};
use crate::config_header::validate_header_name;
#[cfg(unix)]
use crate::config_path::{
    path_inspection_failed, validate_non_world_writable_parent, validate_path,
};

pub(crate) const MAX_PHP_ALLOWED_EXTENSIONS: usize = 16;
pub(crate) const MAX_PHP_DENY_PATH_PREFIXES: usize = 128;
pub(crate) const MAX_PHP_HIDE_RESPONSE_HEADERS: usize = 64;
pub(crate) const MAX_PHP_STDERR_FAILURE_PATTERNS: usize = 32;
pub(crate) const MAX_PHP_PARAMS: usize = 128;
pub(crate) const MAX_PHP_FPM_RETRY_METHODS: usize = 16;
pub(crate) const MAX_PHP_FPM_RETRY_STATUSES: usize = 100;
pub(crate) const MAX_PHP_INTERCEPT_ERROR_STATUSES: usize = 200;
const MAX_PHP_FPM_MANAGED_WORKERS: usize = 256;
const MAX_PHP_FPM_MANAGED_MAX_REQUESTS: usize = 1_000_000;
const MAX_PHP_FPM_MANAGED_MAX_SPAWN_RATE: usize = 1024;
const MAX_PHP_FPM_MANAGED_BACKLOG: i32 = 65_535;
const MAX_PHP_FPM_MANAGED_TIMEOUT_SECS: u64 = 86_400;
const MAX_PHP_FPM_SLOWLOG_TRACE_DEPTH: usize = 512;
const MAX_PHP_STDERR_FAILURE_PATTERN_BYTES: usize = 512;
const MAX_PHP_PARAM_NAME_BYTES: usize = 128;
const MAX_PHP_PARAM_VALUE_BYTES: usize = 16 * 1024;
const PHP_FPM_SAFE_RETRY_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "TRACE"];

pub(crate) fn validate_php_params(params: &BTreeMap<String, String>) -> Result<(), ConfigError> {
    if params.len() > MAX_PHP_PARAMS {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.params",
            reason: "at most 128 parameters are allowed",
        });
    }
    for (name, value) in params {
        validate_php_param_name(name)?;
        validate_php_param_value(value)?;
        warn_high_risk_php_param(name, value);
    }
    Ok(())
}

pub(crate) fn validate_php_index(index: &str) -> Result<(), ConfigError> {
    if index.trim().is_empty()
        || index.contains('/')
        || index.contains('\\')
        || index == "."
        || index == ".."
        || !index.ends_with(".php")
    {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.index",
            reason: "index must be a plain .php file name",
        });
    }
    Ok(())
}

pub(crate) fn validate_php_extensions(extensions: &[String]) -> Result<(), ConfigError> {
    if extensions.is_empty() {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.allowed_extensions",
            reason: "at least one extension is required",
        });
    }
    if extensions.len() > MAX_PHP_ALLOWED_EXTENSIONS {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.allowed_extensions",
            reason: "at most 16 extensions are allowed",
        });
    }
    let mut seen = BTreeSet::new();
    for extension in extensions {
        if extension.trim().is_empty()
            || extension.starts_with('.')
            || extension.contains('/')
            || extension.contains('\\')
            || extension
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'))
        {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.allowed_extensions",
                reason: "extensions must be plain extension names without dots or separators",
            });
        }
        if !seen.insert(extension.to_ascii_lowercase()) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.allowed_extensions",
                reason: "duplicate extensions are not allowed",
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_php_deny_path_prefixes(prefixes: &[String]) -> Result<(), ConfigError> {
    if prefixes.len() > MAX_PHP_DENY_PATH_PREFIXES {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.deny_path_prefixes",
            reason: "at most 128 prefixes are allowed",
        });
    }
    let mut seen = BTreeSet::new();
    for prefix in prefixes {
        if prefix.is_empty()
            || !prefix.starts_with('/')
            || prefix.contains('\0')
            || prefix.contains('\\')
            || prefix.contains('?')
            || prefix.contains('#')
            || prefix.chars().any(char::is_control)
            || prefix
                .split('/')
                .any(|segment| segment == "." || segment == "..")
        {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.deny_path_prefixes",
                reason: "prefixes must be absolute URI paths without dot segments, query, fragment, backslash, or control characters",
            });
        }
        if !seen.insert(prefix.clone()) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.deny_path_prefixes",
                reason: "duplicate prefixes are not allowed",
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_php_stderr_failure_patterns(patterns: &[String]) -> Result<(), ConfigError> {
    if patterns.len() > MAX_PHP_STDERR_FAILURE_PATTERNS {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.stderr_failure_patterns",
            reason: "at most 32 patterns are allowed",
        });
    }
    let mut seen = BTreeSet::new();
    for pattern in patterns {
        if pattern.is_empty()
            || pattern.len() > MAX_PHP_STDERR_FAILURE_PATTERN_BYTES
            || pattern.bytes().any(|byte| matches!(byte, 0..=31 | 127))
        {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.stderr_failure_patterns",
                reason: "patterns must be 1 to 512 bytes and must not contain ASCII control characters",
            });
        }
        if !seen.insert(pattern.clone()) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.stderr_failure_patterns",
                reason: "duplicate patterns are not allowed",
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_php_hide_response_headers(headers: &[String]) -> Result<(), ConfigError> {
    if headers.len() > MAX_PHP_HIDE_RESPONSE_HEADERS {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.hide_response_headers",
            reason: "at most 64 headers are allowed",
        });
    }
    let mut seen = BTreeSet::new();
    for header in headers {
        validate_header_name("php.hide_response_headers", header)?;
        let normalized = header.to_ascii_lowercase();
        if !seen.insert(normalized) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.hide_response_headers",
                reason: "duplicate headers are not allowed",
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_php_fpm_retry_methods(methods: &[String]) -> Result<(), ConfigError> {
    if methods.len() > MAX_PHP_FPM_RETRY_METHODS {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.retry_methods",
            reason: "at most 16 methods are allowed",
        });
    }
    let mut seen = HashSet::new();
    for method in methods {
        if method.is_empty()
            || method.len() > 32
            || !method
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.fpm.retry_methods",
                reason: "methods must be uppercase HTTP method tokens",
            });
        }
        if !seen.insert(method.clone()) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.fpm.retry_methods",
                reason: "contains duplicate methods",
            });
        }
        if !PHP_FPM_SAFE_RETRY_METHODS.iter().any(|safe| safe == method) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.fpm.retry_methods",
                reason: "only safe HTTP methods GET, HEAD, OPTIONS, and TRACE are allowed",
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_php_fpm_retry_statuses(statuses: &[u16]) -> Result<(), ConfigError> {
    if statuses.len() > MAX_PHP_FPM_RETRY_STATUSES {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.retry_statuses",
            reason: "at most 100 statuses are allowed",
        });
    }
    let mut seen = BTreeSet::new();
    for status in statuses {
        if !(500..=599).contains(status) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.fpm.retry_statuses",
                reason: "statuses must be HTTP server error statuses from 500 through 599",
            });
        }
        if !seen.insert(*status) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.fpm.retry_statuses",
                reason: "duplicate statuses are not allowed",
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_php_intercept_error_statuses(statuses: &[u16]) -> Result<(), ConfigError> {
    if statuses.len() > MAX_PHP_INTERCEPT_ERROR_STATUSES {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.intercept_error_statuses",
            reason: "at most 200 statuses are allowed",
        });
    }
    let mut seen = BTreeSet::new();
    for status in statuses {
        if !(400..=599).contains(status) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.intercept_error_statuses",
                reason: "statuses must be HTTP error statuses from 400 through 599",
            });
        }
        if !seen.insert(*status) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.intercept_error_statuses",
                reason: "duplicate statuses are not allowed",
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn validate_php_fpm_managed_config(
    config: &PhpFpmConfig,
    scope: &'static str,
) -> Result<(), ConfigError> {
    let Some(binary) = &config.php_fpm_binary else {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.php_fpm_binary",
            reason: "managed php-fpm requires php_fpm_binary",
        });
    };
    if binary.as_os_str().is_empty() || !binary.is_absolute() {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.php_fpm_binary",
            reason: "must be an absolute path",
        });
    }
    if binary
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ConfigError::UnsafePath {
            field: format!("{scope}.fpm.php_fpm_binary"),
            path: binary.to_path_buf(),
        });
    }
    validate_non_world_writable_parent(format!("{scope}.fpm.php_fpm_binary"), Some(binary))?;
    let metadata = fs::metadata(binary).map_err(|error| {
        path_inspection_failed(format!("{scope}.fpm.php_fpm_binary"), binary, error)
    })?;
    if !metadata.is_file() {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.php_fpm_binary",
            reason: "must point to a regular executable file",
        });
    }

    let Some(socket_dir) = &config.socket_dir else {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.socket_dir",
            reason: "managed php-fpm requires socket_dir",
        });
    };
    if socket_dir.as_os_str().is_empty() || !socket_dir.is_absolute() {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.socket_dir",
            reason: "must be an absolute path",
        });
    }
    if !valid_php_fpm_managed_config_path_value(socket_dir) {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.socket_dir",
            reason: "must be valid UTF-8 without control characters or quotes",
        });
    }
    validate_path(format!("{scope}.fpm.socket_dir"), Some(socket_dir))?;
    validate_non_world_writable_parent(
        format!("{scope}.fpm.socket_dir"),
        Some(&socket_dir.join("fluxheim-managed.sock")),
    )?;

    if config.workers == 0 || config.workers > MAX_PHP_FPM_MANAGED_WORKERS {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.workers",
            reason: "must be between 1 and 256",
        });
    }
    validate_php_fpm_process_manager(config)?;
    validate_optional_managed_timeout(
        "php.fpm.process_idle_timeout_secs",
        config.process_idle_timeout_secs,
    )?;
    validate_optional_managed_timeout(
        "php.fpm.request_terminate_timeout_secs",
        config.request_terminate_timeout_secs,
    )?;
    validate_optional_managed_timeout(
        "php.fpm.request_slowlog_timeout_secs",
        config.request_slowlog_timeout_secs,
    )?;
    if let Some(listen_backlog) = config.listen_backlog
        && !(-1..=MAX_PHP_FPM_MANAGED_BACKLOG).contains(&listen_backlog)
    {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.listen_backlog",
            reason: "must be -1 or between 0 and 65535",
        });
    }
    match (&config.listen_owner, &config.listen_group) {
        (Some(owner), Some(group)) => {
            validate_php_fpm_managed_identity("php.fpm.listen_owner", owner)?;
            validate_php_fpm_managed_identity("php.fpm.listen_group", group)?;
        }
        (None, None) => {}
        _ => {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.fpm.listen_owner",
                reason: "managed php-fpm listen_owner and listen_group must be configured together",
            });
        }
    }
    if let Some(listen_mode) = &config.listen_mode {
        validate_php_fpm_managed_listen_mode(listen_mode)?;
    }
    if config.max_requests_per_worker > MAX_PHP_FPM_MANAGED_MAX_REQUESTS {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.max_requests_per_worker",
            reason: "must be between 0 and 1000000",
        });
    }
    if config.request_slowlog_trace_depth == 0
        || config.request_slowlog_trace_depth > MAX_PHP_FPM_SLOWLOG_TRACE_DEPTH
    {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.request_slowlog_trace_depth",
            reason: "must be between 1 and 512",
        });
    }
    match (&config.user, &config.group) {
        (Some(user), Some(group)) => {
            validate_php_fpm_managed_identity("php.fpm.user", user)?;
            validate_php_fpm_managed_identity("php.fpm.group", group)?;
        }
        (None, None) => {}
        _ => {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.fpm.user",
                reason: "managed php-fpm user and group must be configured together",
            });
        }
    }
    validate_php_fpm_managed_optional_directory(
        scope,
        "php.fpm.session_save_path",
        &config.session_save_path,
    )?;
    validate_php_fpm_managed_optional_directory(
        scope,
        "php.fpm.upload_tmp_dir",
        &config.upload_tmp_dir,
    )?;

    Ok(())
}

#[cfg(unix)]
fn validate_php_fpm_process_manager(config: &PhpFpmConfig) -> Result<(), ConfigError> {
    match config.process_manager {
        PhpFpmProcessManager::Static => {
            if config.start_servers.is_some()
                || config.min_spare_servers.is_some()
                || config.max_spare_servers.is_some()
                || config.max_spawn_rate.is_some()
                || config.process_idle_timeout_secs.is_some()
            {
                return Err(ConfigError::InvalidPhpConfig {
                    field: "php.fpm.process_manager",
                    reason: "static mode accepts workers and max_requests_per_worker only",
                });
            }
        }
        PhpFpmProcessManager::Dynamic => {
            let min_spare = config
                .min_spare_servers
                .ok_or(ConfigError::InvalidPhpConfig {
                    field: "php.fpm.min_spare_servers",
                    reason: "dynamic mode requires min_spare_servers",
                })?;
            let max_spare = config
                .max_spare_servers
                .ok_or(ConfigError::InvalidPhpConfig {
                    field: "php.fpm.max_spare_servers",
                    reason: "dynamic mode requires max_spare_servers",
                })?;
            if min_spare == 0 || min_spare > config.workers {
                return Err(ConfigError::InvalidPhpConfig {
                    field: "php.fpm.min_spare_servers",
                    reason: "must be between 1 and workers",
                });
            }
            if max_spare < min_spare || max_spare > config.workers {
                return Err(ConfigError::InvalidPhpConfig {
                    field: "php.fpm.max_spare_servers",
                    reason: "must be between min_spare_servers and workers",
                });
            }
            let start_servers = config.start_servers.unwrap_or_else(|| {
                let midpoint = min_spare.saturating_add(max_spare) / 2;
                midpoint.clamp(min_spare, max_spare)
            });
            if start_servers == 0 || start_servers > config.workers {
                return Err(ConfigError::InvalidPhpConfig {
                    field: "php.fpm.start_servers",
                    reason: "must be between 1 and workers",
                });
            }
            if let Some(max_spawn_rate) = config.max_spawn_rate
                && (max_spawn_rate == 0 || max_spawn_rate > MAX_PHP_FPM_MANAGED_MAX_SPAWN_RATE)
            {
                return Err(ConfigError::InvalidPhpConfig {
                    field: "php.fpm.max_spawn_rate",
                    reason: "must be between 1 and 1024",
                });
            }
            if config.process_idle_timeout_secs.is_some() {
                return Err(ConfigError::InvalidPhpConfig {
                    field: "php.fpm.process_idle_timeout_secs",
                    reason: "only ondemand mode uses process_idle_timeout_secs",
                });
            }
        }
        PhpFpmProcessManager::Ondemand => {
            if config.start_servers.is_some()
                || config.min_spare_servers.is_some()
                || config.max_spare_servers.is_some()
                || config.max_spawn_rate.is_some()
            {
                return Err(ConfigError::InvalidPhpConfig {
                    field: "php.fpm.process_manager",
                    reason: "ondemand mode accepts workers, process_idle_timeout_secs, and max_requests_per_worker only",
                });
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_optional_managed_timeout(
    field: &'static str,
    value: Option<u64>,
) -> Result<(), ConfigError> {
    if let Some(value) = value
        && value > MAX_PHP_FPM_MANAGED_TIMEOUT_SECS
    {
        return Err(ConfigError::InvalidPhpConfig {
            field,
            reason: "must be less than or equal to 86400 seconds",
        });
    }
    Ok(())
}

#[cfg(unix)]
fn validate_php_fpm_managed_optional_directory(
    scope: &'static str,
    field: &'static str,
    path: &Option<PathBuf>,
) -> Result<(), ConfigError> {
    let Some(path) = path else {
        return Ok(());
    };
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(ConfigError::InvalidPhpConfig {
            field,
            reason: "must be an absolute path",
        });
    }
    if !valid_php_fpm_managed_config_path_value(path) {
        return Err(ConfigError::InvalidPhpConfig {
            field,
            reason: "must be valid UTF-8 without control characters or quotes",
        });
    }
    let scoped_field = format!(
        "{scope}.fpm.{}",
        field.strip_prefix("php.fpm.").unwrap_or(field)
    );
    validate_path(scoped_field.clone(), Some(path))?;
    validate_non_world_writable_parent(scoped_field, Some(path))
}

#[cfg(unix)]
fn valid_php_fpm_managed_config_path_value(path: &Path) -> bool {
    path.to_str().is_some_and(|value| {
        !value
            .bytes()
            .any(|byte| matches!(byte, 0..=31 | 127 | b'\'' | b'"'))
    })
}

#[cfg(unix)]
fn validate_php_fpm_managed_identity(field: &'static str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty() || value.len() > 64 {
        return Err(ConfigError::InvalidPhpConfig {
            field,
            reason: "must be 1 to 64 bytes",
        });
    }
    if value.starts_with('-')
        || !value.bytes().all(
            |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'.' | b'-'),
        )
    {
        return Err(ConfigError::InvalidPhpConfig {
            field,
            reason: "must contain only letters, numbers, underscore, dot, or dash and cannot start with dash",
        });
    }
    Ok(())
}

#[cfg(unix)]
fn validate_php_fpm_managed_listen_mode(value: &str) -> Result<(), ConfigError> {
    match value {
        "0600" | "0660" => Ok(()),
        _ => Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.listen_mode",
            reason: "must be \"0600\" or \"0660\"",
        }),
    }
}

fn validate_php_param_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty() || name.len() > MAX_PHP_PARAM_NAME_BYTES {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.params",
            reason: "parameter names must be 1 to 128 bytes",
        });
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.params",
            reason: "parameter names must use uppercase ASCII letters, digits, and underscores",
        });
    }
    if name
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_digit())
    {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.params",
            reason: "parameter names must not start with a digit",
        });
    }
    if name.starts_with("HTTP_") {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.params",
            reason: "HTTP_* request header parameters cannot be overridden with php.params",
        });
    }
    if protected_php_param_name(name) {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.params",
            reason: "parameter name is managed by Fluxheim and cannot be overridden",
        });
    }
    Ok(())
}

fn validate_php_param_value(value: &str) -> Result<(), ConfigError> {
    if value.len() > MAX_PHP_PARAM_VALUE_BYTES {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.params",
            reason: "parameter values must be at most 16KiB",
        });
    }
    if value.bytes().any(|byte| matches!(byte, 0..=31 | 127)) {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.params",
            reason: "parameter values must not contain ASCII control characters",
        });
    }
    Ok(())
}

fn warn_high_risk_php_param(name: &str, value: &str) {
    if !matches!(name, "PHP_VALUE" | "PHP_ADMIN_VALUE") {
        return;
    }
    let value = value.to_ascii_lowercase();
    if name == "PHP_ADMIN_VALUE" && value.contains("disable_functions=") {
        log::error!(
            "php.params.PHP_ADMIN_VALUE overrides disable_functions; verify this is intentional before production deployment"
        );
    }
    for directive in [
        "open_basedir",
        "disable_functions",
        "allow_url_include",
        "allow_url_fopen",
    ] {
        if value.contains(directive) {
            log::warn!(
                "php.params.{name} contains high-risk PHP directive {directive:?}; review this setting before production use"
            );
        }
    }
}

pub(crate) fn protected_php_param_name(name: &str) -> bool {
    matches!(
        name,
        "AUTH_TYPE"
            | "CONTENT_LENGTH"
            | "CONTENT_TYPE"
            | "DOCUMENT_ROOT"
            | "DOCUMENT_URI"
            | "GATEWAY_INTERFACE"
            | "HTTPS"
            | "HTTP_HOST"
            | "HTTP_PROXY"
            | "PATH_INFO"
            | "PATH_TRANSLATED"
            | "QUERY_STRING"
            | "REDIRECT_STATUS"
            | "REMOTE_ADDR"
            | "REMOTE_PORT"
            | "REQUEST_METHOD"
            | "REQUEST_SCHEME"
            | "REQUEST_URI"
            | "SCRIPT_FILENAME"
            | "SCRIPT_NAME"
            | "SERVER_ADDR"
            | "SERVER_NAME"
            | "SERVER_PORT"
            | "SERVER_PROTOCOL"
            | "SERVER_SOFTWARE"
    )
}
