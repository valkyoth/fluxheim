use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;

use crate::config::ConfigError;

pub(crate) const MAX_PHP_PARAMS: usize = 128;
pub(crate) const MAX_PHP_FPM_RETRY_METHODS: usize = 16;
pub(crate) const MAX_PHP_FPM_RETRY_STATUSES: usize = 100;
pub(crate) const MAX_PHP_INTERCEPT_ERROR_STATUSES: usize = 200;
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
