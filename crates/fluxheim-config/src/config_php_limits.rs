use crate::config::{ByteSize, ConfigError};
use crate::config_php::{MAX_PHP_MAX_IN_FLIGHT, PhpConfig};

const MAX_PHP_STDERR_LOG_BYTES: usize = 1024 * 1024;
const MAX_PHP_RESPONSE_CONFIG_BYTES: usize = 64 * 1024 * 1024;
const MAX_PHP_RESPONSE_HEADER_CONFIG_BYTES: usize = 1024 * 1024;

pub(crate) fn validate_php_limits(config: &PhpConfig) -> Result<(), ConfigError> {
    validate_php_max_in_flight(config.max_in_flight)?;
    validate_optional_nonzero_bytes("php.max_request_body_bytes", config.max_request_body_bytes)?;
    validate_request_body_spool_pair(config)?;
    validate_php_response_limits(config.max_response_bytes, config.max_response_header_bytes)?;
    if config.server_port == Some(0) {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.server_port",
            reason: "must be greater than zero",
        });
    }
    validate_php_stderr_limit(config.stderr_max_bytes)
}

fn validate_php_max_in_flight(max_in_flight: usize) -> Result<(), ConfigError> {
    if max_in_flight == 0 || max_in_flight > MAX_PHP_MAX_IN_FLIGHT {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.max_in_flight",
            reason: "must be between 1 and 4096",
        });
    }
    Ok(())
}

fn validate_optional_nonzero_bytes(
    field: &'static str,
    value: Option<ByteSize>,
) -> Result<(), ConfigError> {
    if value.is_some_and(|bytes| bytes.as_u64() == 0) {
        return Err(ConfigError::InvalidPhpConfig {
            field,
            reason: "must be greater than zero",
        });
    }
    Ok(())
}

fn validate_request_body_spool_pair(config: &PhpConfig) -> Result<(), ConfigError> {
    validate_optional_nonzero_bytes(
        "php.request_body_spool_threshold_bytes",
        config.request_body_spool_threshold_bytes,
    )?;
    if let (Some(spool_threshold), Some(max_request_body)) = (
        config.request_body_spool_threshold_bytes,
        config.max_request_body_bytes,
    ) && spool_threshold.as_u64() >= max_request_body.as_u64()
    {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.request_body_spool_threshold_bytes",
            reason: "must be less than php.max_request_body_bytes when both are set",
        });
    }
    if config.request_body_spool_threshold_bytes.is_some()
        && config.request_body_spool_dir.is_none()
    {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.request_body_spool_dir",
            reason: "is required when php.request_body_spool_threshold_bytes is set",
        });
    }
    if config.request_body_spool_dir.is_some()
        && config.request_body_spool_threshold_bytes.is_none()
    {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.request_body_spool_threshold_bytes",
            reason: "is required when php.request_body_spool_dir is set",
        });
    }
    Ok(())
}

fn validate_php_response_limits(
    max_response_bytes: ByteSize,
    max_response_header_bytes: ByteSize,
) -> Result<(), ConfigError> {
    if max_response_bytes.as_u64() == 0 {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.max_response_bytes",
            reason: "must be greater than zero",
        });
    }
    if max_response_bytes.as_u64() > MAX_PHP_RESPONSE_CONFIG_BYTES as u64 {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.max_response_bytes",
            reason: "must be less than or equal to 64MiB",
        });
    }
    if max_response_header_bytes.as_u64() == 0 {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.max_response_header_bytes",
            reason: "must be greater than zero",
        });
    }
    if max_response_header_bytes.as_u64() > MAX_PHP_RESPONSE_HEADER_CONFIG_BYTES as u64 {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.max_response_header_bytes",
            reason: "must be less than or equal to 1MiB",
        });
    }
    Ok(())
}

fn validate_php_stderr_limit(stderr_max_bytes: ByteSize) -> Result<(), ConfigError> {
    if stderr_max_bytes.as_u64() == 0 {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.stderr_max_bytes",
            reason: "must be greater than zero",
        });
    }
    if stderr_max_bytes.as_u64() > MAX_PHP_STDERR_LOG_BYTES as u64 {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.stderr_max_bytes",
            reason: "must be less than or equal to 1MiB",
        });
    }
    Ok(())
}
