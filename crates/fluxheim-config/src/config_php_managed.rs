#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};

use crate::config::ConfigError;
use crate::config_path::{
    path_inspection_failed, validate_non_world_writable_parent, validate_path,
};
use crate::config_php::{PhpFpmConfig, PhpFpmProcessManager};

const MAX_PHP_FPM_MANAGED_WORKERS: usize = 256;
const MAX_PHP_FPM_MANAGED_MAX_REQUESTS: usize = 1_000_000;
const MAX_PHP_FPM_MANAGED_MAX_SPAWN_RATE: usize = 1024;
const MAX_PHP_FPM_MANAGED_BACKLOG: i32 = 65_535;
const MAX_PHP_FPM_MANAGED_TIMEOUT_SECS: u64 = 86_400;
const MAX_PHP_FPM_SLOWLOG_TRACE_DEPTH: usize = 512;

pub fn validate_php_fpm_managed_config(
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
    let metadata = fs::symlink_metadata(binary).map_err(|error| {
        path_inspection_failed(format!("{scope}.fpm.php_fpm_binary"), binary, error)
    })?;
    if !metadata.is_file() {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.php_fpm_binary",
            reason: "must point directly to a regular executable file",
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

fn valid_php_fpm_managed_config_path_value(path: &Path) -> bool {
    path.to_str().is_some_and(|value| {
        !value
            .bytes()
            .any(|byte| matches!(byte, 0..=31 | 127 | b'\'' | b'"'))
    })
}

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

fn validate_php_fpm_managed_listen_mode(value: &str) -> Result<(), ConfigError> {
    match value {
        "0600" | "0660" => Ok(()),
        _ => Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.listen_mode",
            reason: "must be \"0600\" or \"0660\"",
        }),
    }
}
