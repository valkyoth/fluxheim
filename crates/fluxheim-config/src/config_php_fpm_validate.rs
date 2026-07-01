use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};

use crate::config::{ConfigError, validate_optional_timeout_secs, validate_required_timeout_secs};
use crate::config_net::{upstream_host, valid_authority};
use crate::config_path::{validate_non_world_writable_parent, validate_path};
#[cfg(unix)]
use crate::config_php::validate_php_fpm_managed_config;
use crate::config_php::{PhpFpmConfig, PhpFpmMode, PhpFpmProcessManager};
use crate::config_php_defaults::{
    default_php_fpm_managed_max_requests, default_php_fpm_managed_workers,
    default_php_fpm_slowlog_trace_depth,
};
use crate::config_php_validation::{
    validate_php_fpm_retry_methods, validate_php_fpm_retry_statuses,
};

const MAX_PHP_FPM_POOL_MAX_IDLE: usize = 1024;
const MAX_PHP_FPM_RETRIES: u8 = 10;
pub const MAX_PHP_FPM_TCP_UPSTREAMS: usize = 64;

pub(crate) fn validate_php_fpm_config(
    config: &PhpFpmConfig,
    scope: &'static str,
) -> Result<(), ConfigError> {
    let endpoint_count = usize::from(config.socket.is_some())
        + usize::from(config.tcp.is_some())
        + usize::from(!config.tcp_upstreams.is_empty());
    match config.mode {
        PhpFpmMode::External => {
            match endpoint_count {
                1 => {}
                0 => {
                    return Err(ConfigError::InvalidPhpConfig {
                        field: "php.fpm",
                        reason: "enabled PHP requires php-fpm socket, tcp, or tcp_upstreams",
                    });
                }
                _ => {
                    return Err(ConfigError::InvalidPhpConfig {
                        field: "php.fpm",
                        reason: "configure only one of socket, tcp, or tcp_upstreams",
                    });
                }
            }
            validate_no_managed_fields_for_external_mode(config)?;
        }
        PhpFpmMode::Managed => {
            if endpoint_count != 0 {
                return Err(ConfigError::InvalidPhpConfig {
                    field: "php.fpm.mode",
                    reason: "managed php-fpm creates its own private socket; do not set socket, tcp, or tcp_upstreams",
                });
            }
            #[cfg(not(unix))]
            {
                return Err(ConfigError::InvalidPhpConfig {
                    field: "php.fpm.mode",
                    reason: "managed php-fpm requires Unix sockets",
                });
            }
            #[cfg(unix)]
            {
                validate_php_fpm_managed_config(config, scope)?;
            }
        }
    }

    validate_php_fpm_socket(config, scope)?;
    validate_php_fpm_tcp_upstreams(config)?;
    validate_php_fpm_retry_policy(config)?;
    validate_php_fpm_keepalive(config)
}

fn validate_no_managed_fields_for_external_mode(config: &PhpFpmConfig) -> Result<(), ConfigError> {
    if config.php_fpm_binary.is_some()
        || config.socket_dir.is_some()
        || config.workers != default_php_fpm_managed_workers()
        || config.max_requests_per_worker != default_php_fpm_managed_max_requests()
        || config.process_manager != PhpFpmProcessManager::Static
        || config.start_servers.is_some()
        || config.min_spare_servers.is_some()
        || config.max_spare_servers.is_some()
        || config.max_spawn_rate.is_some()
        || config.process_idle_timeout_secs.is_some()
        || config.listen_backlog.is_some()
        || config.listen_owner.is_some()
        || config.listen_group.is_some()
        || config.listen_mode.is_some()
        || config.request_terminate_timeout_secs.is_some()
        || config.request_terminate_timeout_track_finished
        || config.request_slowlog_timeout_secs.is_some()
        || config.request_slowlog_trace_depth != default_php_fpm_slowlog_trace_depth()
        || !config.clear_env
        || !config.catch_workers_output
        || !config.decorate_workers_output
        || config.session_save_path.is_some()
        || config.upload_tmp_dir.is_some()
        || config.user.is_some()
        || config.group.is_some()
    {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.mode",
            reason: "managed php-fpm fields require mode = \"managed\"",
        });
    }
    Ok(())
}

fn validate_php_fpm_socket(config: &PhpFpmConfig, scope: &'static str) -> Result<(), ConfigError> {
    if let Some(socket) = &config.socket {
        let field = format!("{scope}.fpm.socket");
        if socket.as_os_str().is_empty() {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.fpm.socket",
                reason: "socket cannot be empty",
            });
        }
        validate_path(field.clone(), Some(socket))?;
        validate_non_world_writable_parent(field, Some(socket))?;
    }
    Ok(())
}

fn validate_php_fpm_tcp_upstreams(config: &PhpFpmConfig) -> Result<(), ConfigError> {
    if let Some(tcp) = &config.tcp
        && !valid_authority(tcp)
    {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.tcp",
            reason: "must be host:port or ip:port",
        });
    }
    if let Some(tcp) = &config.tcp {
        validate_php_fpm_tcp_endpoint(tcp, config.allow_private_tcp_upstreams, "php.fpm.tcp")?;
    }
    if config.tcp_upstreams.len() > MAX_PHP_FPM_TCP_UPSTREAMS {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.tcp_upstreams",
            reason: "at most 64 upstreams are allowed",
        });
    }
    let mut seen_tcp_upstreams = BTreeSet::new();
    for tcp in &config.tcp_upstreams {
        if !valid_authority(tcp) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.fpm.tcp_upstreams",
                reason: "entries must be host:port or ip:port",
            });
        }
        validate_php_fpm_tcp_endpoint(
            tcp,
            config.allow_private_tcp_upstreams,
            "php.fpm.tcp_upstreams",
        )?;
        if !seen_tcp_upstreams.insert(tcp.to_ascii_lowercase()) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.fpm.tcp_upstreams",
                reason: "duplicate upstreams are not allowed",
            });
        }
    }
    Ok(())
}

fn validate_php_fpm_retry_policy(config: &PhpFpmConfig) -> Result<(), ConfigError> {
    validate_optional_timeout_secs("php.fpm.connect_timeout_secs", config.connect_timeout_secs)?;
    validate_optional_timeout_secs("php.fpm.read_timeout_secs", config.read_timeout_secs)?;
    validate_optional_timeout_secs("php.fpm.write_timeout_secs", config.write_timeout_secs)?;
    validate_optional_timeout_secs("php.fpm.retry_timeout_secs", config.retry_timeout_secs)?;
    if config.max_retries > MAX_PHP_FPM_RETRIES {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.max_retries",
            reason: "must be less than or equal to 10",
        });
    }
    validate_php_fpm_retry_methods(&config.retry_methods)?;
    validate_php_fpm_retry_statuses(&config.retry_statuses)
}

fn validate_php_fpm_keepalive(config: &PhpFpmConfig) -> Result<(), ConfigError> {
    if !config.keepalive {
        return Ok(());
    }
    if config.pool_max_idle == 0 {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.pool_max_idle",
            reason: "must be greater than zero when php.fpm.keepalive is enabled",
        });
    }
    if config.pool_max_idle > MAX_PHP_FPM_POOL_MAX_IDLE {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.fpm.pool_max_idle",
            reason: "must be less than or equal to 1024",
        });
    }
    validate_required_timeout_secs("php.fpm.idle_timeout_secs", config.idle_timeout_secs)
}

fn validate_php_fpm_tcp_endpoint(
    authority: &str,
    allow_private_tcp_upstreams: bool,
    field: &'static str,
) -> Result<(), ConfigError> {
    let Some(host) = upstream_host(authority) else {
        return Err(ConfigError::InvalidPhpConfig {
            field,
            reason: "entries must be host:port or ip:port",
        });
    };
    let Ok(address) = host.parse::<IpAddr>() else {
        return Ok(());
    };
    if php_fpm_tcp_ip_always_invalid(address) {
        return Err(ConfigError::InvalidPhpConfig {
            field,
            reason: "must not use unspecified or multicast IP literals",
        });
    }
    if !allow_private_tcp_upstreams && php_fpm_tcp_ip_requires_private_opt_in(address) {
        return Err(ConfigError::InvalidPhpConfig {
            field,
            reason: "loopback, private, or link-local IP literals require allow_private_tcp_upstreams = true",
        });
    }
    Ok(())
}

fn php_fpm_tcp_ip_always_invalid(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_unspecified() || address.is_broadcast() || address.is_multicast()
        }
        IpAddr::V6(address) => address.is_unspecified() || address.is_multicast(),
    }
}

fn php_fpm_tcp_ip_requires_private_opt_in(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_loopback() || address.is_private() || address.is_link_local()
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || ipv6_is_unique_local(address)
                || ipv6_is_unicast_link_local(address)
        }
    }
}

fn ipv6_is_unique_local(address: Ipv6Addr) -> bool {
    address.segments()[0] & 0xfe00 == 0xfc00
}

fn ipv6_is_unicast_link_local(address: Ipv6Addr) -> bool {
    address.segments()[0] & 0xffc0 == 0xfe80
}
