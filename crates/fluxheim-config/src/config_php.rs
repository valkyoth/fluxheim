use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{
    ByteSize, ConfigError, ProxyErrorPageConfig, extend_unique, validate_optional_timeout_secs,
    validate_required_timeout_secs,
};
use crate::config_net::{upstream_host, valid_authority};
use crate::config_path::{
    path_existing_prefix_contains_symlink, path_inspection_failed,
    validate_non_world_writable_parent, validate_path,
};
#[cfg(unix)]
pub use crate::config_php_managed::validate_php_fpm_managed_config;
pub use crate::config_php_validation::{
    MAX_PHP_ALLOWED_EXTENSIONS, MAX_PHP_DENY_PATH_PREFIXES, MAX_PHP_FPM_RETRY_METHODS,
    MAX_PHP_FPM_RETRY_STATUSES, MAX_PHP_HIDE_RESPONSE_HEADERS, MAX_PHP_INTERCEPT_ERROR_STATUSES,
    MAX_PHP_PARAMS, MAX_PHP_STDERR_FAILURE_PATTERNS, protected_php_param_name,
    validate_php_deny_path_prefixes, validate_php_extensions, validate_php_fpm_retry_methods,
    validate_php_fpm_retry_statuses, validate_php_hide_response_headers, validate_php_index,
    validate_php_intercept_error_statuses, validate_php_params,
    validate_php_stderr_failure_patterns,
};
use crate::config_route::validate_route_path;

pub const DEFAULT_PHP_MAX_IN_FLIGHT: usize = 8;
pub const MAX_PHP_MAX_IN_FLIGHT: usize = 4096;

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PhpPreset {
    #[default]
    None,
    #[serde(rename = "wordpress")]
    WordPress,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhpConfig {
    #[serde(default)]
    pub preset: PhpPreset,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub runtime: PhpRuntime,
    #[serde(default)]
    pub root: Option<PathBuf>,
    #[serde(default)]
    pub resolve_root_symlink: bool,
    #[serde(default)]
    pub fpm_root: Option<PathBuf>,
    #[serde(default = "default_php_index")]
    pub index: String,
    #[serde(default = "default_php_allowed_extensions")]
    pub allowed_extensions: Vec<String>,
    #[serde(default)]
    pub deny_path_prefixes: Vec<String>,
    #[serde(default = "default_php_request_timeout_secs")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_php_max_in_flight")]
    pub max_in_flight: usize,
    #[serde(default)]
    pub max_request_body_bytes: Option<ByteSize>,
    #[serde(default)]
    pub request_body_spool_threshold_bytes: Option<ByteSize>,
    #[serde(default)]
    pub request_body_spool_dir: Option<PathBuf>,
    #[serde(default = "default_php_max_response_bytes")]
    pub max_response_bytes: ByteSize,
    #[serde(default = "default_php_max_response_header_bytes")]
    pub max_response_header_bytes: ByteSize,
    #[serde(default)]
    pub path_info: PhpPathInfoMode,
    #[serde(default)]
    pub try_files: PhpTryFilesMode,
    #[serde(default = "default_true")]
    pub pass_request_headers: bool,
    #[serde(default = "default_true")]
    pub pass_request_body: bool,
    #[serde(default)]
    pub server_port: Option<u16>,
    #[serde(default = "default_true")]
    pub stderr_log: bool,
    #[serde(default)]
    pub stderr_log_level: PhpStderrLogLevel,
    #[serde(default = "default_php_stderr_max_bytes")]
    pub stderr_max_bytes: ByteSize,
    #[serde(default)]
    pub stderr_failure_patterns: Vec<String>,
    #[serde(default)]
    pub hide_response_headers: Vec<String>,
    #[serde(default)]
    pub ignore_origin_cache_headers: bool,
    #[serde(default)]
    pub intercept_error_statuses: Vec<u16>,
    #[serde(default)]
    pub error_pages: Vec<ProxyErrorPageConfig>,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    #[serde(default)]
    pub fpm: PhpFpmConfig,
}

impl Default for PhpConfig {
    fn default() -> Self {
        Self {
            preset: PhpPreset::default(),
            enabled: false,
            runtime: PhpRuntime::default(),
            root: None,
            resolve_root_symlink: false,
            fpm_root: None,
            index: default_php_index(),
            allowed_extensions: default_php_allowed_extensions(),
            deny_path_prefixes: Vec::new(),
            request_timeout_secs: default_php_request_timeout_secs(),
            max_in_flight: default_php_max_in_flight(),
            max_request_body_bytes: None,
            request_body_spool_threshold_bytes: None,
            request_body_spool_dir: None,
            max_response_bytes: default_php_max_response_bytes(),
            max_response_header_bytes: default_php_max_response_header_bytes(),
            path_info: PhpPathInfoMode::default(),
            try_files: PhpTryFilesMode::default(),
            pass_request_headers: true,
            pass_request_body: true,
            server_port: None,
            stderr_log: true,
            stderr_log_level: PhpStderrLogLevel::default(),
            stderr_max_bytes: default_php_stderr_max_bytes(),
            stderr_failure_patterns: Vec::new(),
            hide_response_headers: Vec::new(),
            ignore_origin_cache_headers: false,
            intercept_error_statuses: Vec::new(),
            error_pages: Vec::new(),
            params: BTreeMap::new(),
            fpm: PhpFpmConfig::default(),
        }
    }
}

impl PhpConfig {
    pub fn apply_preset_defaults(&mut self) {
        match self.preset {
            PhpPreset::None => {}
            PhpPreset::WordPress => self.apply_wordpress_preset_defaults(),
        }
    }

    fn apply_wordpress_preset_defaults(&mut self) {
        if self.try_files == PhpTryFilesMode::FrontController {
            self.try_files = PhpTryFilesMode::WordPress;
        }
        extend_unique(
            &mut self.deny_path_prefixes,
            [
                "/wp-content/uploads/",
                "/wp-content/blogs.dir/",
                "/blogs.dir/",
                "/uploads/",
                "/files/",
            ]
            .map(str::to_owned),
        );
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(root) = &mut self.root
            && root.is_relative()
        {
            *root = base_dir.join(&root);
        }
        if let Some(fpm_root) = &mut self.fpm_root
            && fpm_root.is_relative()
        {
            *fpm_root = base_dir.join(&fpm_root);
        }
        if let Some(spool_dir) = &mut self.request_body_spool_dir
            && spool_dir.is_relative()
        {
            *spool_dir = base_dir.join(&spool_dir);
        }
        self.fpm.resolve_relative_paths(base_dir);
        for error_page in &mut self.error_pages {
            error_page.resolve_relative_paths(base_dir);
        }
    }

    pub fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if !matches!(self.runtime, PhpRuntime::PhpFpm) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.runtime",
                reason: "only php-fpm is supported in this release",
            });
        }

        let root_field = format!("{scope}.root");
        let Some(root) = &self.root else {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.root",
                reason: "enabled PHP requires a root",
            });
        };
        if root.as_os_str().is_empty() {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.root",
                reason: "root cannot be empty",
            });
        }
        validate_php_root_path(root_field.clone(), root, self.resolve_root_symlink)?;
        validate_non_world_writable_parent(root_field.clone(), Some(root))?;
        if self.resolve_root_symlink
            && let Ok(metadata) = fs::symlink_metadata(root)
            && metadata.file_type().is_symlink()
        {
            let resolved = root
                .canonicalize()
                .map_err(|error| path_inspection_failed(root_field.clone(), root, error))?;
            validate_non_world_writable_parent(format!("{root_field}.resolved"), Some(&resolved))?;
        }
        if let Some(fpm_root) = &self.fpm_root {
            if fpm_root.as_os_str().is_empty() {
                return Err(ConfigError::InvalidPhpConfig {
                    field: "php.fpm_root",
                    reason: "fpm_root cannot be empty",
                });
            }
            if !fpm_root.is_absolute() {
                return Err(ConfigError::InvalidPhpConfig {
                    field: "php.fpm_root",
                    reason: "fpm_root must be absolute after relative path resolution",
                });
            }
            let fpm_root_field = format!("{scope}.fpm_root");
            validate_path(fpm_root_field.clone(), Some(fpm_root))?;
            validate_non_world_writable_parent(fpm_root_field, Some(fpm_root))?;
        }

        validate_php_index(&self.index)?;
        validate_php_extensions(&self.allowed_extensions)?;
        validate_php_deny_path_prefixes(&self.deny_path_prefixes)?;
        validate_php_params(&self.params)?;
        validate_required_timeout_secs("php.request_timeout_secs", self.request_timeout_secs)?;
        if self.max_in_flight == 0 || self.max_in_flight > MAX_PHP_MAX_IN_FLIGHT {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.max_in_flight",
                reason: "must be between 1 and 4096",
            });
        }
        if self
            .max_request_body_bytes
            .is_some_and(|bytes| bytes.as_u64() == 0)
        {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.max_request_body_bytes",
                reason: "must be greater than zero",
            });
        }
        if self
            .request_body_spool_threshold_bytes
            .is_some_and(|bytes| bytes.as_u64() == 0)
        {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.request_body_spool_threshold_bytes",
                reason: "must be greater than zero",
            });
        }
        if let (Some(spool_threshold), Some(max_request_body)) = (
            self.request_body_spool_threshold_bytes,
            self.max_request_body_bytes,
        ) && spool_threshold.as_u64() >= max_request_body.as_u64()
        {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.request_body_spool_threshold_bytes",
                reason: "must be less than php.max_request_body_bytes when both are set",
            });
        }
        if self.request_body_spool_threshold_bytes.is_some()
            && self.request_body_spool_dir.is_none()
        {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.request_body_spool_dir",
                reason: "is required when php.request_body_spool_threshold_bytes is set",
            });
        }
        if self.request_body_spool_dir.is_some()
            && self.request_body_spool_threshold_bytes.is_none()
        {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.request_body_spool_threshold_bytes",
                reason: "is required when php.request_body_spool_dir is set",
            });
        }
        if let Some(spool_dir) = &self.request_body_spool_dir {
            if spool_dir.as_os_str().is_empty() {
                return Err(ConfigError::InvalidPhpConfig {
                    field: "php.request_body_spool_dir",
                    reason: "cannot be empty",
                });
            }
            let spool_dir_field = format!("{scope}.request_body_spool_dir");
            validate_php_request_body_spool_dir(spool_dir_field, spool_dir)?;
        }
        if self.max_response_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.max_response_bytes",
                reason: "must be greater than zero",
            });
        }
        if self.max_response_bytes.as_u64() > MAX_PHP_RESPONSE_CONFIG_BYTES as u64 {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.max_response_bytes",
                reason: "must be less than or equal to 64MiB",
            });
        }
        if self.max_response_header_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.max_response_header_bytes",
                reason: "must be greater than zero",
            });
        }
        if self.max_response_header_bytes.as_u64() > MAX_PHP_RESPONSE_HEADER_CONFIG_BYTES as u64 {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.max_response_header_bytes",
                reason: "must be less than or equal to 1MiB",
            });
        }
        if self.server_port == Some(0) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.server_port",
                reason: "must be greater than zero",
            });
        }
        if self.stderr_max_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.stderr_max_bytes",
                reason: "must be greater than zero",
            });
        }
        if self.stderr_max_bytes.as_u64() > MAX_PHP_STDERR_LOG_BYTES as u64 {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.stderr_max_bytes",
                reason: "must be less than or equal to 1MiB",
            });
        }
        validate_php_stderr_failure_patterns(&self.stderr_failure_patterns)?;
        validate_php_hide_response_headers(&self.hide_response_headers)?;
        validate_php_intercept_error_statuses(&self.intercept_error_statuses)?;
        validate_php_error_pages(&self.error_pages)?;

        self.fpm.validate(scope)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum PhpRuntime {
    #[default]
    #[serde(rename = "php-fpm")]
    PhpFpm,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum PhpPathInfoMode {
    #[default]
    #[serde(rename = "disabled")]
    Disabled,
    #[serde(rename = "split", alias = "strict")]
    Split,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum PhpTryFilesMode {
    #[default]
    #[serde(rename = "front-controller")]
    FrontController,
    #[serde(rename = "wordpress")]
    WordPress,
    #[serde(rename = "strict")]
    Strict,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum PhpStderrLogLevel {
    #[serde(rename = "error")]
    Error,
    #[default]
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "debug")]
    Debug,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum PhpFpmMode {
    #[default]
    #[serde(rename = "external")]
    External,
    #[serde(rename = "managed")]
    Managed,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum PhpFpmProcessManager {
    #[default]
    #[serde(rename = "static")]
    Static,
    #[serde(rename = "dynamic")]
    Dynamic,
    #[serde(rename = "ondemand")]
    Ondemand,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhpFpmConfig {
    #[serde(default)]
    pub mode: PhpFpmMode,
    #[serde(default)]
    pub socket: Option<PathBuf>,
    #[serde(default)]
    pub tcp: Option<String>,
    #[serde(default)]
    pub tcp_upstreams: Vec<String>,
    #[serde(default)]
    pub allow_private_tcp_upstreams: bool,
    #[serde(default)]
    pub php_fpm_binary: Option<PathBuf>,
    #[serde(default)]
    pub socket_dir: Option<PathBuf>,
    #[serde(default = "default_php_fpm_managed_workers")]
    pub workers: usize,
    #[serde(default = "default_php_fpm_managed_max_requests")]
    pub max_requests_per_worker: usize,
    #[serde(default)]
    pub process_manager: PhpFpmProcessManager,
    #[serde(default)]
    pub start_servers: Option<usize>,
    #[serde(default)]
    pub min_spare_servers: Option<usize>,
    #[serde(default)]
    pub max_spare_servers: Option<usize>,
    #[serde(default)]
    pub max_spawn_rate: Option<usize>,
    #[serde(default)]
    pub process_idle_timeout_secs: Option<u64>,
    #[serde(default)]
    pub listen_backlog: Option<i32>,
    #[serde(default)]
    pub listen_owner: Option<String>,
    #[serde(default)]
    pub listen_group: Option<String>,
    #[serde(default)]
    pub listen_mode: Option<String>,
    #[serde(default)]
    pub request_terminate_timeout_secs: Option<u64>,
    #[serde(default)]
    pub request_terminate_timeout_track_finished: bool,
    #[serde(default)]
    pub request_slowlog_timeout_secs: Option<u64>,
    #[serde(default = "default_php_fpm_slowlog_trace_depth")]
    pub request_slowlog_trace_depth: usize,
    #[serde(default = "default_true")]
    pub clear_env: bool,
    #[serde(default = "default_true")]
    pub catch_workers_output: bool,
    #[serde(default = "default_true")]
    pub decorate_workers_output: bool,
    #[serde(default)]
    pub session_save_path: Option<PathBuf>,
    #[serde(default)]
    pub upload_tmp_dir: Option<PathBuf>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub keepalive: bool,
    #[serde(default = "default_php_fpm_pool_max_idle")]
    pub pool_max_idle: usize,
    #[serde(default = "default_php_fpm_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub connect_timeout_secs: Option<u64>,
    #[serde(default)]
    pub read_timeout_secs: Option<u64>,
    #[serde(default)]
    pub write_timeout_secs: Option<u64>,
    #[serde(default)]
    pub max_retries: u8,
    #[serde(default)]
    pub retry_timeout_secs: Option<u64>,
    #[serde(default = "default_php_fpm_retry_methods")]
    pub retry_methods: Vec<String>,
    #[serde(default)]
    pub retry_invalid_response: bool,
    #[serde(default)]
    pub retry_statuses: Vec<u16>,
}

impl Default for PhpFpmConfig {
    fn default() -> Self {
        Self {
            mode: PhpFpmMode::External,
            socket: None,
            tcp: None,
            tcp_upstreams: Vec::new(),
            allow_private_tcp_upstreams: false,
            php_fpm_binary: None,
            socket_dir: None,
            workers: default_php_fpm_managed_workers(),
            max_requests_per_worker: default_php_fpm_managed_max_requests(),
            process_manager: PhpFpmProcessManager::Static,
            start_servers: None,
            min_spare_servers: None,
            max_spare_servers: None,
            max_spawn_rate: None,
            process_idle_timeout_secs: None,
            listen_backlog: None,
            listen_owner: None,
            listen_group: None,
            listen_mode: None,
            request_terminate_timeout_secs: None,
            request_terminate_timeout_track_finished: false,
            request_slowlog_timeout_secs: None,
            request_slowlog_trace_depth: default_php_fpm_slowlog_trace_depth(),
            clear_env: true,
            catch_workers_output: true,
            decorate_workers_output: true,
            session_save_path: None,
            upload_tmp_dir: None,
            user: None,
            group: None,
            keepalive: false,
            pool_max_idle: default_php_fpm_pool_max_idle(),
            idle_timeout_secs: default_php_fpm_idle_timeout_secs(),
            connect_timeout_secs: None,
            read_timeout_secs: None,
            write_timeout_secs: None,
            max_retries: 0,
            retry_timeout_secs: None,
            retry_methods: default_php_fpm_retry_methods(),
            retry_invalid_response: false,
            retry_statuses: Vec::new(),
        }
    }
}

const MAX_PHP_FPM_POOL_MAX_IDLE: usize = 1024;
const MAX_PHP_FPM_RETRIES: u8 = 10;
pub const MAX_PHP_FPM_TCP_UPSTREAMS: usize = 64;
pub const MAX_PHP_ERROR_PAGES: usize = 64;
const MAX_PHP_STDERR_LOG_BYTES: usize = 1024 * 1024;
const MAX_PHP_RESPONSE_CONFIG_BYTES: usize = 64 * 1024 * 1024;
const MAX_PHP_RESPONSE_HEADER_CONFIG_BYTES: usize = 1024 * 1024;

impl PhpFpmConfig {
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(socket) = &mut self.socket
            && socket.is_relative()
        {
            *socket = base_dir.join(&socket);
        }
        if let Some(socket_dir) = &mut self.socket_dir
            && socket_dir.is_relative()
        {
            *socket_dir = base_dir.join(&socket_dir);
        }
        if let Some(session_save_path) = &mut self.session_save_path
            && session_save_path.is_relative()
        {
            *session_save_path = base_dir.join(&session_save_path);
        }
        if let Some(upload_tmp_dir) = &mut self.upload_tmp_dir
            && upload_tmp_dir.is_relative()
        {
            *upload_tmp_dir = base_dir.join(&upload_tmp_dir);
        }
    }

    pub fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        let endpoint_count = usize::from(self.socket.is_some())
            + usize::from(self.tcp.is_some())
            + usize::from(!self.tcp_upstreams.is_empty());
        match self.mode {
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
                if self.php_fpm_binary.is_some()
                    || self.socket_dir.is_some()
                    || self.workers != default_php_fpm_managed_workers()
                    || self.max_requests_per_worker != default_php_fpm_managed_max_requests()
                    || self.process_manager != PhpFpmProcessManager::Static
                    || self.start_servers.is_some()
                    || self.min_spare_servers.is_some()
                    || self.max_spare_servers.is_some()
                    || self.max_spawn_rate.is_some()
                    || self.process_idle_timeout_secs.is_some()
                    || self.listen_backlog.is_some()
                    || self.listen_owner.is_some()
                    || self.listen_group.is_some()
                    || self.listen_mode.is_some()
                    || self.request_terminate_timeout_secs.is_some()
                    || self.request_terminate_timeout_track_finished
                    || self.request_slowlog_timeout_secs.is_some()
                    || self.request_slowlog_trace_depth != default_php_fpm_slowlog_trace_depth()
                    || !self.clear_env
                    || !self.catch_workers_output
                    || !self.decorate_workers_output
                    || self.session_save_path.is_some()
                    || self.upload_tmp_dir.is_some()
                    || self.user.is_some()
                    || self.group.is_some()
                {
                    return Err(ConfigError::InvalidPhpConfig {
                        field: "php.fpm.mode",
                        reason: "managed php-fpm fields require mode = \"managed\"",
                    });
                }
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
                    validate_php_fpm_managed_config(self, scope)?;
                }
            }
        }

        if let Some(socket) = &self.socket {
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
        if let Some(tcp) = &self.tcp
            && !valid_authority(tcp)
        {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.fpm.tcp",
                reason: "must be host:port or ip:port",
            });
        }
        if let Some(tcp) = &self.tcp {
            validate_php_fpm_tcp_endpoint(tcp, self.allow_private_tcp_upstreams, "php.fpm.tcp")?;
        }
        if self.tcp_upstreams.len() > MAX_PHP_FPM_TCP_UPSTREAMS {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.fpm.tcp_upstreams",
                reason: "at most 64 upstreams are allowed",
            });
        }
        let mut seen_tcp_upstreams = BTreeSet::new();
        for tcp in &self.tcp_upstreams {
            if !valid_authority(tcp) {
                return Err(ConfigError::InvalidPhpConfig {
                    field: "php.fpm.tcp_upstreams",
                    reason: "entries must be host:port or ip:port",
                });
            }
            validate_php_fpm_tcp_endpoint(
                tcp,
                self.allow_private_tcp_upstreams,
                "php.fpm.tcp_upstreams",
            )?;
            if !seen_tcp_upstreams.insert(tcp.to_ascii_lowercase()) {
                return Err(ConfigError::InvalidPhpConfig {
                    field: "php.fpm.tcp_upstreams",
                    reason: "duplicate upstreams are not allowed",
                });
            }
        }

        validate_optional_timeout_secs("php.fpm.connect_timeout_secs", self.connect_timeout_secs)?;
        validate_optional_timeout_secs("php.fpm.read_timeout_secs", self.read_timeout_secs)?;
        validate_optional_timeout_secs("php.fpm.write_timeout_secs", self.write_timeout_secs)?;
        validate_optional_timeout_secs("php.fpm.retry_timeout_secs", self.retry_timeout_secs)?;
        if self.max_retries > MAX_PHP_FPM_RETRIES {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.fpm.max_retries",
                reason: "must be less than or equal to 10",
            });
        }
        validate_php_fpm_retry_methods(&self.retry_methods)?;
        validate_php_fpm_retry_statuses(&self.retry_statuses)?;
        if self.keepalive {
            if self.pool_max_idle == 0 {
                return Err(ConfigError::InvalidPhpConfig {
                    field: "php.fpm.pool_max_idle",
                    reason: "must be greater than zero when php.fpm.keepalive is enabled",
                });
            }
            if self.pool_max_idle > MAX_PHP_FPM_POOL_MAX_IDLE {
                return Err(ConfigError::InvalidPhpConfig {
                    field: "php.fpm.pool_max_idle",
                    reason: "must be less than or equal to 1024",
                });
            }
            validate_required_timeout_secs("php.fpm.idle_timeout_secs", self.idle_timeout_secs)?;
        }
        Ok(())
    }
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

fn default_php_fpm_managed_workers() -> usize {
    4
}

fn default_php_fpm_managed_max_requests() -> usize {
    1000
}

fn default_php_fpm_slowlog_trace_depth() -> usize {
    20
}
fn default_php_index() -> String {
    "index.php".to_owned()
}

fn default_php_allowed_extensions() -> Vec<String> {
    vec!["php".to_owned()]
}

fn default_php_request_timeout_secs() -> u64 {
    30
}

fn default_php_max_in_flight() -> usize {
    DEFAULT_PHP_MAX_IN_FLIGHT
}

fn default_php_max_response_bytes() -> ByteSize {
    ByteSize::from_bytes(64 * 1024 * 1024)
}

fn default_php_max_response_header_bytes() -> ByteSize {
    ByteSize::from_bytes(64 * 1024)
}

fn default_php_stderr_max_bytes() -> ByteSize {
    ByteSize::from_bytes(2048)
}

fn default_php_fpm_pool_max_idle() -> usize {
    8
}

fn default_php_fpm_idle_timeout_secs() -> u64 {
    60
}

fn default_php_fpm_retry_methods() -> Vec<String> {
    vec!["GET".to_owned(), "HEAD".to_owned(), "OPTIONS".to_owned()]
}

fn default_true() -> bool {
    true
}

fn validate_php_request_body_spool_dir(field: String, path: &Path) -> Result<(), ConfigError> {
    validate_path(field.clone(), Some(path))?;
    #[cfg(unix)]
    match crate::fs_trust::existing_path_or_parent_has_insecure_write_permissions(path) {
        Ok(true) => {
            return Err(ConfigError::UnsafePath {
                field,
                path: path.to_path_buf(),
            });
        }
        Ok(false) => {}
        Err(error) => {
            return Err(path_inspection_failed(field, path, error));
        }
    }
    #[cfg(not(unix))]
    validate_non_world_writable_parent(field.clone(), Some(path))?;

    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_dir() => {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.request_body_spool_dir",
                reason: "must be a directory when it already exists",
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(path_inspection_failed(field, path, error));
        }
    }

    Ok(())
}

fn validate_php_error_pages(error_pages: &[ProxyErrorPageConfig]) -> Result<(), ConfigError> {
    if error_pages.len() > MAX_PHP_ERROR_PAGES {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.error_pages",
            reason: "at most 64 error pages are allowed",
        });
    }
    let mut seen = BTreeSet::new();
    for error_page in error_pages {
        if !(400..=599).contains(&error_page.status) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.error_pages.status",
                reason: "statuses must be HTTP error statuses from 400 through 599",
            });
        }
        validate_route_path("php.error_pages.path", &error_page.path, false).map_err(|_| {
            ConfigError::InvalidPhpConfig {
                field: "php.error_pages.path",
                reason: "must be an absolute internal request path",
            }
        })?;
        error_page.web.validate()?;
        if !error_page.web.enabled() {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.error_pages.web.root",
                reason: "is required for each PHP error page",
            });
        }
        if !seen.insert(error_page.status) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.error_pages.status",
                reason: "duplicate statuses are not allowed",
            });
        }
    }
    Ok(())
}

fn validate_php_root_path(
    field: impl Into<String>,
    path: &Path,
    allow_final_symlink: bool,
) -> Result<(), ConfigError> {
    let field = field.into();
    if !allow_final_symlink {
        return validate_path(field, Some(path));
    }

    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ConfigError::UnsafePath {
            field,
            path: path.to_path_buf(),
        });
    }

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        match path_existing_prefix_contains_symlink(parent) {
            Ok(true) => {
                return Err(ConfigError::UnsafePath {
                    field,
                    path: path.to_path_buf(),
                });
            }
            Ok(false) => {}
            Err(error) => {
                return Err(path_inspection_failed(field, path, error));
            }
        }
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let resolved = path
                .canonicalize()
                .map_err(|error| path_inspection_failed(field.clone(), path, error))?;
            validate_path(format!("{field}.resolved"), Some(&resolved))?;
        }
        Ok(_) => validate_path(field, Some(path))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(path_inspection_failed(field, path, error));
        }
    }

    Ok(())
}
