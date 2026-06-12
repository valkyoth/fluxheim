use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{
    ByteSize, ConfigError, ProxyErrorPageConfig, extend_unique, validate_optional_timeout_secs,
    validate_required_timeout_secs,
};
use crate::config_header::validate_header_name;
use crate::config_net::valid_authority;
use crate::config_path::{
    path_existing_prefix_contains_symlink, path_inspection_failed,
    validate_non_world_writable_parent, validate_path,
};
use crate::config_route::validate_route_path;

pub const MAX_PHP_ALLOWED_EXTENSIONS: usize = 16;
pub const MAX_PHP_DENY_PATH_PREFIXES: usize = 128;
pub const MAX_PHP_HIDE_RESPONSE_HEADERS: usize = 64;
pub const MAX_PHP_STDERR_FAILURE_PATTERNS: usize = 32;
pub const MAX_PHP_PARAMS: usize = 128;
pub const MAX_PHP_FPM_RETRY_METHODS: usize = 16;
pub const MAX_PHP_FPM_RETRY_STATUSES: usize = 100;
pub const MAX_PHP_INTERCEPT_ERROR_STATUSES: usize = 200;
pub const DEFAULT_PHP_MAX_IN_FLIGHT: usize = 8;
pub const MAX_PHP_MAX_IN_FLIGHT: usize = 4096;
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

pub fn validate_php_params(params: &BTreeMap<String, String>) -> Result<(), ConfigError> {
    if params.len() > MAX_PHP_PARAMS {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.params",
            reason: "at most 128 parameters are allowed",
        });
    }
    for (name, value) in params {
        validate_php_param_name(name)?;
        validate_php_param_value(value)?;
    }
    Ok(())
}

pub fn validate_php_index(index: &str) -> Result<(), ConfigError> {
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

pub fn validate_php_extensions(extensions: &[String]) -> Result<(), ConfigError> {
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

pub fn validate_php_deny_path_prefixes(prefixes: &[String]) -> Result<(), ConfigError> {
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

pub fn validate_php_stderr_failure_patterns(patterns: &[String]) -> Result<(), ConfigError> {
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

pub fn validate_php_hide_response_headers(headers: &[String]) -> Result<(), ConfigError> {
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

pub fn validate_php_fpm_retry_methods(methods: &[String]) -> Result<(), ConfigError> {
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

pub fn validate_php_fpm_retry_statuses(statuses: &[u16]) -> Result<(), ConfigError> {
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

pub fn validate_php_intercept_error_statuses(statuses: &[u16]) -> Result<(), ConfigError> {
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

pub fn protected_php_param_name(name: &str) -> bool {
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
            | "PHP_ADMIN_VALUE"
            | "PHP_VALUE"
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
