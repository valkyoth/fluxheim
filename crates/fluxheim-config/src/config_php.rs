use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{ByteSize, ConfigError, ProxyErrorPageConfig, validate_required_timeout_secs};
use crate::config_path::{validate_non_world_writable_parent, validate_path};
use crate::config_php_defaults::{
    default_php_allowed_extensions, default_php_fpm_idle_timeout_secs,
    default_php_fpm_managed_max_requests, default_php_fpm_managed_workers,
    default_php_fpm_pool_max_idle, default_php_fpm_retry_methods,
    default_php_fpm_slowlog_trace_depth, default_php_index, default_php_max_in_flight,
    default_php_max_response_bytes, default_php_max_response_header_bytes,
    default_php_request_timeout_secs, default_php_stderr_max_bytes, default_true,
};
pub use crate::config_php_fpm_validate::MAX_PHP_FPM_TCP_UPSTREAMS;
use crate::config_php_fpm_validate::validate_php_fpm_config;
use crate::config_php_limits::validate_php_limits;
#[cfg(unix)]
pub use crate::config_php_managed::validate_php_fpm_managed_config;
pub use crate::config_php_paths::MAX_PHP_ERROR_PAGES;
use crate::config_php_paths::{
    php_root_resolved_path, validate_php_error_pages, validate_php_request_body_spool_dir,
    validate_php_root_path,
};
use crate::config_php_preset::apply_php_preset_defaults;
pub use crate::config_php_types::{
    PhpFpmMode, PhpFpmProcessManager, PhpPathInfoMode, PhpPreset, PhpRuntime, PhpStderrLogLevel,
    PhpTryFilesMode,
};
pub use crate::config_php_validation::{
    MAX_PHP_ALLOWED_EXTENSIONS, MAX_PHP_DENY_PATH_PREFIXES, MAX_PHP_FPM_RETRY_METHODS,
    MAX_PHP_FPM_RETRY_STATUSES, MAX_PHP_HIDE_RESPONSE_HEADERS, MAX_PHP_INTERCEPT_ERROR_STATUSES,
    MAX_PHP_PARAMS, MAX_PHP_STDERR_FAILURE_PATTERNS, protected_php_param_name,
    validate_php_deny_path_prefixes, validate_php_extensions, validate_php_fpm_retry_methods,
    validate_php_fpm_retry_statuses, validate_php_hide_response_headers, validate_php_index,
    validate_php_intercept_error_statuses, validate_php_params,
    validate_php_stderr_failure_patterns,
};

pub const DEFAULT_PHP_MAX_IN_FLIGHT: usize = 8;
pub const MAX_PHP_MAX_IN_FLIGHT: usize = 4096;

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
        apply_php_preset_defaults(self);
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
            && let Some(resolved) = php_root_resolved_path(root_field.clone(), root)?
        {
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
            if matches!(self.fpm.mode, PhpFpmMode::Managed) {
                validate_non_world_writable_parent(fpm_root_field, Some(fpm_root))?;
            }
        }

        validate_php_index(&self.index)?;
        validate_php_extensions(&self.allowed_extensions)?;
        validate_php_deny_path_prefixes(&self.deny_path_prefixes)?;
        validate_php_params(&self.params)?;
        validate_required_timeout_secs("php.request_timeout_secs", self.request_timeout_secs)?;
        validate_php_limits(self)?;
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
        validate_php_stderr_failure_patterns(&self.stderr_failure_patterns)?;
        validate_php_hide_response_headers(&self.hide_response_headers)?;
        validate_php_intercept_error_statuses(&self.intercept_error_statuses)?;
        validate_php_error_pages(&self.error_pages)?;

        self.fpm.validate(scope)?;
        Ok(())
    }
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
        validate_php_fpm_config(self, scope)
    }
}
