use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use toml::value::{Datetime, Offset};

#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400000;

const MAX_CONFIG_DIRECTORY_FILES: usize = 256;
const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;
const MAX_ADMIN_HEALTH_PATH_BYTES: usize = 2048;
const DEFAULT_ADMIN_HEALTH_PATH: &str = "/_fluxheim/health";
const DEFAULT_UPSTREAM: &str = "127.0.0.1:3000";

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub headers: HeaderPolicyConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub web: WebConfig,
    #[serde(default)]
    pub vhosts: Vec<VhostConfig>,
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigLoadError> {
        let config = match path {
            Some(path) => {
                let path = canonical_config_source(path)?;
                if path.is_dir() {
                    Self::load_dir(&path)?
                } else {
                    Self::load_file(&path)?
                }
            }
            None => Self::default(),
        };

        config.validate().map_err(ConfigLoadError::Validate)?;
        Ok(config)
    }

    fn load_file(path: &Path) -> Result<Self, ConfigLoadError> {
        let mut fragment = ConfigFragment::load(path)?;
        if let Some(parent) = path.parent() {
            fragment.resolve_relative_paths(parent);
        }

        let mut config = Self::default();
        config.merge(fragment);
        Ok(config)
    }

    fn load_dir(path: &Path) -> Result<Self, ConfigLoadError> {
        let mut files = toml_files(path)?;
        files.sort();

        let mut config = Self::default();
        for file in files {
            let mut fragment = ConfigFragment::load(&file)?;
            if let Some(parent) = file.parent() {
                fragment.resolve_relative_paths(parent);
            }
            config.merge(fragment);
        }

        Ok(config)
    }

    fn merge(&mut self, fragment: ConfigFragment) {
        if let Some(server) = fragment.server {
            self.server.merge(server);
        }
        if let Some(admin) = fragment.admin {
            self.admin = admin;
        }
        if let Some(metrics) = fragment.metrics {
            self.metrics = metrics;
        }
        if let Some(logging) = fragment.logging {
            self.logging = logging;
        }
        if let Some(headers) = fragment.headers {
            self.headers = headers;
        }
        if let Some(tls) = fragment.tls {
            self.tls = tls;
        }
        if let Some(proxy) = fragment.proxy {
            self.proxy = proxy;
        }
        if let Some(cache) = fragment.cache {
            self.cache = cache;
        }
        if let Some(web) = fragment.web {
            self.web = web;
        }
        self.vhosts.extend(fragment.vhosts);
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.server.validate()?;
        self.admin.validate()?;
        self.metrics.validate()?;
        self.logging.validate()?;
        self.headers.validate()?;
        self.tls.validate()?;
        self.validate_tls_listeners()?;
        self.proxy.validate()?;
        self.cache.validate("cache")?;
        self.web.validate()?;
        self.validate_vhosts()?;
        Ok(())
    }

    fn validate_tls_listeners(&self) -> Result<(), ConfigError> {
        if self.server.tls_listen.is_empty() {
            return Ok(());
        }
        if !self.tls.enabled {
            return Err(ConfigError::TlsListenerWithoutTls);
        }
        if self.tls.certificates.is_empty() {
            return Err(ConfigError::TlsListenerWithoutStaticCertificate);
        }

        Ok(())
    }

    fn validate_vhosts(&self) -> Result<(), ConfigError> {
        let mut seen_names = std::collections::HashSet::new();
        let mut seen_hosts = std::collections::HashSet::new();

        for vhost in &self.vhosts {
            vhost.validate()?;
            vhost.validate_tls(&self.tls)?;

            if !seen_names.insert(vhost.name.clone()) {
                return Err(ConfigError::DuplicateVhostName {
                    name: vhost.name.clone(),
                });
            }

            for host in &vhost.hosts {
                let normalized_host =
                    normalize_host_pattern(host).ok_or_else(|| ConfigError::InvalidVhostHost {
                        vhost: vhost.name.clone(),
                        host: host.clone(),
                    })?;
                if !seen_hosts.insert(normalized_host.clone()) {
                    return Err(ConfigError::DuplicateVhostHost {
                        host: normalized_host,
                    });
                }
            }
        }

        if let Some(default_vhost) = &self.server.default_vhost
            && !self.vhosts.iter().any(|vhost| &vhost.name == default_vhost)
        {
            return Err(ConfigError::UnknownDefaultVhost {
                name: default_vhost.clone(),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigFragment {
    #[serde(default)]
    server: Option<ServerConfigFragment>,
    #[serde(default)]
    admin: Option<AdminConfig>,
    #[serde(default)]
    metrics: Option<MetricsConfig>,
    #[serde(default)]
    logging: Option<LoggingConfig>,
    #[serde(default)]
    headers: Option<HeaderPolicyConfig>,
    #[serde(default)]
    tls: Option<TlsConfig>,
    #[serde(default)]
    proxy: Option<ProxyConfig>,
    #[serde(default)]
    cache: Option<CacheConfig>,
    #[serde(default)]
    web: Option<WebConfig>,
    #[serde(default)]
    vhosts: Vec<VhostConfig>,
}

impl ConfigFragment {
    fn load(path: &Path) -> Result<Self, ConfigLoadError> {
        if !regular_visible_toml_file(path)? {
            return Err(ConfigLoadError::InvalidPath {
                path: path.to_path_buf(),
            });
        }
        let raw = read_regular_config_file_to_string(path)?;
        toml::from_str(&raw).map_err(ConfigLoadError::Parse)
    }

    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(server) = &mut self.server {
            server.resolve_relative_paths(base_dir);
        }
        if let Some(tls) = &mut self.tls {
            tls.resolve_relative_paths(base_dir);
        }
        if let Some(admin) = &mut self.admin {
            admin.resolve_relative_paths(base_dir);
        }
        if let Some(logging) = &mut self.logging {
            logging.resolve_relative_paths(base_dir);
        }
        if let Some(cache) = &mut self.cache {
            cache.resolve_relative_paths(base_dir);
        }
        if let Some(web) = &mut self.web {
            web.resolve_relative_paths(base_dir);
        }
        for vhost in &mut self.vhosts {
            vhost.resolve_relative_paths(base_dir);
        }
    }
}

impl ServerConfigFragment {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(process) = &mut self.process {
            process.resolve_relative_paths(base_dir);
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: Vec<String>,
    #[serde(default)]
    pub tls_listen: Vec<String>,
    #[serde(default)]
    pub default_vhost: Option<String>,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub limits: ServerLimitsConfig,
    #[serde(default)]
    pub process: ServerProcessConfig,
    #[serde(default)]
    pub https_redirect: HttpsRedirectConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            tls_listen: Vec::new(),
            default_vhost: None,
            trusted_proxies: Vec::new(),
            limits: ServerLimitsConfig::default(),
            process: ServerProcessConfig::default(),
            https_redirect: HttpsRedirectConfig::default(),
        }
    }
}

impl ServerConfig {
    fn merge(&mut self, fragment: ServerConfigFragment) {
        if let Some(listen) = fragment.listen {
            self.listen = listen;
        }
        if let Some(tls_listen) = fragment.tls_listen {
            self.tls_listen = tls_listen;
        }
        if let Some(default_vhost) = fragment.default_vhost {
            self.default_vhost = Some(default_vhost);
        }
        if let Some(trusted_proxies) = fragment.trusted_proxies {
            self.trusted_proxies = trusted_proxies;
        }
        if let Some(limits) = fragment.limits {
            self.limits = limits;
        }
        if let Some(process) = fragment.process {
            self.process = process;
        }
        if let Some(https_redirect) = fragment.https_redirect {
            self.https_redirect = https_redirect;
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.listen.is_empty() {
            return Err(ConfigError::EmptyListeners);
        }

        for listen in &self.listen {
            if listen.parse::<SocketAddr>().is_err() {
                return Err(ConfigError::InvalidListenAddress {
                    address: listen.clone(),
                });
            }
        }
        for listen in &self.tls_listen {
            if listen.parse::<SocketAddr>().is_err() {
                return Err(ConfigError::InvalidListenAddress {
                    address: listen.clone(),
                });
            }
        }
        if self.https_redirect.enabled && self.tls_listen.is_empty() {
            return Err(ConfigError::HttpsRedirectWithoutTlsListener);
        }

        if let Some(default_vhost) = &self.default_vhost
            && default_vhost.trim().is_empty()
        {
            return Err(ConfigError::EmptyDefaultVhost);
        }
        for proxy in &self.trusted_proxies {
            if !valid_trusted_proxy(proxy) {
                return Err(ConfigError::InvalidTrustedProxy {
                    value: proxy.clone(),
                });
            }
        }

        self.limits.validate()?;
        self.process.validate()?;
        self.https_redirect.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServerConfigFragment {
    #[serde(default)]
    listen: Option<Vec<String>>,
    #[serde(default)]
    tls_listen: Option<Vec<String>>,
    #[serde(default)]
    default_vhost: Option<String>,
    #[serde(default)]
    trusted_proxies: Option<Vec<String>>,
    #[serde(default)]
    limits: Option<ServerLimitsConfig>,
    #[serde(default)]
    process: Option<ServerProcessConfig>,
    #[serde(default)]
    https_redirect: Option<HttpsRedirectConfig>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpsRedirectConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_https_redirect_status")]
    pub status: u16,
    #[serde(default)]
    pub target_port: Option<u16>,
}

impl Default for HttpsRedirectConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            status: default_https_redirect_status(),
            target_port: None,
        }
    }
}

impl HttpsRedirectConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !matches!(self.status, 301 | 302 | 307 | 308) {
            return Err(ConfigError::InvalidHttpsRedirectStatus {
                status: self.status,
            });
        }
        if self.target_port == Some(0) {
            return Err(ConfigError::InvalidHttpsRedirectTargetPort);
        }

        Ok(())
    }
}

fn default_https_redirect_status() -> u16 {
    308
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerProcessConfig {
    #[serde(default)]
    pub daemon: bool,
    #[serde(default)]
    pub error_log: Option<PathBuf>,
    #[serde(default = "default_process_pid_file")]
    pub pid_file: PathBuf,
    #[serde(default = "default_process_upgrade_sock")]
    pub upgrade_sock: PathBuf,
    #[serde(default = "default_process_threads")]
    pub threads: usize,
    #[serde(default = "default_process_listener_tasks_per_fd")]
    pub listener_tasks_per_fd: usize,
    #[serde(default = "default_true")]
    pub work_stealing: bool,
    #[serde(default = "default_process_upstream_keepalive_pool_size")]
    pub upstream_keepalive_pool_size: usize,
    #[serde(default = "default_process_max_retries")]
    pub max_retries: usize,
    #[serde(default)]
    pub grace_period_seconds: Option<u64>,
    #[serde(default)]
    pub graceful_shutdown_timeout_seconds: Option<u64>,
}

impl Default for ServerProcessConfig {
    fn default() -> Self {
        Self {
            daemon: false,
            error_log: None,
            pid_file: default_process_pid_file(),
            upgrade_sock: default_process_upgrade_sock(),
            threads: default_process_threads(),
            listener_tasks_per_fd: default_process_listener_tasks_per_fd(),
            work_stealing: true,
            upstream_keepalive_pool_size: default_process_upstream_keepalive_pool_size(),
            max_retries: default_process_max_retries(),
            grace_period_seconds: None,
            graceful_shutdown_timeout_seconds: None,
        }
    }
}

impl ServerProcessConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(error_log) = &mut self.error_log
            && error_log.is_relative()
        {
            *error_log = base_dir.join(&error_log);
        }
        if self.pid_file.is_relative() {
            self.pid_file = base_dir.join(&self.pid_file);
        }
        if self.upgrade_sock.is_relative() {
            self.upgrade_sock = base_dir.join(&self.upgrade_sock);
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        validate_optional_process_path("server.process.error_log", self.error_log.as_deref())?;
        validate_required_process_path("server.process.pid_file", &self.pid_file)?;
        validate_required_process_path("server.process.upgrade_sock", &self.upgrade_sock)?;
        validate_process_usize("server.process.threads", self.threads, 1, 1024)?;
        validate_process_usize(
            "server.process.listener_tasks_per_fd",
            self.listener_tasks_per_fd,
            1,
            1024,
        )?;
        validate_process_usize(
            "server.process.upstream_keepalive_pool_size",
            self.upstream_keepalive_pool_size,
            1,
            1_000_000,
        )?;
        validate_process_usize("server.process.max_retries", self.max_retries, 0, 1024)?;
        validate_process_optional_duration(
            "server.process.grace_period_seconds",
            self.grace_period_seconds,
        )?;
        validate_process_optional_duration(
            "server.process.graceful_shutdown_timeout_seconds",
            self.graceful_shutdown_timeout_seconds,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_admin_listen")]
    pub listen: String,
    #[serde(default = "default_admin_require_loopback")]
    pub require_loopback: bool,
    #[serde(default)]
    pub token_env: Option<String>,
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    #[serde(default)]
    pub snapshot_store: Option<PathBuf>,
    #[serde(default)]
    pub self_healing: AdminSelfHealingConfig,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_admin_listen(),
            require_loopback: default_admin_require_loopback(),
            token_env: None,
            token_file: None,
            snapshot_store: None,
            self_healing: AdminSelfHealingConfig::default(),
        }
    }
}

impl AdminConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(token_file) = &mut self.token_file
            && token_file.is_relative()
        {
            *token_file = base_dir.join(&token_file);
        }
        if let Some(snapshot_store) = &mut self.snapshot_store
            && snapshot_store.is_relative()
        {
            *snapshot_store = base_dir.join(&snapshot_store);
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let listen = self.listen.parse::<SocketAddr>().map_err(|_| {
            ConfigError::InvalidAdminListenAddress {
                address: self.listen.clone(),
            }
        })?;

        validate_optional_env("admin.token_env", self.token_env.as_deref())?;
        validate_optional_path("admin.token_file", self.token_file.as_deref())?;
        validate_optional_path("admin.snapshot_store", self.snapshot_store.as_deref())?;
        validate_path("admin.token_file", self.token_file.as_deref())?;
        validate_path("admin.snapshot_store", self.snapshot_store.as_deref())?;
        validate_non_world_writable_parent("admin.token_file", self.token_file.as_deref())?;
        validate_non_world_writable_parent("admin.snapshot_store", self.snapshot_store.as_deref())?;
        self.self_healing.validate()?;

        if !self.enabled {
            return Ok(());
        }

        if self.require_loopback && !listen.ip().is_loopback() {
            return Err(ConfigError::AdminListenNotLoopback {
                address: self.listen.clone(),
            });
        }

        match (&self.token_env, &self.token_file) {
            (None, None) => Err(ConfigError::MissingAdminAuth),
            (Some(_), Some(_)) => Err(ConfigError::ConflictingAdminAuth),
            (Some(_), None) | (None, Some(_)) => {
                if self.snapshot_store.is_none() {
                    Err(ConfigError::MissingAdminSnapshotStore)
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSelfHealingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_admin_validation_window_secs")]
    pub validation_window_secs: u64,
    #[serde(default = "default_admin_health_path")]
    pub health_path: String,
    #[serde(default = "default_admin_min_successful_checks")]
    pub min_successful_checks: usize,
    #[serde(default = "default_admin_max_error_rate_per_mille")]
    pub max_error_rate_per_mille: u16,
}

impl Default for AdminSelfHealingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            validation_window_secs: default_admin_validation_window_secs(),
            health_path: default_admin_health_path(),
            min_successful_checks: default_admin_min_successful_checks(),
            max_error_rate_per_mille: default_admin_max_error_rate_per_mille(),
        }
    }
}

impl AdminSelfHealingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.validation_window_secs == 0 {
            return Err(ConfigError::InvalidAdminSelfHealing {
                field: "admin.self_healing.validation_window_secs",
            });
        }
        if self.min_successful_checks == 0 {
            return Err(ConfigError::InvalidAdminSelfHealing {
                field: "admin.self_healing.min_successful_checks",
            });
        }
        if self.max_error_rate_per_mille > 1000 {
            return Err(ConfigError::InvalidAdminSelfHealing {
                field: "admin.self_healing.max_error_rate_per_mille",
            });
        }
        if !self.health_path.starts_with('/')
            || self.health_path.trim() != self.health_path
            || self.health_path.len() > MAX_ADMIN_HEALTH_PATH_BYTES
            || self
                .health_path
                .bytes()
                .any(|byte| byte.is_ascii_control() || matches!(byte, b' ' | b'\\' | b'?' | b'#'))
            || (self.health_path.starts_with("/_fluxheim/")
                && self.health_path != DEFAULT_ADMIN_HEALTH_PATH)
        {
            return Err(ConfigError::InvalidAdminHealthPath {
                path: self.health_path.clone(),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_listen")]
    pub listen: String,
    #[serde(default = "default_metrics_require_loopback")]
    pub require_loopback: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_metrics_listen(),
            require_loopback: default_metrics_require_loopback(),
        }
    }
}

impl MetricsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let listen = self.listen.parse::<SocketAddr>().map_err(|_| {
            ConfigError::InvalidMetricsListenAddress {
                address: self.listen.clone(),
            }
        })?;

        if self.enabled && self.require_loopback && !listen.ip().is_loopback() {
            return Err(ConfigError::MetricsListenNotLoopback {
                address: self.listen.clone(),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default)]
    pub level: LoggingLevel,
    #[serde(default)]
    pub format: LoggingFormat,
    #[serde(default)]
    pub target: LoggingTarget,
    #[serde(default)]
    pub file: LoggingFileConfig,
    #[serde(default)]
    pub access: AccessLoggingConfig,
}

impl LoggingConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.file.path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.file.validate()?;
        self.access.validate()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingFileConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub append: bool,
}

impl Default for LoggingFileConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: None,
            append: true,
        }
    }
}

impl LoggingFileConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        #[cfg(feature = "privacy-mode")]
        if self.enabled {
            return Err(ConfigError::PrivacyModeFileLogging);
        }

        if self.enabled && self.path.is_none() {
            return Err(ConfigError::MissingLoggingFilePath);
        }

        if self
            .path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(ConfigError::EmptyLoggingFilePath);
        }

        validate_path("logging.file.path", self.path.as_deref())?;
        #[cfg(unix)]
        if let Some(path) = self.path.as_deref()
            && path_existing_parent_is_world_writable(path).unwrap_or(true)
        {
            return Err(ConfigError::UnsafePath {
                field: "logging.file.path".to_owned(),
                path: path.to_path_buf(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LoggingLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    Off,
}

impl LoggingLevel {
    pub fn as_filter(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Off => "off",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LoggingFormat {
    Text,
    #[default]
    Json,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LoggingTarget {
    Stdout,
    #[default]
    Stderr,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessLoggingConfig {
    #[serde(default = "default_access_logging_enabled")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub include_host: bool,
    #[serde(default = "default_true")]
    pub include_path: bool,
    #[serde(default = "default_true")]
    pub request_id: bool,
    #[serde(default = "default_request_id_header")]
    pub request_id_header: String,
}

impl Default for AccessLoggingConfig {
    fn default() -> Self {
        Self {
            enabled: default_access_logging_enabled(),
            include_host: true,
            include_path: true,
            request_id: true,
            request_id_header: default_request_id_header(),
        }
    }
}

impl AccessLoggingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        #[cfg(feature = "privacy-mode")]
        if self.enabled {
            return Err(ConfigError::PrivacyModeAccessLogging);
        }

        if self.request_id {
            validate_header_name("logging.access.request_id_header", &self.request_id_header)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderPolicyConfig {
    #[serde(default)]
    pub request: RequestHeaderPolicyConfig,
    #[serde(default)]
    pub response: ResponseHeaderPolicyConfig,
}

impl HeaderPolicyConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        self.request.validate()?;
        self.response.validate()
    }

    pub fn with_vhost_overlay(&self, overlay: &VhostHeaderPolicyConfig) -> Self {
        let mut policy = self.clone();
        policy.request.apply_overlay(&overlay.request);
        policy.response.apply_overlay(&overlay.response);
        policy
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VhostHeaderPolicyConfig {
    #[serde(default)]
    pub request: RequestHeaderPolicyOverlayConfig,
    #[serde(default)]
    pub response: ResponseHeaderPolicyOverlayConfig,
}

impl VhostHeaderPolicyConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        self.request.validate()?;
        self.response.validate()
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestHeaderPolicyOverlayConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub strip_inbound_client_ip_headers: Option<bool>,
    #[serde(default)]
    pub x_forwarded_for: Option<ForwardedClientIpHeaderMode>,
    #[serde(default)]
    pub x_forwarded_host: Option<bool>,
    #[serde(default)]
    pub x_forwarded_proto: Option<bool>,
    #[serde(default)]
    pub forwarded: Option<bool>,
    #[serde(default)]
    pub unset: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    #[serde(default)]
    pub add: BTreeMap<String, String>,
    #[serde(default)]
    pub append: BTreeMap<String, HeaderValues>,
    #[serde(default)]
    pub operations: HeaderOperationsConfig,
}

impl RequestHeaderPolicyOverlayConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_header_add_aliases(
            "vhosts.headers.request",
            &self.set,
            &self.add,
            &self.operations.add,
        )?;
        let unset = combined_header_unset(&self.unset, &self.remove, &self.operations.remove);
        let set = combined_header_set(&self.set, &self.add, &self.operations.add);
        validate_header_mutations("vhosts.headers.request", &unset, &set, &self.append)
    }

    fn effective_unset(&self) -> Vec<String> {
        combined_header_unset(&self.unset, &self.remove, &self.operations.remove)
    }

    fn effective_set(&self) -> BTreeMap<String, String> {
        combined_header_set(&self.set, &self.add, &self.operations.add)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestHeaderPolicyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub strip_inbound_client_ip_headers: bool,
    #[serde(default)]
    pub x_forwarded_for: ForwardedClientIpHeaderMode,
    #[serde(default = "default_true")]
    pub x_forwarded_host: bool,
    #[serde(default = "default_true")]
    pub x_forwarded_proto: bool,
    #[serde(default)]
    pub forwarded: bool,
    #[serde(default)]
    pub unset: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    #[serde(default)]
    pub add: BTreeMap<String, String>,
    #[serde(default)]
    pub append: BTreeMap<String, HeaderValues>,
    #[serde(default)]
    pub operations: HeaderOperationsConfig,
}

impl Default for RequestHeaderPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strip_inbound_client_ip_headers: true,
            #[cfg(not(feature = "privacy-mode"))]
            x_forwarded_for: ForwardedClientIpHeaderMode::Replace,
            #[cfg(feature = "privacy-mode")]
            x_forwarded_for: ForwardedClientIpHeaderMode::Off,
            x_forwarded_host: true,
            x_forwarded_proto: true,
            forwarded: false,
            unset: Vec::new(),
            remove: Vec::new(),
            set: BTreeMap::new(),
            add: BTreeMap::new(),
            append: BTreeMap::new(),
            operations: HeaderOperationsConfig::default(),
        }
    }
}

impl RequestHeaderPolicyConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_header_add_aliases(
            "headers.request",
            &self.set,
            &self.add,
            &self.operations.add,
        )?;
        let unset = self.effective_unset();
        let set = self.effective_set();
        validate_header_mutations("headers.request", &unset, &set, &self.append)?;
        Ok(())
    }

    pub fn effective_unset(&self) -> Vec<String> {
        combined_header_unset(&self.unset, &self.remove, &self.operations.remove)
    }

    pub fn effective_set(&self) -> BTreeMap<String, String> {
        combined_header_set(&self.set, &self.add, &self.operations.add)
    }

    fn apply_overlay(&mut self, overlay: &RequestHeaderPolicyOverlayConfig) {
        if let Some(enabled) = overlay.enabled {
            self.enabled = enabled;
        }
        if let Some(strip) = overlay.strip_inbound_client_ip_headers {
            self.strip_inbound_client_ip_headers = strip;
        }
        if let Some(mode) = overlay.x_forwarded_for {
            self.x_forwarded_for = mode;
        }
        if let Some(enabled) = overlay.x_forwarded_host {
            self.x_forwarded_host = enabled;
        }
        if let Some(enabled) = overlay.x_forwarded_proto {
            self.x_forwarded_proto = enabled;
        }
        if let Some(enabled) = overlay.forwarded {
            self.forwarded = enabled;
        }
        merge_header_mutations(
            &mut self.unset,
            &mut self.set,
            &mut self.append,
            &overlay.effective_unset(),
            &overlay.effective_set(),
            &overlay.append,
        );
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ForwardedClientIpHeaderMode {
    Off,
    #[default]
    Replace,
    Append,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeaderPolicyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub strict_transport_security: Option<String>,
    #[serde(default)]
    pub content_security_policy: Option<String>,
    #[serde(default = "default_x_content_type_options")]
    pub x_content_type_options: Option<String>,
    #[serde(default = "default_x_frame_options")]
    pub x_frame_options: Option<String>,
    #[serde(default = "default_referrer_policy")]
    pub referrer_policy: Option<String>,
    #[serde(default = "default_response_unset_headers")]
    pub unset: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    #[serde(default)]
    pub add: BTreeMap<String, String>,
    #[serde(default)]
    pub append: BTreeMap<String, HeaderValues>,
    #[serde(default)]
    pub operations: HeaderOperationsConfig,
}

impl Default for ResponseHeaderPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strict_transport_security: None,
            content_security_policy: None,
            x_content_type_options: default_x_content_type_options(),
            x_frame_options: default_x_frame_options(),
            referrer_policy: default_referrer_policy(),
            unset: default_response_unset_headers(),
            remove: Vec::new(),
            set: BTreeMap::new(),
            add: BTreeMap::new(),
            append: BTreeMap::new(),
            operations: HeaderOperationsConfig::default(),
        }
    }
}

impl ResponseHeaderPolicyConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_optional_header_value(
            "headers.response.strict_transport_security",
            self.strict_transport_security.as_deref(),
        )?;
        validate_optional_header_value(
            "headers.response.content_security_policy",
            self.content_security_policy.as_deref(),
        )?;
        validate_optional_header_value(
            "headers.response.x_content_type_options",
            self.x_content_type_options.as_deref(),
        )?;
        validate_optional_header_value(
            "headers.response.x_frame_options",
            self.x_frame_options.as_deref(),
        )?;
        validate_optional_header_value(
            "headers.response.referrer_policy",
            self.referrer_policy.as_deref(),
        )?;
        validate_header_add_aliases(
            "headers.response",
            &self.set,
            &self.add,
            &self.operations.add,
        )?;
        let unset = self.effective_unset();
        let set = self.effective_set();
        validate_header_mutations("headers.response", &unset, &set, &self.append)?;

        Ok(())
    }

    pub fn effective_unset(&self) -> Vec<String> {
        combined_header_unset(&self.unset, &self.remove, &self.operations.remove)
    }

    pub fn effective_set(&self) -> BTreeMap<String, String> {
        combined_header_set(&self.set, &self.add, &self.operations.add)
    }

    fn apply_overlay(&mut self, overlay: &ResponseHeaderPolicyOverlayConfig) {
        if let Some(enabled) = overlay.enabled {
            self.enabled = enabled;
        }
        if let Some(value) = &overlay.strict_transport_security {
            self.strict_transport_security = value.clone();
        }
        if let Some(value) = &overlay.content_security_policy {
            self.content_security_policy = value.clone();
        }
        if let Some(value) = &overlay.x_content_type_options {
            self.x_content_type_options = value.clone();
        }
        if let Some(value) = &overlay.x_frame_options {
            self.x_frame_options = value.clone();
        }
        if let Some(value) = &overlay.referrer_policy {
            self.referrer_policy = value.clone();
        }
        merge_header_mutations(
            &mut self.unset,
            &mut self.set,
            &mut self.append,
            &overlay.effective_unset(),
            &overlay.effective_set(),
            &overlay.append,
        );
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeaderPolicyOverlayConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub strict_transport_security: Option<Option<String>>,
    #[serde(default)]
    pub content_security_policy: Option<Option<String>>,
    #[serde(default)]
    pub x_content_type_options: Option<Option<String>>,
    #[serde(default)]
    pub x_frame_options: Option<Option<String>>,
    #[serde(default)]
    pub referrer_policy: Option<Option<String>>,
    #[serde(default)]
    pub unset: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    #[serde(default)]
    pub add: BTreeMap<String, String>,
    #[serde(default)]
    pub append: BTreeMap<String, HeaderValues>,
    #[serde(default)]
    pub operations: HeaderOperationsConfig,
}

impl ResponseHeaderPolicyOverlayConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_optional_header_value(
            "vhosts.headers.response.strict_transport_security",
            self.strict_transport_security
                .as_ref()
                .and_then(Option::as_deref),
        )?;
        validate_optional_header_value(
            "vhosts.headers.response.content_security_policy",
            self.content_security_policy
                .as_ref()
                .and_then(Option::as_deref),
        )?;
        validate_optional_header_value(
            "vhosts.headers.response.x_content_type_options",
            self.x_content_type_options
                .as_ref()
                .and_then(Option::as_deref),
        )?;
        validate_optional_header_value(
            "vhosts.headers.response.x_frame_options",
            self.x_frame_options.as_ref().and_then(Option::as_deref),
        )?;
        validate_optional_header_value(
            "vhosts.headers.response.referrer_policy",
            self.referrer_policy.as_ref().and_then(Option::as_deref),
        )?;
        validate_header_add_aliases(
            "vhosts.headers.response",
            &self.set,
            &self.add,
            &self.operations.add,
        )?;
        let unset = self.effective_unset();
        let set = self.effective_set();
        validate_header_mutations("vhosts.headers.response", &unset, &set, &self.append)
    }

    fn effective_unset(&self) -> Vec<String> {
        combined_header_unset(&self.unset, &self.remove, &self.operations.remove)
    }

    fn effective_set(&self) -> BTreeMap<String, String> {
        combined_header_set(&self.set, &self.add, &self.operations.add)
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderOperationsConfig {
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub add: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum HeaderValues {
    One(String),
    Many(Vec<String>),
}

impl HeaderValues {
    pub fn iter(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        match self {
            Self::One(value) => Box::new(std::iter::once(value.as_str())),
            Self::Many(values) => Box::new(values.iter().map(String::as_str)),
        }
    }

    fn extend(&mut self, extra: &Self) {
        let mut values = self.iter().map(str::to_owned).collect::<Vec<_>>();
        values.extend(extra.iter().map(str::to_owned));
        *self = Self::Many(values);
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerLimitsConfig {
    #[serde(default = "default_max_request_header_bytes")]
    pub max_request_header_bytes: ByteSize,
    #[serde(default = "default_max_uri_bytes")]
    pub max_uri_bytes: ByteSize,
    #[serde(default = "default_max_request_headers")]
    pub max_request_headers: usize,
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: ByteSize,
}

impl Default for ServerLimitsConfig {
    fn default() -> Self {
        Self {
            max_request_header_bytes: default_max_request_header_bytes(),
            max_uri_bytes: default_max_uri_bytes(),
            max_request_headers: default_max_request_headers(),
            max_request_body_bytes: default_max_request_body_bytes(),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ByteSize(u64);

impl ByteSize {
    pub const fn from_bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub fn as_usize(self) -> usize {
        self.0.try_into().unwrap_or(usize::MAX)
    }
}

impl Serialize for ByteSize {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ByteSizeVisitor)
    }
}

struct ByteSizeVisitor;

impl Visitor<'_> for ByteSizeVisitor {
    type Value = ByteSize;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a byte count integer or string like \"64KiB\"")
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(ByteSize(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let value = u64::try_from(value).map_err(E::custom)?;
        Ok(ByteSize(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        ByteSize::from_str(value).map_err(E::custom)
    }
}

impl FromStr for ByteSize {
    type Err = ByteSizeParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input.trim();
        if input.is_empty() {
            return Err(ByteSizeParseError);
        }

        let split_at = input
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(input.len());
        let (digits, unit) = input.split_at(split_at);
        if digits.is_empty() {
            return Err(ByteSizeParseError);
        }

        let value = digits.parse::<u64>().map_err(|_| ByteSizeParseError)?;
        let multiplier = match unit.trim().to_ascii_lowercase().as_str() {
            "" | "b" => 1,
            "k" | "kb" | "kib" => 1024,
            "m" | "mb" | "mib" => 1024 * 1024,
            "g" | "gb" | "gib" => 1024 * 1024 * 1024,
            _ => return Err(ByteSizeParseError),
        };

        value
            .checked_mul(multiplier)
            .map(ByteSize)
            .ok_or(ByteSizeParseError)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ByteSizeParseError;

impl Display for ByteSizeParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid byte size")
    }
}

impl Error for ByteSizeParseError {}

impl ServerLimitsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_request_header_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidLimit {
                field: "server.limits.max_request_header_bytes",
            });
        }
        if self.max_uri_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidLimit {
                field: "server.limits.max_uri_bytes",
            });
        }
        if self.max_request_headers == 0 {
            return Err(ConfigError::InvalidLimit {
                field: "server.limits.max_request_headers",
            });
        }
        if self.max_request_body_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidLimit {
                field: "server.limits.max_request_body_bytes",
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub backend: TlsBackend,
    #[serde(default)]
    pub certificates: Vec<StaticCertificateConfig>,
    #[serde(default)]
    pub acme: AcmeConfig,
}

impl TlsConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        for certificate in &mut self.certificates {
            certificate.resolve_relative_paths(base_dir);
        }
        self.acme.resolve_relative_paths(base_dir);
    }

    fn validate(&self) -> Result<(), ConfigError> {
        for certificate in &self.certificates {
            certificate.validate("tls.certificates")?;
        }
        self.acme.validate()
    }

    fn acme_issuer_exists(&self, issuer: &str) -> bool {
        self.acme
            .issuers
            .iter()
            .any(|candidate| candidate.name == issuer)
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsBackend {
    #[default]
    Rustls,
    Openssl,
    Boringssl,
    S2n,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StaticCertificateConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl StaticCertificateConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if self.cert_path.is_relative() {
            self.cert_path = base_dir.join(&self.cert_path);
        }
        if self.key_path.is_relative() {
            self.key_path = base_dir.join(&self.key_path);
        }
    }

    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if self.cert_path.as_os_str().is_empty() {
            return Err(ConfigError::EmptyTlsCertificatePath { scope });
        }
        if self.key_path.as_os_str().is_empty() {
            return Err(ConfigError::EmptyTlsKeyPath { scope });
        }
        let cert_field = format!("{scope}.cert_path");
        let key_field = format!("{scope}.key_path");
        validate_path(cert_field.clone(), Some(&self.cert_path))?;
        validate_path(key_field.clone(), Some(&self.key_path))?;
        validate_non_world_writable_parent(cert_field, Some(&self.cert_path))?;
        validate_non_world_writable_parent(key_field, Some(&self.key_path))?;

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub storage: Option<PathBuf>,
    #[serde(default = "default_acme_contact_email")]
    pub contact_email: Option<String>,
    #[serde(default = "default_acme_default_issuer")]
    pub default_issuer: String,
    #[serde(default)]
    pub challenge: AcmeChallenge,
    #[serde(default)]
    pub renewal: AcmeRenewalConfig,
    #[serde(default = "default_acme_issuers")]
    pub issuers: Vec<AcmeIssuerConfig>,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            storage: None,
            contact_email: default_acme_contact_email(),
            default_issuer: default_acme_default_issuer(),
            challenge: AcmeChallenge::default(),
            renewal: AcmeRenewalConfig::default(),
            issuers: default_acme_issuers(),
        }
    }
}

impl AcmeConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(storage) = &mut self.storage
            && storage.is_relative()
        {
            *storage = base_dir.join(&storage);
        }
        for issuer in &mut self.issuers {
            issuer.resolve_relative_paths(base_dir);
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled {
            let Some(storage) = &self.storage else {
                return Err(ConfigError::MissingAcmeStorage);
            };
            if storage.as_os_str().is_empty() {
                return Err(ConfigError::EmptyAcmeStorage);
            }
            validate_path("tls.acme.storage", Some(storage))?;
            validate_non_world_writable_parent("tls.acme.storage", Some(storage))?;
            if self.contact_email.as_deref().is_none_or(invalid_email) {
                return Err(ConfigError::InvalidAcmeContactEmail);
            }
        }

        self.renewal.validate()?;

        if self.default_issuer.trim().is_empty() {
            return Err(ConfigError::EmptyAcmeIssuerName {
                scope: "tls.acme.default_issuer",
            });
        }

        let mut seen = std::collections::HashSet::new();
        for issuer in &self.issuers {
            issuer.validate()?;
            if !seen.insert(issuer.name.clone()) {
                return Err(ConfigError::DuplicateAcmeIssuerName {
                    name: issuer.name.clone(),
                });
            }
        }

        if !self
            .issuers
            .iter()
            .any(|issuer| issuer.name == self.default_issuer)
        {
            return Err(ConfigError::UnknownAcmeIssuer {
                name: self.default_issuer.clone(),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum AcmeChallenge {
    #[default]
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    #[serde(rename = "http-01")]
    Http01,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeRenewalConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_acme_renew_before_secs")]
    pub renew_before_secs: u64,
    #[serde(default)]
    pub renew_after: Option<toml::value::Datetime>,
    #[serde(default = "default_acme_renewal_check_interval_secs")]
    pub check_interval_secs: u64,
    #[serde(default = "default_acme_renewal_retry_initial_secs")]
    pub retry_initial_secs: u64,
    #[serde(default = "default_acme_renewal_retry_max_secs")]
    pub retry_max_secs: u64,
    #[serde(default = "default_true")]
    pub reload_after_renewal: bool,
    #[serde(default = "default_true")]
    pub zero_downtime_reload: bool,
}

impl Default for AcmeRenewalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            renew_before_secs: default_acme_renew_before_secs(),
            renew_after: None,
            check_interval_secs: default_acme_renewal_check_interval_secs(),
            retry_initial_secs: default_acme_renewal_retry_initial_secs(),
            retry_max_secs: default_acme_renewal_retry_max_secs(),
            reload_after_renewal: true,
            zero_downtime_reload: true,
        }
    }
}

impl AcmeRenewalConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.renew_before_secs == 0 {
            return Err(ConfigError::InvalidAcmeRenewalDuration {
                field: "tls.acme.renewal.renew_before_secs",
            });
        }
        if self.check_interval_secs == 0 {
            return Err(ConfigError::InvalidAcmeRenewalDuration {
                field: "tls.acme.renewal.check_interval_secs",
            });
        }
        if self.retry_initial_secs == 0 {
            return Err(ConfigError::InvalidAcmeRenewalDuration {
                field: "tls.acme.renewal.retry_initial_secs",
            });
        }
        if self.retry_max_secs == 0 {
            return Err(ConfigError::InvalidAcmeRenewalDuration {
                field: "tls.acme.renewal.retry_max_secs",
            });
        }
        if self.retry_initial_secs > self.retry_max_secs {
            return Err(ConfigError::AcmeRenewalRetryInitialExceedsMax);
        }
        if self
            .renew_after
            .as_ref()
            .is_some_and(invalid_acme_renew_after_datetime)
        {
            return Err(ConfigError::InvalidAcmeRenewAfterDatetime);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeIssuerConfig {
    pub name: String,
    pub directory_url: String,
    #[serde(default)]
    pub eab: Option<AcmeExternalAccountBindingConfig>,
}

impl AcmeIssuerConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(eab) = &mut self.eab {
            eab.resolve_relative_paths(base_dir);
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.name.trim().is_empty() {
            return Err(ConfigError::EmptyAcmeIssuerName {
                scope: "tls.acme.issuers.name",
            });
        }
        if !valid_https_url(&self.directory_url) {
            return Err(ConfigError::InvalidAcmeDirectoryUrl {
                issuer: self.name.clone(),
                url: self.directory_url.clone(),
            });
        }
        if let Some(eab) = &self.eab {
            eab.validate(&self.name)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeExternalAccountBindingConfig {
    #[serde(default)]
    pub key_id_env: Option<String>,
    #[serde(default)]
    pub key_id_file: Option<PathBuf>,
    #[serde(default)]
    pub hmac_key_env: Option<String>,
    #[serde(default)]
    pub hmac_key_file: Option<PathBuf>,
}

impl AcmeExternalAccountBindingConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.key_id_file
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
        if let Some(path) = &mut self.hmac_key_file
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
    }

    fn validate(&self, issuer: &str) -> Result<(), ConfigError> {
        validate_secret_source(
            issuer,
            "key_id",
            self.key_id_env.as_deref(),
            self.key_id_file.as_ref(),
        )?;
        validate_secret_source(
            issuer,
            "hmac_key",
            self.hmac_key_env.as_deref(),
            self.hmac_key_file.as_ref(),
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub upstream_tls: bool,
    #[serde(default)]
    pub upstream_sni: Option<String>,
    #[serde(default)]
    pub load_balance: LoadBalanceConfig,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            upstream: Some(default_upstream()),
            upstreams: Vec::new(),
            upstream_tls: false,
            upstream_sni: None,
            load_balance: LoadBalanceConfig::default(),
        }
    }
}

impl ProxyConfig {
    pub fn primary_upstream(&self) -> &str {
        self.upstreams
            .first()
            .map(String::as_str)
            .or(self.upstream.as_deref())
            .unwrap_or(DEFAULT_UPSTREAM)
    }

    pub fn upstream_sni(&self) -> String {
        self.upstream_sni
            .clone()
            .unwrap_or_else(|| upstream_host(self.primary_upstream()).unwrap_or_default())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.upstream.is_some() && !self.upstreams.is_empty() {
            return Err(ConfigError::ConflictingProxyUpstreams);
        }

        if let Some(upstream) = &self.upstream
            && !valid_authority(upstream)
        {
            return Err(ConfigError::InvalidUpstream {
                address: upstream.clone(),
            });
        }

        for upstream in &self.upstreams {
            if !valid_authority(upstream) {
                return Err(ConfigError::InvalidUpstream {
                    address: upstream.clone(),
                });
            }
        }

        if let Some(sni) = &self.upstream_sni
            && sni.trim().is_empty()
        {
            return Err(ConfigError::EmptyUpstreamSni);
        }

        self.load_balance.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceConfig {
    #[serde(default = "default_lb_max_iterations")]
    pub max_iterations: usize,
    #[serde(default)]
    pub health_check: LoadBalanceHealthCheckConfig,
}

impl Default for LoadBalanceConfig {
    fn default() -> Self {
        Self {
            max_iterations: default_lb_max_iterations(),
            health_check: LoadBalanceHealthCheckConfig::default(),
        }
    }
}

impl LoadBalanceConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_iterations == 0 {
            return Err(ConfigError::InvalidLoadBalanceMaxIterations);
        }

        self.health_check.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceHealthCheckConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_lb_health_check_interval_secs")]
    pub interval_secs: u64,
    #[serde(default = "default_lb_health_check_threshold")]
    pub consecutive_success: usize,
    #[serde(default = "default_lb_health_check_threshold")]
    pub consecutive_failure: usize,
    #[serde(default)]
    pub parallel: bool,
}

impl Default for LoadBalanceHealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: default_lb_health_check_interval_secs(),
            consecutive_success: default_lb_health_check_threshold(),
            consecutive_failure: default_lb_health_check_threshold(),
            parallel: false,
        }
    }
}

impl LoadBalanceHealthCheckConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.interval_secs == 0 {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.interval_secs",
            });
        }
        if self.consecutive_success == 0 {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.consecutive_success",
            });
        }
        if self.consecutive_failure == 0 {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.consecutive_failure",
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VhostConfig {
    pub name: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub tls: VhostTlsConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub headers: VhostHeaderPolicyConfig,
    #[serde(default)]
    pub web: WebConfig,
}

impl VhostConfig {
    pub fn normalized_hosts(&self) -> Vec<String> {
        self.hosts
            .iter()
            .filter_map(|host| normalize_host_pattern(host))
            .collect()
    }

    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        self.tls.resolve_relative_paths(base_dir);
        self.cache.resolve_relative_paths(base_dir);
        self.web.resolve_relative_paths(base_dir);
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.name.trim().is_empty() {
            return Err(ConfigError::EmptyVhostName);
        }

        if self.hosts.is_empty() {
            return Err(ConfigError::EmptyVhostHosts {
                vhost: self.name.clone(),
            });
        }

        self.proxy.validate()?;
        self.cache.validate("vhosts.cache")?;
        self.headers.validate()?;
        self.web.validate()?;

        for host in &self.hosts {
            if normalize_host_pattern(host).is_none() {
                return Err(ConfigError::InvalidVhostHost {
                    vhost: self.name.clone(),
                    host: host.clone(),
                });
            }
        }

        Ok(())
    }

    fn validate_tls(&self, global_tls: &TlsConfig) -> Result<(), ConfigError> {
        self.tls.validate("vhosts.tls", &self.hosts, global_tls)
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VhostTlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub certificate: Option<StaticCertificateConfig>,
    #[serde(default)]
    pub acme: VhostAcmeConfig,
}

impl VhostTlsConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(certificate) = &mut self.certificate {
            certificate.resolve_relative_paths(base_dir);
        }
    }

    fn validate(
        &self,
        scope: &'static str,
        vhost_hosts: &[String],
        global_tls: &TlsConfig,
    ) -> Result<(), ConfigError> {
        if let Some(certificate) = &self.certificate {
            certificate.validate(scope)?;
        }

        if self.enabled && self.certificate.is_none() && !self.acme.enabled {
            return Err(ConfigError::TlsEnabledWithoutCertificateSource { scope });
        }

        self.acme.validate(scope, vhost_hosts, global_tls)
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VhostAcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
}

impl VhostAcmeConfig {
    fn validate(
        &self,
        scope: &'static str,
        vhost_hosts: &[String],
        global_tls: &TlsConfig,
    ) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if !global_tls.acme.enabled {
            return Err(ConfigError::VhostAcmeWithoutGlobalAcme { scope });
        }

        let issuer = self
            .issuer
            .as_deref()
            .unwrap_or(&global_tls.acme.default_issuer);
        if issuer.trim().is_empty() {
            return Err(ConfigError::EmptyAcmeIssuerName {
                scope: "vhosts.tls.acme.issuer",
            });
        }
        if !global_tls.acme_issuer_exists(issuer) {
            return Err(ConfigError::UnknownAcmeIssuer {
                name: issuer.to_owned(),
            });
        }

        let domains: Vec<&str> = if self.domains.is_empty() {
            vhost_hosts
                .iter()
                .map(String::as_str)
                .filter(|host| !host.starts_with("*."))
                .collect()
        } else {
            self.domains.iter().map(String::as_str).collect()
        };

        if domains.is_empty() {
            return Err(ConfigError::EmptyVhostAcmeDomains { scope });
        }

        for domain in domains {
            if normalize_host(domain).is_none() {
                return Err(ConfigError::InvalidVhostAcmeDomain {
                    scope,
                    domain: domain.to_owned(),
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_image_extensions")]
    pub image_extensions: Vec<String>,
    #[serde(default = "default_cache_methods")]
    pub methods: Vec<String>,
    #[serde(default = "default_cache_max_object_bytes")]
    pub max_object_bytes: ByteSize,
    #[serde(default)]
    pub memory: CacheMemoryConfig,
    #[serde(default)]
    pub disk: CacheDiskConfig,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            image_extensions: default_cache_image_extensions(),
            methods: default_cache_methods(),
            max_object_bytes: default_cache_max_object_bytes(),
            memory: CacheMemoryConfig::default(),
            disk: CacheDiskConfig::default(),
        }
    }
}

impl CacheConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.disk.path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
    }

    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if self.image_extensions.is_empty() {
            return Err(ConfigError::EmptyCacheImageExtensions { scope });
        }
        for extension in &self.image_extensions {
            let extension = extension.trim();
            if extension.is_empty()
                || extension.starts_with('.')
                || extension.contains('/')
                || extension.contains('\\')
                || extension.chars().any(char::is_whitespace)
            {
                return Err(ConfigError::InvalidCacheImageExtension {
                    scope,
                    extension: extension.to_owned(),
                });
            }
        }

        if self.methods.is_empty() {
            return Err(ConfigError::EmptyCacheMethods { scope });
        }
        for method in &self.methods {
            if !valid_http_token(method) || method.chars().any(char::is_lowercase) {
                return Err(ConfigError::InvalidCacheMethod {
                    scope,
                    method: method.clone(),
                });
            }
        }

        if self.max_object_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidCacheMaxObjectBytes { scope });
        }

        if self.enabled && !self.has_enabled_tier() {
            return Err(ConfigError::CacheEnabledWithoutStorageTier { scope });
        }

        self.memory.validate(scope, self.max_object_bytes)?;
        self.disk.validate(scope, self.max_object_bytes)?;
        Ok(())
    }

    pub fn has_enabled_tier(&self) -> bool {
        self.memory.enabled || self.disk.enabled
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheMemoryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_memory_max_size_bytes")]
    pub max_size_bytes: ByteSize,
}

impl Default for CacheMemoryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_size_bytes: default_cache_memory_max_size_bytes(),
        }
    }
}

impl CacheMemoryConfig {
    fn validate(&self, scope: &'static str, max_object_bytes: ByteSize) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.max_size_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidCacheTierMaxSize {
                field: format!("{scope}.memory.max_size_bytes"),
            });
        }

        if self.max_size_bytes < max_object_bytes {
            return Err(ConfigError::CacheTierSmallerThanMaxObject {
                tier: format!("{scope}.memory"),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default = "default_cache_disk_max_size_bytes")]
    pub max_size_bytes: ByteSize,
}

impl Default for CacheDiskConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: None,
            max_size_bytes: default_cache_disk_max_size_bytes(),
        }
    }
}

impl CacheDiskConfig {
    fn validate(&self, scope: &'static str, max_object_bytes: ByteSize) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        let Some(path) = &self.path else {
            return Err(ConfigError::MissingCacheDiskPath { scope });
        };

        if path.as_os_str().is_empty() {
            return Err(ConfigError::EmptyCacheDiskPath { scope });
        }
        let path_field = format!("{scope}.disk.path");
        validate_path(path_field.clone(), Some(path))?;
        #[cfg(unix)]
        if path_existing_parent_is_world_writable(path).unwrap_or(true) {
            return Err(ConfigError::UnsafePath {
                field: path_field,
                path: path.to_path_buf(),
            });
        }

        if self.max_size_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidCacheTierMaxSize {
                field: format!("{scope}.disk.max_size_bytes"),
            });
        }

        if self.max_size_bytes < max_object_bytes {
            return Err(ConfigError::CacheTierSmallerThanMaxObject {
                tier: format!("{scope}.disk"),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebConfig {
    #[serde(default)]
    pub root: Option<PathBuf>,
    #[serde(default = "default_index_files")]
    pub index_files: Vec<String>,
    #[serde(default = "default_true")]
    pub deny_dotfiles: bool,
    #[serde(default = "default_static_cache_control")]
    pub cache_control: String,
    #[serde(default)]
    pub expires: Option<String>,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            root: None,
            index_files: default_index_files(),
            deny_dotfiles: true,
            cache_control: default_static_cache_control(),
            expires: None,
        }
    }
}

impl WebConfig {
    pub fn enabled(&self) -> bool {
        self.root.is_some()
    }

    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(root) = &mut self.root
            && root.is_relative()
        {
            *root = base_dir.join(&root);
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(root) = &self.root
            && root.as_os_str().is_empty()
        {
            return Err(ConfigError::EmptyWebRoot);
        }
        validate_path("web.root", self.root.as_deref())?;

        if self.index_files.is_empty() {
            return Err(ConfigError::EmptyIndexFiles);
        }

        for index in &self.index_files {
            if index.trim().is_empty()
                || index.contains('/')
                || index.contains('\\')
                || index == "."
                || index == ".."
            {
                return Err(ConfigError::InvalidIndexFile {
                    file: index.clone(),
                });
            }
        }
        validate_optional_header_value("web.cache_control", Some(&self.cache_control))?;
        validate_optional_header_value("web.expires", self.expires.as_deref())?;

        Ok(())
    }
}

#[derive(Debug)]
pub enum ConfigLoadError {
    InvalidPath { path: PathBuf },
    Read(std::io::Error),
    Parse(toml::de::Error),
    Validate(ConfigError),
}

impl Display for ConfigLoadError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath { path } => {
                write!(
                    formatter,
                    "config path must be a readable .toml file or directory, got {}",
                    path.display()
                )
            }
            Self::Read(error) => write!(formatter, "failed to read config: {error}"),
            Self::Parse(error) => write!(formatter, "failed to parse config: {error}"),
            Self::Validate(error) => write!(formatter, "invalid config: {error}"),
        }
    }
}

impl Error for ConfigLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidPath { .. } => None,
            Self::Read(error) => Some(error),
            Self::Parse(error) => Some(error),
            Self::Validate(error) => Some(error),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ConfigError {
    EmptyListeners,
    InvalidListenAddress {
        address: String,
    },
    EmptyDefaultVhost,
    UnknownDefaultVhost {
        name: String,
    },
    InvalidTrustedProxy {
        value: String,
    },
    InvalidProcessSetting {
        field: &'static str,
    },
    HttpsRedirectWithoutTlsListener,
    InvalidHttpsRedirectStatus {
        status: u16,
    },
    InvalidHttpsRedirectTargetPort,
    EmptyProcessPath {
        field: &'static str,
    },
    InvalidLimit {
        field: &'static str,
    },
    InvalidAdminListenAddress {
        address: String,
    },
    AdminListenNotLoopback {
        address: String,
    },
    MissingAdminAuth,
    ConflictingAdminAuth,
    MissingAdminSnapshotStore,
    EmptyAdminSecretSource {
        field: &'static str,
    },
    EmptyAdminPath {
        field: &'static str,
    },
    UnsafePath {
        field: String,
        path: PathBuf,
    },
    InvalidAdminSelfHealing {
        field: &'static str,
    },
    InvalidAdminHealthPath {
        path: String,
    },
    InvalidMetricsListenAddress {
        address: String,
    },
    MetricsListenNotLoopback {
        address: String,
    },
    PrivacyModeAccessLogging,
    PrivacyModeFileLogging,
    MissingLoggingFilePath,
    EmptyLoggingFilePath,
    InvalidHeaderName {
        field: &'static str,
        name: String,
    },
    InvalidHeaderValue {
        field: &'static str,
        name: String,
    },
    ConflictingHeaderAdd {
        field: &'static str,
        name: String,
    },
    InvalidResponseHeaderValue {
        field: &'static str,
    },
    EmptyTlsCertificatePath {
        scope: &'static str,
    },
    EmptyTlsKeyPath {
        scope: &'static str,
    },
    TlsEnabledWithoutCertificateSource {
        scope: &'static str,
    },
    TlsListenerWithoutTls,
    TlsListenerWithoutStaticCertificate,
    MissingAcmeStorage,
    EmptyAcmeStorage,
    InvalidAcmeContactEmail,
    InvalidAcmeRenewalDuration {
        field: &'static str,
    },
    InvalidAcmeRenewAfterDatetime,
    AcmeRenewalRetryInitialExceedsMax,
    EmptyAcmeIssuerName {
        scope: &'static str,
    },
    DuplicateAcmeIssuerName {
        name: String,
    },
    UnknownAcmeIssuer {
        name: String,
    },
    InvalidAcmeDirectoryUrl {
        issuer: String,
        url: String,
    },
    InvalidAcmeEabSecretSource {
        issuer: String,
        field: &'static str,
    },
    ConflictingAcmeEabSecretSource {
        issuer: String,
        field: &'static str,
    },
    VhostAcmeWithoutGlobalAcme {
        scope: &'static str,
    },
    EmptyVhostAcmeDomains {
        scope: &'static str,
    },
    InvalidVhostAcmeDomain {
        scope: &'static str,
        domain: String,
    },
    InvalidUpstream {
        address: String,
    },
    ConflictingProxyUpstreams,
    EmptyUpstreamSni,
    InvalidLoadBalanceMaxIterations,
    InvalidLoadBalanceHealthCheck {
        field: &'static str,
    },
    EmptyCacheImageExtensions {
        scope: &'static str,
    },
    InvalidCacheImageExtension {
        scope: &'static str,
        extension: String,
    },
    EmptyCacheMethods {
        scope: &'static str,
    },
    InvalidCacheMethod {
        scope: &'static str,
        method: String,
    },
    InvalidCacheMaxObjectBytes {
        scope: &'static str,
    },
    CacheEnabledWithoutStorageTier {
        scope: &'static str,
    },
    InvalidCacheTierMaxSize {
        field: String,
    },
    CacheTierSmallerThanMaxObject {
        tier: String,
    },
    MissingCacheDiskPath {
        scope: &'static str,
    },
    EmptyCacheDiskPath {
        scope: &'static str,
    },
    EmptyWebRoot,
    EmptyIndexFiles,
    InvalidIndexFile {
        file: String,
    },
    EmptyVhostName,
    EmptyVhostHosts {
        vhost: String,
    },
    InvalidVhostHost {
        vhost: String,
        host: String,
    },
    DuplicateVhostName {
        name: String,
    },
    DuplicateVhostHost {
        host: String,
    },
}

impl Display for ConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyListeners => write!(formatter, "at least one listener is required"),
            Self::InvalidListenAddress { address } => {
                write!(
                    formatter,
                    "listener address must be ip:port, got {address:?}"
                )
            }
            Self::EmptyDefaultVhost => write!(formatter, "server.default_vhost cannot be empty"),
            Self::UnknownDefaultVhost { name } => {
                write!(
                    formatter,
                    "server.default_vhost references unknown vhost {name:?}"
                )
            }
            Self::InvalidTrustedProxy { value } => write!(
                formatter,
                "server.trusted_proxies entries must be IP addresses or CIDR ranges, got {value:?}"
            ),
            Self::InvalidProcessSetting { field } => {
                write!(formatter, "{field} is outside the supported process range")
            }
            Self::HttpsRedirectWithoutTlsListener => write!(
                formatter,
                "server.https_redirect.enabled requires at least one server.tls_listen address"
            ),
            Self::InvalidHttpsRedirectStatus { status } => write!(
                formatter,
                "server.https_redirect.status must be one of 301, 302, 307, or 308, got {status}"
            ),
            Self::InvalidHttpsRedirectTargetPort => {
                write!(
                    formatter,
                    "server.https_redirect.target_port must be greater than zero"
                )
            }
            Self::EmptyProcessPath { field } => write!(formatter, "{field} cannot be empty"),
            Self::InvalidLimit { field } => write!(formatter, "{field} must be greater than zero"),
            Self::InvalidAdminListenAddress { address } => write!(
                formatter,
                "admin.listen must be an ip:port listener address, got {address:?}"
            ),
            Self::AdminListenNotLoopback { address } => write!(
                formatter,
                "admin.listen must be loopback when admin.require_loopback = true, got {address:?}"
            ),
            Self::MissingAdminAuth => write!(
                formatter,
                "admin.enabled requires admin.token_env or admin.token_file"
            ),
            Self::ConflictingAdminAuth => write!(
                formatter,
                "admin.token_env and admin.token_file cannot both be configured"
            ),
            Self::MissingAdminSnapshotStore => write!(
                formatter,
                "admin.enabled requires admin.snapshot_store for snapshot and rollback commands"
            ),
            Self::EmptyAdminSecretSource { field } => {
                write!(formatter, "{field} cannot be empty")
            }
            Self::EmptyAdminPath { field } => write!(formatter, "{field} cannot be empty"),
            Self::UnsafePath { field, path } => write!(
                formatter,
                "{field} must not contain parent-directory traversal, got {}",
                path.display()
            ),
            Self::InvalidAdminSelfHealing { field } => {
                write!(formatter, "{field} must be within the allowed range")
            }
            Self::InvalidAdminHealthPath { path } => write!(
                formatter,
                "admin.self_healing.health_path must be an absolute path no longer than {MAX_ADMIN_HEALTH_PATH_BYTES} bytes, without whitespace, controls, backslashes, query, or fragment markers, and must not shadow protected /_fluxheim/ admin endpoints, got {path:?}"
            ),
            Self::InvalidMetricsListenAddress { address } => write!(
                formatter,
                "metrics.listen must be an ip:port listener address, got {address:?}"
            ),
            Self::MetricsListenNotLoopback { address } => write!(
                formatter,
                "metrics.listen must be loopback when metrics.require_loopback = true, got {address:?}"
            ),
            Self::PrivacyModeAccessLogging => write!(
                formatter,
                "privacy-mode builds do not allow logging.access.enabled = true"
            ),
            Self::PrivacyModeFileLogging => write!(
                formatter,
                "privacy-mode builds do not allow logging.file.enabled = true"
            ),
            Self::MissingLoggingFilePath => {
                write!(formatter, "logging.file.enabled requires logging.file.path")
            }
            Self::EmptyLoggingFilePath => write!(formatter, "logging.file.path cannot be empty"),
            Self::InvalidHeaderName { field, name } => {
                write!(
                    formatter,
                    "{field} contains invalid HTTP header name {name:?}"
                )
            }
            Self::InvalidHeaderValue { field, name } => write!(
                formatter,
                "{field}.{name} must be a non-empty HTTP header value without control characters"
            ),
            Self::ConflictingHeaderAdd { field, name } => write!(
                formatter,
                "{field} defines header {name:?} in more than one add/set table"
            ),
            Self::InvalidResponseHeaderValue { field } => write!(
                formatter,
                "{field} must be a non-empty HTTP response header value without control characters"
            ),
            Self::EmptyTlsCertificatePath { scope } => {
                write!(formatter, "{scope}.cert_path cannot be empty")
            }
            Self::EmptyTlsKeyPath { scope } => {
                write!(formatter, "{scope}.key_path cannot be empty")
            }
            Self::TlsEnabledWithoutCertificateSource { scope } => write!(
                formatter,
                "{scope}.enabled requires a static certificate or ACME"
            ),
            Self::TlsListenerWithoutTls => {
                write!(formatter, "server.tls_listen requires tls.enabled = true")
            }
            Self::TlsListenerWithoutStaticCertificate => write!(
                formatter,
                "server.tls_listen requires at least one global [[tls.certificates]] entry"
            ),
            Self::MissingAcmeStorage => {
                write!(
                    formatter,
                    "tls.acme.storage is required when ACME is enabled"
                )
            }
            Self::EmptyAcmeStorage => write!(formatter, "tls.acme.storage cannot be empty"),
            Self::InvalidAcmeContactEmail => {
                write!(
                    formatter,
                    "tls.acme.contact_email must be a valid email address when ACME is enabled"
                )
            }
            Self::InvalidAcmeRenewalDuration { field } => {
                write!(formatter, "{field} must be greater than zero")
            }
            Self::InvalidAcmeRenewAfterDatetime => write!(
                formatter,
                "tls.acme.renewal.renew_after must be a full TOML offset datetime"
            ),
            Self::AcmeRenewalRetryInitialExceedsMax => write!(
                formatter,
                "tls.acme.renewal.retry_initial_secs cannot exceed retry_max_secs"
            ),
            Self::EmptyAcmeIssuerName { scope } => write!(formatter, "{scope} cannot be empty"),
            Self::DuplicateAcmeIssuerName { name } => {
                write!(formatter, "duplicate ACME issuer {name:?}")
            }
            Self::UnknownAcmeIssuer { name } => write!(formatter, "unknown ACME issuer {name:?}"),
            Self::InvalidAcmeDirectoryUrl { issuer, url } => write!(
                formatter,
                "ACME issuer {issuer:?} must use an https directory URL, got {url:?}"
            ),
            Self::InvalidAcmeEabSecretSource { issuer, field } => write!(
                formatter,
                "ACME issuer {issuer:?} EAB {field} must be read from an env var or file"
            ),
            Self::ConflictingAcmeEabSecretSource { issuer, field } => write!(
                formatter,
                "ACME issuer {issuer:?} EAB {field} cannot use both env var and file"
            ),
            Self::VhostAcmeWithoutGlobalAcme { scope } => {
                write!(formatter, "{scope}.acme.enabled requires tls.acme.enabled")
            }
            Self::EmptyVhostAcmeDomains { scope } => {
                write!(
                    formatter,
                    "{scope}.acme needs at least one non-wildcard domain"
                )
            }
            Self::InvalidVhostAcmeDomain { scope, domain } => write!(
                formatter,
                "{scope}.acme.domains must contain concrete DNS names, got {domain:?}"
            ),
            Self::InvalidUpstream { address } => {
                write!(
                    formatter,
                    "upstream must be host:port or ip:port, got {address:?}"
                )
            }
            Self::ConflictingProxyUpstreams => write!(
                formatter,
                "proxy.upstream and proxy.upstreams cannot both be configured; use proxy.upstreams for one or many targets"
            ),
            Self::EmptyUpstreamSni => write!(formatter, "upstream_sni cannot be empty"),
            Self::InvalidLoadBalanceMaxIterations => {
                write!(
                    formatter,
                    "proxy.load_balance.max_iterations must be greater than zero"
                )
            }
            Self::InvalidLoadBalanceHealthCheck { field } => {
                write!(formatter, "{field} must be greater than zero")
            }
            Self::EmptyCacheImageExtensions { scope } => {
                write!(formatter, "{scope}.image_extensions cannot be empty")
            }
            Self::InvalidCacheImageExtension { scope, extension } => write!(
                formatter,
                "{scope}.image_extensions must contain bare file extensions, got {extension:?}"
            ),
            Self::EmptyCacheMethods { scope } => {
                write!(formatter, "{scope}.methods cannot be empty")
            }
            Self::InvalidCacheMethod { scope, method } => write!(
                formatter,
                "{scope}.methods must contain uppercase HTTP method tokens, got {method:?}"
            ),
            Self::InvalidCacheMaxObjectBytes { scope } => {
                write!(
                    formatter,
                    "{scope}.max_object_bytes must be greater than zero"
                )
            }
            Self::CacheEnabledWithoutStorageTier { scope } => {
                write!(
                    formatter,
                    "{scope}.enabled requires cache.memory.enabled or cache.disk.enabled"
                )
            }
            Self::InvalidCacheTierMaxSize { field } => {
                write!(formatter, "{field} must be greater than zero")
            }
            Self::CacheTierSmallerThanMaxObject { tier } => write!(
                formatter,
                "{tier}.max_size_bytes must be at least cache.max_object_bytes"
            ),
            Self::MissingCacheDiskPath { scope } => {
                write!(
                    formatter,
                    "{scope}.disk.path is required when disk cache is enabled"
                )
            }
            Self::EmptyCacheDiskPath { scope } => {
                write!(formatter, "{scope}.disk.path cannot be empty")
            }
            Self::EmptyWebRoot => write!(formatter, "web root cannot be empty"),
            Self::EmptyIndexFiles => write!(formatter, "at least one web index file is required"),
            Self::InvalidIndexFile { file } => write!(
                formatter,
                "web index file must be a plain file name, got {file:?}"
            ),
            Self::EmptyVhostName => write!(formatter, "vhost name cannot be empty"),
            Self::EmptyVhostHosts { vhost } => {
                write!(formatter, "vhost {vhost:?} must define at least one host")
            }
            Self::InvalidVhostHost { vhost, host } => {
                write!(formatter, "vhost {vhost:?} has invalid host {host:?}")
            }
            Self::DuplicateVhostName { name } => write!(formatter, "duplicate vhost name {name:?}"),
            Self::DuplicateVhostHost { host } => write!(formatter, "duplicate vhost host {host:?}"),
        }
    }
}

impl Error for ConfigError {}

fn default_listen() -> Vec<String> {
    vec!["127.0.0.1:8080".to_owned()]
}

fn default_admin_listen() -> String {
    "127.0.0.1:9090".to_owned()
}

fn default_admin_require_loopback() -> bool {
    true
}

fn default_admin_validation_window_secs() -> u64 {
    30
}

fn default_admin_health_path() -> String {
    DEFAULT_ADMIN_HEALTH_PATH.to_owned()
}

fn default_admin_min_successful_checks() -> usize {
    1
}

fn default_admin_max_error_rate_per_mille() -> u16 {
    100
}

fn default_metrics_listen() -> String {
    "127.0.0.1:9091".to_owned()
}

fn default_metrics_require_loopback() -> bool {
    true
}

fn default_access_logging_enabled() -> bool {
    !cfg!(feature = "privacy-mode")
}

fn default_request_id_header() -> String {
    "x-request-id".to_owned()
}

fn default_max_request_header_bytes() -> ByteSize {
    ByteSize::from_bytes(64 * 1024)
}

fn default_max_uri_bytes() -> ByteSize {
    ByteSize::from_bytes(8 * 1024)
}

fn default_max_request_headers() -> usize {
    100
}

fn default_max_request_body_bytes() -> ByteSize {
    ByteSize::from_bytes(16 * 1024 * 1024)
}

fn default_process_pid_file() -> PathBuf {
    PathBuf::from("/run/fluxheim/fluxheim.pid")
}

fn default_process_upgrade_sock() -> PathBuf {
    PathBuf::from("/run/fluxheim/fluxheim-upgrade.sock")
}

fn default_process_threads() -> usize {
    1
}

fn default_process_listener_tasks_per_fd() -> usize {
    1
}

fn default_process_upstream_keepalive_pool_size() -> usize {
    128
}

fn default_process_max_retries() -> usize {
    16
}

fn default_acme_contact_email() -> Option<String> {
    None
}

fn default_acme_default_issuer() -> String {
    "letsencrypt".to_owned()
}

fn default_acme_renew_before_secs() -> u64 {
    30 * 24 * 60 * 60
}

fn default_acme_renewal_check_interval_secs() -> u64 {
    60 * 60
}

fn default_acme_renewal_retry_initial_secs() -> u64 {
    5 * 60
}

fn default_acme_renewal_retry_max_secs() -> u64 {
    24 * 60 * 60
}

fn default_acme_issuers() -> Vec<AcmeIssuerConfig> {
    vec![
        AcmeIssuerConfig {
            name: "letsencrypt".to_owned(),
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_owned(),
            eab: None,
        },
        AcmeIssuerConfig {
            name: "letsencrypt-staging".to_owned(),
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".to_owned(),
            eab: None,
        },
        AcmeIssuerConfig {
            name: "actalis".to_owned(),
            directory_url: "https://acme-api.actalis.com/acme/directory".to_owned(),
            eab: Some(AcmeExternalAccountBindingConfig {
                key_id_env: Some("FLUXHEIM_ACTALIS_EAB_KID".to_owned()),
                key_id_file: None,
                hmac_key_env: Some("FLUXHEIM_ACTALIS_EAB_HMAC_KEY".to_owned()),
                hmac_key_file: None,
            }),
        },
    ]
}

fn default_upstream() -> String {
    "127.0.0.1:3000".to_owned()
}

fn default_lb_max_iterations() -> usize {
    256
}

fn default_lb_health_check_interval_secs() -> u64 {
    1
}

fn default_lb_health_check_threshold() -> usize {
    1
}

fn default_cache_image_extensions() -> Vec<String> {
    ["avif", "gif", "jpeg", "jpg", "png", "svg", "webp"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn default_cache_methods() -> Vec<String> {
    ["GET", "HEAD"].into_iter().map(str::to_owned).collect()
}

fn default_cache_max_object_bytes() -> ByteSize {
    ByteSize::from_bytes(32 * 1024 * 1024)
}

fn default_cache_memory_max_size_bytes() -> ByteSize {
    ByteSize::from_bytes(1024 * 1024 * 1024)
}

fn default_cache_disk_max_size_bytes() -> ByteSize {
    ByteSize::from_bytes(10 * 1024 * 1024 * 1024)
}

fn default_index_files() -> Vec<String> {
    vec!["index.html".to_owned()]
}

fn default_static_cache_control() -> String {
    "public, max-age=60".to_owned()
}

fn default_true() -> bool {
    true
}

fn default_x_content_type_options() -> Option<String> {
    Some("nosniff".to_owned())
}

fn default_x_frame_options() -> Option<String> {
    Some("DENY".to_owned())
}

fn default_referrer_policy() -> Option<String> {
    Some("no-referrer".to_owned())
}

fn default_response_unset_headers() -> Vec<String> {
    vec!["server".to_owned(), "x-powered-by".to_owned()]
}

fn canonical_config_source(path: &Path) -> Result<PathBuf, ConfigLoadError> {
    let metadata = fs::symlink_metadata(path).map_err(ConfigLoadError::Read)?;
    if metadata.file_type().is_symlink() {
        return Err(ConfigLoadError::InvalidPath {
            path: path.to_path_buf(),
        });
    }
    if existing_path_contains_symlink(path).map_err(ConfigLoadError::Read)? {
        return Err(ConfigLoadError::InvalidPath {
            path: path.to_path_buf(),
        });
    }

    let path = path.canonicalize().map_err(ConfigLoadError::Read)?;
    if path.is_dir() || regular_visible_toml_file(&path)? {
        return Ok(path);
    }

    Err(ConfigLoadError::InvalidPath { path })
}

fn toml_files(dir: &Path) -> Result<Vec<PathBuf>, ConfigLoadError> {
    let entries = fs::read_dir(dir).map_err(ConfigLoadError::Read)?;
    let mut files = Vec::new();

    for entry in entries {
        let entry = entry.map_err(ConfigLoadError::Read)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(ConfigLoadError::Read)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        if is_visible_toml_file(&path) {
            files.push(path);
            if files.len() > MAX_CONFIG_DIRECTORY_FILES {
                return Err(ConfigLoadError::Read(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "config directory {} contains more than {} TOML files",
                        dir.display(),
                        MAX_CONFIG_DIRECTORY_FILES
                    ),
                )));
            }
        }
    }

    Ok(files)
}

fn regular_visible_toml_file(path: &Path) -> Result<bool, ConfigLoadError> {
    if !is_visible_toml_file(path) {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(path).map_err(ConfigLoadError::Read)?;
    Ok(!metadata.file_type().is_symlink() && metadata.is_file())
}

fn read_regular_config_file_to_string(path: &Path) -> Result<String, ConfigLoadError> {
    let metadata = fs::symlink_metadata(path).map_err(ConfigLoadError::Read)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ConfigLoadError::InvalidPath {
            path: path.to_path_buf(),
        });
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(O_NOFOLLOW);

    let file = options.open(path).map_err(ConfigLoadError::Read)?;
    let metadata = file.metadata().map_err(ConfigLoadError::Read)?;
    if !metadata.is_file() {
        return Err(ConfigLoadError::InvalidPath {
            path: path.to_path_buf(),
        });
    }
    if metadata.len() > MAX_CONFIG_FILE_BYTES {
        return Err(ConfigLoadError::Read(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "config file {} exceeds {} bytes",
                path.display(),
                MAX_CONFIG_FILE_BYTES
            ),
        )));
    }

    let mut contents = String::new();
    let mut limited = file.take(MAX_CONFIG_FILE_BYTES.saturating_add(1));
    limited
        .read_to_string(&mut contents)
        .map_err(ConfigLoadError::Read)?;
    if contents.len() as u64 > MAX_CONFIG_FILE_BYTES {
        return Err(ConfigLoadError::Read(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "config file {} changed while reading and exceeded {} bytes",
                path.display(),
                MAX_CONFIG_FILE_BYTES
            ),
        )));
    }
    Ok(contents)
}

fn existing_path_contains_symlink(path: &Path) -> std::io::Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }

    Ok(false)
}

fn is_visible_toml_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|file_name| file_name.to_str()) else {
        return false;
    };

    !file_name.starts_with('.')
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("toml"))
}

fn valid_authority(authority: &str) -> bool {
    authority.parse::<SocketAddr>().is_ok() || split_host_port(authority).is_some()
}

fn valid_trusted_proxy(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return false;
    }

    let Some((address, prefix)) = value.split_once('/') else {
        return value.parse::<IpAddr>().is_ok();
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match address {
        IpAddr::V4(_) => prefix <= 32,
        IpAddr::V6(_) => prefix <= 128,
    }
}

fn valid_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(
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
                    | b'0'..=b'9'
                    | b'A'..=b'Z'
            )
        })
}

fn valid_https_url(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("https://")
        && value.len() > "https://".len()
        && !value.chars().any(char::is_whitespace)
}

fn invalid_email(value: &str) -> bool {
    let value = value.trim();
    value.is_empty()
        || value.chars().any(char::is_whitespace)
        || !value.contains('@')
        || value.starts_with('@')
        || value.ends_with('@')
}

fn invalid_acme_renew_after_datetime(value: &Datetime) -> bool {
    value.date.is_none()
        || value.time.is_none()
        || value.offset.is_none()
        || value
            .time
            .and_then(|time| time.second)
            .is_some_and(|second| second > 59)
        || matches!(value.offset, Some(Offset::Custom { minutes }) if minutes <= -1_440 || minutes >= 1_440)
}

fn validate_secret_source(
    issuer: &str,
    field: &'static str,
    env: Option<&str>,
    file: Option<&PathBuf>,
) -> Result<(), ConfigError> {
    let env = env.map(str::trim).filter(|value| !value.is_empty());
    let file = file.filter(|path| !path.as_os_str().is_empty());
    let file_field = format!("tls.acme.issuers.{issuer}.eab.{field}_file");
    validate_path(file_field.clone(), file.map(PathBuf::as_path))?;
    validate_non_world_writable_parent(file_field, file.map(PathBuf::as_path))?;

    match (env, file) {
        (Some(_), None) | (None, Some(_)) => Ok(()),
        (None, None) => Err(ConfigError::InvalidAcmeEabSecretSource {
            issuer: issuer.to_owned(),
            field,
        }),
        (Some(_), Some(_)) => Err(ConfigError::ConflictingAcmeEabSecretSource {
            issuer: issuer.to_owned(),
            field,
        }),
    }
}

fn validate_optional_env(field: &'static str, env: Option<&str>) -> Result<(), ConfigError> {
    if env.is_some_and(|value| value.trim().is_empty()) {
        return Err(ConfigError::EmptyAdminSecretSource { field });
    }
    Ok(())
}

fn validate_optional_path(field: &'static str, path: Option<&Path>) -> Result<(), ConfigError> {
    if path.is_some_and(|path| path.as_os_str().is_empty()) {
        return Err(ConfigError::EmptyAdminPath { field });
    }
    Ok(())
}

fn validate_path(field: impl Into<String>, path: Option<&Path>) -> Result<(), ConfigError> {
    let field = field.into();
    let Some(path) = path else {
        return Ok(());
    };

    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ConfigError::UnsafePath {
            field,
            path: path.to_path_buf(),
        });
    }

    if path_existing_prefix_contains_symlink(path).unwrap_or(true) {
        return Err(ConfigError::UnsafePath {
            field,
            path: path.to_path_buf(),
        });
    }

    Ok(())
}

fn validate_non_world_writable_parent(
    field: impl Into<String>,
    path: Option<&Path>,
) -> Result<(), ConfigError> {
    let field = field.into();
    let Some(path) = path else {
        return Ok(());
    };

    #[cfg(unix)]
    if path_existing_parent_is_world_writable(path).unwrap_or(true) {
        return Err(ConfigError::UnsafePath {
            field,
            path: path.to_path_buf(),
        });
    }

    #[cfg(not(unix))]
    let _ = (field, path);

    Ok(())
}

fn validate_process_usize(
    field: &'static str,
    value: usize,
    min: usize,
    max: usize,
) -> Result<(), ConfigError> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(ConfigError::InvalidProcessSetting { field })
    }
}

fn validate_optional_process_path(
    field: &'static str,
    path: Option<&Path>,
) -> Result<(), ConfigError> {
    if let Some(path) = path {
        validate_required_process_path(field, path)?;
    }
    Ok(())
}

fn validate_required_process_path(field: &'static str, path: &Path) -> Result<(), ConfigError> {
    if path.as_os_str().is_empty() {
        return Err(ConfigError::EmptyProcessPath { field });
    }
    validate_path(field, Some(path))?;
    #[cfg(unix)]
    if path_existing_parent_is_world_writable(path).unwrap_or(true) {
        return Err(ConfigError::UnsafePath {
            field: field.to_owned(),
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn validate_process_optional_duration(
    field: &'static str,
    value: Option<u64>,
) -> Result<(), ConfigError> {
    match value {
        Some(0) => Err(ConfigError::InvalidProcessSetting { field }),
        Some(_) | None => Ok(()),
    }
}

fn path_existing_prefix_contains_symlink(path: &Path) -> std::io::Result<bool> {
    let mut current = PathBuf::new();

    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }

    Ok(false)
}

#[cfg(unix)]
fn path_existing_parent_is_world_writable(path: &Path) -> std::io::Result<bool> {
    let mut current = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    loop {
        match fs::symlink_metadata(current) {
            Ok(metadata) => return Ok(metadata.permissions().mode() & 0o002 != 0),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let Some(parent) = current.parent() else {
                    return Ok(false);
                };
                if parent == current {
                    return Ok(false);
                }
                current = parent;
            }
            Err(error) => return Err(error),
        }
    }
}

fn validate_optional_header_value(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), ConfigError> {
    let Some(value) = value else {
        return Ok(());
    };

    if value.trim().is_empty()
        || value.as_bytes().iter().any(|byte| {
            matches!(
                byte,
                0x00..=0x08 | 0x0a..=0x1f | 0x7f
            )
        })
    {
        return Err(ConfigError::InvalidResponseHeaderValue { field });
    }

    Ok(())
}

fn validate_header_mutations(
    field: &'static str,
    unset: &[String],
    set: &BTreeMap<String, String>,
    append: &BTreeMap<String, HeaderValues>,
) -> Result<(), ConfigError> {
    for name in unset {
        validate_header_name(field, name)?;
    }
    for (name, value) in set {
        validate_header_name(field, name)?;
        validate_header_mutation_value(field, name, value)?;
    }
    for (name, values) in append {
        validate_header_name(field, name)?;
        for value in values.iter() {
            validate_header_mutation_value(field, name, value)?;
        }
    }

    Ok(())
}

fn validate_header_add_aliases(
    field: &'static str,
    set: &BTreeMap<String, String>,
    add: &BTreeMap<String, String>,
    operations_add: &BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    let mut seen = std::collections::BTreeSet::new();
    for name in set.keys() {
        seen.insert(name.to_ascii_lowercase());
    }
    for name in add.keys().chain(operations_add.keys()) {
        let normalized = name.to_ascii_lowercase();
        if !seen.insert(normalized) {
            return Err(ConfigError::ConflictingHeaderAdd {
                field,
                name: name.clone(),
            });
        }
    }

    Ok(())
}

fn combined_header_unset(
    unset: &[String],
    remove: &[String],
    operations_remove: &[String],
) -> Vec<String> {
    let mut combined = Vec::with_capacity(unset.len() + remove.len() + operations_remove.len());
    combined.extend(unset.iter().cloned());
    combined.extend(remove.iter().cloned());
    combined.extend(operations_remove.iter().cloned());
    combined
}

fn combined_header_set(
    set: &BTreeMap<String, String>,
    add: &BTreeMap<String, String>,
    operations_add: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut combined = set.clone();
    combined.extend(
        add.iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    combined.extend(
        operations_add
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    combined
}

fn merge_header_mutations(
    unset: &mut Vec<String>,
    set: &mut BTreeMap<String, String>,
    append: &mut BTreeMap<String, HeaderValues>,
    overlay_unset: &[String],
    overlay_set: &BTreeMap<String, String>,
    overlay_append: &BTreeMap<String, HeaderValues>,
) {
    unset.extend(overlay_unset.iter().cloned());
    for (name, value) in overlay_set {
        set.insert(name.clone(), value.clone());
    }
    for (name, values) in overlay_append {
        append
            .entry(name.clone())
            .and_modify(|existing| existing.extend(values))
            .or_insert_with(|| values.clone());
    }
}

fn validate_header_name(field: &'static str, name: &str) -> Result<(), ConfigError> {
    let normalized = name.trim();
    if normalized != name || !valid_http_header_name(name) {
        return Err(ConfigError::InvalidHeaderName {
            field,
            name: name.to_owned(),
        });
    }

    Ok(())
}

fn validate_header_mutation_value(
    field: &'static str,
    name: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.trim().is_empty()
        || value
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, 0x00..=0x08 | 0x0a..=0x1f | 0x7f))
    {
        return Err(ConfigError::InvalidHeaderValue {
            field,
            name: name.to_owned(),
        });
    }

    Ok(())
}

fn valid_http_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            matches!(
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
                    | b'0'..=b'9'
                    | b'A'..=b'Z'
                    | b'a'..=b'z'
            )
        })
}

pub fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty()
        || host.contains('*')
        || host.contains('/')
        || host.contains('\\')
        || host.contains('?')
        || host.contains('#')
        || host.contains('@')
        || host.chars().any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return None;
    }

    if let Some(stripped) = host.strip_prefix('[') {
        let (addr, rest) = stripped.split_once(']')?;
        if !rest.is_empty() && !valid_port_suffix(rest) {
            return None;
        }
        return Some(addr.to_ascii_lowercase());
    }

    let host = if let Some((candidate, port)) = host.rsplit_once(':') {
        if !candidate.contains(':') && !candidate.is_empty() && port.parse::<u16>().is_ok() {
            candidate
        } else {
            host
        }
    } else {
        host
    };

    if host.is_empty() || host.starts_with('.') {
        return None;
    }

    Some(host.to_ascii_lowercase())
}

pub fn normalize_host_pattern(host: &str) -> Option<String> {
    let host = host.trim();
    if let Some(suffix) = host.strip_prefix("*.") {
        let suffix = normalize_host(suffix)?;
        if suffix.contains(':') {
            return None;
        }
        Some(format!("*.{suffix}"))
    } else {
        normalize_host(host)
    }
}

fn valid_port_suffix(rest: &str) -> bool {
    rest.strip_prefix(':')
        .is_some_and(|port| !port.is_empty() && port.parse::<u16>().is_ok())
}

fn upstream_host(authority: &str) -> Option<String> {
    if let Ok(socket) = authority.parse::<SocketAddr>() {
        return Some(socket.ip().to_string());
    }

    split_host_port(authority).map(|(host, _port)| host.to_owned())
}

fn split_host_port(authority: &str) -> Option<(&str, u16)> {
    let (host, port) = authority.rsplit_once(':')?;
    if host.trim().is_empty() || port.trim().is_empty() {
        return None;
    }

    let port = port.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }

    let host = host.trim_matches(['[', ']']);
    if host.trim().is_empty() || host.contains('/') {
        return None;
    }

    Some((host, port))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        AdminConfig, AdminSelfHealingConfig, ByteSize, CacheConfig, Config, ConfigError,
        ConfigLoadError, HeaderPolicyConfig, LoggingConfig, MetricsConfig, ProxyConfig,
        ServerConfig, ServerLimitsConfig, VhostConfig, VhostHeaderPolicyConfig, WebConfig,
        normalize_host, normalize_host_pattern,
    };

    #[test]
    fn default_config_is_valid() {
        Config::default().validate().unwrap();
        assert_eq!(Config::default().logging.level, super::LoggingLevel::Info);
        assert_eq!(Config::default().logging.format, super::LoggingFormat::Json);
        assert!(Config::default().headers.request.enabled);
        assert!(
            Config::default()
                .headers
                .request
                .strip_inbound_client_ip_headers
        );
        #[cfg(not(feature = "privacy-mode"))]
        assert_eq!(
            Config::default().headers.request.x_forwarded_for,
            super::ForwardedClientIpHeaderMode::Replace
        );
        #[cfg(feature = "privacy-mode")]
        assert_eq!(
            Config::default().headers.request.x_forwarded_for,
            super::ForwardedClientIpHeaderMode::Off
        );
        assert_eq!(
            Config::default()
                .headers
                .response
                .x_content_type_options
                .as_deref(),
            Some("nosniff")
        );
        assert_eq!(
            Config::default()
                .headers
                .response
                .x_frame_options
                .as_deref(),
            Some("DENY")
        );
        assert_eq!(
            Config::default()
                .headers
                .response
                .referrer_policy
                .as_deref(),
            Some("no-referrer")
        );
        assert_eq!(
            Config::default().headers.response.unset,
            ["server", "x-powered-by"]
        );
        assert_eq!(Config::default().web.cache_control, "public, max-age=60");
        assert_eq!(Config::default().server.process.threads, 1);
        assert_eq!(Config::default().server.process.listener_tasks_per_fd, 1);
        assert_eq!(Config::default().server.process.max_retries, 16);
        #[cfg(not(feature = "privacy-mode"))]
        assert!(Config::default().logging.access.enabled);
        #[cfg(feature = "privacy-mode")]
        assert!(!Config::default().logging.access.enabled);
    }

    #[test]
    fn parses_minimal_toml() {
        let config: Config = toml::from_str(
            r#"
            [server]
            listen = ["127.0.0.1:18080"]
            tls_listen = ["127.0.0.1:18443"]

            [proxy]
            upstream = "origin.example.test:443"
            upstream_tls = true
            upstream_sni = "origin.example.test"
            "#,
        )
        .unwrap();

        assert_eq!(config.server.listen, ["127.0.0.1:18080"]);
        assert_eq!(config.server.tls_listen, ["127.0.0.1:18443"]);
        assert_eq!(
            config.proxy.upstream.as_deref(),
            Some("origin.example.test:443")
        );
        assert!(config.proxy.upstream_tls);
        assert_eq!(config.proxy.upstream_sni(), "origin.example.test");
    }

    #[test]
    fn parses_server_process_settings() {
        let config: Config = toml::from_str(
            r#"
            [server.process]
            daemon = false
            error_log = "/run/fluxheim/error.log"
            pid_file = "/run/fluxheim/fluxheim.pid"
            upgrade_sock = "/run/fluxheim/fluxheim-upgrade.sock"
            threads = 4
            listener_tasks_per_fd = 2
            work_stealing = false
            upstream_keepalive_pool_size = 512
            max_retries = 8
            grace_period_seconds = 10
            graceful_shutdown_timeout_seconds = 30
            "#,
        )
        .unwrap();

        assert!(!config.server.process.daemon);
        assert_eq!(
            config.server.process.error_log.as_deref(),
            Some(Path::new("/run/fluxheim/error.log"))
        );
        assert_eq!(
            config.server.process.pid_file,
            PathBuf::from("/run/fluxheim/fluxheim.pid")
        );
        assert_eq!(
            config.server.process.upgrade_sock,
            PathBuf::from("/run/fluxheim/fluxheim-upgrade.sock")
        );
        assert_eq!(config.server.process.threads, 4);
        assert_eq!(config.server.process.listener_tasks_per_fd, 2);
        assert!(!config.server.process.work_stealing);
        assert_eq!(config.server.process.upstream_keepalive_pool_size, 512);
        assert_eq!(config.server.process.max_retries, 8);
        assert_eq!(config.server.process.grace_period_seconds, Some(10));
        assert_eq!(
            config.server.process.graceful_shutdown_timeout_seconds,
            Some(30)
        );
        config.validate().unwrap();
    }

    #[test]
    fn parses_static_cache_headers() {
        let config: Config = toml::from_str(
            r#"
            [web]
            root = "public"
            cache_control = "public, max-age=31536000, immutable"
            expires = "Wed, 21 Oct 2030 07:28:00 GMT"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.web.cache_control,
            "public, max-age=31536000, immutable"
        );
        assert_eq!(
            config.web.expires.as_deref(),
            Some("Wed, 21 Oct 2030 07:28:00 GMT")
        );
    }

    #[test]
    fn parses_proxy_upstream_pool() {
        let config: Config = toml::from_str(
            r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]

            [proxy.load_balance]
            max_iterations = 16

            [proxy.load_balance.health_check]
            enabled = true
            interval_secs = 2
            consecutive_success = 2
            consecutive_failure = 3
            parallel = true
            "#,
        )
        .unwrap();

        assert_eq!(
            config.proxy.upstreams,
            ["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()]
        );
        assert_eq!(config.proxy.load_balance.max_iterations, 16);
        assert!(config.proxy.load_balance.health_check.enabled);
        assert_eq!(config.proxy.load_balance.health_check.interval_secs, 2);
        assert_eq!(
            config.proxy.load_balance.health_check.consecutive_success,
            2
        );
        assert_eq!(
            config.proxy.load_balance.health_check.consecutive_failure,
            3
        );
        assert!(config.proxy.load_balance.health_check.parallel);
        config.validate().unwrap();
    }

    #[test]
    fn rejects_ambiguous_proxy_upstream_aliases() {
        let config: Config = toml::from_str(
            r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            upstreams = ["127.0.0.1:3001"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::ConflictingProxyUpstreams)
        );
    }

    #[test]
    fn upstreams_can_be_used_as_primary_proxy_targets() {
        let config: Config = toml::from_str(
            r#"
            [proxy]
            upstreams = ["origin-a.example.test:443", "origin-b.example.test:443"]
            upstream_tls = true
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(config.proxy.primary_upstream(), "origin-a.example.test:443");
        assert_eq!(config.proxy.upstream_sni(), "origin-a.example.test");
    }

    #[test]
    fn parses_request_header_policy() {
        let config: Config = toml::from_str(
            r#"
            [headers.request]
            enabled = true
            strip_inbound_client_ip_headers = true
            x_forwarded_for = "append"
            x_forwarded_host = false
            x_forwarded_proto = true
            forwarded = true
            unset = ["x-powered-by"]

            [headers.request.set]
            host = "backend.internal"
            x-proxy-by = "Fluxheim"

            [headers.request.append]
            via = "fluxheim"
            "#,
        )
        .unwrap();

        let policy = &config.headers.request;
        assert!(policy.enabled);
        assert!(policy.strip_inbound_client_ip_headers);
        assert_eq!(
            policy.x_forwarded_for,
            super::ForwardedClientIpHeaderMode::Append
        );
        assert!(!policy.x_forwarded_host);
        assert!(policy.x_forwarded_proto);
        assert!(policy.forwarded);
        assert_eq!(policy.unset, ["x-powered-by"]);
        assert_eq!(
            policy.set.get("host").map(String::as_str),
            Some("backend.internal")
        );
        assert_eq!(
            policy.set.get("x-proxy-by").map(String::as_str),
            Some("Fluxheim")
        );
        assert_eq!(
            policy
                .append
                .get("via")
                .and_then(|values| values.iter().next()),
            Some("fluxheim")
        );
        config.validate().unwrap();
    }

    #[test]
    fn parses_user_friendly_header_operations() {
        let config: Config = toml::from_str(
            r#"
            [headers.request]
            remove = ["x-powered-by"]

            [headers.request.add]
            x-internal-route = "true"

            [headers.request.operations]
            remove = ["server"]
            add = { x-extra-route = "edge" }

            [headers.response]
            remove = ["x-origin-banner"]

            [headers.response.operations]
            remove = ["x-debug"]
            add = { cache-control = "public, max-age=60" }
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(
            config.headers.request.effective_unset(),
            ["x-powered-by", "server"]
        );
        assert_eq!(
            config
                .headers
                .request
                .effective_set()
                .get("x-internal-route")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            config
                .headers
                .request
                .effective_set()
                .get("x-extra-route")
                .map(String::as_str),
            Some("edge")
        );
        assert!(
            config
                .headers
                .response
                .effective_unset()
                .contains(&"x-origin-banner".to_owned())
        );
        assert!(
            config
                .headers
                .response
                .effective_unset()
                .contains(&"x-debug".to_owned())
        );
        assert_eq!(
            config
                .headers
                .response
                .effective_set()
                .get("cache-control")
                .map(String::as_str),
            Some("public, max-age=60")
        );
    }

    #[test]
    fn rejects_conflicting_header_add_aliases() {
        let config: Config = toml::from_str(
            r#"
            [headers.response.set]
            cache-control = "public, max-age=60"

            [headers.response.add]
            Cache-Control = "private, no-store"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::ConflictingHeaderAdd {
                field: "headers.response",
                name: "Cache-Control".to_owned()
            })
        );

        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "api"
            hosts = ["api.example.test"]

            [vhosts.headers.request.add]
            x-route = "api"

            [vhosts.headers.request.operations]
            add = { x-route = "legacy" }
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::ConflictingHeaderAdd {
                field: "vhosts.headers.request",
                name: "x-route".to_owned()
            })
        );
    }

    #[test]
    fn parses_response_header_policy() {
        let config: Config = toml::from_str(
            r#"
            [headers.response]
            enabled = true
            strict_transport_security = "max-age=31536000; includeSubDomains"
            content_security_policy = "default-src 'self'"
            x_content_type_options = "nosniff"
            x_frame_options = "SAMEORIGIN"
            referrer_policy = "strict-origin-when-cross-origin"
            unset = ["server", "x-powered-by"]

            [headers.response.set]
            cache-control = "public, max-age=60"
            access-control-allow-origin = "https://example.test"

            [headers.response.append]
            vary = ["Accept-Encoding", "Origin"]
            set-cookie = "fluxheim=1; HttpOnly; Secure; SameSite=Lax"
            "#,
        )
        .unwrap();

        let policy = &config.headers.response;
        assert!(policy.enabled);
        assert_eq!(
            policy.strict_transport_security.as_deref(),
            Some("max-age=31536000; includeSubDomains")
        );
        assert_eq!(
            policy.content_security_policy.as_deref(),
            Some("default-src 'self'")
        );
        assert_eq!(policy.x_frame_options.as_deref(), Some("SAMEORIGIN"));
        assert_eq!(
            policy.referrer_policy.as_deref(),
            Some("strict-origin-when-cross-origin")
        );
        assert_eq!(policy.unset, ["server", "x-powered-by"]);
        assert_eq!(
            policy.set.get("cache-control").map(String::as_str),
            Some("public, max-age=60")
        );
        assert_eq!(
            policy
                .append
                .get("vary")
                .map(|values| values.iter().collect::<Vec<_>>()),
            Some(vec!["Accept-Encoding", "Origin"])
        );
        config.validate().unwrap();
    }

    #[test]
    fn parses_vhost_header_policy_overlay() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "api"
            hosts = ["api.example.test"]

            [vhosts.headers.request]
            x_forwarded_for = "off"
            unset = ["x-powered-by"]
            remove = ["x-legacy-route"]

            [vhosts.headers.request.set]
            host = "api.internal"

            [vhosts.headers.request.operations]
            remove = ["x-old-api"]
            add = { x-api-route = "true" }

            [vhosts.headers.response]
            x_frame_options = "SAMEORIGIN"
            unset = ["server"]
            remove = ["x-origin-banner"]

            [vhosts.headers.response.set]
            access-control-allow-origin = "https://app.example.test"

            [vhosts.headers.response.append]
            vary = "Origin"

            [vhosts.headers.response.operations]
            remove = ["x-debug"]
            add = { x-response-route = "api" }
            "#,
        )
        .unwrap();

        let headers = &config.vhosts[0].headers;
        assert_eq!(
            headers.request.x_forwarded_for,
            Some(super::ForwardedClientIpHeaderMode::Off)
        );
        assert_eq!(headers.request.unset, ["x-powered-by"]);
        assert_eq!(
            headers.request.effective_unset(),
            ["x-powered-by", "x-legacy-route", "x-old-api"]
        );
        assert_eq!(
            headers.request.set.get("host").map(String::as_str),
            Some("api.internal")
        );
        assert_eq!(
            headers
                .request
                .effective_set()
                .get("x-api-route")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            headers
                .response
                .x_frame_options
                .as_ref()
                .and_then(Option::as_deref),
            Some("SAMEORIGIN")
        );
        assert_eq!(headers.response.unset, ["server"]);
        assert_eq!(
            headers.response.effective_unset(),
            ["server", "x-origin-banner", "x-debug"]
        );
        assert_eq!(
            headers
                .response
                .set
                .get("access-control-allow-origin")
                .map(String::as_str),
            Some("https://app.example.test")
        );
        assert_eq!(
            headers
                .response
                .append
                .get("vary")
                .and_then(|values| values.iter().next()),
            Some("Origin")
        );
        assert_eq!(
            headers
                .response
                .effective_set()
                .get("x-response-route")
                .map(String::as_str),
            Some("api")
        );
        config.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_response_header_value() {
        let config: Config = toml::from_str(
            r#"
            [headers.response]
            x_frame_options = "DENY\nx-bad: injected"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidResponseHeaderValue {
                field: "headers.response.x_frame_options"
            })
        );
    }

    #[test]
    fn rejects_invalid_static_cache_header_value() {
        let config: Config = toml::from_str(
            r#"
            [web]
            root = "public"
            cache_control = "public\nx-bad: injected"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidResponseHeaderValue {
                field: "web.cache_control"
            })
        );
    }

    #[test]
    fn rejects_invalid_server_process_settings() {
        let config: Config = toml::from_str(
            r#"
            [server.process]
            threads = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidProcessSetting {
                field: "server.process.threads"
            })
        );

        let config: Config = toml::from_str(
            r#"
            [server.process]
            grace_period_seconds = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidProcessSetting {
                field: "server.process.grace_period_seconds"
            })
        );

        let config: Config = toml::from_str(
            r#"
            [server.process]
            pid_file = ""
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::EmptyProcessPath {
                field: "server.process.pid_file"
            })
        );

        let config: Config = toml::from_str(
            r#"
            [server.process]
            upgrade_sock = "../fluxheim.sock"
            "#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsafePath { field, .. }) if field == "server.process.upgrade_sock"
        ));

        #[cfg(unix)]
        {
            let config: Config = toml::from_str(
                r#"
                [server.process]
                pid_file = "/tmp/fluxheim.pid"
                "#,
            )
            .unwrap();

            assert!(matches!(
                config.validate(),
                Err(ConfigError::UnsafePath { field, .. }) if field == "server.process.pid_file"
            ));
        }
    }

    #[test]
    fn rejects_invalid_generic_header_name() {
        let config: Config = toml::from_str(
            r#"
            [headers.response.set]
            "bad header" = "value"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHeaderName {
                field: "headers.response",
                name: "bad header".to_owned()
            })
        );
    }

    #[test]
    fn rejects_invalid_generic_header_value() {
        let config: Config = toml::from_str(
            r#"
            [headers.request.set]
            x-test = "ok\nx-bad: injected"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHeaderValue {
                field: "headers.request",
                name: "x-test".to_owned()
            })
        );
    }

    #[test]
    fn rejects_invalid_load_balance_max_iterations() {
        let config: Config = toml::from_str(
            r#"
            [proxy.load_balance]
            max_iterations = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidLoadBalanceMaxIterations)
        );
    }

    #[test]
    fn rejects_invalid_load_balance_health_check() {
        let config: Config = toml::from_str(
            r#"
            [proxy.load_balance.health_check]
            interval_secs = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.interval_secs"
            })
        );
    }

    #[test]
    fn parses_server_limits() {
        let config: Config = toml::from_str(
            r#"
            [server]
            trusted_proxies = ["127.0.0.1", "10.0.0.0/8", "2001:db8::/32"]

            [server.limits]
            max_request_header_bytes = "32KiB"
            max_uri_bytes = 4096
            max_request_headers = 32
            max_request_body_bytes = "2MiB"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.server.limits.max_request_header_bytes,
            ByteSize::from_bytes(32 * 1024)
        );
        assert_eq!(
            config.server.limits.max_uri_bytes,
            ByteSize::from_bytes(4096)
        );
        assert_eq!(config.server.limits.max_request_headers, 32);
        assert_eq!(
            config.server.limits.max_request_body_bytes,
            ByteSize::from_bytes(2 * 1024 * 1024)
        );
        assert_eq!(
            config.server.trusted_proxies,
            ["127.0.0.1", "10.0.0.0/8", "2001:db8::/32"]
        );
        config.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_trusted_proxy_range() {
        let config: Config = toml::from_str(
            r#"
            [server]
            trusted_proxies = ["10.0.0.0/99"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTrustedProxy {
                value: "10.0.0.0/99".to_owned()
            })
        );
    }

    #[test]
    fn parses_tls_acme_config_with_actalis_eab() {
        let config: Config = toml::from_str(
            r#"
            [tls]
            enabled = true
            backend = "rustls"

            [tls.acme]
            enabled = true
            storage = "/var/lib/fluxheim/acme"
            contact_email = "admin@example.test"
            default_issuer = "actalis"
            challenge = "tls-alpn-01"

            [tls.acme.renewal]
            enabled = true
            renew_before_secs = 2592000
            renew_after = 2026-06-01T00:00:00Z
            check_interval_secs = 3600
            retry_initial_secs = 300
            retry_max_secs = 86400
            reload_after_renewal = true
            zero_downtime_reload = true

            [[tls.acme.issuers]]
            name = "actalis"
            directory_url = "https://acme-api.actalis.com/acme/directory"

            [tls.acme.issuers.eab]
            key_id_env = "FLUXHEIM_ACTALIS_EAB_KID"
            hmac_key_env = "FLUXHEIM_ACTALIS_EAB_HMAC_KEY"
            "#,
        )
        .unwrap();

        assert!(config.tls.enabled);
        assert_eq!(config.tls.backend, super::TlsBackend::Rustls);
        assert!(config.tls.acme.enabled);
        assert_eq!(
            config.tls.acme.storage,
            Some(PathBuf::from("/var/lib/fluxheim/acme"))
        );
        assert_eq!(config.tls.acme.default_issuer, "actalis");
        assert_eq!(config.tls.acme.renewal.renew_before_secs, 2_592_000);
        assert!(config.tls.acme.renewal.renew_after.is_some());
        config.validate().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_tls_certificate_paths_under_world_writable_parent() {
        let config: Config = toml::from_str(
            r#"
            [tls]
            enabled = true

            [[tls.certificates]]
            cert_path = "/tmp/fullchain.pem"
            key_path = "/var/lib/fluxheim/key.pem"
            "#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsafePath { field, .. }) if field == "tls.certificates.cert_path"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_acme_paths_under_world_writable_parent() {
        let config: Config = toml::from_str(
            r#"
            [tls.acme]
            enabled = true
            storage = "/tmp/fluxheim-acme"
            contact_email = "admin@example.test"
            default_issuer = "actalis"

            [[tls.acme.issuers]]
            name = "actalis"
            directory_url = "https://acme-api.actalis.com/acme/directory"

            [tls.acme.issuers.eab]
            key_id_env = "FLUXHEIM_ACTALIS_EAB_KID"
            hmac_key_env = "FLUXHEIM_ACTALIS_EAB_HMAC_KEY"
            "#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsafePath { field, .. }) if field == "tls.acme.storage"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_acme_eab_secret_paths_under_world_writable_parent() {
        let config: Config = toml::from_str(
            r#"
            [tls.acme]
            enabled = true
            storage = "/var/lib/fluxheim/acme"
            contact_email = "admin@example.test"
            default_issuer = "actalis"

            [[tls.acme.issuers]]
            name = "actalis"
            directory_url = "https://acme-api.actalis.com/acme/directory"

            [tls.acme.issuers.eab]
            key_id_file = "/tmp/actalis-kid"
            hmac_key_env = "FLUXHEIM_ACTALIS_EAB_HMAC_KEY"
            "#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsafePath { field, .. })
                if field == "tls.acme.issuers.actalis.eab.key_id_file"
        ));
    }

    #[test]
    fn rejects_zero_acme_renewal_duration() {
        let config: Config = toml::from_str(
            r#"
            [tls.acme.renewal]
            renew_before_secs = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidAcmeRenewalDuration {
                field: "tls.acme.renewal.renew_before_secs"
            })
        );
    }

    #[test]
    fn rejects_local_acme_renew_after_datetime() {
        let config: Config = toml::from_str(
            r#"
            [tls.acme.renewal]
            renew_after = 2026-06-01T00:00:00
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidAcmeRenewAfterDatetime)
        );
    }

    #[test]
    fn rejects_acme_renewal_retry_initial_over_max() {
        let config: Config = toml::from_str(
            r#"
            [tls.acme.renewal]
            retry_initial_secs = 60
            retry_max_secs = 30
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::AcmeRenewalRetryInitialExceedsMax)
        );
    }

    #[test]
    fn rejects_enabled_acme_without_storage() {
        let config: Config = toml::from_str(
            r#"
            [tls.acme]
            enabled = true
            contact_email = "admin@example.test"
            "#,
        )
        .unwrap();

        assert_eq!(config.validate(), Err(ConfigError::MissingAcmeStorage));
    }

    #[test]
    fn rejects_vhost_tls_without_certificate_source() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.tls]
            enabled = true
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::TlsEnabledWithoutCertificateSource {
                scope: "vhosts.tls"
            })
        );
    }

    #[test]
    fn rejects_vhost_acme_without_global_acme() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.tls.acme]
            enabled = true
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::VhostAcmeWithoutGlobalAcme {
                scope: "vhosts.tls"
            })
        );
    }

    #[test]
    fn accepts_vhost_acme_inheriting_exact_hosts() {
        let config: Config = toml::from_str(
            r#"
            [tls.acme]
            enabled = true
            storage = "/var/lib/fluxheim/acme"
            contact_email = "admin@example.test"

            [[vhosts]]
            name = "example"
            hosts = ["example.test", "*.example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.tls.acme]
            enabled = true
            "#,
        )
        .unwrap();

        config.validate().unwrap();
    }

    #[test]
    fn rejects_zero_server_limits() {
        let config: Config = toml::from_str(
            r#"
            [server.limits]
            max_uri_bytes = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidLimit {
                field: "server.limits.max_uri_bytes"
            })
        );
    }

    #[test]
    fn parses_cache_config() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            enabled = true
            image_extensions = ["jpg", "webp"]
            methods = ["GET"]
            max_object_bytes = "4MiB"

            [cache.memory]
            enabled = true
            max_size_bytes = "1GiB"

            [cache.disk]
            enabled = true
            path = "/var/cache/fluxheim"
            max_size_bytes = "10GiB"
            "#,
        )
        .unwrap();

        assert!(config.cache.enabled);
        assert_eq!(
            config.cache.image_extensions,
            ["jpg".to_owned(), "webp".to_owned()]
        );
        assert_eq!(config.cache.methods, ["GET".to_owned()]);
        assert_eq!(
            config.cache.max_object_bytes,
            ByteSize::from_bytes(4 * 1024 * 1024)
        );
        assert!(config.cache.memory.enabled);
        assert_eq!(
            config.cache.memory.max_size_bytes,
            ByteSize::from_bytes(1024 * 1024 * 1024)
        );
        assert_eq!(
            config.cache.disk.path,
            Some(PathBuf::from("/var/cache/fluxheim"))
        );
        assert_eq!(
            config.cache.disk.max_size_bytes,
            ByteSize::from_bytes(10 * 1024 * 1024 * 1024)
        );
        config.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_cache_method() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            enabled = true
            methods = ["get"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheMethod {
                scope: "cache",
                method: "get".to_owned()
            })
        );
    }

    #[test]
    fn rejects_invalid_cache_extension() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            enabled = true
            image_extensions = [".jpg"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheImageExtension {
                scope: "cache",
                extension: ".jpg".to_owned()
            })
        );
    }

    #[test]
    fn rejects_enabled_cache_without_storage_tier() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            enabled = true
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::CacheEnabledWithoutStorageTier { scope: "cache" })
        );
    }

    #[test]
    fn requires_disk_cache_path_when_enabled() {
        let config: Config = toml::from_str(
            r#"
            [cache.disk]
            enabled = true
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::MissingCacheDiskPath { scope: "cache" })
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_disk_cache_under_world_writable_parent() {
        let config: Config = toml::from_str(
            r#"
            [cache.disk]
            enabled = true
            path = "/tmp/fluxheim-cache"
            "#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsafePath { field, .. }) if field == "cache.disk.path"
        ));
    }

    #[test]
    fn rejects_zero_memory_cache_size_when_enabled() {
        let config: Config = toml::from_str(
            r#"
            [cache.memory]
            enabled = true
            max_size_bytes = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheTierMaxSize {
                field: "cache.memory.max_size_bytes".to_owned()
            })
        );
    }

    #[test]
    fn rejects_cache_tier_smaller_than_max_object() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            max_object_bytes = "64MiB"

            [cache.memory]
            enabled = true
            max_size_bytes = "32MiB"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::CacheTierSmallerThanMaxObject {
                tier: "cache.memory".to_owned()
            })
        );
    }

    #[test]
    fn rejects_empty_listeners() {
        let config = Config {
            server: ServerConfig {
                listen: vec![],
                tls_listen: Vec::new(),
                default_vhost: None,
                trusted_proxies: Vec::new(),
                limits: ServerLimitsConfig::default(),
                ..ServerConfig::default()
            },
            admin: AdminConfig::default(),
            metrics: MetricsConfig::default(),
            logging: LoggingConfig::default(),
            headers: HeaderPolicyConfig::default(),
            tls: super::TlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            web: WebConfig::default(),
            vhosts: vec![],
        };

        assert_eq!(config.validate(), Err(ConfigError::EmptyListeners));
    }

    #[test]
    fn rejects_invalid_tls_listener() {
        let config = Config {
            server: ServerConfig {
                tls_listen: vec!["localhost:8443".to_owned()],
                ..ServerConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidListenAddress {
                address: "localhost:8443".to_owned()
            })
        );
    }

    #[test]
    fn parses_https_redirect_config() {
        let config: Config = toml::from_str(
            r#"
            [server]
            listen = ["127.0.0.1:8080"]
            tls_listen = ["127.0.0.1:8443"]

            [server.https_redirect]
            enabled = true
            status = 301
            target_port = 8443

            [tls]
            enabled = true

            [[tls.certificates]]
            cert_path = "fullchain.pem"
            key_path = "key.pem"
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.server.https_redirect.enabled);
        assert_eq!(config.server.https_redirect.status, 301);
        assert_eq!(config.server.https_redirect.target_port, Some(8443));
    }

    #[test]
    fn rejects_https_redirect_without_tls_listener() {
        let config: Config = toml::from_str(
            r#"
            [server.https_redirect]
            enabled = true
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::HttpsRedirectWithoutTlsListener)
        );
    }

    #[test]
    fn rejects_invalid_https_redirect_status() {
        let config: Config = toml::from_str(
            r#"
            [server]
            tls_listen = ["127.0.0.1:8443"]

            [server.https_redirect]
            enabled = true
            status = 200
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHttpsRedirectStatus { status: 200 })
        );
    }

    #[test]
    fn rejects_invalid_https_redirect_target_port() {
        let config: Config = toml::from_str(
            r#"
            [server]
            tls_listen = ["127.0.0.1:8443"]

            [server.https_redirect]
            enabled = true
            target_port = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHttpsRedirectTargetPort)
        );
    }

    #[test]
    fn parses_admin_config_with_self_healing() {
        let config: Config = toml::from_str(
            r#"
            [admin]
            enabled = true
            listen = "127.0.0.1:9090"
            token_env = "FLUXHEIM_ADMIN_TOKEN"
            snapshot_store = "/var/lib/fluxheim/snapshots"

            [admin.self_healing]
            enabled = true
            validation_window_secs = 45
            health_path = "/_fluxheim/health"
            min_successful_checks = 2
            max_error_rate_per_mille = 50
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.admin.enabled);
        assert!(config.admin.self_healing.enabled);
        assert_eq!(
            config.admin.snapshot_store.as_deref(),
            Some(Path::new("/var/lib/fluxheim/snapshots"))
        );
    }

    #[test]
    fn parses_metrics_config() {
        let config: Config = toml::from_str(
            r#"
            [metrics]
            enabled = true
            listen = "127.0.0.1:9091"
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.metrics.enabled);
        assert_eq!(config.metrics.listen, "127.0.0.1:9091");
    }

    #[test]
    fn parses_access_logging_config() {
        let config: Config = toml::from_str(
            r#"
            [logging]
            level = "debug"
            format = "text"
            target = "stdout"

            [logging.access]
            enabled = false
            include_host = false
            include_path = false
            request_id = false
            request_id_header = "x-correlation-id"
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(config.logging.level, super::LoggingLevel::Debug);
        assert_eq!(config.logging.format, super::LoggingFormat::Text);
        assert_eq!(config.logging.target, super::LoggingTarget::Stdout);
        assert!(!config.logging.access.enabled);
        assert!(!config.logging.access.include_host);
        assert!(!config.logging.access.include_path);
        assert!(!config.logging.access.request_id);
        assert_eq!(config.logging.access.request_id_header, "x-correlation-id");
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn parses_file_logging_config() {
        let config: Config = toml::from_str(
            r#"
            [logging.file]
            enabled = true
            path = "/var/log/fluxheim/fluxheim.log"
            append = false
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.logging.file.enabled);
        assert_eq!(
            config.logging.file.path.as_deref(),
            Some(std::path::Path::new("/var/log/fluxheim/fluxheim.log"))
        );
        assert!(!config.logging.file.append);
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn rejects_file_logging_without_path() {
        let config: Config = toml::from_str(
            r#"
            [logging.file]
            enabled = true
            "#,
        )
        .unwrap();

        assert_eq!(config.validate(), Err(ConfigError::MissingLoggingFilePath));
    }

    #[test]
    fn rejects_empty_file_logging_path() {
        let config: Config = toml::from_str(
            r#"
            [logging.file]
            path = ""
            "#,
        )
        .unwrap();

        assert_eq!(config.validate(), Err(ConfigError::EmptyLoggingFilePath));
    }

    #[test]
    fn rejects_file_logging_path_traversal() {
        let config: Config = toml::from_str(
            r#"
            [logging.file]
            path = "../fluxheim.log"
            "#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsafePath { field, .. }) if field == "logging.file.path"
        ));
    }

    #[cfg(all(not(feature = "privacy-mode"), unix))]
    #[test]
    fn rejects_file_logging_under_world_writable_parent() {
        let config: Config = toml::from_str(
            r#"
            [logging.file]
            path = "/tmp/fluxheim.log"
            "#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsafePath { field, .. }) if field == "logging.file.path"
        ));
    }

    #[test]
    fn rejects_invalid_access_log_request_id_header() {
        let config: Config = toml::from_str(
            r#"
            [logging.access]
            request_id_header = "bad header"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHeaderName {
                field: "logging.access.request_id_header",
                name: "bad header".to_owned(),
            })
        );
    }

    #[cfg(feature = "privacy-mode")]
    #[test]
    fn privacy_mode_rejects_access_logging() {
        let config: Config = toml::from_str(
            r#"
            [logging.access]
            enabled = true
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::PrivacyModeAccessLogging)
        );
    }

    #[cfg(feature = "privacy-mode")]
    #[test]
    fn privacy_mode_rejects_file_logging() {
        let config: Config = toml::from_str(
            r#"
            [logging.file]
            enabled = true
            path = "/tmp/fluxheim.log"
            "#,
        )
        .unwrap();

        assert_eq!(config.validate(), Err(ConfigError::PrivacyModeFileLogging));
    }

    #[test]
    fn rejects_remote_metrics_listener_by_default() {
        let config = Config {
            metrics: MetricsConfig {
                enabled: true,
                listen: "0.0.0.0:9091".to_owned(),
                ..MetricsConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::MetricsListenNotLoopback {
                address: "0.0.0.0:9091".to_owned()
            })
        );
    }

    #[test]
    fn rejects_enabled_admin_without_auth() {
        let config = Config {
            admin: AdminConfig {
                enabled: true,
                snapshot_store: Some(PathBuf::from("/var/lib/fluxheim/snapshots")),
                ..AdminConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(config.validate(), Err(ConfigError::MissingAdminAuth));
    }

    #[test]
    fn rejects_enabled_admin_without_snapshot_store() {
        let config = Config {
            admin: AdminConfig {
                enabled: true,
                token_env: Some("FLUXHEIM_ADMIN_TOKEN".to_owned()),
                ..AdminConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::MissingAdminSnapshotStore)
        );
    }

    #[test]
    fn rejects_remote_admin_listener_by_default() {
        let config = Config {
            admin: AdminConfig {
                enabled: true,
                listen: "0.0.0.0:9090".to_owned(),
                token_env: Some("FLUXHEIM_ADMIN_TOKEN".to_owned()),
                snapshot_store: Some(PathBuf::from("/var/lib/fluxheim/snapshots")),
                ..AdminConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::AdminListenNotLoopback {
                address: "0.0.0.0:9090".to_owned()
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_admin_paths_under_world_writable_parent() {
        let token_config = Config {
            admin: AdminConfig {
                token_file: Some(PathBuf::from("/tmp/fluxheim-admin-token")),
                ..AdminConfig::default()
            },
            ..Config::default()
        };
        assert!(matches!(
            token_config.validate(),
            Err(ConfigError::UnsafePath { field, .. }) if field == "admin.token_file"
        ));

        let snapshot_config = Config {
            admin: AdminConfig {
                snapshot_store: Some(PathBuf::from("/tmp/fluxheim-admin-snapshots")),
                ..AdminConfig::default()
            },
            ..Config::default()
        };
        assert!(matches!(
            snapshot_config.validate(),
            Err(ConfigError::UnsafePath { field, .. }) if field == "admin.snapshot_store"
        ));
    }

    #[test]
    fn rejects_invalid_admin_self_healing_window() {
        let config = Config {
            admin: AdminConfig {
                self_healing: AdminSelfHealingConfig {
                    validation_window_secs: 0,
                    ..AdminSelfHealingConfig::default()
                },
                ..AdminConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidAdminSelfHealing {
                field: "admin.self_healing.validation_window_secs"
            })
        );
    }

    #[test]
    fn rejects_unsafe_admin_health_paths() {
        for health_path in [
            "relative/path".to_owned(),
            "/_fluxheim/health query".to_owned(),
            "/_fluxheim/health\tbad".to_owned(),
            "/_fluxheim\\health".to_owned(),
            "/_fluxheim/health?ready=1".to_owned(),
            "/_fluxheim/health#ready".to_owned(),
            "/_fluxheim/status".to_owned(),
            "/_fluxheim/reload".to_owned(),
            "/".to_owned() + &"a".repeat(super::MAX_ADMIN_HEALTH_PATH_BYTES),
        ] {
            let config = Config {
                admin: AdminConfig {
                    self_healing: AdminSelfHealingConfig {
                        health_path,
                        ..AdminSelfHealingConfig::default()
                    },
                    ..AdminConfig::default()
                },
                ..Config::default()
            };

            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidAdminHealthPath { .. })
            ));
        }
    }

    #[test]
    fn rejects_tls_listener_without_tls_enabled() {
        let config = Config {
            server: ServerConfig {
                tls_listen: vec!["127.0.0.1:8443".to_owned()],
                ..ServerConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(config.validate(), Err(ConfigError::TlsListenerWithoutTls));
    }

    #[test]
    fn rejects_tls_listener_without_static_certificate() {
        let config = Config {
            server: ServerConfig {
                tls_listen: vec!["127.0.0.1:8443".to_owned()],
                ..ServerConfig::default()
            },
            tls: super::TlsConfig {
                enabled: true,
                ..super::TlsConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::TlsListenerWithoutStaticCertificate)
        );
    }

    #[test]
    fn accepts_tls_listener_with_static_certificate() {
        let config = Config {
            server: ServerConfig {
                tls_listen: vec!["127.0.0.1:8443".to_owned()],
                ..ServerConfig::default()
            },
            tls: super::TlsConfig {
                enabled: true,
                certificates: vec![super::StaticCertificateConfig {
                    cert_path: PathBuf::from("fullchain.pem"),
                    key_path: PathBuf::from("key.pem"),
                }],
                ..super::TlsConfig::default()
            },
            ..Config::default()
        };

        config.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_upstream() {
        let config = Config {
            server: ServerConfig::default(),
            admin: AdminConfig::default(),
            metrics: MetricsConfig::default(),
            logging: LoggingConfig::default(),
            headers: HeaderPolicyConfig::default(),
            tls: super::TlsConfig::default(),
            proxy: ProxyConfig {
                upstream: Some("https://origin.example.test".to_owned()),
                upstream_tls: true,
                upstream_sni: None,
                ..ProxyConfig::default()
            },
            cache: CacheConfig::default(),
            web: WebConfig::default(),
            vhosts: vec![],
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidUpstream {
                address: "https://origin.example.test".to_owned()
            })
        );
    }

    #[test]
    fn rejects_empty_index_files() {
        let config = Config {
            server: ServerConfig::default(),
            admin: AdminConfig::default(),
            metrics: MetricsConfig::default(),
            logging: LoggingConfig::default(),
            headers: HeaderPolicyConfig::default(),
            tls: super::TlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            web: WebConfig {
                root: Some(PathBuf::from("public")),
                index_files: vec![],
                deny_dotfiles: true,
                ..WebConfig::default()
            },
            vhosts: vec![],
        };

        assert_eq!(config.validate(), Err(ConfigError::EmptyIndexFiles));
    }

    #[test]
    fn rejects_nested_index_files() {
        let config = Config {
            server: ServerConfig::default(),
            admin: AdminConfig::default(),
            metrics: MetricsConfig::default(),
            logging: LoggingConfig::default(),
            headers: HeaderPolicyConfig::default(),
            tls: super::TlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            web: WebConfig {
                root: Some(PathBuf::from("public")),
                index_files: vec!["pages/index.html".to_owned()],
                deny_dotfiles: true,
                ..WebConfig::default()
            },
            vhosts: vec![],
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidIndexFile {
                file: "pages/index.html".to_owned()
            })
        );
    }

    #[test]
    fn normalizes_host_names() {
        assert_eq!(
            normalize_host("Example.COM:443"),
            Some("example.com".to_owned())
        );
        assert_eq!(
            normalize_host("example.com."),
            Some("example.com".to_owned())
        );
        assert_eq!(normalize_host("[::1]:443"), Some("::1".to_owned()));
        assert_eq!(normalize_host("bad host"), None);
        assert_eq!(normalize_host("example.com?next=https://evil.test"), None);
        assert_eq!(normalize_host("example.com#fragment"), None);
        assert_eq!(normalize_host("user@example.com"), None);
        assert_eq!(normalize_host("example.com\u{0001}"), None);
        assert_eq!(normalize_host("*.example.com"), None);
        assert_eq!(
            normalize_host_pattern("*.Example.COM"),
            Some("*.example.com".to_owned())
        );
        assert_eq!(normalize_host_pattern("*bad.example.com"), None);
    }

    #[test]
    fn parses_vhosts() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "example.com"
            hosts = ["example.com", "www.example.com"]

            [vhosts.proxy]
            upstream = "127.0.0.1:3001"

            [vhosts.web]
            root = "/srv/sites/example"

            [vhosts.cache]
            enabled = true

            [vhosts.cache.memory]
            enabled = true
            "#,
        )
        .unwrap();

        assert_eq!(config.vhosts.len(), 1);
        assert!(config.vhosts[0].cache.enabled);
        assert_eq!(
            config.vhosts[0].normalized_hosts(),
            ["example.com".to_owned(), "www.example.com".to_owned()]
        );
        config.validate().unwrap();
    }

    #[test]
    fn rejects_duplicate_vhost_hosts() {
        let config = Config {
            server: ServerConfig::default(),
            admin: AdminConfig::default(),
            metrics: MetricsConfig::default(),
            logging: LoggingConfig::default(),
            headers: HeaderPolicyConfig::default(),
            tls: super::TlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            web: WebConfig::default(),
            vhosts: vec![
                VhostConfig {
                    name: "first.example".to_owned(),
                    hosts: vec!["Example.com".to_owned()],
                    tls: super::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    headers: VhostHeaderPolicyConfig::default(),
                    web: WebConfig::default(),
                },
                VhostConfig {
                    name: "second.example".to_owned(),
                    hosts: vec!["example.com:443".to_owned()],
                    tls: super::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    headers: VhostHeaderPolicyConfig::default(),
                    web: WebConfig::default(),
                },
            ],
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::DuplicateVhostHost {
                host: "example.com".to_owned()
            })
        );
    }

    #[test]
    fn rejects_unknown_default_vhost() {
        let config = Config {
            server: ServerConfig {
                listen: vec!["127.0.0.1:8080".to_owned()],
                tls_listen: Vec::new(),
                default_vhost: Some("missing".to_owned()),
                trusted_proxies: Vec::new(),
                limits: ServerLimitsConfig::default(),
                ..ServerConfig::default()
            },
            vhosts: vec![VhostConfig {
                name: "known".to_owned(),
                hosts: vec!["known.example".to_owned()],
                tls: super::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                headers: VhostHeaderPolicyConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::UnknownDefaultVhost {
                name: "missing".to_owned()
            })
        );
    }

    #[test]
    fn accepts_wildcard_vhost_host() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "wild".to_owned(),
                hosts: vec!["*.example.com".to_owned()],
                tls: super::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                headers: VhostHeaderPolicyConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };

        assert_eq!(
            config.vhosts[0].normalized_hosts(),
            ["*.example.com".to_owned()]
        );
        config.validate().unwrap();
    }

    #[test]
    fn loads_config_directory_in_sorted_order() {
        let dir = TestDir::new("config-dir");
        fs::create_dir_all(dir.path().join("site")).unwrap();
        fs::write(
            dir.path().join("00-server.toml"),
            r#"
            [server]
            listen = ["127.0.0.1:19090"]
            default_vhost = "example"
            "#,
        )
        .unwrap();
        fs::write(
            dir.path().join("10-vhost.toml"),
            r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.web]
            root = "site"
            "#,
        )
        .unwrap();
        fs::write(dir.path().join(".ignored.toml"), "this is not toml").unwrap();
        fs::write(dir.path().join("ignored.txt"), "ignored").unwrap();

        let config = Config::load(Some(dir.path())).unwrap();

        assert_eq!(config.server.listen, ["127.0.0.1:19090"]);
        assert_eq!(config.server.default_vhost, Some("example".to_owned()));
        assert_eq!(config.vhosts.len(), 1);
        assert_eq!(config.vhosts[0].web.root, Some(dir.path().join("site")));
    }

    #[test]
    fn rejects_config_directory_with_too_many_toml_files() {
        let dir = TestDir::new("config-dir-too-many-files");
        for index in 0..=super::MAX_CONFIG_DIRECTORY_FILES {
            fs::write(dir.path().join(format!("{index:03}.toml")), "[server]\n").unwrap();
        }

        let error = Config::load(Some(dir.path())).unwrap_err();

        assert!(
            matches!(error, ConfigLoadError::Read(error) if error.kind() == std::io::ErrorKind::InvalidData)
        );
    }

    #[test]
    fn resolves_relative_cache_disk_paths_from_config_file() {
        let dir = TestDir::new("cache-path");
        fs::write(
            dir.path().join("fluxheim.toml"),
            r#"
            [cache.disk]
            enabled = true
            path = "cache"
            max_size_bytes = "1GiB"
            "#,
        )
        .unwrap();

        let config = Config::load(Some(&dir.path().join("fluxheim.toml"))).unwrap();

        assert_eq!(config.cache.disk.path, Some(dir.path().join("cache")));
    }

    #[test]
    fn resolves_relative_server_process_paths_from_config_file() {
        let dir = TestDir::new("server-process-paths");
        fs::write(
            dir.path().join("fluxheim.toml"),
            r#"
            [server.process]
            error_log = "logs/error.log"
            pid_file = "run/fluxheim.pid"
            upgrade_sock = "run/fluxheim-upgrade.sock"
            "#,
        )
        .unwrap();

        let config = Config::load(Some(&dir.path().join("fluxheim.toml"))).unwrap();

        assert_eq!(
            config.server.process.error_log,
            Some(dir.path().join("logs/error.log"))
        );
        assert_eq!(
            config.server.process.pid_file,
            dir.path().join("run/fluxheim.pid")
        );
        assert_eq!(
            config.server.process.upgrade_sock,
            dir.path().join("run/fluxheim-upgrade.sock")
        );
    }

    #[test]
    fn resolves_relative_logging_file_path_from_config_file() {
        let dir = TestDir::new("logging-file-path");
        fs::write(
            dir.path().join("fluxheim.toml"),
            r#"
            [logging.file]
            path = "logs/fluxheim.log"
            "#,
        )
        .unwrap();

        let config = Config::load(Some(&dir.path().join("fluxheim.toml"))).unwrap();

        assert_eq!(
            config.logging.file.path,
            Some(dir.path().join("logs/fluxheim.log"))
        );
    }

    #[test]
    fn resolves_relative_tls_paths_from_config_file() {
        let dir = TestDir::new("tls-paths");
        fs::write(
            dir.path().join("fluxheim.toml"),
            r#"
            [[tls.certificates]]
            cert_path = "tls/fullchain.pem"
            key_path = "tls/key.pem"

            [tls.acme]
            storage = "acme"

            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.tls.certificate]
            cert_path = "vhosts/example/fullchain.pem"
            key_path = "vhosts/example/key.pem"
            "#,
        )
        .unwrap();

        let config = Config::load(Some(&dir.path().join("fluxheim.toml"))).unwrap();

        assert_eq!(
            config.tls.certificates[0].cert_path,
            dir.path().join("tls/fullchain.pem")
        );
        assert_eq!(config.tls.acme.storage, Some(dir.path().join("acme")));
        assert_eq!(
            config.vhosts[0].tls.certificate.as_ref().unwrap().key_path,
            dir.path().join("vhosts/example/key.pem")
        );
    }

    #[test]
    fn rejects_config_relative_paths_with_parent_traversal() {
        let dir = TestDir::new("unsafe-paths");
        fs::write(
            dir.path().join("fluxheim.toml"),
            r#"
            [web]
            root = "../outside"
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&dir.path().join("fluxheim.toml"))).unwrap_err();

        assert!(matches!(
            error,
            ConfigLoadError::Validate(ConfigError::UnsafePath { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_runtime_path_below_symlinked_directory() {
        let dir = TestDir::new("runtime-path-parent-symlink");
        let real_dir = dir.path().join("real");
        let symlink_dir = dir.path().join("linked");
        fs::create_dir_all(real_dir.join("public")).unwrap();
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();
        fs::write(
            dir.path().join("fluxheim.toml"),
            r#"
            [web]
            root = "linked/public"
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&dir.path().join("fluxheim.toml"))).unwrap_err();

        assert!(matches!(
            error,
            ConfigLoadError::Validate(ConfigError::UnsafePath { field, .. })
                if field == "web.root"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_runtime_path() {
        let dir = TestDir::new("runtime-path-symlink");
        let real_root = dir.path().join("public-real");
        let symlink_root = dir.path().join("public");
        fs::create_dir(&real_root).unwrap();
        std::os::unix::fs::symlink(&real_root, &symlink_root).unwrap();
        fs::write(
            dir.path().join("fluxheim.toml"),
            r#"
            [web]
            root = "public"
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&dir.path().join("fluxheim.toml"))).unwrap_err();

        assert!(matches!(
            error,
            ConfigLoadError::Validate(ConfigError::UnsafePath { field, .. })
                if field == "web.root"
        ));
    }

    #[test]
    fn rejects_non_toml_config_file() {
        let dir = TestDir::new("non-toml-config");
        let path = dir.path().join("fluxheim.txt");
        fs::write(&path, "[server]\n").unwrap();

        let error = Config::load(Some(&path)).unwrap_err();

        assert!(matches!(error, ConfigLoadError::InvalidPath { .. }));
    }

    #[test]
    fn rejects_oversized_config_file() {
        let dir = TestDir::new("oversized-config");
        let path = dir.path().join("fluxheim.toml");
        fs::write(
            &path,
            vec![b'#'; (super::MAX_CONFIG_FILE_BYTES + 1) as usize],
        )
        .unwrap();

        let error = Config::load(Some(&path)).unwrap_err();

        assert!(
            matches!(error, ConfigLoadError::Read(error) if error.kind() == std::io::ErrorKind::InvalidData)
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_config_file() {
        let dir = TestDir::new("config-file-symlink");
        let real_path = dir.path().join("real.toml");
        let symlink_path = dir.path().join("fluxheim.toml");
        fs::write(&real_path, "[server]\n").unwrap();
        std::os::unix::fs::symlink(&real_path, &symlink_path).unwrap();

        let error = Config::load(Some(&symlink_path)).unwrap_err();

        assert!(matches!(error, ConfigLoadError::InvalidPath { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_config_directory_source() {
        let dir = TestDir::new("config-dir-symlink");
        let real_dir = dir.path().join("real");
        let symlink_dir = dir.path().join("linked");
        fs::create_dir(&real_dir).unwrap();
        fs::write(real_dir.join("fluxheim.toml"), "[server]\n").unwrap();
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

        let error = Config::load(Some(&symlink_dir)).unwrap_err();

        assert!(matches!(error, ConfigLoadError::InvalidPath { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_config_source_below_symlinked_directory() {
        let dir = TestDir::new("config-dir-parent-symlink");
        let real_dir = dir.path().join("real");
        let symlink_dir = dir.path().join("linked");
        fs::create_dir(&real_dir).unwrap();
        fs::write(real_dir.join("fluxheim.toml"), "[server]\n").unwrap();
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

        let error = Config::load(Some(&symlink_dir.join("fluxheim.toml"))).unwrap_err();

        assert!(matches!(error, ConfigLoadError::InvalidPath { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn ignores_symlinked_config_directory_entries() {
        let dir = TestDir::new("config-dir-entry-symlink");
        let outside_dir = TestDir::new("config-dir-entry-symlink-outside");
        let outside = outside_dir.path().join("outside.toml");
        fs::write(
            dir.path().join("00-server.toml"),
            r#"
            [server]
            listen = ["127.0.0.1:19090"]
            "#,
        )
        .unwrap();
        fs::write(
            &outside,
            r#"
            [[vhosts]]
            name = "linked"
            hosts = ["linked.example"]
            "#,
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, dir.path().join("10-linked.toml")).unwrap();

        let config = Config::load(Some(dir.path())).unwrap();

        assert_eq!(config.server.listen, ["127.0.0.1:19090"]);
        assert!(config.vhosts.is_empty());
    }

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "fluxheim-config-test-{label}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
