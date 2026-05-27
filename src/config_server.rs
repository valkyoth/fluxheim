use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{ByteSize, ConfigError, validate_config_list_len};
use crate::config_net::valid_trusted_proxy;
use crate::config_path::{validate_optional_process_path, validate_required_process_path};

pub(crate) const MAX_SERVER_LISTENERS: usize = 64;
pub(crate) const MAX_TRUSTED_PROXIES: usize = 512;

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
    pub proxy_protocol: DownstreamProxyProtocol,
    #[serde(default)]
    pub regex_enabled: bool,
    #[serde(default)]
    pub limits: ServerLimitsConfig,
    #[serde(default)]
    pub process: ServerProcessConfig,
    #[serde(default)]
    pub https_redirect: HttpsRedirectConfig,
    #[serde(default)]
    pub host_routing: HostRoutingConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            tls_listen: Vec::new(),
            default_vhost: None,
            trusted_proxies: Vec::new(),
            proxy_protocol: DownstreamProxyProtocol::Off,
            regex_enabled: false,
            limits: ServerLimitsConfig::default(),
            process: ServerProcessConfig::default(),
            https_redirect: HttpsRedirectConfig::default(),
            host_routing: HostRoutingConfig::default(),
        }
    }
}

impl ServerConfig {
    pub(crate) fn merge(&mut self, fragment: ServerConfigFragment) {
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
        if let Some(proxy_protocol) = fragment.proxy_protocol {
            self.proxy_protocol = proxy_protocol;
        }
        if let Some(regex_enabled) = fragment.regex_enabled {
            self.regex_enabled = regex_enabled;
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
        if let Some(host_routing) = fragment.host_routing {
            self.host_routing = host_routing;
        }
    }

    pub(crate) fn validate_with_runtime_path_validation(
        &self,
        validate_runtime_paths: bool,
    ) -> Result<(), ConfigError> {
        if self.listen.is_empty() {
            return Err(ConfigError::EmptyListeners);
        }
        validate_config_list_len("server.listen", self.listen.len(), MAX_SERVER_LISTENERS)?;
        validate_config_list_len(
            "server.tls_listen",
            self.tls_listen.len(),
            MAX_SERVER_LISTENERS,
        )?;
        validate_config_list_len(
            "server.trusted_proxies",
            self.trusted_proxies.len(),
            MAX_TRUSTED_PROXIES,
        )?;

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
        if self.proxy_protocol != DownstreamProxyProtocol::Off && self.trusted_proxies.is_empty() {
            return Err(ConfigError::InvalidServerProxyProtocolPolicy {
                reason: "server.proxy_protocol requires server.trusted_proxies so client identity cannot be spoofed by direct peers",
            });
        }

        self.limits.validate()?;
        self.process
            .validate_with_runtime_path_validation(validate_runtime_paths)?;
        self.https_redirect.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DownstreamProxyProtocol {
    #[default]
    Off,
    V1,
    V2,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerConfigFragment {
    #[serde(default)]
    listen: Option<Vec<String>>,
    #[serde(default)]
    tls_listen: Option<Vec<String>>,
    #[serde(default)]
    default_vhost: Option<String>,
    #[serde(default)]
    trusted_proxies: Option<Vec<String>>,
    #[serde(default)]
    proxy_protocol: Option<DownstreamProxyProtocol>,
    #[serde(default)]
    regex_enabled: Option<bool>,
    #[serde(default)]
    limits: Option<ServerLimitsConfig>,
    #[serde(default)]
    process: Option<ServerProcessConfig>,
    #[serde(default)]
    https_redirect: Option<HttpsRedirectConfig>,
    #[serde(default)]
    host_routing: Option<HostRoutingConfig>,
}

impl ServerConfigFragment {
    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(process) = &mut self.process {
            process.resolve_relative_paths(base_dir);
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostRoutingConfig {
    #[serde(default)]
    pub strict: bool,
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
    #[serde(default = "default_process_certificate_reload_sock")]
    pub certificate_reload_sock: PathBuf,
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
            certificate_reload_sock: default_process_certificate_reload_sock(),
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
        if self.certificate_reload_sock.is_relative() {
            self.certificate_reload_sock = base_dir.join(&self.certificate_reload_sock);
        }
    }

    fn validate_with_runtime_path_validation(
        &self,
        validate_runtime_paths: bool,
    ) -> Result<(), ConfigError> {
        if validate_runtime_paths {
            validate_optional_process_path("server.process.error_log", self.error_log.as_deref())?;
            validate_required_process_path("server.process.pid_file", &self.pid_file)?;
            validate_required_process_path("server.process.upgrade_sock", &self.upgrade_sock)?;
            validate_required_process_path(
                "server.process.certificate_reload_sock",
                &self.certificate_reload_sock,
            )?;
        }
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

fn default_listen() -> Vec<String> {
    vec!["127.0.0.1:8080".to_owned()]
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
    default_process_runtime_path("fluxheim.pid")
}

fn default_process_upgrade_sock() -> PathBuf {
    default_process_runtime_path("fluxheim-upgrade.sock")
}

fn default_process_certificate_reload_sock() -> PathBuf {
    default_process_runtime_path("fluxheim-cert-reload.sock")
}

#[cfg(not(test))]
fn default_process_runtime_path(name: &str) -> PathBuf {
    PathBuf::from("/run/fluxheim").join(name)
}

#[cfg(test)]
fn default_process_runtime_path(name: &str) -> PathBuf {
    crate::test_support::safe_relative_path(
        &crate::test_support::test_root(),
        &format!("run/{name}"),
    )
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

fn validate_process_optional_duration(
    field: &'static str,
    value: Option<u64>,
) -> Result<(), ConfigError> {
    match value {
        Some(0) => Err(ConfigError::InvalidProcessSetting { field }),
        Some(_) | None => Ok(()),
    }
}

fn default_true() -> bool {
    true
}
