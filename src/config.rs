use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use toml::value::{Datetime, Offset};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(any(target_os = "linux", target_os = "android"))]
const O_NOFOLLOW: i32 = 0o400000;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const O_NOFOLLOW: i32 = 0x0100;

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!(
    "O_NOFOLLOW is unknown on this Unix platform; audit symlink-safe file opening before building Fluxheim"
);

const MAX_CONFIG_DIRECTORY_FILES: usize = 256;
const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;
const MAX_ADMIN_HEALTH_PATH_BYTES: usize = 2048;
const MAX_SERVER_LISTENERS: usize = 64;
const MAX_TRUSTED_PROXIES: usize = 512;
const MAX_VHOSTS: usize = 1024;
const MAX_VHOST_NAME_BYTES: usize = 128;
const MAX_VHOST_HOSTS: usize = 64;
const MAX_VHOST_ROUTES: usize = 256;
const MAX_ROUTE_NAME_BYTES: usize = 128;
const MAX_TLS_CURVE_PREFERENCES: usize = 16;
const MAX_TLS_CIPHER_SUITES: usize = 32;
const MAX_TLS_CERTIFICATES: usize = 1024;
const MAX_ACME_ISSUERS: usize = 128;
const MAX_VHOST_ACME_DOMAINS: usize = 64;
const MAX_WEB_INDEX_FILES: usize = 32;
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
    pub tracing: TracingConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub headers: HeaderPolicyConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub compression: CompressionConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub cache_purger: CachePurgerConfig,
    #[serde(default)]
    pub web: WebConfig,
    #[serde(default)]
    pub vhosts: Vec<VhostConfig>,
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigLoadError> {
        Self::load_with_runtime_path_validation(path, true)
    }

    pub fn load_without_runtime_paths(path: Option<&Path>) -> Result<Self, ConfigLoadError> {
        Self::load_with_runtime_path_validation(path, false)
    }

    fn load_with_runtime_path_validation(
        path: Option<&Path>,
        validate_runtime_paths: bool,
    ) -> Result<Self, ConfigLoadError> {
        let mut config = match path {
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

        config.apply_presets();
        config
            .validate_with_runtime_path_validation(validate_runtime_paths)
            .map_err(ConfigLoadError::Validate)?;
        Ok(config)
    }

    fn load_file(path: &Path) -> Result<Self, ConfigLoadError> {
        let mut fragment = ConfigFragment::load(path)?;
        let include_conf_d = fragment.include_conf_d;
        let parent = path.parent();
        if let Some(parent) = parent {
            fragment.resolve_relative_paths(parent);
        }

        let mut config = Self::default();
        config.merge(fragment);
        if include_conf_d && let Some(parent) = parent {
            config.merge_conf_d(parent)?;
        }
        Ok(config)
    }

    fn load_dir(path: &Path) -> Result<Self, ConfigLoadError> {
        let files = config_directory_files(path)?;

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

    fn merge_conf_d(&mut self, base_dir: &Path) -> Result<(), ConfigLoadError> {
        let conf_dir = base_dir.join("conf.d");
        if !conf_dir.try_exists().map_err(ConfigLoadError::Read)? {
            return Ok(());
        }

        let metadata = fs::symlink_metadata(&conf_dir).map_err(ConfigLoadError::Read)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ConfigLoadError::InvalidPath { path: conf_dir });
        }

        let mut files = toml_files(&conf_dir)?;
        files.sort();
        for file in files {
            let mut fragment = ConfigFragment::load(&file)?;
            if let Some(parent) = file.parent() {
                fragment.resolve_relative_paths(parent);
            }
            self.merge(fragment);
        }

        Ok(())
    }

    fn apply_presets(&mut self) {
        self.cache.apply_preset_defaults();
        for vhost in &mut self.vhosts {
            vhost.cache.apply_preset_defaults();
            vhost.php.apply_preset_defaults();
            for route in &mut vhost.routes {
                if let Some(cache) = &mut route.cache {
                    cache.apply_preset_defaults();
                }
                if let Some(php) = &mut route.php {
                    php.apply_preset_defaults();
                }
            }
        }
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
        if let Some(tracing) = fragment.tracing {
            self.tracing = tracing;
        }
        if let Some(logging) = fragment.logging {
            self.logging = logging;
        }
        if let Some(headers) = fragment.headers {
            self.headers = headers;
        }
        if let Some(tls) = fragment.tls {
            self.tls.merge(tls);
        }
        if let Some(proxy) = fragment.proxy {
            self.proxy = proxy;
        }
        if let Some(compression) = fragment.compression {
            self.compression = compression;
        }
        if let Some(cache) = fragment.cache {
            self.cache = cache;
        }
        if let Some(cache_purger) = fragment.cache_purger {
            self.cache_purger = cache_purger;
        }
        if let Some(web) = fragment.web {
            self.web = web;
        }
        self.vhosts.extend(fragment.vhosts);
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.validate_with_runtime_path_validation(true)
    }

    fn validate_with_runtime_path_validation(
        &self,
        validate_runtime_paths: bool,
    ) -> Result<(), ConfigError> {
        self.server
            .validate_with_runtime_path_validation(validate_runtime_paths)?;
        self.admin.validate()?;
        self.metrics.validate()?;
        self.tracing.validate()?;
        self.logging.validate()?;
        self.headers.validate()?;
        self.tls.validate()?;
        self.validate_acme_challenge_runtime()?;
        self.validate_tls_listeners()?;
        self.proxy.validate()?;
        self.compression.validate()?;
        self.cache.validate("cache")?;
        self.cache_purger.validate()?;
        self.web.validate()?;
        self.validate_vhosts()?;
        self.validate_compliance_internal_crypto()?;
        Ok(())
    }

    fn validate_acme_challenge_runtime(&self) -> Result<(), ConfigError> {
        if !self.tls.acme.enabled || self.tls.acme.challenge != AcmeChallenge::TlsAlpn01 {
            return Ok(());
        }
        if self.tls.backend != TlsBackend::Rustls {
            return Err(ConfigError::InvalidTlsPolicy {
                field: "tls.acme.challenge",
                reason: "tls-alpn-01 managed ACME is currently supported only by the rustls backend",
            });
        }
        if self.server.tls_listen.is_empty() {
            return Err(ConfigError::InvalidTlsPolicy {
                field: "tls.acme.challenge",
                reason: "tls-alpn-01 managed ACME requires at least one server.tls_listen address",
            });
        }

        Ok(())
    }

    fn validate_tls_listeners(&self) -> Result<(), ConfigError> {
        if self.server.tls_listen.is_empty() {
            return Ok(());
        }
        if !self.tls.enabled {
            return Err(ConfigError::TlsListenerWithoutTls);
        }
        if !self.has_tls_listener_fallback_certificate() {
            return Err(ConfigError::TlsListenerWithoutStaticCertificate);
        }

        Ok(())
    }

    fn validate_compliance_internal_crypto(&self) -> Result<(), ConfigError> {
        let compliance_mode = self.tls.compliance_mode();
        if !compliance_mode.required() {
            return Ok(());
        }

        if self.admin.enabled && !crate::internal_crypto::admin_mac_is_compliance_capable() {
            return Err(ConfigError::InvalidCompliancePolicy {
                field: "admin.enabled",
                reason: "FIPS/ISO-required mode allows the admin API only when bearer-token verification is routed through a validated provider; rebuild with tls-openssl-fips or tls-rustls-fips, or disable admin.enabled",
            });
        }

        if self.tls.acme.enabled {
            return Err(ConfigError::InvalidCompliancePolicy {
                field: "tls.acme.enabled",
                reason: "FIPS/ISO-required mode currently rejects managed ACME because account key generation, JWS account signing, EAB handling, outbound ACME HTTPS transport, and TLS-ALPN challenge certificate generation are not fully routed through the selected validated provider; use externally issued static certificates or an externally evidenced renewal process for the FIPS evidence boundary",
            });
        }

        if self.metrics.otlp.enabled
            && !fips_allowed_local_otlp_endpoint(&self.metrics.otlp.endpoint)
        {
            return Err(ConfigError::InvalidCompliancePolicy {
                field: "metrics.otlp.endpoint",
                reason: "FIPS/ISO-required mode allows OTLP metrics export only to a numeric local http://127.0.0.1 or http://[::1] loopback collector; remote, localhost, or HTTPS OTLP export needs provider-aligned outbound TLS evidence first",
            });
        }

        if self.tracing.otlp.enabled
            && !fips_allowed_local_otlp_endpoint(&self.tracing.otlp.endpoint)
        {
            return Err(ConfigError::InvalidCompliancePolicy {
                field: "tracing.otlp.endpoint",
                reason: "FIPS/ISO-required mode allows OTLP trace export only to a numeric local http://127.0.0.1 or http://[::1] loopback collector; remote, localhost, or HTTPS OTLP export needs provider-aligned outbound TLS evidence first",
            });
        }

        let require_disk_cache_encryption = self.tls.fips.require_disk_cache_encryption
            || self.tls.iso19790.require_disk_cache_encryption;

        validate_cache_compliance_internal_crypto(
            &self.cache,
            "cache",
            require_disk_cache_encryption,
        )?;
        for vhost in &self.vhosts {
            validate_cache_compliance_internal_crypto(
                &vhost.cache,
                "vhosts.cache",
                require_disk_cache_encryption,
            )
            .map_err(|source| ConfigError::VhostSection {
                vhost: vhost.name.clone(),
                section: "cache",
                source: Box::new(source),
            })?;
            for route in &vhost.routes {
                if let Some(cache) = &route.cache {
                    validate_cache_compliance_internal_crypto(
                        cache,
                        "vhosts.routes.cache",
                        require_disk_cache_encryption,
                    )
                    .map_err(|source| ConfigError::RouteSection {
                        vhost: vhost.name.clone(),
                        route: route.name.clone(),
                        section: "cache",
                        source: Box::new(source),
                    })?;
                }
            }
        }

        Ok(())
    }

    fn has_tls_listener_fallback_certificate(&self) -> bool {
        if !self.tls.certificates.is_empty() {
            return true;
        }

        let Some(default_vhost) = &self.server.default_vhost else {
            return false;
        };

        self.vhosts.iter().any(|vhost| {
            &vhost.name == default_vhost
                && vhost.tls.enabled
                && (vhost.tls.certificate.is_some() || self.vhost_has_managed_acme_source(vhost))
        })
    }

    #[cfg(feature = "acme")]
    fn vhost_has_managed_acme_source(&self, vhost: &VhostConfig) -> bool {
        self.tls.acme.enabled && self.tls.acme.storage.is_some() && vhost.tls.acme.enabled
    }

    #[cfg(not(feature = "acme"))]
    fn vhost_has_managed_acme_source(&self, _vhost: &VhostConfig) -> bool {
        false
    }

    fn validate_vhosts(&self) -> Result<(), ConfigError> {
        validate_config_list_len("vhosts", self.vhosts.len(), MAX_VHOSTS)?;

        let mut seen_names = std::collections::HashSet::new();
        let mut seen_hosts = std::collections::HashSet::new();

        for vhost in &self.vhosts {
            vhost.validate()?;
            vhost
                .validate_tls(&self.tls, self.vhost_has_shared_managed_acme_source(vhost))
                .map_err(|source| ConfigError::VhostSection {
                    vhost: vhost.name.clone(),
                    section: "tls",
                    source: Box::new(source),
                })?;

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

    #[cfg(feature = "acme")]
    fn vhost_has_shared_managed_acme_source(&self, vhost: &VhostConfig) -> bool {
        if !self.tls.acme.enabled || self.tls.acme.storage.is_none() {
            return false;
        }
        if vhost.tls.certificate.is_some() || vhost.tls.acme.enabled {
            return false;
        }
        let hosts = vhost
            .hosts
            .iter()
            .filter(|host| !host.starts_with("*."))
            .filter_map(|host| normalize_host(host))
            .collect::<Vec<_>>();
        if hosts.is_empty() {
            return false;
        }

        self.vhosts.iter().any(|candidate| {
            candidate.name != vhost.name
                && candidate.tls.enabled
                && candidate.tls.acme.enabled
                && managed_acme_domains_for_vhost(candidate)
                    .is_some_and(|domains| hosts.iter().all(|host| domains.contains(host)))
        })
    }

    #[cfg(not(feature = "acme"))]
    fn vhost_has_shared_managed_acme_source(&self, _vhost: &VhostConfig) -> bool {
        false
    }
}

#[cfg(feature = "acme")]
fn managed_acme_domains_for_vhost(
    vhost: &VhostConfig,
) -> Option<std::collections::HashSet<String>> {
    let domains = if vhost.tls.acme.domains.is_empty() {
        &vhost.hosts
    } else {
        &vhost.tls.acme.domains
    };
    let domains = domains
        .iter()
        .filter(|domain| !domain.starts_with("*."))
        .filter_map(|domain| normalize_host(domain))
        .collect::<std::collections::HashSet<_>>();
    (!domains.is_empty()).then_some(domains)
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigFragment {
    #[serde(default)]
    include_conf_d: bool,
    #[serde(default)]
    server: Option<ServerConfigFragment>,
    #[serde(default)]
    admin: Option<AdminConfig>,
    #[serde(default)]
    metrics: Option<MetricsConfig>,
    #[serde(default)]
    tracing: Option<TracingConfig>,
    #[serde(default)]
    logging: Option<LoggingConfig>,
    #[serde(default)]
    headers: Option<HeaderPolicyConfig>,
    #[serde(default)]
    tls: Option<TlsConfigFragment>,
    #[serde(default)]
    proxy: Option<ProxyConfig>,
    #[serde(default)]
    compression: Option<CompressionConfig>,
    #[serde(default)]
    cache: Option<CacheConfig>,
    #[serde(default)]
    cache_purger: Option<CachePurgerConfig>,
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
        toml::from_str(&raw).map_err(|source| ConfigLoadError::Parse {
            path: path.to_path_buf(),
            source,
        })
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
        if let Some(metrics) = &mut self.metrics {
            metrics.resolve_relative_paths(base_dir);
        }
        if let Some(tracing) = &mut self.tracing {
            tracing.resolve_relative_paths(base_dir);
        }
        if let Some(logging) = &mut self.logging {
            logging.resolve_relative_paths(base_dir);
        }
        if let Some(proxy) = &mut self.proxy {
            proxy.resolve_relative_paths(base_dir);
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
    pub proxy_protocol: DownstreamProxyProtocol,
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
            limits: ServerLimitsConfig::default(),
            process: ServerProcessConfig::default(),
            https_redirect: HttpsRedirectConfig::default(),
            host_routing: HostRoutingConfig::default(),
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
        if let Some(proxy_protocol) = fragment.proxy_protocol {
            self.proxy_protocol = proxy_protocol;
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

    fn validate_with_runtime_path_validation(
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
    proxy_protocol: Option<DownstreamProxyProtocol>,
    #[serde(default)]
    limits: Option<ServerLimitsConfig>,
    #[serde(default)]
    process: Option<ServerProcessConfig>,
    #[serde(default)]
    https_redirect: Option<HttpsRedirectConfig>,
    #[serde(default)]
    host_routing: Option<HostRoutingConfig>,
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
    pub transport: AdminTransportConfig,
    #[serde(default)]
    pub health: AdminHealthConfig,
    #[serde(default)]
    pub auth_throttle: AdminAuthThrottleConfig,
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
            transport: AdminTransportConfig::default(),
            health: AdminHealthConfig::default(),
            auth_throttle: AdminAuthThrottleConfig::default(),
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
        self.auth_throttle.validate()?;
        self.self_healing.validate()?;

        if !self.enabled {
            return Ok(());
        }

        if self.require_loopback && !listen.ip().is_loopback() {
            return Err(ConfigError::AdminListenNotLoopback {
                address: self.listen.clone(),
            });
        }
        if !listen.ip().is_loopback()
            && self.transport.mode != AdminRemoteTransportMode::TrustedTlsTerminator
        {
            return Err(ConfigError::RemoteAdminRequiresSecureTransport {
                address: self.listen.clone(),
            });
        }
        if self.health.unauthenticated && !listen.ip().is_loopback() {
            return Err(ConfigError::UnauthenticatedAdminHealthNotLoopback {
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

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminTransportConfig {
    #[serde(default)]
    pub mode: AdminRemoteTransportMode,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminRemoteTransportMode {
    #[default]
    LocalOnly,
    TrustedTlsTerminator,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminHealthConfig {
    #[serde(default)]
    pub unauthenticated: bool,
    #[serde(default)]
    pub response: AdminHealthResponseMode,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminHealthResponseMode {
    Minimal,
    #[default]
    Status,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminAuthThrottleConfig {
    #[serde(default = "default_admin_auth_throttle_enabled")]
    pub enabled: bool,
    #[serde(default = "default_admin_auth_throttle_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_admin_auth_throttle_per_source_failures")]
    pub per_source_failures: usize,
    #[serde(default = "default_admin_auth_throttle_global_failures")]
    pub global_failures: usize,
    #[serde(default = "default_admin_auth_throttle_base_lockout_secs")]
    pub base_lockout_secs: u64,
    #[serde(default = "default_admin_auth_throttle_max_lockout_secs")]
    pub max_lockout_secs: u64,
    #[serde(default = "default_admin_auth_throttle_max_sources")]
    pub max_sources: usize,
}

impl Default for AdminAuthThrottleConfig {
    fn default() -> Self {
        Self {
            enabled: default_admin_auth_throttle_enabled(),
            window_secs: default_admin_auth_throttle_window_secs(),
            per_source_failures: default_admin_auth_throttle_per_source_failures(),
            global_failures: default_admin_auth_throttle_global_failures(),
            base_lockout_secs: default_admin_auth_throttle_base_lockout_secs(),
            max_lockout_secs: default_admin_auth_throttle_max_lockout_secs(),
            max_sources: default_admin_auth_throttle_max_sources(),
        }
    }
}

impl AdminAuthThrottleConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.window_secs == 0 {
            return Err(ConfigError::InvalidAdminAuthThrottle {
                field: "admin.auth_throttle.window_secs",
            });
        }
        if self.per_source_failures == 0 {
            return Err(ConfigError::InvalidAdminAuthThrottle {
                field: "admin.auth_throttle.per_source_failures",
            });
        }
        if self.global_failures == 0 {
            return Err(ConfigError::InvalidAdminAuthThrottle {
                field: "admin.auth_throttle.global_failures",
            });
        }
        if self.base_lockout_secs == 0 {
            return Err(ConfigError::InvalidAdminAuthThrottle {
                field: "admin.auth_throttle.base_lockout_secs",
            });
        }
        if self.max_lockout_secs < self.base_lockout_secs {
            return Err(ConfigError::InvalidAdminAuthThrottle {
                field: "admin.auth_throttle.max_lockout_secs",
            });
        }
        if self.max_sources == 0 {
            return Err(ConfigError::InvalidAdminAuthThrottle {
                field: "admin.auth_throttle.max_sources",
            });
        }

        Ok(())
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
    #[serde(default)]
    pub otlp: MetricsOtlpExportConfig,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_metrics_listen(),
            require_loopback: default_metrics_require_loopback(),
            otlp: MetricsOtlpExportConfig::default(),
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
        if !self.enabled && self.otlp.enabled {
            return Err(ConfigError::InvalidMetricsPolicy {
                field: "metrics.otlp.enabled",
                reason: "OTLP metrics export requires metrics.enabled = true",
            });
        }
        self.otlp.validate()?;

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsOtlpExportConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_otlp_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_metrics_otlp_service_name")]
    pub service_name: String,
    #[serde(default = "default_metrics_otlp_interval_secs")]
    pub interval_secs: u64,
    #[serde(default = "default_metrics_otlp_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub tls_ca_cert_path: Option<PathBuf>,
}

impl Default for MetricsOtlpExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_metrics_otlp_endpoint(),
            service_name: default_metrics_otlp_service_name(),
            interval_secs: default_metrics_otlp_interval_secs(),
            timeout_secs: default_metrics_otlp_timeout_secs(),
            tls_ca_cert_path: None,
        }
    }
}

impl MetricsConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        self.otlp.resolve_relative_paths(base_dir);
    }
}

impl MetricsOtlpExportConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.tls_ca_cert_path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
    }
}

impl MetricsOtlpExportConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        #[cfg(not(feature = "metrics-otlp"))]
        return Err(ConfigError::MetricsOtlpExportNotCompiled);

        #[cfg(feature = "metrics-otlp")]
        {
            if !valid_http_otlp_endpoint(&self.endpoint) {
                return Err(ConfigError::InvalidMetricsPolicy {
                    field: "metrics.otlp.endpoint",
                    reason: "OTLP metrics export requires an http://host[:port]/path or https://host[:port]/path endpoint without query, fragment, or credentials",
                });
            }
            warn_plaintext_remote_otlp_endpoint("metrics.otlp.endpoint", &self.endpoint);
            validate_otlp_ca_cert_path(
                "metrics.otlp.tls_ca_cert_path",
                self.tls_ca_cert_path.as_deref(),
            )
            .map_err(|reason| ConfigError::InvalidMetricsPolicy {
                field: "metrics.otlp.tls_ca_cert_path",
                reason,
            })?;
            if !valid_service_name(&self.service_name) {
                return Err(ConfigError::InvalidMetricsPolicy {
                    field: "metrics.otlp.service_name",
                    reason: "service name must be 1..=128 visible ASCII bytes without control characters",
                });
            }
            if self.interval_secs == 0 || self.interval_secs > 3600 {
                return Err(ConfigError::InvalidMetricsPolicy {
                    field: "metrics.otlp.interval_secs",
                    reason: "interval must be between 1 and 3600 seconds",
                });
            }
            if self.timeout_secs == 0 || self.timeout_secs > 60 {
                return Err(ConfigError::InvalidMetricsPolicy {
                    field: "metrics.otlp.timeout_secs",
                    reason: "timeout must be between 1 and 60 seconds",
                });
            }
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TracingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: TracingMode,
    #[serde(default = "default_true")]
    pub traceparent: bool,
    #[serde(default = "default_true")]
    pub log_trace_id: bool,
    #[serde(default)]
    pub otlp: OtlpTraceExportConfig,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: TracingMode::default(),
            traceparent: true,
            log_trace_id: true,
            otlp: OtlpTraceExportConfig::default(),
        }
    }
}

impl TracingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        #[cfg(not(feature = "otel-tracing"))]
        if self.enabled {
            return Err(ConfigError::TracingNotCompiled);
        }

        #[cfg(feature = "privacy-mode")]
        if self.enabled {
            return Err(ConfigError::PrivacyModeTracing);
        }

        if self.enabled && self.mode == TracingMode::Off {
            return Err(ConfigError::InvalidTracingPolicy {
                field: "tracing.mode",
                reason: "tracing.enabled requires tracing.mode other than off",
            });
        }
        if !self.enabled && self.otlp.enabled {
            return Err(ConfigError::InvalidTracingPolicy {
                field: "tracing.otlp.enabled",
                reason: "OTLP trace export requires tracing.enabled = true",
            });
        }
        if !self.enabled {
            return Ok(());
        }
        if !self.traceparent && self.mode == TracingMode::PropagateOnly {
            return Err(ConfigError::InvalidTracingPolicy {
                field: "tracing.traceparent",
                reason: "propagate_only mode requires traceparent propagation",
            });
        }
        self.otlp.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TracingMode {
    Off,
    #[default]
    PropagateOnly,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OtlpTraceExportConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_otlp_trace_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_otlp_service_name")]
    pub service_name: String,
    #[serde(default = "default_otlp_queue_size")]
    pub queue_size: usize,
    #[serde(default = "default_otlp_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub tls_ca_cert_path: Option<PathBuf>,
}

impl Default for OtlpTraceExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_otlp_trace_endpoint(),
            service_name: default_otlp_service_name(),
            queue_size: default_otlp_queue_size(),
            timeout_secs: default_otlp_timeout_secs(),
            tls_ca_cert_path: None,
        }
    }
}

impl TracingConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        self.otlp.resolve_relative_paths(base_dir);
    }
}

impl OtlpTraceExportConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.tls_ca_cert_path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
    }
}

impl OtlpTraceExportConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        #[cfg(not(feature = "otel-otlp"))]
        return Err(ConfigError::OtlpTraceExportNotCompiled);

        #[cfg(feature = "otel-otlp")]
        {
            if !valid_http_otlp_endpoint(&self.endpoint) {
                return Err(ConfigError::InvalidTracingPolicy {
                    field: "tracing.otlp.endpoint",
                    reason: "OTLP trace export requires an http://host[:port]/path or https://host[:port]/path endpoint without query, fragment, or credentials",
                });
            }
            warn_plaintext_remote_otlp_endpoint("tracing.otlp.endpoint", &self.endpoint);
            validate_otlp_ca_cert_path(
                "tracing.otlp.tls_ca_cert_path",
                self.tls_ca_cert_path.as_deref(),
            )
            .map_err(|reason| ConfigError::InvalidTracingPolicy {
                field: "tracing.otlp.tls_ca_cert_path",
                reason,
            })?;
            if !valid_service_name(&self.service_name) {
                return Err(ConfigError::InvalidTracingPolicy {
                    field: "tracing.otlp.service_name",
                    reason: "service name must be 1..=128 visible ASCII bytes without control characters",
                });
            }
            if self.queue_size == 0 || self.queue_size > 1_000_000 {
                return Err(ConfigError::InvalidTracingPolicy {
                    field: "tracing.otlp.queue_size",
                    reason: "queue size must be between 1 and 1,000,000",
                });
            }
            if self.timeout_secs == 0 || self.timeout_secs > 60 {
                return Err(ConfigError::InvalidTracingPolicy {
                    field: "tracing.otlp.timeout_secs",
                    reason: "timeout must be between 1 and 60 seconds",
                });
            }
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePurgerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_purger_interval_secs")]
    pub interval_secs: u64,
    #[serde(default = "default_cache_purger_limit")]
    pub limit: usize,
    #[serde(default = "default_cache_purger_batches")]
    pub batches: usize,
}

impl Default for CachePurgerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: default_cache_purger_interval_secs(),
            limit: default_cache_purger_limit(),
            batches: default_cache_purger_batches(),
        }
    }
}

impl CachePurgerConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled {
            #[cfg(not(feature = "cache"))]
            return Err(ConfigError::CachePurgerNotCompiled);
        }

        if self.interval_secs == 0 || self.interval_secs > 86_400 {
            return Err(ConfigError::InvalidCachePurgerPolicy {
                field: "cache_purger.interval_secs",
                reason: "interval must be between 1 and 86400 seconds",
            });
        }
        if self.limit == 0 || self.limit > 100_000 {
            return Err(ConfigError::InvalidCachePurgerPolicy {
                field: "cache_purger.limit",
                reason: "limit must be between 1 and 100000 indexed entries",
            });
        }
        if self.batches == 0 || self.batches > 100 {
            return Err(ConfigError::InvalidCachePurgerPolicy {
                field: "cache_purger.batches",
                reason: "batches must be between 1 and 100",
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
        validate_non_world_writable_parent("logging.file.path", self.path.as_deref())?;
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
    pub include_client_ip: bool,
    #[serde(default = "default_true")]
    pub include_path: bool,
    #[serde(default = "default_true")]
    pub include_route: bool,
    #[serde(default = "default_true")]
    pub include_upstream: bool,
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
            include_client_ip: true,
            include_path: true,
            include_route: true,
            include_upstream: true,
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

const MAX_HEADER_MUTATION_NAMES: usize = 128;
const MAX_HEADER_APPEND_VALUES: usize = 32;
const MAX_RESPONSE_HEADER_REWRITE_RULES: usize = 32;

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
    pub x_real_ip: Option<bool>,
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
    pub x_real_ip: bool,
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
            x_real_ip: false,
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
        if let Some(enabled) = overlay.x_real_ip {
            self.x_real_ip = enabled;
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
    pub hsts: Option<ResponseHstsConfig>,
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
    #[serde(default)]
    pub rewrite: ResponseHeaderRewriteConfig,
}

impl Default for ResponseHeaderPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strict_transport_security: None,
            hsts: None,
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
            rewrite: ResponseHeaderRewriteConfig::default(),
        }
    }
}

impl ResponseHeaderPolicyConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_optional_header_value(
            "headers.response.strict_transport_security",
            self.strict_transport_security.as_deref(),
        )?;
        if self.strict_transport_security.is_some() && self.hsts.is_some() {
            return Err(ConfigError::InvalidResponseHeaderValue {
                field: "headers.response.hsts",
            });
        }
        if let Some(hsts) = &self.hsts {
            hsts.validate("headers.response.hsts")?;
        }
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
        self.rewrite.validate("headers.response.rewrite")?;

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
        if let Some(value) = &overlay.hsts {
            self.hsts = value.clone();
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
        self.rewrite.merge(&overlay.rewrite);
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeaderRewriteConfig {
    #[serde(default)]
    pub location: Vec<ResponseHeaderRewriteRuleConfig>,
    #[serde(default)]
    pub refresh: Vec<ResponseHeaderRewriteRuleConfig>,
    #[serde(default)]
    pub cookie_domain: Vec<ResponseHeaderRewriteRuleConfig>,
    #[serde(default)]
    pub cookie_path: Vec<ResponseHeaderRewriteRuleConfig>,
}

impl ResponseHeaderRewriteConfig {
    fn validate(&self, field: &'static str) -> Result<(), ConfigError> {
        validate_response_header_rewrite_rules(field, "location", &self.location)?;
        validate_response_header_rewrite_rules(field, "refresh", &self.refresh)?;
        validate_cookie_domain_rewrite_rules(field, &self.cookie_domain)?;
        validate_cookie_path_rewrite_rules(field, &self.cookie_path)
    }

    fn merge(&mut self, overlay: &Self) {
        self.location.extend(overlay.location.iter().cloned());
        self.refresh.extend(overlay.refresh.iter().cloned());
        self.cookie_domain
            .extend(overlay.cookie_domain.iter().cloned());
        self.cookie_path.extend(overlay.cookie_path.iter().cloned());
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeaderRewriteRuleConfig {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHstsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_hsts_max_age_secs")]
    pub max_age_secs: u64,
    #[serde(default)]
    pub include_subdomains: bool,
    #[serde(default)]
    pub preload: bool,
}

impl Default for ResponseHstsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_age_secs: default_hsts_max_age_secs(),
            include_subdomains: false,
            preload: false,
        }
    }
}

impl ResponseHstsConfig {
    fn validate(&self, field: &'static str) -> Result<(), ConfigError> {
        if self.enabled && self.max_age_secs == 0 {
            return Err(ConfigError::InvalidResponseHeaderValue { field });
        }
        Ok(())
    }

    pub fn header_value(&self) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let mut value = format!("max-age={}", self.max_age_secs);
        if self.include_subdomains {
            value.push_str("; includeSubDomains");
        }
        if self.preload {
            value.push_str("; preload");
        }
        Some(value)
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
    pub hsts: Option<Option<ResponseHstsConfig>>,
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
    #[serde(default)]
    pub rewrite: ResponseHeaderRewriteConfig,
}

impl ResponseHeaderPolicyOverlayConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_optional_header_value(
            "vhosts.headers.response.strict_transport_security",
            self.strict_transport_security
                .as_ref()
                .and_then(Option::as_deref),
        )?;
        if self.strict_transport_security.is_some() && self.hsts.is_some() {
            return Err(ConfigError::InvalidResponseHeaderValue {
                field: "vhosts.headers.response.hsts",
            });
        }
        if let Some(Some(hsts)) = &self.hsts {
            hsts.validate("vhosts.headers.response.hsts")?;
        }
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
        validate_header_mutations("vhosts.headers.response", &unset, &set, &self.append)?;
        self.rewrite.validate("vhosts.headers.response.rewrite")
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

    fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(values) => values.len(),
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

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
    pub profile: TlsPolicyProfile,
    #[serde(default)]
    pub min_protocol: Option<TlsProtocolVersion>,
    #[serde(default)]
    pub alpn: TlsAlpnPolicy,
    #[serde(default)]
    pub curve_preferences: Vec<TlsCurvePreference>,
    #[serde(default)]
    pub cipher_suites: Vec<TlsCipherSuite>,
    #[serde(default)]
    pub client_auth: TlsClientAuthConfig,
    #[serde(default)]
    pub certificates: Vec<StaticCertificateConfig>,
    #[serde(default)]
    pub fips: TlsFipsConfig,
    #[serde(default)]
    pub iso19790: TlsIso19790Config,
    #[serde(default)]
    pub acme: AcmeConfig,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TlsConfigFragment {
    enabled: Option<bool>,
    backend: Option<TlsBackend>,
    profile: Option<TlsPolicyProfile>,
    min_protocol: Option<TlsProtocolVersion>,
    alpn: Option<TlsAlpnPolicy>,
    curve_preferences: Option<Vec<TlsCurvePreference>>,
    cipher_suites: Option<Vec<TlsCipherSuite>>,
    client_auth: Option<TlsClientAuthConfigFragment>,
    certificates: Option<Vec<StaticCertificateConfig>>,
    fips: Option<TlsFipsConfigFragment>,
    iso19790: Option<TlsIso19790ConfigFragment>,
    acme: Option<AcmeConfigFragment>,
}

impl TlsConfig {
    fn merge(&mut self, fragment: TlsConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(backend) = fragment.backend {
            self.backend = backend;
        }
        if let Some(profile) = fragment.profile {
            self.profile = profile;
        }
        if let Some(min_protocol) = fragment.min_protocol {
            self.min_protocol = Some(min_protocol);
        }
        if let Some(alpn) = fragment.alpn {
            self.alpn = alpn;
        }
        if let Some(curve_preferences) = fragment.curve_preferences {
            self.curve_preferences = curve_preferences;
        }
        if let Some(cipher_suites) = fragment.cipher_suites {
            self.cipher_suites = cipher_suites;
        }
        if let Some(client_auth) = fragment.client_auth {
            self.client_auth.merge(client_auth);
        }
        if let Some(certificates) = fragment.certificates {
            self.certificates = certificates;
        }
        if let Some(fips) = fragment.fips {
            self.fips.merge(fips);
        }
        if let Some(iso19790) = fragment.iso19790 {
            self.iso19790.merge(iso19790);
        }
        if let Some(acme) = fragment.acme {
            self.acme.merge(acme);
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        validate_config_list_len(
            "tls.curve_preferences",
            self.curve_preferences.len(),
            MAX_TLS_CURVE_PREFERENCES,
        )?;
        validate_config_list_len(
            "tls.cipher_suites",
            self.cipher_suites.len(),
            MAX_TLS_CIPHER_SUITES,
        )?;
        validate_config_list_len(
            "tls.certificates",
            self.certificates.len(),
            MAX_TLS_CERTIFICATES,
        )?;

        let effective_min_protocol = self.effective_min_protocol();
        if self.profile == TlsPolicyProfile::Modern
            && effective_min_protocol != TlsProtocolVersion::Tls13
        {
            return Err(ConfigError::InvalidTlsPolicy {
                field: "tls.min_protocol",
                reason: "tls.profile = \"modern\" requires min_protocol = \"tls1.3\"",
            });
        }
        if effective_min_protocol == TlsProtocolVersion::Tls13
            && !self.cipher_suites.is_empty()
            && self.cipher_suites.iter().any(|cipher| cipher.is_tls12())
        {
            return Err(ConfigError::InvalidTlsPolicy {
                field: "tls.cipher_suites",
                reason: "TLS 1.2 cipher suites cannot be used when min_protocol = \"tls1.3\"",
            });
        }
        if self.backend == TlsBackend::S2n {
            if effective_min_protocol == TlsProtocolVersion::Tls13 {
                return Err(ConfigError::InvalidTlsPolicy {
                    field: "tls.min_protocol",
                    reason: "the s2n backend does not expose a Fluxheim-controlled TLS 1.3-only listener policy yet",
                });
            }
            if self.effective_alpn() != TlsAlpnPolicy::Http1AndHttp2 {
                return Err(ConfigError::InvalidTlsPolicy {
                    field: "tls.alpn",
                    reason: "the s2n backend currently supports only \"http1-and-http2\" in Fluxheim listener policy",
                });
            }
            if !self.curve_preferences.is_empty() {
                return Err(ConfigError::InvalidTlsPolicy {
                    field: "tls.curve_preferences",
                    reason: "the s2n backend does not expose Fluxheim-controlled listener curve preferences yet",
                });
            }
            if !self.cipher_suites.is_empty() {
                return Err(ConfigError::InvalidTlsPolicy {
                    field: "tls.cipher_suites",
                    reason: "the s2n backend does not expose Fluxheim-controlled listener cipher allow-lists yet",
                });
            }
            if self.client_auth.mode != TlsClientAuthMode::Off {
                return Err(ConfigError::InvalidTlsPolicy {
                    field: "tls.client_auth.mode",
                    reason: "the s2n backend has mTLS primitives, but Fluxheim does not yet expose panic-free CA bundle loading for listener client auth; use rustls, OpenSSL, or BoringSSL for client certificate authentication",
                });
            }
        }
        if self.backend == TlsBackend::Boringssl
            && self.cipher_suites.iter().any(|cipher| !cipher.is_tls12())
        {
            return Err(ConfigError::InvalidTlsPolicy {
                field: "tls.cipher_suites",
                reason: "the BoringSSL backend does not expose Fluxheim-controlled TLS 1.3 cipher-suite allow-lists; omit TLS 1.3 cipher_suites or use the OpenSSL/rustls backend",
            });
        }
        #[cfg(not(feature = "tls-rustls-fips"))]
        if self.backend == TlsBackend::Rustls
            && self
                .effective_curve_preferences()
                .contains(&TlsCurvePreference::X25519MlKem768)
        {
            return Err(ConfigError::InvalidTlsPolicy {
                field: "tls.curve_preferences",
                reason: "X25519MLKEM768 needs a rustls crypto provider with post-quantum key exchange support; the default rustls backend currently uses ring",
            });
        }
        self.validate_fips_policy()?;
        self.client_auth.validate()?;

        for certificate in &self.certificates {
            certificate.validate("tls.certificates")?;
        }
        self.acme.validate()
    }

    fn validate_fips_policy(&self) -> Result<(), ConfigError> {
        let compliance_mode = self.compliance_mode();
        if !compliance_mode.required() {
            return Ok(());
        }
        if self
            .effective_curve_preferences()
            .iter()
            .any(|curve| !curve.is_fips_approved())
        {
            return Err(ConfigError::InvalidTlsPolicy {
                field: "tls.curve_preferences",
                reason: compliance_mode.non_nist_group_reason(),
            });
        }
        if self
            .effective_cipher_suites()
            .iter()
            .any(|cipher| !cipher.is_fips_approved())
        {
            return Err(ConfigError::InvalidTlsPolicy {
                field: "tls.cipher_suites",
                reason: compliance_mode.non_approved_cipher_reason(),
            });
        }

        #[cfg(not(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips")))]
        {
            Err(ConfigError::InvalidTlsPolicy {
                field: compliance_mode.config_field(),
                reason: compliance_mode.missing_feature_reason(),
            })
        }

        #[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
        {
            #[cfg(feature = "tls-rustls-fips")]
            if self.backend == TlsBackend::Rustls {
                return Ok(());
            }
            #[cfg(feature = "tls-openssl-fips")]
            if self.backend == TlsBackend::Openssl {
                return Ok(());
            }
            Err(ConfigError::InvalidTlsPolicy {
                field: "tls.backend",
                reason: compliance_mode.backend_reason(),
            })
        }
    }

    pub fn compliance_mode(&self) -> TlsComplianceMode {
        match (self.fips.required, self.iso19790.required) {
            (false, false) => TlsComplianceMode::None,
            (true, false) => TlsComplianceMode::Fips1403,
            (false, true) => TlsComplianceMode::Iso19790,
            (true, true) => TlsComplianceMode::Fips1403AndIso19790,
        }
    }

    pub fn effective_min_protocol(&self) -> TlsProtocolVersion {
        self.min_protocol
            .unwrap_or_else(|| self.profile.default_min_protocol())
    }

    pub fn effective_alpn(&self) -> TlsAlpnPolicy {
        self.alpn
    }

    pub fn effective_curve_preferences(&self) -> Vec<TlsCurvePreference> {
        if self.curve_preferences.is_empty() {
            self.profile.default_curve_preferences()
        } else {
            self.curve_preferences.clone()
        }
    }

    pub fn effective_cipher_suites(&self) -> Vec<TlsCipherSuite> {
        if self.cipher_suites.is_empty() {
            self.profile.default_cipher_suites()
        } else {
            self.cipher_suites.clone()
        }
    }

    fn acme_issuer_exists(&self, issuer: &str) -> bool {
        self.acme
            .issuers
            .iter()
            .any(|candidate| candidate.name == issuer)
    }
}

impl TlsConfigFragment {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(client_auth) = &mut self.client_auth {
            client_auth.resolve_relative_paths(base_dir);
        }
        if let Some(certificates) = &mut self.certificates {
            for certificate in certificates {
                certificate.resolve_relative_paths(base_dir);
            }
        }
        if let Some(acme) = &mut self.acme {
            acme.resolve_relative_paths(base_dir);
        }
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsClientAuthConfig {
    #[serde(default)]
    pub mode: TlsClientAuthMode,
    #[serde(default)]
    pub ca_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TlsClientAuthConfigFragment {
    mode: Option<TlsClientAuthMode>,
    ca_path: Option<PathBuf>,
}

impl TlsClientAuthConfig {
    fn merge(&mut self, fragment: TlsClientAuthConfigFragment) {
        if let Some(mode) = fragment.mode {
            self.mode = mode;
        }
        if let Some(ca_path) = fragment.ca_path {
            self.ca_path = Some(ca_path);
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        match (self.mode, &self.ca_path) {
            (TlsClientAuthMode::Off, None) => return Ok(()),
            (TlsClientAuthMode::Optional | TlsClientAuthMode::Required, None) => {
                return Err(ConfigError::InvalidTlsPolicy {
                    field: "tls.client_auth.ca_path",
                    reason: "tls.client_auth.mode requires a client CA bundle path",
                });
            }
            (_, Some(_)) => {}
        }
        let Some(ca_path) = &self.ca_path else {
            return Ok(());
        };
        if ca_path.as_os_str().is_empty() {
            return Err(ConfigError::InvalidTlsPolicy {
                field: "tls.client_auth.ca_path",
                reason: "tls.client_auth.ca_path cannot be empty",
            });
        }
        validate_path("tls.client_auth.ca_path", Some(ca_path))?;
        validate_non_world_writable_parent("tls.client_auth.ca_path", Some(ca_path))?;
        Ok(())
    }
}

impl TlsClientAuthConfigFragment {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.ca_path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsClientAuthMode {
    #[default]
    Off,
    Optional,
    Required,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFipsConfig {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub require_disk_cache_encryption: bool,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsIso19790Config {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub require_disk_cache_encryption: bool,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TlsFipsConfigFragment {
    required: Option<bool>,
    require_disk_cache_encryption: Option<bool>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TlsIso19790ConfigFragment {
    required: Option<bool>,
    require_disk_cache_encryption: Option<bool>,
}

impl TlsFipsConfig {
    fn merge(&mut self, fragment: TlsFipsConfigFragment) {
        if let Some(required) = fragment.required {
            self.required = required;
        }
        if let Some(require_disk_cache_encryption) = fragment.require_disk_cache_encryption {
            self.require_disk_cache_encryption = require_disk_cache_encryption;
        }
    }
}

impl TlsIso19790Config {
    fn merge(&mut self, fragment: TlsIso19790ConfigFragment) {
        if let Some(required) = fragment.required {
            self.required = required;
        }
        if let Some(require_disk_cache_encryption) = fragment.require_disk_cache_encryption {
            self.require_disk_cache_encryption = require_disk_cache_encryption;
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TlsComplianceMode {
    None,
    Fips1403,
    Iso19790,
    Fips1403AndIso19790,
}

impl TlsComplianceMode {
    pub fn required(self) -> bool {
        !matches!(self, Self::None)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Fips1403 => "FIPS 140-3",
            Self::Iso19790 => "ISO/IEC 19790",
            Self::Fips1403AndIso19790 => "FIPS 140-3 / ISO/IEC 19790",
        }
    }

    pub fn config_field(self) -> &'static str {
        match self {
            Self::None | Self::Fips1403 | Self::Fips1403AndIso19790 => "tls.fips.required",
            Self::Iso19790 => "tls.iso19790.required",
        }
    }

    fn non_nist_group_reason(self) -> &'static str {
        match self {
            Self::Iso19790 => {
                "tls.iso19790.required rejects non-NIST or unproven hybrid groups; use CurveP256 and/or CurveP384 until a validated provider supports more"
            }
            Self::None | Self::Fips1403 | Self::Fips1403AndIso19790 => {
                "tls.fips.required rejects non-NIST or unproven hybrid groups; use CurveP256 and/or CurveP384 until a validated provider supports more"
            }
        }
    }

    fn non_approved_cipher_reason(self) -> &'static str {
        match self {
            Self::Iso19790 => {
                "tls.iso19790.required rejects non-approved cipher suites such as ChaCha20; use AES-GCM/SHA-2 suites from the selected validated provider"
            }
            Self::None | Self::Fips1403 | Self::Fips1403AndIso19790 => {
                "tls.fips.required rejects non-FIPS cipher suites such as ChaCha20; use AES-GCM/SHA-2 suites from the selected validated provider"
            }
        }
    }

    #[cfg(not(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips")))]
    fn missing_feature_reason(self) -> &'static str {
        match self {
            Self::Iso19790 => {
                "ISO/IEC 19790-required mode requires a FIPS/ISO-capable TLS backend feature such as tls-rustls-fips, tls-openssl-fips, or tls-openssl-iso19790; see docs/fips.md"
            }
            Self::None | Self::Fips1403 | Self::Fips1403AndIso19790 => {
                "FIPS-required mode requires a FIPS-capable TLS backend feature such as tls-rustls-fips or tls-openssl-fips; see docs/fips.md"
            }
        }
    }

    #[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
    fn backend_reason(self) -> &'static str {
        match self {
            Self::Iso19790 => {
                "tls.iso19790.required requires a configured backend supported by this FIPS/ISO-capable build"
            }
            Self::None | Self::Fips1403 | Self::Fips1403AndIso19790 => {
                "tls.fips.required requires a configured backend supported by this FIPS-capable build"
            }
        }
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

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsPolicyProfile {
    Modern,
    #[default]
    Intermediate,
    Compat,
}

impl TlsPolicyProfile {
    const fn default_min_protocol(self) -> TlsProtocolVersion {
        match self {
            Self::Modern => TlsProtocolVersion::Tls13,
            Self::Intermediate | Self::Compat => TlsProtocolVersion::Tls12,
        }
    }

    fn default_curve_preferences(self) -> Vec<TlsCurvePreference> {
        vec![
            TlsCurvePreference::X25519,
            TlsCurvePreference::P256,
            TlsCurvePreference::P384,
        ]
    }

    fn default_cipher_suites(self) -> Vec<TlsCipherSuite> {
        match self {
            Self::Modern => vec![
                TlsCipherSuite::Tls13Aes256GcmSha384,
                TlsCipherSuite::Tls13Chacha20Poly1305Sha256,
                TlsCipherSuite::Tls13Aes128GcmSha256,
            ],
            Self::Intermediate | Self::Compat => vec![
                TlsCipherSuite::Tls13Aes256GcmSha384,
                TlsCipherSuite::Tls13Chacha20Poly1305Sha256,
                TlsCipherSuite::Tls13Aes128GcmSha256,
                TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256,
                TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256,
                TlsCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384,
                TlsCipherSuite::TlsEcdheRsaWithAes256GcmSha384,
                TlsCipherSuite::TlsEcdheEcdsaWithChacha20Poly1305Sha256,
                TlsCipherSuite::TlsEcdheRsaWithChacha20Poly1305Sha256,
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub enum TlsProtocolVersion {
    #[serde(rename = "tls1.2", alias = "TLS1.2", alias = "VersionTLS12")]
    Tls12,
    #[serde(rename = "tls1.3", alias = "TLS1.3", alias = "VersionTLS13")]
    Tls13,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsAlpnPolicy {
    Http1,
    Http2,
    #[default]
    Http1AndHttp2,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub enum TlsCurvePreference {
    #[serde(rename = "x25519", alias = "X25519")]
    X25519,
    #[serde(rename = "p256", alias = "P-256", alias = "CurveP256")]
    P256,
    #[serde(rename = "p384", alias = "P-384", alias = "CurveP384")]
    P384,
    #[serde(
        rename = "x25519-mlkem768",
        alias = "X25519MLKEM768",
        alias = "X25519-MLKEM768"
    )]
    X25519MlKem768,
}

impl TlsCurvePreference {
    const fn is_fips_approved(self) -> bool {
        matches!(self, Self::P256 | Self::P384)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub enum TlsCipherSuite {
    #[serde(rename = "TLS_AES_256_GCM_SHA384")]
    Tls13Aes256GcmSha384,
    #[serde(rename = "TLS_CHACHA20_POLY1305_SHA256")]
    Tls13Chacha20Poly1305Sha256,
    #[serde(rename = "TLS_AES_128_GCM_SHA256")]
    Tls13Aes128GcmSha256,
    #[serde(rename = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")]
    TlsEcdheEcdsaWithAes128GcmSha256,
    #[serde(rename = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")]
    TlsEcdheRsaWithAes128GcmSha256,
    #[serde(rename = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")]
    TlsEcdheEcdsaWithAes256GcmSha384,
    #[serde(rename = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")]
    TlsEcdheRsaWithAes256GcmSha384,
    #[serde(rename = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256")]
    TlsEcdheEcdsaWithChacha20Poly1305Sha256,
    #[serde(rename = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")]
    TlsEcdheRsaWithChacha20Poly1305Sha256,
}

impl TlsCipherSuite {
    const fn is_tls12(&self) -> bool {
        !matches!(
            self,
            Self::Tls13Aes256GcmSha384
                | Self::Tls13Chacha20Poly1305Sha256
                | Self::Tls13Aes128GcmSha256
        )
    }

    const fn is_fips_approved(self) -> bool {
        matches!(
            self,
            Self::Tls13Aes256GcmSha384
                | Self::Tls13Aes128GcmSha256
                | Self::TlsEcdheEcdsaWithAes128GcmSha256
                | Self::TlsEcdheRsaWithAes128GcmSha256
                | Self::TlsEcdheEcdsaWithAes256GcmSha384
                | Self::TlsEcdheRsaWithAes256GcmSha384
        )
    }
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
    pub automation: AcmeAutomationMode,
    #[serde(default)]
    pub renewal: AcmeRenewalConfig,
    #[serde(default = "default_acme_issuers")]
    pub issuers: Vec<AcmeIssuerConfig>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AcmeConfigFragment {
    enabled: Option<bool>,
    storage: Option<PathBuf>,
    contact_email: Option<String>,
    default_issuer: Option<String>,
    challenge: Option<AcmeChallenge>,
    automation: Option<AcmeAutomationMode>,
    renewal: Option<AcmeRenewalConfigFragment>,
    issuers: Option<Vec<AcmeIssuerConfig>>,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            storage: None,
            contact_email: default_acme_contact_email(),
            default_issuer: default_acme_default_issuer(),
            challenge: AcmeChallenge::default(),
            automation: AcmeAutomationMode::default(),
            renewal: AcmeRenewalConfig::default(),
            issuers: default_acme_issuers(),
        }
    }
}

impl AcmeConfig {
    fn merge(&mut self, fragment: AcmeConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(storage) = fragment.storage {
            self.storage = Some(storage);
        }
        if let Some(contact_email) = fragment.contact_email {
            self.contact_email = Some(contact_email);
        }
        if let Some(default_issuer) = fragment.default_issuer {
            self.default_issuer = default_issuer;
        }
        if let Some(challenge) = fragment.challenge {
            self.challenge = challenge;
        }
        if let Some(automation) = fragment.automation {
            self.automation = automation;
        }
        if let Some(renewal) = fragment.renewal {
            self.renewal.merge(renewal);
        }
        if let Some(issuers) = fragment.issuers {
            self.issuers = issuers;
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        validate_config_list_len("tls.acme.issuers", self.issuers.len(), MAX_ACME_ISSUERS)?;

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

impl AcmeConfigFragment {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(storage) = &mut self.storage
            && storage.is_relative()
        {
            *storage = base_dir.join(&storage);
        }
        if let Some(issuers) = &mut self.issuers {
            for issuer in issuers {
                issuer.resolve_relative_paths(base_dir);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum AcmeChallenge {
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    #[default]
    #[serde(rename = "http-01")]
    Http01,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum AcmeAutomationMode {
    #[default]
    #[serde(rename = "background")]
    Background,
    #[serde(rename = "external")]
    External,
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

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AcmeRenewalConfigFragment {
    enabled: Option<bool>,
    renew_before_secs: Option<u64>,
    renew_after: Option<toml::value::Datetime>,
    check_interval_secs: Option<u64>,
    retry_initial_secs: Option<u64>,
    retry_max_secs: Option<u64>,
    reload_after_renewal: Option<bool>,
    zero_downtime_reload: Option<bool>,
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
    fn merge(&mut self, fragment: AcmeRenewalConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(renew_before_secs) = fragment.renew_before_secs {
            self.renew_before_secs = renew_before_secs;
        }
        if let Some(renew_after) = fragment.renew_after {
            self.renew_after = Some(renew_after);
        }
        if let Some(check_interval_secs) = fragment.check_interval_secs {
            self.check_interval_secs = check_interval_secs;
        }
        if let Some(retry_initial_secs) = fragment.retry_initial_secs {
            self.retry_initial_secs = retry_initial_secs;
        }
        if let Some(retry_max_secs) = fragment.retry_max_secs {
            self.retry_max_secs = retry_max_secs;
        }
        if let Some(reload_after_renewal) = fragment.reload_after_renewal {
            self.reload_after_renewal = reload_after_renewal;
        }
        if let Some(zero_downtime_reload) = fragment.zero_downtime_reload {
            self.zero_downtime_reload = zero_downtime_reload;
        }
    }

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
    pub key_id_credential: Option<String>,
    #[serde(default)]
    pub hmac_key_env: Option<String>,
    #[serde(default)]
    pub hmac_key_file: Option<PathBuf>,
    #[serde(default)]
    pub hmac_key_credential: Option<String>,
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
            self.key_id_credential.as_deref(),
        )?;
        validate_secret_source(
            issuer,
            "hmac_key",
            self.hmac_key_env.as_deref(),
            self.hmac_key_file.as_ref(),
            self.hmac_key_credential.as_deref(),
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
    pub upstream_weights: Vec<usize>,
    #[serde(default)]
    pub backup_upstreams: Vec<String>,
    #[serde(default)]
    pub drain_upstreams: Vec<String>,
    #[serde(default)]
    pub upstream_tls: bool,
    #[serde(default)]
    pub upstream_sni: Option<String>,
    #[serde(default = "default_true")]
    pub upstream_verify_cert: bool,
    #[serde(default = "default_true")]
    pub upstream_verify_hostname: bool,
    #[serde(default)]
    pub upstream_alternative_cn: Option<String>,
    #[serde(default)]
    pub upstream_ca_path: Option<PathBuf>,
    #[serde(default)]
    pub upstream_client_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub upstream_client_key_path: Option<PathBuf>,
    #[serde(default)]
    pub upstream_proxy_protocol: UpstreamProxyProtocol,
    #[serde(default)]
    pub upstream_http_version: UpstreamHttpVersion,
    #[serde(default)]
    pub upstream_h2_max_streams: Option<usize>,
    #[serde(default)]
    pub upstream_h2_ping_interval_secs: Option<u64>,
    #[serde(default)]
    pub connect_timeout_secs: Option<u64>,
    #[serde(default)]
    pub upstream_total_connection_timeout_secs: Option<u64>,
    #[serde(default)]
    pub upstream_idle_timeout_secs: Option<u64>,
    #[serde(default)]
    pub upstream_tcp_keepalive_idle_secs: Option<u64>,
    #[serde(default)]
    pub upstream_tcp_keepalive_interval_secs: Option<u64>,
    #[serde(default)]
    pub upstream_tcp_keepalive_count: Option<usize>,
    #[serde(default)]
    pub upstream_tcp_user_timeout_ms: Option<u64>,
    #[serde(default)]
    pub upstream_tcp_recv_buffer_bytes: Option<ByteSize>,
    #[serde(default)]
    pub upstream_dscp: Option<u8>,
    #[serde(default)]
    pub upstream_tcp_fast_open: bool,
    #[serde(default)]
    pub read_timeout_secs: Option<u64>,
    #[serde(default)]
    pub send_timeout_secs: Option<u64>,
    #[serde(default)]
    pub downstream_write_timeout_secs: Option<u64>,
    #[serde(default)]
    pub downstream_min_send_rate_bytes_per_sec: Option<usize>,
    #[serde(default)]
    pub error_pages: Vec<ProxyErrorPageConfig>,
    #[serde(default)]
    pub load_balance: LoadBalanceConfig,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamProxyProtocol {
    #[default]
    Off,
    V1,
    V2,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamHttpVersion {
    #[default]
    Http1,
    Http2,
    Http1AndHttp2,
}

const MAX_PROXY_UPSTREAMS: usize = 64;
const MAX_PROXY_UPSTREAM_WEIGHT: usize = 1000;
const MAX_PROXY_UPSTREAM_TOTAL_WEIGHT: usize = u16::MAX as usize;
const MAX_PROXY_ERROR_PAGES: usize = 64;
const MAX_PROXY_UPSTREAM_H2_STREAMS: usize = 1024;
const MAX_PROXY_UPSTREAM_TCP_KEEPALIVE_COUNT: usize = 128;
const MAX_PROXY_UPSTREAM_TCP_RECV_BUFFER_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PROXY_UPSTREAM_DSCP: u8 = 63;

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            upstream: Some(default_upstream()),
            upstreams: Vec::new(),
            upstream_weights: Vec::new(),
            backup_upstreams: Vec::new(),
            drain_upstreams: Vec::new(),
            upstream_tls: false,
            upstream_sni: None,
            upstream_verify_cert: true,
            upstream_verify_hostname: true,
            upstream_alternative_cn: None,
            upstream_ca_path: None,
            upstream_client_cert_path: None,
            upstream_client_key_path: None,
            upstream_proxy_protocol: UpstreamProxyProtocol::Off,
            upstream_http_version: UpstreamHttpVersion::Http1,
            upstream_h2_max_streams: None,
            upstream_h2_ping_interval_secs: None,
            connect_timeout_secs: None,
            upstream_total_connection_timeout_secs: None,
            upstream_idle_timeout_secs: None,
            upstream_tcp_keepalive_idle_secs: None,
            upstream_tcp_keepalive_interval_secs: None,
            upstream_tcp_keepalive_count: None,
            upstream_tcp_user_timeout_ms: None,
            upstream_tcp_recv_buffer_bytes: None,
            upstream_dscp: None,
            upstream_tcp_fast_open: false,
            read_timeout_secs: None,
            send_timeout_secs: None,
            downstream_write_timeout_secs: None,
            downstream_min_send_rate_bytes_per_sec: None,
            error_pages: Vec::new(),
            load_balance: LoadBalanceConfig::default(),
        }
    }
}

impl ProxyConfig {
    pub fn disabled() -> Self {
        Self {
            upstream: None,
            ..Self::default()
        }
    }

    pub fn has_configured_upstream(&self) -> bool {
        self.upstream.is_some() || !self.upstreams.is_empty()
    }

    pub fn configured_primary_upstream(&self) -> Option<&str> {
        self.upstreams
            .first()
            .map(String::as_str)
            .or(self.upstream.as_deref())
    }

    pub fn primary_upstream(&self) -> &str {
        self.configured_primary_upstream()
            .unwrap_or(DEFAULT_UPSTREAM)
    }

    pub fn upstream_sni(&self) -> String {
        self.upstream_sni
            .clone()
            .unwrap_or_else(|| upstream_host(self.primary_upstream()).unwrap_or_default())
    }

    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.upstream_ca_path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
        if let Some(path) = &mut self.upstream_client_cert_path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
        if let Some(path) = &mut self.upstream_client_key_path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
        for error_page in &mut self.error_pages {
            error_page.resolve_relative_paths(base_dir);
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.upstream.is_some() && !self.upstreams.is_empty() {
            return Err(ConfigError::ConflictingProxyUpstreams);
        }
        if self.upstreams.len() > MAX_PROXY_UPSTREAMS {
            return Err(ConfigError::TooManyProxyUpstreams {
                max: MAX_PROXY_UPSTREAMS,
            });
        }
        if !self.upstream_weights.is_empty() {
            if self.upstream.is_some() || self.upstream_weights.len() != self.upstreams.len() {
                return Err(ConfigError::InvalidProxyUpstreamWeights {
                    reason: "upstream_weights must match proxy.upstreams and cannot be used with proxy.upstream",
                });
            }
            let mut total_weight = 0usize;
            for weight in &self.upstream_weights {
                if *weight == 0 {
                    return Err(ConfigError::InvalidProxyUpstreamWeights {
                        reason: "weights must be greater than zero",
                    });
                }
                if *weight > MAX_PROXY_UPSTREAM_WEIGHT {
                    return Err(ConfigError::InvalidProxyUpstreamWeights {
                        reason: "each weight must be at most 1000",
                    });
                }
                total_weight = total_weight.saturating_add(*weight);
            }
            if total_weight > MAX_PROXY_UPSTREAM_TOTAL_WEIGHT {
                return Err(ConfigError::InvalidProxyUpstreamWeights {
                    reason: "total upstream weight is too large",
                });
            }
        }
        if self.error_pages.len() > MAX_PROXY_ERROR_PAGES {
            return Err(ConfigError::TooManyProxyErrorPages {
                max: MAX_PROXY_ERROR_PAGES,
            });
        }

        if let Some(upstream) = &self.upstream
            && !valid_authority(upstream)
        {
            return Err(ConfigError::InvalidUpstream {
                address: upstream.clone(),
            });
        }

        let mut seen_upstreams = std::collections::HashSet::new();
        for upstream in &self.upstreams {
            if !valid_authority(upstream) {
                return Err(ConfigError::InvalidUpstream {
                    address: upstream.clone(),
                });
            }
            if !seen_upstreams.insert(upstream.to_ascii_lowercase()) {
                return Err(ConfigError::DuplicateProxyUpstream {
                    upstream: upstream.clone(),
                });
            }
        }
        self.validate_upstream_policy()?;

        if let Some(sni) = &self.upstream_sni
            && sni.trim().is_empty()
        {
            return Err(ConfigError::EmptyUpstreamSni);
        }
        if !self.upstream_verify_cert && self.upstream_verify_hostname {
            return Err(ConfigError::InvalidProxyTlsPolicy {
                reason: "upstream_verify_hostname must be false when upstream_verify_cert = false",
            });
        }
        if !self.upstream_tls
            && (self.upstream_ca_path.is_some()
                || self.upstream_client_cert_path.is_some()
                || self.upstream_client_key_path.is_some())
        {
            return Err(ConfigError::InvalidProxyTlsPolicy {
                reason: "upstream TLS trust roots or client certificates require upstream_tls = true",
            });
        }
        if !self.upstream_verify_cert && self.upstream_ca_path.is_some() {
            return Err(ConfigError::InvalidProxyTlsPolicy {
                reason: "upstream_ca_path requires upstream_verify_cert = true",
            });
        }
        match (
            &self.upstream_client_cert_path,
            &self.upstream_client_key_path,
        ) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => {
                return Err(ConfigError::InvalidProxyTlsPolicy {
                    reason: "upstream_client_cert_path and upstream_client_key_path must be configured together",
                });
            }
        }
        for (field, path) in [
            ("proxy.upstream_ca_path", self.upstream_ca_path.as_deref()),
            (
                "proxy.upstream_client_cert_path",
                self.upstream_client_cert_path.as_deref(),
            ),
            (
                "proxy.upstream_client_key_path",
                self.upstream_client_key_path.as_deref(),
            ),
        ] {
            validate_path(field, path)?;
            validate_non_world_writable_parent(field, path)?;
        }
        if self.upstream_proxy_protocol != UpstreamProxyProtocol::Off
            && !self.has_configured_upstream()
        {
            return Err(ConfigError::InvalidProxyTlsPolicy {
                reason: "upstream_proxy_protocol requires a configured proxy upstream",
            });
        }
        if self.upstream_http_version != UpstreamHttpVersion::Http1
            && !self.has_configured_upstream()
        {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_http_version",
                reason: "requires a configured proxy upstream",
            });
        }
        if self.upstream_h2_max_streams.is_some()
            && self.upstream_http_version == UpstreamHttpVersion::Http1
        {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_h2_max_streams",
                reason: "requires upstream_http_version to allow http2",
            });
        }
        if self.upstream_h2_ping_interval_secs.is_some()
            && self.upstream_http_version == UpstreamHttpVersion::Http1
        {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_h2_ping_interval_secs",
                reason: "requires upstream_http_version to allow http2",
            });
        }
        if self
            .upstream_h2_max_streams
            .is_some_and(|streams| streams == 0 || streams > MAX_PROXY_UPSTREAM_H2_STREAMS)
        {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_h2_max_streams",
                reason: "must be between 1 and 1024",
            });
        }
        #[cfg(all(
            feature = "tls-s2n",
            not(any(
                feature = "tls-rustls-backend",
                feature = "tls-openssl",
                feature = "tls-boringssl"
            ))
        ))]
        if self.upstream_ca_path.is_some()
            || self.upstream_client_cert_path.is_some()
            || self.upstream_client_key_path.is_some()
        {
            return Err(ConfigError::InvalidProxyTlsPolicy {
                reason: "the s2n backend does not yet expose panic-free upstream CA and client certificate loading in Fluxheim; use rustls, OpenSSL, or BoringSSL for upstream mTLS and custom trust roots",
            });
        }
        if let Some(alternative_cn) = &self.upstream_alternative_cn {
            if alternative_cn.contains('*') {
                return Err(ConfigError::InvalidProxyTlsPolicy {
                    reason: "upstream_alternative_cn must not contain wildcards",
                });
            }
            if normalize_host(alternative_cn).is_none() {
                return Err(ConfigError::InvalidProxyTlsPolicy {
                    reason: "upstream_alternative_cn must be a valid hostname",
                });
            }
        }

        validate_optional_timeout_secs("proxy.connect_timeout_secs", self.connect_timeout_secs)?;
        validate_optional_timeout_secs(
            "proxy.upstream_total_connection_timeout_secs",
            self.upstream_total_connection_timeout_secs,
        )?;
        validate_optional_timeout_secs(
            "proxy.upstream_idle_timeout_secs",
            self.upstream_idle_timeout_secs,
        )?;
        validate_optional_timeout_secs(
            "proxy.upstream_tcp_keepalive_idle_secs",
            self.upstream_tcp_keepalive_idle_secs,
        )?;
        validate_optional_timeout_secs(
            "proxy.upstream_tcp_keepalive_interval_secs",
            self.upstream_tcp_keepalive_interval_secs,
        )?;
        if self.upstream_tcp_keepalive_count.is_some()
            || self.upstream_tcp_keepalive_idle_secs.is_some()
            || self.upstream_tcp_keepalive_interval_secs.is_some()
            || self.upstream_tcp_user_timeout_ms.is_some()
        {
            match (
                self.upstream_tcp_keepalive_idle_secs,
                self.upstream_tcp_keepalive_interval_secs,
                self.upstream_tcp_keepalive_count,
            ) {
                (Some(_), Some(_), Some(count))
                    if (1..=MAX_PROXY_UPSTREAM_TCP_KEEPALIVE_COUNT).contains(&count) => {}
                _ => {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstream_tcp_keepalive_count",
                        reason: "TCP keepalive requires idle_secs, interval_secs, and count, with count between 1 and 128",
                    });
                }
            }
        }
        if self
            .upstream_tcp_user_timeout_ms
            .is_some_and(|milliseconds| milliseconds == 0)
        {
            return Err(ConfigError::InvalidProxyTimeout {
                field: "proxy.upstream_tcp_user_timeout_ms",
            });
        }
        if self.upstream_tcp_recv_buffer_bytes.is_some_and(|bytes| {
            bytes.as_u64() == 0 || bytes.as_u64() > MAX_PROXY_UPSTREAM_TCP_RECV_BUFFER_BYTES
        }) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_tcp_recv_buffer_bytes",
                reason: "must be between 1 byte and 256MiB",
            });
        }
        if self
            .upstream_dscp
            .is_some_and(|dscp| dscp > MAX_PROXY_UPSTREAM_DSCP)
        {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_dscp",
                reason: "must be a DSCP value between 0 and 63",
            });
        }
        validate_optional_timeout_secs("proxy.read_timeout_secs", self.read_timeout_secs)?;
        validate_optional_timeout_secs("proxy.send_timeout_secs", self.send_timeout_secs)?;
        validate_optional_timeout_secs(
            "proxy.upstream_h2_ping_interval_secs",
            self.upstream_h2_ping_interval_secs,
        )?;
        validate_optional_timeout_secs(
            "proxy.downstream_write_timeout_secs",
            self.downstream_write_timeout_secs,
        )?;
        if self
            .downstream_min_send_rate_bytes_per_sec
            .is_some_and(|rate| rate == 0)
        {
            return Err(ConfigError::InvalidProxyTimeout {
                field: "proxy.downstream_min_send_rate_bytes_per_sec",
            });
        }

        let mut statuses = std::collections::HashSet::new();
        for error_page in &self.error_pages {
            error_page.validate()?;
            if !statuses.insert(error_page.status) {
                return Err(ConfigError::DuplicateProxyErrorPageStatus {
                    status: error_page.status,
                });
            }
        }

        self.load_balance.validate()?;
        Ok(())
    }

    fn validate_upstream_policy(&self) -> Result<(), ConfigError> {
        if self.backup_upstreams.is_empty() && self.drain_upstreams.is_empty() {
            return Ok(());
        }
        if self.upstreams.len() < 2 || self.upstream.is_some() {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstreams",
                reason: "backup_upstreams and drain_upstreams require proxy.upstreams with at least two entries",
            });
        }
        let configured = self
            .upstreams
            .iter()
            .map(|upstream| upstream.to_ascii_lowercase())
            .collect::<HashSet<_>>();
        let backup = validate_proxy_upstream_subset(
            "proxy.backup_upstreams",
            &self.backup_upstreams,
            &configured,
        )?;
        let drain = validate_proxy_upstream_subset(
            "proxy.drain_upstreams",
            &self.drain_upstreams,
            &configured,
        )?;
        if !backup.is_disjoint(&drain) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.backup_upstreams",
                reason: "backup_upstreams and drain_upstreams must not overlap",
            });
        }
        let primary_count = configured.len().saturating_sub(backup.len() + drain.len());
        if primary_count == 0 {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstreams",
                reason: "at least one upstream must remain primary and not drained",
            });
        }
        Ok(())
    }
}

fn validate_proxy_upstream_subset(
    field: &'static str,
    values: &[String],
    configured: &HashSet<String>,
) -> Result<HashSet<String>, ConfigError> {
    let mut seen = HashSet::new();
    for upstream in values {
        if !valid_authority(upstream) {
            return Err(ConfigError::InvalidUpstream {
                address: upstream.clone(),
            });
        }
        let normalized = upstream.to_ascii_lowercase();
        if !configured.contains(&normalized) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field,
                reason: "each entry must also be present in proxy.upstreams",
            });
        }
        if !seen.insert(normalized) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field,
                reason: "duplicate upstream policy entries are not allowed",
            });
        }
    }
    Ok(seen)
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyErrorPageConfig {
    pub status: u16,
    pub path: String,
    #[serde(default)]
    pub web: WebConfig,
}

impl ProxyErrorPageConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        self.web.resolve_relative_paths(base_dir);
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !(400..=599).contains(&self.status) {
            return Err(ConfigError::InvalidProxyErrorPageStatus {
                status: self.status,
            });
        }
        validate_route_path("proxy.error_pages.path", &self.path, false).map_err(|_| {
            ConfigError::InvalidProxyErrorPagePath {
                path: self.path.clone(),
            }
        })?;
        self.web.validate()?;
        if !self.web.enabled() {
            return Err(ConfigError::MissingProxyErrorPageRoot {
                status: self.status,
            });
        }
        Ok(())
    }
}

const DEFAULT_COMPRESSION_MIN_BYTES: u64 = 1024;
const DEFAULT_COMPRESSION_MAX_INPUT_BYTES: u64 = 1024 * 1024;
const DEFAULT_COMPRESSION_MAX_OUTPUT_BYTES: u64 = 2 * 1024 * 1024;
const DEFAULT_COMPRESSION_GZIP_LEVEL: u32 = 4;
const DEFAULT_COMPRESSION_ZSTD_LEVEL: i32 = 3;
const DEFAULT_COMPRESSION_BROTLI_QUALITY: u32 = 4;
const MAX_COMPRESSION_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_COMPRESSION_OUTPUT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_compression_gzip_enabled")]
    pub gzip: bool,
    #[serde(default)]
    pub zstd: bool,
    #[serde(default)]
    pub brotli: bool,
    #[serde(default = "default_compression_min_bytes")]
    pub min_bytes: ByteSize,
    #[serde(default = "default_compression_max_input_bytes")]
    pub max_input_bytes: ByteSize,
    #[serde(default = "default_compression_max_output_bytes")]
    pub max_output_bytes: ByteSize,
    #[serde(default = "default_compression_gzip_level")]
    pub gzip_level: u32,
    #[serde(default = "default_compression_zstd_level")]
    pub zstd_level: i32,
    #[serde(default = "default_compression_brotli_quality")]
    pub brotli_quality: u32,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            gzip: true,
            zstd: false,
            brotli: false,
            min_bytes: default_compression_min_bytes(),
            max_input_bytes: default_compression_max_input_bytes(),
            max_output_bytes: default_compression_max_output_bytes(),
            gzip_level: default_compression_gzip_level(),
            zstd_level: default_compression_zstd_level(),
            brotli_quality: default_compression_brotli_quality(),
        }
    }
}

impl CompressionConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if !self.gzip && !self.zstd && !self.brotli {
            return Err(ConfigError::InvalidCompressionPolicy {
                field: "compression",
            });
        }
        if self.min_bytes.as_u64() == 0 || self.min_bytes.as_u64() > self.max_input_bytes.as_u64() {
            return Err(ConfigError::InvalidCompressionPolicy {
                field: "compression.min_bytes",
            });
        }
        if self.max_input_bytes.as_u64() == 0
            || self.max_input_bytes.as_u64() > MAX_COMPRESSION_INPUT_BYTES
        {
            return Err(ConfigError::InvalidCompressionPolicy {
                field: "compression.max_input_bytes",
            });
        }
        if self.max_output_bytes.as_u64() < self.min_bytes.as_u64()
            || self.max_output_bytes.as_u64() > MAX_COMPRESSION_OUTPUT_BYTES
        {
            return Err(ConfigError::InvalidCompressionPolicy {
                field: "compression.max_output_bytes",
            });
        }
        if self.gzip_level > 9 {
            return Err(ConfigError::InvalidCompressionPolicy {
                field: "compression.gzip_level",
            });
        }
        if !(1..=19).contains(&self.zstd_level) {
            return Err(ConfigError::InvalidCompressionPolicy {
                field: "compression.zstd_level",
            });
        }
        if self.brotli_quality > 11 {
            return Err(ConfigError::InvalidCompressionPolicy {
                field: "compression.brotli_quality",
            });
        }
        Ok(())
    }
}

fn default_compression_min_bytes() -> ByteSize {
    ByteSize::from_bytes(DEFAULT_COMPRESSION_MIN_BYTES)
}

fn default_compression_gzip_enabled() -> bool {
    true
}

fn default_compression_max_input_bytes() -> ByteSize {
    ByteSize::from_bytes(DEFAULT_COMPRESSION_MAX_INPUT_BYTES)
}

fn default_compression_max_output_bytes() -> ByteSize {
    ByteSize::from_bytes(DEFAULT_COMPRESSION_MAX_OUTPUT_BYTES)
}

fn default_compression_gzip_level() -> u32 {
    DEFAULT_COMPRESSION_GZIP_LEVEL
}

fn default_compression_zstd_level() -> i32 {
    DEFAULT_COMPRESSION_ZSTD_LEVEL
}

fn default_compression_brotli_quality() -> u32 {
    DEFAULT_COMPRESSION_BROTLI_QUALITY
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceConfig {
    #[serde(default)]
    pub selection: LoadBalanceSelection,
    #[serde(default)]
    pub hash_header: Option<String>,
    #[serde(default)]
    pub hash_cookie: Option<String>,
    #[serde(default = "default_lb_max_iterations")]
    pub max_iterations: usize,
    #[serde(default)]
    pub health_check: LoadBalanceHealthCheckConfig,
    #[serde(default)]
    pub passive_health: LoadBalancePassiveHealthConfig,
    #[serde(default)]
    pub slow_start: LoadBalanceSlowStartConfig,
    #[serde(default)]
    pub retry: LoadBalanceRetryConfig,
}

impl Default for LoadBalanceConfig {
    fn default() -> Self {
        Self {
            selection: LoadBalanceSelection::default(),
            hash_header: None,
            hash_cookie: None,
            max_iterations: default_lb_max_iterations(),
            health_check: LoadBalanceHealthCheckConfig::default(),
            passive_health: LoadBalancePassiveHealthConfig::default(),
            slow_start: LoadBalanceSlowStartConfig::default(),
            retry: LoadBalanceRetryConfig::default(),
        }
    }
}

impl LoadBalanceConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.selection.requires_hash_header() {
            let Some(header) = self.hash_header.as_deref() else {
                return Err(ConfigError::InvalidLoadBalanceSelection {
                    reason: "header-hash selections require proxy.load_balance.hash_header",
                });
            };
            if !valid_http_header_name(header) {
                return Err(ConfigError::InvalidHeaderName {
                    field: "proxy.load_balance.hash_header",
                    name: header.to_owned(),
                });
            }
        } else if self.hash_header.is_some() {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.hash_header can only be used with header-hash selections",
            });
        }
        if self.selection.requires_hash_cookie() {
            let Some(cookie) = self.hash_cookie.as_deref() else {
                return Err(ConfigError::InvalidLoadBalanceSelection {
                    reason: "cookie-hash selections require proxy.load_balance.hash_cookie",
                });
            };
            if !valid_http_header_name(cookie) {
                return Err(ConfigError::InvalidLoadBalanceSelection {
                    reason: "proxy.load_balance.hash_cookie must be a valid cookie name",
                });
            }
        } else if self.hash_cookie.is_some() {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.hash_cookie can only be used with cookie-hash selections",
            });
        }
        if self.max_iterations == 0 {
            return Err(ConfigError::InvalidLoadBalanceMaxIterations);
        }

        self.health_check.validate()?;
        self.passive_health.validate()?;
        self.slow_start.validate()?;
        self.retry.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoadBalanceSelection {
    #[default]
    RoundRobin,
    LeastConnections,
    PowerOfTwo,
    SourceHash,
    UriHash,
    HeaderHash,
    CookieHash,
    ConsistentSourceHash,
    ConsistentUriHash,
    ConsistentHeaderHash,
    ConsistentCookieHash,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoadBalanceHealthCheckProtocol {
    #[default]
    Tcp,
    Http,
}

impl LoadBalanceSelection {
    fn requires_hash_header(self) -> bool {
        matches!(self, Self::HeaderHash | Self::ConsistentHeaderHash)
    }

    fn requires_hash_cookie(self) -> bool {
        matches!(self, Self::CookieHash | Self::ConsistentCookieHash)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceHealthCheckConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub protocol: LoadBalanceHealthCheckProtocol,
    #[serde(default = "default_lb_health_check_interval_secs")]
    pub interval_secs: u64,
    #[serde(default = "default_lb_health_check_threshold")]
    pub consecutive_success: usize,
    #[serde(default = "default_lb_health_check_threshold")]
    pub consecutive_failure: usize,
    #[serde(default)]
    pub parallel: bool,
    #[serde(default = "default_lb_health_check_path")]
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub expected_statuses: Vec<u16>,
    #[serde(default)]
    pub reuse_connection: bool,
    #[serde(default)]
    pub port_override: Option<u16>,
}

impl Default for LoadBalanceHealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            protocol: LoadBalanceHealthCheckProtocol::default(),
            interval_secs: default_lb_health_check_interval_secs(),
            consecutive_success: default_lb_health_check_threshold(),
            consecutive_failure: default_lb_health_check_threshold(),
            parallel: false,
            path: default_lb_health_check_path(),
            host: None,
            expected_statuses: Vec::new(),
            reuse_connection: false,
            port_override: None,
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
        if !valid_health_check_path(&self.path) {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.path",
            });
        }
        if let Some(host) = &self.host
            && !valid_health_check_host(host)
        {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.host",
            });
        }
        if self.expected_statuses.len() > 32 {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.expected_statuses",
            });
        }
        let mut seen_statuses = std::collections::HashSet::new();
        for status in &self.expected_statuses {
            if !(100..=599).contains(status) || !seen_statuses.insert(*status) {
                return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                    field: "proxy.load_balance.health_check.expected_statuses",
                });
            }
        }
        if self.port_override.is_some_and(|port| port == 0) {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.port_override",
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalancePassiveHealthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_lb_passive_consecutive_failure")]
    pub consecutive_failure: usize,
    #[serde(default = "default_lb_passive_ejection_secs")]
    pub ejection_secs: u64,
    #[serde(default)]
    pub failure_statuses: Vec<u16>,
    #[serde(default)]
    pub max_latency_ms: u64,
}

impl Default for LoadBalancePassiveHealthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            consecutive_failure: default_lb_passive_consecutive_failure(),
            ejection_secs: default_lb_passive_ejection_secs(),
            failure_statuses: Vec::new(),
            max_latency_ms: 0,
        }
    }
}

impl LoadBalancePassiveHealthConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.consecutive_failure == 0 || self.consecutive_failure > 1000 {
            return Err(ConfigError::InvalidLoadBalancePassiveHealth {
                field: "proxy.load_balance.passive_health.consecutive_failure",
            });
        }
        if self.ejection_secs == 0 || self.ejection_secs > 3600 {
            return Err(ConfigError::InvalidLoadBalancePassiveHealth {
                field: "proxy.load_balance.passive_health.ejection_secs",
            });
        }
        if self.max_latency_ms > 600_000 {
            return Err(ConfigError::InvalidLoadBalancePassiveHealth {
                field: "proxy.load_balance.passive_health.max_latency_ms",
            });
        }
        if self.failure_statuses.len() > 64
            || self
                .failure_statuses
                .iter()
                .any(|status| !(500..=599).contains(status))
        {
            return Err(ConfigError::InvalidLoadBalancePassiveHealth {
                field: "proxy.load_balance.passive_health.failure_statuses",
            });
        }
        Ok(())
    }
}

fn default_lb_passive_consecutive_failure() -> usize {
    3
}

fn default_lb_passive_ejection_secs() -> u64 {
    30
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceSlowStartConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_lb_slow_start_duration_secs")]
    pub duration_secs: u64,
}

impl Default for LoadBalanceSlowStartConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            duration_secs: default_lb_slow_start_duration_secs(),
        }
    }
}

impl LoadBalanceSlowStartConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.duration_secs == 0 || self.duration_secs > 3600 {
            return Err(ConfigError::InvalidLoadBalanceSlowStart {
                field: "proxy.load_balance.slow_start.duration_secs",
            });
        }
        Ok(())
    }
}

fn default_lb_slow_start_duration_secs() -> u64 {
    30
}

const MAX_LB_RETRIES: u8 = 10;
const MAX_LB_RETRY_METHODS: usize = 16;
const MAX_LB_RETRY_BUDGET_PER_WINDOW: u32 = 1_000_000;
const LB_SAFE_RETRY_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "TRACE"];

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceRetryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_lb_retry_max_retries")]
    pub max_retries: u8,
    #[serde(default = "default_lb_retry_methods")]
    pub methods: Vec<String>,
    #[serde(default)]
    pub budget_per_window: u32,
    #[serde(default = "default_lb_retry_budget_window_secs")]
    pub budget_window_secs: u64,
}

impl Default for LoadBalanceRetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_retries: default_lb_retry_max_retries(),
            methods: default_lb_retry_methods(),
            budget_per_window: 0,
            budget_window_secs: default_lb_retry_budget_window_secs(),
        }
    }
}

impl LoadBalanceRetryConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_retries > MAX_LB_RETRIES {
            return Err(ConfigError::InvalidLoadBalanceRetry {
                field: "proxy.load_balance.retry.max_retries",
            });
        }
        if self.methods.len() > MAX_LB_RETRY_METHODS {
            return Err(ConfigError::InvalidLoadBalanceRetry {
                field: "proxy.load_balance.retry.methods",
            });
        }
        if self.budget_per_window > MAX_LB_RETRY_BUDGET_PER_WINDOW {
            return Err(ConfigError::InvalidLoadBalanceRetry {
                field: "proxy.load_balance.retry.budget_per_window",
            });
        }
        if self.budget_window_secs == 0 || self.budget_window_secs > 3600 {
            return Err(ConfigError::InvalidLoadBalanceRetry {
                field: "proxy.load_balance.retry.budget_window_secs",
            });
        }
        let mut seen = HashSet::new();
        for method in &self.methods {
            if method.is_empty()
                || method.len() > 32
                || !method
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(ConfigError::InvalidLoadBalanceRetry {
                    field: "proxy.load_balance.retry.methods",
                });
            }
            if !seen.insert(method.clone())
                || !LB_SAFE_RETRY_METHODS
                    .iter()
                    .any(|safe_method| safe_method == method)
            {
                return Err(ConfigError::InvalidLoadBalanceRetry {
                    field: "proxy.load_balance.retry.methods",
                });
            }
        }
        Ok(())
    }
}

fn default_lb_retry_max_retries() -> u8 {
    1
}

fn default_lb_retry_methods() -> Vec<String> {
    vec!["GET".to_owned(), "HEAD".to_owned(), "OPTIONS".to_owned()]
}

fn default_lb_retry_budget_window_secs() -> u64 {
    1
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VhostConfig {
    pub name: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub max_request_body_bytes: Option<ByteSize>,
    #[serde(default)]
    pub access: AccessPolicyConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub concurrency: ConcurrencyLimitConfig,
    #[serde(default)]
    pub tls: VhostTlsConfig,
    #[serde(default)]
    pub acme_challenge: VhostAcmeChallengeConfig,
    #[serde(default)]
    pub redirect: VhostRedirectConfig,
    #[serde(default = "disabled_proxy_config")]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub compression: Option<CompressionConfig>,
    #[serde(default)]
    pub headers: VhostHeaderPolicyConfig,
    #[serde(default)]
    pub php: PhpConfig,
    #[serde(default)]
    pub web: WebConfig,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
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
        self.proxy.resolve_relative_paths(base_dir);
        self.cache.resolve_relative_paths(base_dir);
        self.php.resolve_relative_paths(base_dir);
        self.web.resolve_relative_paths(base_dir);
        for route in &mut self.routes {
            route.resolve_relative_paths(base_dir);
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.name.trim().is_empty() {
            return Err(ConfigError::EmptyVhostName);
        }
        if self.name.len() > MAX_VHOST_NAME_BYTES {
            return Err(ConfigError::InvalidConfigNameLength {
                field: "vhosts.name",
                max: MAX_VHOST_NAME_BYTES,
            });
        }

        if self.hosts.is_empty() {
            return Err(ConfigError::EmptyVhostHosts {
                vhost: self.name.clone(),
            });
        }
        validate_config_list_len(
            format!("vhost {:?}.hosts", self.name),
            self.hosts.len(),
            MAX_VHOST_HOSTS,
        )?;
        validate_config_list_len(
            format!("vhost {:?}.routes", self.name),
            self.routes.len(),
            MAX_VHOST_ROUTES,
        )?;

        self.proxy
            .validate()
            .map_err(|source| ConfigError::VhostSection {
                vhost: self.name.clone(),
                section: "proxy",
                source: Box::new(source),
            })?;
        self.acme_challenge.validate(&self.name)?;
        self.redirect.validate(&self.name)?;
        self.access
            .validate("vhosts.access")
            .map_err(|source| ConfigError::VhostSection {
                vhost: self.name.clone(),
                section: "access",
                source: Box::new(source),
            })?;
        self.rate_limit
            .validate("vhosts.rate_limit")
            .map_err(|source| ConfigError::VhostSection {
                vhost: self.name.clone(),
                section: "rate_limit",
                source: Box::new(source),
            })?;
        self.concurrency
            .validate("vhosts.concurrency")
            .map_err(|source| ConfigError::VhostSection {
                vhost: self.name.clone(),
                section: "concurrency",
                source: Box::new(source),
            })?;
        self.cache
            .validate("vhosts.cache")
            .map_err(|source| ConfigError::VhostSection {
                vhost: self.name.clone(),
                section: "cache",
                source: Box::new(source),
            })?;
        if let Some(compression) = &self.compression {
            compression
                .validate()
                .map_err(|source| ConfigError::VhostSection {
                    vhost: self.name.clone(),
                    section: "compression",
                    source: Box::new(source),
                })?;
        }
        self.headers
            .validate()
            .map_err(|source| ConfigError::VhostSection {
                vhost: self.name.clone(),
                section: "headers",
                source: Box::new(source),
            })?;
        self.php
            .validate("vhosts.php")
            .map_err(|source| ConfigError::VhostSection {
                vhost: self.name.clone(),
                section: "php",
                source: Box::new(source),
            })?;
        self.web
            .validate()
            .map_err(|source| ConfigError::VhostSection {
                vhost: self.name.clone(),
                section: "web",
                source: Box::new(source),
            })?;
        self.validate_routes()?;
        if matches!(self.max_request_body_bytes, Some(bytes) if bytes.as_u64() == 0) {
            return Err(ConfigError::InvalidVhostLimit {
                vhost: self.name.clone(),
                field: "max_request_body_bytes",
            });
        }

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

    fn validate_routes(&self) -> Result<(), ConfigError> {
        let mut fallback_seen = false;
        for route in &self.routes {
            route.validate(&self.name)?;
            if route.fallback {
                if fallback_seen {
                    return Err(ConfigError::DuplicateFallbackRoute {
                        vhost: self.name.clone(),
                    });
                }
                fallback_seen = true;
            }
        }
        if self.redirect.enabled && fallback_seen {
            return Err(ConfigError::VhostRedirectConflictsWithFallback {
                vhost: self.name.clone(),
            });
        }
        Ok(())
    }

    fn validate_tls(
        &self,
        global_tls: &TlsConfig,
        has_shared_certificate_source: bool,
    ) -> Result<(), ConfigError> {
        self.tls.validate(
            "vhosts.tls",
            &self.hosts,
            global_tls,
            has_shared_certificate_source,
        )
    }
}

const MAX_ACCESS_RULES: usize = 256;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessPolicyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

impl Default for AccessPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

impl AccessPolicyConfig {
    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        validate_access_rule_list(scope, "allow", &self.allow)?;
        validate_access_rule_list(scope, "deny", &self.deny)?;
        Ok(())
    }
}

fn validate_access_rule_list(
    scope: &'static str,
    field: &'static str,
    values: &[String],
) -> Result<(), ConfigError> {
    validate_config_list_len(format!("{scope}.{field}"), values.len(), MAX_ACCESS_RULES)?;

    let mut seen = BTreeSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed != value || !valid_ip_matcher(trimmed) {
            return Err(ConfigError::InvalidAccessRule {
                field: access_rule_field(scope, field),
                value: value.clone(),
            });
        }
        if !seen.insert(trimmed.to_ascii_lowercase()) {
            return Err(ConfigError::DuplicateAccessRule {
                field: access_rule_field(scope, field),
                value: value.clone(),
            });
        }
    }

    Ok(())
}

fn access_rule_field(scope: &'static str, field: &'static str) -> &'static str {
    match (scope, field) {
        ("vhosts.access", "allow") => "vhosts.access.allow",
        ("vhosts.access", "deny") => "vhosts.access.deny",
        ("vhosts.routes.access", "allow") => "vhosts.routes.access.allow",
        ("vhosts.routes.access", "deny") => "vhosts.routes.access.deny",
        _ => "access",
    }
}

const MAX_RATE_LIMIT_REQUESTS_PER_SECOND: u32 = 1_000_000;
const MAX_RATE_LIMIT_BURST: u32 = 1_000_000;
const MAX_RATE_LIMIT_TABLE_ENTRIES: usize = 1_000_000;
const MAX_RATE_LIMIT_ENTRY_TTL_SECS: u64 = 86_400;
const MAX_RATE_LIMIT_DELAY_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RateLimitMode {
    #[default]
    Nodelay,
    Delay,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub requests_per_second: u32,
    #[serde(default)]
    pub burst: u32,
    #[serde(default = "default_rate_limit_status")]
    pub status: u16,
    #[serde(default = "default_rate_limit_table_max_entries")]
    pub table_max_entries: usize,
    #[serde(default = "default_rate_limit_entry_ttl_secs")]
    pub entry_ttl_secs: u64,
    #[serde(default)]
    pub mode: RateLimitMode,
    #[serde(default = "default_rate_limit_max_delay_ms")]
    pub max_delay_ms: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_second: 0,
            burst: 0,
            status: default_rate_limit_status(),
            table_max_entries: default_rate_limit_table_max_entries(),
            entry_ttl_secs: default_rate_limit_entry_ttl_secs(),
            mode: RateLimitMode::Nodelay,
            max_delay_ms: default_rate_limit_max_delay_ms(),
        }
    }
}

impl RateLimitConfig {
    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.requests_per_second == 0
            || self.requests_per_second > MAX_RATE_LIMIT_REQUESTS_PER_SECOND
        {
            return Err(ConfigError::InvalidRateLimit {
                field: rate_limit_field(scope, "requests_per_second"),
            });
        }
        if self.burst > MAX_RATE_LIMIT_BURST {
            return Err(ConfigError::InvalidRateLimit {
                field: rate_limit_field(scope, "burst"),
            });
        }
        if !(400..=599).contains(&self.status) {
            return Err(ConfigError::InvalidRateLimit {
                field: rate_limit_field(scope, "status"),
            });
        }
        if self.table_max_entries == 0 || self.table_max_entries > MAX_RATE_LIMIT_TABLE_ENTRIES {
            return Err(ConfigError::InvalidRateLimit {
                field: rate_limit_field(scope, "table_max_entries"),
            });
        }
        if self.entry_ttl_secs == 0 || self.entry_ttl_secs > MAX_RATE_LIMIT_ENTRY_TTL_SECS {
            return Err(ConfigError::InvalidRateLimit {
                field: rate_limit_field(scope, "entry_ttl_secs"),
            });
        }
        if matches!(self.mode, RateLimitMode::Delay) && self.max_delay_ms == 0 {
            return Err(ConfigError::InvalidRateLimit {
                field: rate_limit_field(scope, "max_delay_ms"),
            });
        }
        if self.max_delay_ms > MAX_RATE_LIMIT_DELAY_MS {
            return Err(ConfigError::InvalidRateLimit {
                field: rate_limit_field(scope, "max_delay_ms"),
            });
        }

        Ok(())
    }
}

fn default_rate_limit_status() -> u16 {
    429
}

fn default_rate_limit_table_max_entries() -> usize {
    65_536
}

fn default_rate_limit_entry_ttl_secs() -> u64 {
    300
}

fn default_rate_limit_max_delay_ms() -> u64 {
    1000
}

fn rate_limit_field(scope: &'static str, field: &'static str) -> &'static str {
    match (scope, field) {
        ("vhosts.rate_limit", "requests_per_second") => "vhosts.rate_limit.requests_per_second",
        ("vhosts.rate_limit", "burst") => "vhosts.rate_limit.burst",
        ("vhosts.rate_limit", "status") => "vhosts.rate_limit.status",
        ("vhosts.rate_limit", "table_max_entries") => "vhosts.rate_limit.table_max_entries",
        ("vhosts.rate_limit", "entry_ttl_secs") => "vhosts.rate_limit.entry_ttl_secs",
        ("vhosts.rate_limit", "max_delay_ms") => "vhosts.rate_limit.max_delay_ms",
        ("vhosts.routes.rate_limit", "requests_per_second") => {
            "vhosts.routes.rate_limit.requests_per_second"
        }
        ("vhosts.routes.rate_limit", "burst") => "vhosts.routes.rate_limit.burst",
        ("vhosts.routes.rate_limit", "status") => "vhosts.routes.rate_limit.status",
        ("vhosts.routes.rate_limit", "table_max_entries") => {
            "vhosts.routes.rate_limit.table_max_entries"
        }
        ("vhosts.routes.rate_limit", "entry_ttl_secs") => "vhosts.routes.rate_limit.entry_ttl_secs",
        ("vhosts.routes.rate_limit", "max_delay_ms") => "vhosts.routes.rate_limit.max_delay_ms",
        _ => "rate_limit",
    }
}

const MAX_CONCURRENCY_LIMIT: usize = 1_000_000;
const MAX_CONCURRENCY_QUEUE_TIMEOUT_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConcurrencyLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub max_in_flight: usize,
    #[serde(default = "default_concurrency_limit_status")]
    pub status: u16,
    #[serde(default)]
    pub queue_timeout_ms: u64,
}

impl Default for ConcurrencyLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_in_flight: 0,
            status: default_concurrency_limit_status(),
            queue_timeout_ms: 0,
        }
    }
}

impl ConcurrencyLimitConfig {
    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.max_in_flight == 0 || self.max_in_flight > MAX_CONCURRENCY_LIMIT {
            return Err(ConfigError::InvalidConcurrencyLimit {
                field: concurrency_limit_field(scope, "max_in_flight"),
            });
        }
        if !(400..=599).contains(&self.status) {
            return Err(ConfigError::InvalidConcurrencyLimit {
                field: concurrency_limit_field(scope, "status"),
            });
        }
        if self.queue_timeout_ms > MAX_CONCURRENCY_QUEUE_TIMEOUT_MS {
            return Err(ConfigError::InvalidConcurrencyLimit {
                field: concurrency_limit_field(scope, "queue_timeout_ms"),
            });
        }

        Ok(())
    }
}

fn default_concurrency_limit_status() -> u16 {
    503
}

fn concurrency_limit_field(scope: &'static str, field: &'static str) -> &'static str {
    match (scope, field) {
        ("vhosts.concurrency", "max_in_flight") => "vhosts.concurrency.max_in_flight",
        ("vhosts.concurrency", "status") => "vhosts.concurrency.status",
        ("vhosts.concurrency", "queue_timeout_ms") => "vhosts.concurrency.queue_timeout_ms",
        ("vhosts.routes.concurrency", "max_in_flight") => "vhosts.routes.concurrency.max_in_flight",
        ("vhosts.routes.concurrency", "status") => "vhosts.routes.concurrency.status",
        ("vhosts.routes.concurrency", "queue_timeout_ms") => {
            "vhosts.routes.concurrency.queue_timeout_ms"
        }
        _ => "concurrency",
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub name: String,
    #[serde(default)]
    pub path_exact: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub fallback: bool,
    #[serde(default)]
    pub https_redirect_exempt: bool,
    #[serde(default)]
    pub strip_prefix: Option<String>,
    #[serde(default)]
    pub rewrite_prefix: Option<String>,
    #[serde(default)]
    pub max_request_body_bytes: Option<ByteSize>,
    #[serde(default)]
    pub access: AccessPolicyConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub concurrency: ConcurrencyLimitConfig,
    #[serde(default)]
    pub redirect: Option<RouteRedirectConfig>,
    #[serde(default)]
    pub proxy: Option<ProxyConfig>,
    #[serde(default)]
    pub web: Option<WebConfig>,
    #[serde(default)]
    pub php: Option<PhpConfig>,
    #[serde(default)]
    pub cache: Option<CacheConfig>,
    #[serde(default)]
    pub compression: Option<CompressionConfig>,
    #[serde(default)]
    pub headers: VhostHeaderPolicyConfig,
}

impl RouteConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(proxy) = &mut self.proxy {
            proxy.resolve_relative_paths(base_dir);
        }
        if let Some(web) = &mut self.web {
            web.resolve_relative_paths(base_dir);
        }
        if let Some(php) = &mut self.php {
            php.resolve_relative_paths(base_dir);
        }
        if let Some(cache) = &mut self.cache {
            cache.resolve_relative_paths(base_dir);
        }
    }

    fn validate(&self, vhost: &str) -> Result<(), ConfigError> {
        if self.name.trim().is_empty() {
            return Err(ConfigError::EmptyRouteName {
                vhost: vhost.to_owned(),
            });
        }
        if self.name.len() > MAX_ROUTE_NAME_BYTES {
            return Err(ConfigError::InvalidConfigNameLength {
                field: "vhosts.routes.name",
                max: MAX_ROUTE_NAME_BYTES,
            });
        }

        let matcher_count = usize::from(self.path_exact.is_some())
            + usize::from(self.path_prefix.is_some())
            + usize::from(self.fallback);
        if matcher_count != 1 {
            return Err(ConfigError::InvalidRouteMatcher {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
            });
        }

        if let Some(path) = &self.path_exact {
            validate_route_path("vhosts.routes.path_exact", path, false).map_err(|_| {
                ConfigError::InvalidRouteMatcher {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                }
            })?;
        }
        if let Some(path) = &self.path_prefix {
            validate_route_path("vhosts.routes.path_prefix", path, true).map_err(|_| {
                ConfigError::InvalidRouteMatcher {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                }
            })?;
        }
        if let Some(path) = &self.strip_prefix {
            validate_route_path("vhosts.routes.strip_prefix", path, true).map_err(|_| {
                ConfigError::InvalidRouteStripPrefix {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                }
            })?;
            let Some(prefix) = &self.path_prefix else {
                return Err(ConfigError::InvalidRouteStripPrefix {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                });
            };
            if !prefix.starts_with(path) && !path.starts_with(prefix) {
                return Err(ConfigError::InvalidRouteStripPrefix {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                });
            }
        }
        if let Some(path) = &self.rewrite_prefix {
            validate_route_rewrite_prefix_path(path).map_err(|_| {
                ConfigError::InvalidRouteRewritePrefix {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                }
            })?;
            if self.strip_prefix.is_none() {
                return Err(ConfigError::InvalidRouteRewritePrefix {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                });
            }
        }
        if self
            .max_request_body_bytes
            .is_some_and(|bytes| bytes.as_u64() == 0)
        {
            return Err(ConfigError::InvalidRouteLimit {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
                field: "max_request_body_bytes",
            });
        }
        self.access
            .validate("vhosts.routes.access")
            .map_err(|source| ConfigError::RouteSection {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
                section: "access",
                source: Box::new(source),
            })?;
        self.rate_limit
            .validate("vhosts.routes.rate_limit")
            .map_err(|source| ConfigError::RouteSection {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
                section: "rate_limit",
                source: Box::new(source),
            })?;
        self.concurrency
            .validate("vhosts.routes.concurrency")
            .map_err(|source| ConfigError::RouteSection {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
                section: "concurrency",
                source: Box::new(source),
            })?;

        let action_count = usize::from(self.redirect.is_some())
            + usize::from(self.proxy.is_some())
            + usize::from(self.web.is_some())
            + usize::from(self.php.is_some());
        if action_count != 1 {
            return Err(ConfigError::InvalidRouteAction {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
            });
        }

        if let Some(redirect) = &self.redirect {
            redirect.validate(vhost, &self.name)?;
        }
        if let Some(proxy) = &self.proxy {
            proxy
                .validate()
                .map_err(|source| ConfigError::RouteSection {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                    section: "proxy",
                    source: Box::new(source),
                })?;
        }
        if let Some(web) = &self.web {
            web.validate().map_err(|source| ConfigError::RouteSection {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
                section: "web",
                source: Box::new(source),
            })?;
            if !web.enabled() {
                return Err(ConfigError::InvalidRouteAction {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                });
            }
        }
        if let Some(php) = &self.php {
            php.validate("vhosts.routes.php")
                .map_err(|source| ConfigError::RouteSection {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                    section: "php",
                    source: Box::new(source),
                })?;
            if !php.enabled {
                return Err(ConfigError::InvalidRouteAction {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                });
            }
        }
        if let Some(cache) = &self.cache {
            cache
                .validate("vhosts.routes.cache")
                .map_err(|source| ConfigError::RouteSection {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                    section: "cache",
                    source: Box::new(source),
                })?;
        }
        if let Some(compression) = &self.compression {
            compression
                .validate()
                .map_err(|source| ConfigError::RouteSection {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                    section: "compression",
                    source: Box::new(source),
                })?;
        }
        self.headers
            .validate()
            .map_err(|source| ConfigError::RouteSection {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
                section: "headers",
                source: Box::new(source),
            })?;
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRedirectConfig {
    pub to: String,
    #[serde(default = "default_route_redirect_status")]
    pub status: u16,
}

impl RouteRedirectConfig {
    fn validate(&self, vhost: &str, route: &str) -> Result<(), ConfigError> {
        if !matches!(self.status, 301 | 302 | 307 | 308) {
            return Err(ConfigError::InvalidRouteRedirectStatus {
                vhost: vhost.to_owned(),
                route: route.to_owned(),
                status: self.status,
            });
        }
        if !valid_redirect_target_template(&self.to) {
            return Err(ConfigError::InvalidRouteRedirectTarget {
                vhost: vhost.to_owned(),
                route: route.to_owned(),
            });
        }
        Ok(())
    }
}

fn default_route_redirect_status() -> u16 {
    308
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VhostRedirectConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default = "default_route_redirect_status")]
    pub status: u16,
}

impl Default for VhostRedirectConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            to: None,
            status: default_route_redirect_status(),
        }
    }
}

impl VhostRedirectConfig {
    fn validate(&self, vhost: &str) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        let Some(to) = &self.to else {
            return Err(ConfigError::MissingVhostRedirectTarget {
                vhost: vhost.to_owned(),
            });
        };
        RouteRedirectConfig {
            to: to.clone(),
            status: self.status,
        }
        .validate(vhost, "vhost-redirect")
    }

    pub fn route_config(&self) -> Option<RouteConfig> {
        if !self.enabled {
            return None;
        }
        let to = self.to.clone()?;

        Some(RouteConfig {
            name: "vhost-redirect".to_owned(),
            path_exact: None,
            path_prefix: None,
            fallback: true,
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            max_request_body_bytes: None,
            access: AccessPolicyConfig::default(),
            rate_limit: RateLimitConfig::default(),
            concurrency: ConcurrencyLimitConfig::default(),
            redirect: Some(RouteRedirectConfig {
                to,
                status: self.status,
            }),
            proxy: None,
            web: None,
            php: None,
            cache: None,
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
        })
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
        has_shared_certificate_source: bool,
    ) -> Result<(), ConfigError> {
        if let Some(certificate) = &self.certificate {
            certificate.validate(scope)?;
        }

        if self.enabled
            && self.certificate.is_none()
            && !self.acme.enabled
            && !has_shared_certificate_source
        {
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
            validate_config_list_len(
                format!("{scope}.acme.domains"),
                self.domains.len(),
                MAX_VHOST_ACME_DOMAINS,
            )?;
            self.domains.iter().map(String::as_str).collect()
        };

        if domains.is_empty() {
            return Err(ConfigError::EmptyVhostAcmeDomains { scope });
        }

        let mut seen_domains = std::collections::HashSet::new();
        for domain in domains {
            let Some(normalized_domain) = normalize_host(domain) else {
                return Err(ConfigError::InvalidVhostAcmeDomain {
                    scope,
                    domain: domain.to_owned(),
                });
            };
            if !seen_domains.insert(normalized_domain.clone()) {
                return Err(ConfigError::DuplicateVhostAcmeDomain {
                    scope,
                    domain: normalized_domain,
                });
            }
        }

        Ok(())
    }
}

const ACME_HTTP_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";
const MAX_ACME_CHALLENGE_UPSTREAMS: usize = 64;

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VhostAcmeChallengeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub upstream_tls: bool,
    #[serde(default)]
    pub connect_timeout_secs: Option<u64>,
    #[serde(default)]
    pub read_timeout_secs: Option<u64>,
    #[serde(default)]
    pub send_timeout_secs: Option<u64>,
}

impl VhostAcmeChallengeConfig {
    fn validate(&self, vhost: &str) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.upstream.is_some() && !self.upstreams.is_empty() {
            return Err(ConfigError::ConflictingAcmeChallengeUpstreams {
                vhost: vhost.to_owned(),
            });
        }
        if self.upstream.is_none() && self.upstreams.is_empty() {
            return Err(ConfigError::MissingAcmeChallengeUpstream {
                vhost: vhost.to_owned(),
            });
        }
        if self.upstreams.len() > MAX_ACME_CHALLENGE_UPSTREAMS {
            return Err(ConfigError::TooManyAcmeChallengeUpstreams {
                vhost: vhost.to_owned(),
                max: MAX_ACME_CHALLENGE_UPSTREAMS,
            });
        }

        if let Some(upstream) = &self.upstream
            && !valid_authority(upstream)
        {
            return Err(ConfigError::InvalidUpstream {
                address: upstream.clone(),
            });
        }
        let mut seen_upstreams = std::collections::HashSet::new();
        for upstream in &self.upstreams {
            if !valid_authority(upstream) {
                return Err(ConfigError::InvalidUpstream {
                    address: upstream.clone(),
                });
            }
            if !seen_upstreams.insert(upstream.to_ascii_lowercase()) {
                return Err(ConfigError::DuplicateAcmeChallengeUpstream {
                    vhost: vhost.to_owned(),
                    upstream: upstream.clone(),
                });
            }
        }

        validate_optional_timeout_secs(
            "vhosts.acme_challenge.connect_timeout_secs",
            self.connect_timeout_secs,
        )?;
        validate_optional_timeout_secs(
            "vhosts.acme_challenge.read_timeout_secs",
            self.read_timeout_secs,
        )?;
        validate_optional_timeout_secs(
            "vhosts.acme_challenge.send_timeout_secs",
            self.send_timeout_secs,
        )?;
        Ok(())
    }

    pub fn route_config(&self) -> Option<RouteConfig> {
        self.enabled.then(|| RouteConfig {
            name: "acme-http-01".to_owned(),
            path_exact: None,
            path_prefix: Some(ACME_HTTP_CHALLENGE_PREFIX.to_owned()),
            fallback: false,
            https_redirect_exempt: true,
            strip_prefix: None,
            rewrite_prefix: None,
            max_request_body_bytes: None,
            access: AccessPolicyConfig::default(),
            rate_limit: RateLimitConfig::default(),
            concurrency: ConcurrencyLimitConfig::default(),
            redirect: None,
            proxy: Some(ProxyConfig {
                upstream: self.upstream.clone(),
                upstreams: self.upstreams.clone(),
                upstream_tls: self.upstream_tls,
                connect_timeout_secs: self.connect_timeout_secs,
                read_timeout_secs: self.read_timeout_secs,
                send_timeout_secs: self.send_timeout_secs,
                ..ProxyConfig::default()
            }),
            web: None,
            php: None,
            cache: None,
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
        })
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CachePreset {
    #[default]
    None,
    #[serde(rename = "wordpress")]
    WordPress,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    #[serde(default)]
    pub preset: CachePreset,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub local_static: bool,
    #[serde(default)]
    pub status_header: Option<String>,
    #[serde(default)]
    pub status_reason_header: Option<String>,
    #[serde(default)]
    pub hide_response_headers: Vec<String>,
    #[serde(default = "default_cache_tag_headers")]
    pub tag_headers: Vec<String>,
    #[serde(default)]
    pub no_store_response_headers: Vec<String>,
    #[serde(default)]
    pub no_store_response_header_values: BTreeMap<String, String>,
    #[serde(default)]
    pub bypass_path_prefixes: Vec<String>,
    #[serde(default)]
    pub bypass_path_exact: Vec<String>,
    #[serde(default)]
    pub bypass_request_headers: Vec<String>,
    #[serde(default)]
    pub bypass_request_header_values: BTreeMap<String, String>,
    #[serde(default)]
    pub bypass_cookie_names: Vec<String>,
    #[serde(default)]
    pub bypass_cookie_name_prefixes: Vec<String>,
    #[serde(default)]
    pub bypass_cookie_values: BTreeMap<String, String>,
    #[serde(default)]
    pub bypass_query_params: Vec<String>,
    #[serde(default)]
    pub bypass_query_values: BTreeMap<String, String>,
    #[serde(default)]
    pub bypass_query: bool,
    #[serde(default)]
    pub allow_client_cache_refresh: bool,
    #[serde(default)]
    pub vary_request_headers: Vec<String>,
    #[serde(default)]
    pub ignore_origin_cache_headers: bool,
    #[serde(default)]
    pub key_namespace: Option<String>,
    #[serde(default = "default_cache_key_parts")]
    pub key_parts: Vec<CacheKeyPart>,
    #[serde(default = "default_cache_min_uses")]
    pub min_uses: u32,
    #[serde(default)]
    pub pass_uncacheable_after: u32,
    #[serde(default)]
    pub range: CacheRangeConfig,
    #[serde(default)]
    pub status_ttls: BTreeMap<u16, u32>,
    #[serde(default)]
    pub default_status_ttl_secs: Option<u32>,
    #[serde(default)]
    pub stale_while_revalidate_secs: Option<u32>,
    #[serde(default)]
    pub stale_if_error_secs: Option<u32>,
    #[serde(default = "default_cache_stale_if_error_on")]
    pub stale_if_error_on: Vec<CacheStaleErrorKind>,
    #[serde(default)]
    pub stale_if_error_statuses: Vec<u16>,
    #[serde(default = "default_cache_include_query")]
    pub include_query: bool,
    #[serde(default = "default_cache_content_types")]
    pub content_types: Vec<String>,
    #[serde(default = "default_cache_static_extensions", alias = "extensions")]
    pub image_extensions: Vec<String>,
    #[serde(default = "default_cache_methods")]
    pub methods: Vec<String>,
    #[serde(default = "default_cache_max_object_bytes")]
    pub max_object_bytes: ByteSize,
    #[serde(default)]
    pub memory: CacheMemoryConfig,
    #[serde(default)]
    pub disk: CacheDiskConfig,
    #[serde(default)]
    pub lock: CacheLockConfig,
    #[serde(default)]
    pub predictor: CachePredictorConfig,
    #[serde(default)]
    pub peer_fill: CachePeerFillConfig,
}

const MAX_CACHE_HEADER_LIST_ENTRIES: usize = 64;
const MAX_CACHE_BYPASS_PATHS: usize = 128;
const MAX_CACHE_BYPASS_HEADERS: usize = 64;
const MAX_CACHE_BYPASS_COOKIES: usize = 128;
const MAX_CACHE_BYPASS_QUERY_PARAMS: usize = 128;
const MAX_CACHE_VARY_REQUEST_HEADERS: usize = 32;
const MAX_CACHE_KEY_PARTS: usize = 4;
const MAX_CACHE_CONTENT_TYPES: usize = 64;
const MAX_CACHE_IMAGE_EXTENSIONS: usize = 128;
const MAX_CACHE_METHODS: usize = 16;
const MAX_CACHE_STATUS_TTLS: usize = 128;
const MAX_CACHE_STALE_IF_ERROR_STATUSES: usize = 100;

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            preset: CachePreset::default(),
            enabled: false,
            local_static: false,
            status_header: None,
            status_reason_header: None,
            hide_response_headers: Vec::new(),
            tag_headers: default_cache_tag_headers(),
            no_store_response_headers: Vec::new(),
            no_store_response_header_values: BTreeMap::new(),
            bypass_path_prefixes: Vec::new(),
            bypass_path_exact: Vec::new(),
            bypass_request_headers: Vec::new(),
            bypass_request_header_values: BTreeMap::new(),
            bypass_cookie_names: Vec::new(),
            bypass_cookie_name_prefixes: Vec::new(),
            bypass_cookie_values: BTreeMap::new(),
            bypass_query_params: Vec::new(),
            bypass_query_values: BTreeMap::new(),
            bypass_query: false,
            allow_client_cache_refresh: false,
            vary_request_headers: Vec::new(),
            ignore_origin_cache_headers: false,
            key_namespace: None,
            key_parts: default_cache_key_parts(),
            min_uses: default_cache_min_uses(),
            pass_uncacheable_after: 0,
            range: CacheRangeConfig::default(),
            status_ttls: BTreeMap::new(),
            default_status_ttl_secs: None,
            stale_while_revalidate_secs: None,
            stale_if_error_secs: None,
            stale_if_error_on: default_cache_stale_if_error_on(),
            stale_if_error_statuses: Vec::new(),
            include_query: default_cache_include_query(),
            content_types: default_cache_content_types(),
            image_extensions: default_cache_static_extensions(),
            methods: default_cache_methods(),
            max_object_bytes: default_cache_max_object_bytes(),
            memory: CacheMemoryConfig::default(),
            disk: CacheDiskConfig::default(),
            lock: CacheLockConfig::default(),
            predictor: CachePredictorConfig::default(),
            peer_fill: CachePeerFillConfig::default(),
        }
    }
}

impl CacheConfig {
    #[cfg(any(feature = "cache", test))]
    pub(crate) fn with_presets(&self) -> Self {
        let mut config = self.clone();
        config.apply_preset_defaults();
        config
    }

    fn apply_preset_defaults(&mut self) {
        match self.preset {
            CachePreset::None => {}
            CachePreset::WordPress => self.apply_wordpress_preset_defaults(),
        }
    }

    fn apply_wordpress_preset_defaults(&mut self) {
        extend_unique(
            &mut self.bypass_path_prefixes,
            ["/wp-admin/", "/feed/"].map(str::to_owned),
        );
        extend_unique(
            &mut self.bypass_path_exact,
            [
                "/index.php",
                "/sitemap.xml",
                "/sitemap_index.xml",
                "/wp-app.php",
                "/wp-comments-popup.php",
                "/wp-comments-post.php",
                "/wp-cron.php",
                "/wp-links-opml.php",
                "/wp-locations.php",
                "/wp-login.php",
                "/wp-mail.php",
                "/wp-register.php",
                "/xmlrpc.php",
            ]
            .map(str::to_owned),
        );
        extend_unique(
            &mut self.bypass_query_params,
            ["preview"].map(str::to_owned),
        );
        self.bypass_query = true;
        extend_unique(
            &mut self.bypass_cookie_name_prefixes,
            [
                "comment_author_",
                "wordpress_",
                "wordpress_logged_in_",
                "wordpress_no_cache",
                "wordpress_sec_",
                "wp-postpass_",
            ]
            .map(str::to_owned),
        );
        extend_unique(
            &mut self.bypass_request_headers,
            ["authorization"].map(str::to_owned),
        );
    }

    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.disk.path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
        self.disk.encryption.resolve_relative_paths(base_dir);
    }

    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        validate_cache_list_len(
            scope,
            "hide_response_headers",
            self.hide_response_headers.len(),
            MAX_CACHE_HEADER_LIST_ENTRIES,
        )?;
        validate_cache_list_len(
            scope,
            "tag_headers",
            self.tag_headers.len(),
            MAX_CACHE_HEADER_LIST_ENTRIES,
        )?;
        validate_cache_list_len(
            scope,
            "no_store_response_headers",
            self.no_store_response_headers.len(),
            MAX_CACHE_HEADER_LIST_ENTRIES,
        )?;
        validate_cache_list_len(
            scope,
            "no_store_response_header_values",
            self.no_store_response_header_values.len(),
            MAX_CACHE_HEADER_LIST_ENTRIES,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_path_prefixes",
            self.bypass_path_prefixes.len(),
            MAX_CACHE_BYPASS_PATHS,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_path_exact",
            self.bypass_path_exact.len(),
            MAX_CACHE_BYPASS_PATHS,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_request_headers",
            self.bypass_request_headers.len(),
            MAX_CACHE_BYPASS_HEADERS,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_request_header_values",
            self.bypass_request_header_values.len(),
            MAX_CACHE_BYPASS_HEADERS,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_cookie_names",
            self.bypass_cookie_names.len(),
            MAX_CACHE_BYPASS_COOKIES,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_cookie_name_prefixes",
            self.bypass_cookie_name_prefixes.len(),
            MAX_CACHE_BYPASS_COOKIES,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_cookie_values",
            self.bypass_cookie_values.len(),
            MAX_CACHE_BYPASS_COOKIES,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_query_params",
            self.bypass_query_params.len(),
            MAX_CACHE_BYPASS_QUERY_PARAMS,
        )?;
        validate_cache_list_len(
            scope,
            "bypass_query_values",
            self.bypass_query_values.len(),
            MAX_CACHE_BYPASS_QUERY_PARAMS,
        )?;
        validate_cache_list_len(
            scope,
            "vary_request_headers",
            self.vary_request_headers.len(),
            MAX_CACHE_VARY_REQUEST_HEADERS,
        )?;
        validate_cache_list_len(
            scope,
            "status_ttls",
            self.status_ttls.len(),
            MAX_CACHE_STATUS_TTLS,
        )?;
        validate_cache_list_len(
            scope,
            "stale_if_error_statuses",
            self.stale_if_error_statuses.len(),
            MAX_CACHE_STALE_IF_ERROR_STATUSES,
        )?;
        validate_cache_list_len(
            scope,
            "content_types",
            self.content_types.len(),
            MAX_CACHE_CONTENT_TYPES,
        )?;
        validate_cache_list_len(
            scope,
            "image_extensions",
            self.image_extensions.len(),
            MAX_CACHE_IMAGE_EXTENSIONS,
        )?;
        validate_cache_list_len(scope, "methods", self.methods.len(), MAX_CACHE_METHODS)?;

        if let Some(status_header) = &self.status_header {
            validate_header_name(scope, status_header)?;
        }
        if let Some(status_reason_header) = &self.status_reason_header {
            validate_header_name(scope, status_reason_header)?;
        }
        for header in &self.hide_response_headers {
            validate_header_name(scope, header)?;
        }
        let mut seen_tag_headers = BTreeSet::new();
        for header in &self.tag_headers {
            validate_header_name(scope, header)?;
            let normalized = header.to_ascii_lowercase();
            if !seen_tag_headers.insert(normalized) {
                return Err(ConfigError::DuplicateCacheTagHeader {
                    scope,
                    header: header.clone(),
                });
            }
        }
        for header in &self.no_store_response_headers {
            validate_header_name(scope, header)?;
        }
        for (header, value) in &self.no_store_response_header_values {
            validate_header_name(scope, header)?;
            validate_cache_no_store_response_header_value(scope, header, value)?;
        }
        for path in &self.bypass_path_prefixes {
            validate_route_path(scope, path, true).map_err(|_| {
                ConfigError::InvalidCacheBypassPath {
                    scope,
                    path: path.clone(),
                }
            })?;
        }
        for path in &self.bypass_path_exact {
            validate_route_path(scope, path, false).map_err(|_| {
                ConfigError::InvalidCacheBypassPath {
                    scope,
                    path: path.clone(),
                }
            })?;
        }
        for header in &self.bypass_request_headers {
            validate_header_name(scope, header)?;
        }
        for (header, value) in &self.bypass_request_header_values {
            validate_header_name(scope, header)?;
            validate_cache_bypass_request_header_value(scope, header, value)?;
        }
        for cookie in &self.bypass_cookie_names {
            validate_cache_cookie_name(scope, cookie)?;
        }
        for cookie in &self.bypass_cookie_name_prefixes {
            validate_cache_cookie_name(scope, cookie)?;
        }
        for (cookie, value) in &self.bypass_cookie_values {
            validate_cache_cookie_name(scope, cookie)?;
            validate_cache_cookie_value(scope, cookie, value)?;
        }
        for param in &self.bypass_query_params {
            validate_cache_query_param(scope, param)?;
        }
        for (param, value) in &self.bypass_query_values {
            validate_cache_query_param(scope, param)?;
            validate_cache_query_value(scope, param, value)?;
        }
        for header in &self.vary_request_headers {
            validate_header_name(scope, header)?;
            if cache_sensitive_request_header(header) {
                return Err(ConfigError::InvalidCacheVaryRequestHeader {
                    scope,
                    header: header.clone(),
                });
            }
        }
        if let Some(namespace) = &self.key_namespace {
            validate_cache_key_namespace(scope, namespace)?;
        }
        if self.key_parts.is_empty() {
            return Err(ConfigError::EmptyCacheKeyParts { scope });
        }
        validate_cache_list_len(
            scope,
            "key_parts",
            self.key_parts.len(),
            MAX_CACHE_KEY_PARTS,
        )?;
        let mut seen_parts = BTreeSet::new();
        for part in &self.key_parts {
            if !seen_parts.insert(*part) {
                return Err(ConfigError::DuplicateCacheKeyPart { scope, part: *part });
            }
        }
        if !seen_parts.contains(&CacheKeyPart::Path) {
            return Err(ConfigError::MissingCacheKeyPath { scope });
        }
        if self.min_uses == 0 {
            return Err(ConfigError::InvalidCacheMinUses { scope });
        }
        for (status, ttl_secs) in &self.status_ttls {
            if !(100..=599).contains(status) || *ttl_secs == 0 {
                return Err(ConfigError::InvalidCacheStatusTtl {
                    scope,
                    status: *status,
                    ttl_secs: *ttl_secs,
                });
            }
        }
        if self.default_status_ttl_secs == Some(0) {
            return Err(ConfigError::InvalidCacheDefaultStatusTtl { scope });
        }
        if self.stale_if_error_secs == Some(0) {
            return Err(ConfigError::InvalidCacheStaleIfErrorTtl { scope });
        }
        if self.stale_while_revalidate_secs == Some(0) {
            return Err(ConfigError::InvalidCacheStaleWhileRevalidateTtl { scope });
        }
        if self.stale_if_error_secs.is_some() && self.stale_if_error_on.is_empty() {
            return Err(ConfigError::EmptyCacheStaleIfErrorOn { scope });
        }
        for status in &self.stale_if_error_statuses {
            if !(500..=599).contains(status) {
                return Err(ConfigError::InvalidCacheStaleIfErrorStatus {
                    scope,
                    status: *status,
                });
            }
        }

        if self.content_types.is_empty() {
            return Err(ConfigError::EmptyCacheContentTypes { scope });
        }
        for content_type in &self.content_types {
            let content_type = content_type.trim();
            let Some((kind, subtype)) = content_type.split_once('/') else {
                return Err(ConfigError::InvalidCacheContentType {
                    scope,
                    content_type: content_type.to_owned(),
                });
            };
            if kind.is_empty()
                || subtype.is_empty()
                || kind == "*"
                || content_type.contains(';')
                || content_type.chars().any(char::is_whitespace)
                || content_type.chars().any(char::is_control)
                || (subtype.contains('*') && subtype != "*")
            {
                return Err(ConfigError::InvalidCacheContentType {
                    scope,
                    content_type: content_type.to_owned(),
                });
            }
        }

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

        self.range.validate(scope, self.max_object_bytes)?;
        self.lock.validate(scope)?;
        self.predictor.validate(scope)?;
        self.peer_fill.validate(scope)?;

        if self.enabled && !self.has_enabled_tier() {
            return Err(ConfigError::CacheEnabledWithoutStorageTier { scope });
        }
        if self.peer_fill.enabled && !self.enabled {
            return Err(ConfigError::InvalidCachePeerFillPolicy {
                scope,
                field: "peer_fill.enabled",
                reason: "peer fill requires the cache policy to be enabled",
            });
        }

        self.memory.validate(scope, self.max_object_bytes)?;
        self.disk.validate(scope, self.max_object_bytes)?;
        Ok(())
    }

    pub fn has_enabled_tier(&self) -> bool {
        self.memory.enabled || self.disk.enabled
    }
}

fn validate_cache_compliance_internal_crypto(
    cache: &CacheConfig,
    scope: &'static str,
    require_disk_cache_encryption: bool,
) -> Result<(), ConfigError> {
    if !cache.disk.enabled {
        return Ok(());
    }

    if !cache.disk.encryption.enabled {
        if require_disk_cache_encryption {
            return Err(ConfigError::InvalidCompliancePolicy {
                field: scope,
                reason: "FIPS/ISO-required mode requires disk cache encryption because tls.fips.require_disk_cache_encryption or tls.iso19790.require_disk_cache_encryption is enabled",
            });
        }
        log::warn!(
            "{scope}.disk.enabled is true in FIPS/ISO-required mode without disk cache encryption; cached response bodies are written at rest without a Fluxheim-managed encryption boundary"
        );
        return Ok(());
    }

    match cache.disk.encryption.provider {
        CacheDiskEncryptionProvider::Local => Err(ConfigError::InvalidCompliancePolicy {
            field: scope,
            reason: "FIPS/ISO-required mode rejects local cache encryption because it currently uses ring AES-GCM; use provider = \"openbao-transit\" with external validation evidence or disable cache encryption",
        }),
        CacheDiskEncryptionProvider::OpenbaoTransit => {
            let address = cache
                .disk
                .encryption
                .openbao
                .address
                .as_deref()
                .unwrap_or_default();
            if !fips_allowed_local_openbao_endpoint(address) {
                return Err(ConfigError::InvalidCompliancePolicy {
                    field: scope,
                    reason: "FIPS/ISO-required mode allows OpenBao Transit only through local http://127.0.0.1 or http://[::1] loopback; remote or HTTPS OpenBao transport needs provider-aligned outbound TLS evidence first",
                });
            }
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheRangeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_range_max_bytes")]
    pub max_bytes: ByteSize,
    #[serde(default)]
    pub slice: CacheRangeSliceConfig,
}

impl Default for CacheRangeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_bytes: default_cache_range_max_bytes(),
            slice: CacheRangeSliceConfig::default(),
        }
    }
}

impl CacheRangeConfig {
    fn validate(&self, scope: &'static str, max_object_bytes: ByteSize) -> Result<(), ConfigError> {
        if self.max_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.max_bytes",
                reason: "max bytes must be greater than zero",
            });
        }
        if self.enabled && !self.slice.enabled && self.max_bytes > max_object_bytes {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.max_bytes",
                reason: "max bytes must not exceed max_object_bytes",
            });
        }
        self.slice
            .validate(scope, self.enabled, self.max_bytes, max_object_bytes)?;
        Ok(())
    }
}

fn default_cache_range_max_bytes() -> ByteSize {
    ByteSize(8 * 1024 * 1024)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheRangeSliceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_range_slice_size_bytes")]
    pub size_bytes: ByteSize,
    #[serde(default = "default_cache_range_slice_max_slices")]
    pub max_slices: u32,
    #[serde(default = "default_cache_range_slice_fill_missing")]
    pub fill_missing: bool,
}

impl Default for CacheRangeSliceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            size_bytes: default_cache_range_slice_size_bytes(),
            max_slices: default_cache_range_slice_max_slices(),
            fill_missing: default_cache_range_slice_fill_missing(),
        }
    }
}

impl CacheRangeSliceConfig {
    fn validate(
        &self,
        scope: &'static str,
        range_enabled: bool,
        range_max_bytes: ByteSize,
        max_object_bytes: ByteSize,
    ) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if !range_enabled {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.slice.enabled",
                reason: "slice caching requires range.enabled = true",
            });
        }
        if self.size_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.slice.size_bytes",
                reason: "slice size must be greater than zero",
            });
        }
        if self.size_bytes > max_object_bytes {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.slice.size_bytes",
                reason: "slice size must not exceed max_object_bytes",
            });
        }
        if self.max_slices == 0 {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.slice.max_slices",
                reason: "max slices must be greater than zero",
            });
        }
        let max_assembled = self
            .size_bytes
            .as_u64()
            .saturating_mul(u64::from(self.max_slices));
        if range_max_bytes.as_u64() > max_assembled {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.max_bytes",
                reason: "max bytes must not exceed range.slice.size_bytes * range.slice.max_slices",
            });
        }
        Ok(())
    }
}

fn default_cache_range_slice_size_bytes() -> ByteSize {
    ByteSize(1024 * 1024)
}

fn default_cache_range_slice_max_slices() -> u32 {
    128
}

fn default_cache_range_slice_fill_missing() -> bool {
    true
}

fn cache_sensitive_request_header(header: &str) -> bool {
    matches!(
        header.to_ascii_lowercase().as_str(),
        "authorization" | "cookie" | "proxy-authorization"
    )
}

fn validate_cache_query_param(scope: &'static str, param: &str) -> Result<(), ConfigError> {
    if param.is_empty()
        || param.len() > 128
        || param.chars().any(|ch| {
            ch.is_control() || ch.is_whitespace() || matches!(ch, '&' | '=' | '#' | '?' | ';')
        })
    {
        return Err(ConfigError::InvalidCacheBypassQueryParam {
            scope,
            param: param.to_owned(),
        });
    }
    Ok(())
}

fn validate_cache_query_value(
    scope: &'static str,
    param: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.trim().is_empty()
        || value.len() > 4096
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || matches!(ch, '&' | '#' | ';'))
    {
        return Err(ConfigError::InvalidCacheBypassQueryValue {
            scope,
            param: param.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn validate_cache_bypass_request_header_value(
    scope: &'static str,
    header: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.trim().is_empty()
        || value.len() > 4096
        || value
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, 0x00..=0x08 | 0x0a..=0x1f | 0x7f))
    {
        return Err(ConfigError::InvalidCacheBypassRequestHeaderValue {
            scope,
            header: header.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn validate_cache_no_store_response_header_value(
    scope: &'static str,
    header: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.trim().is_empty()
        || value.len() > 4096
        || value
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, 0x00..=0x08 | 0x0a..=0x1f | 0x7f))
    {
        return Err(ConfigError::InvalidCacheNoStoreResponseHeaderValue {
            scope,
            header: header.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn validate_cache_cookie_name(scope: &'static str, name: &str) -> Result<(), ConfigError> {
    if name.is_empty() || name.len() > 128 || !valid_cookie_name(name) {
        return Err(ConfigError::InvalidCacheBypassCookieName {
            scope,
            name: name.to_owned(),
        });
    }
    Ok(())
}

fn validate_cache_cookie_value(
    scope: &'static str,
    name: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.len() > 1024
        || value
            .bytes()
            .any(|byte| byte < 0x20 || byte == 0x7f || matches!(byte, b';' | b','))
    {
        return Err(ConfigError::InvalidCacheBypassCookieValue {
            scope,
            name: name.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn valid_cookie_name(value: &str) -> bool {
    value.bytes().all(|byte| {
        matches!(byte, 0x21 | 0x23..=0x27 | 0x2a..=0x2b | 0x2d..=0x2e | 0x30..=0x39 | 0x41..=0x5a | 0x5e..=0x7a | 0x7c | 0x7e)
    })
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheKeyPart {
    Method,
    Host,
    Path,
    Query,
}

impl Display for CacheKeyPart {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Method => formatter.write_str("method"),
            Self::Host => formatter.write_str("host"),
            Self::Path => formatter.write_str("path"),
            Self::Query => formatter.write_str("query"),
        }
    }
}

fn extend_unique(target: &mut Vec<String>, values: impl IntoIterator<Item = String>) {
    for value in values {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
        }
    }
}

fn default_cache_key_parts() -> Vec<CacheKeyPart> {
    vec![
        CacheKeyPart::Method,
        CacheKeyPart::Host,
        CacheKeyPart::Path,
        CacheKeyPart::Query,
    ]
}

fn default_cache_tag_headers() -> Vec<String> {
    ["surrogate-key", "cache-tag", "x-cache-tags"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn validate_cache_key_namespace(scope: &'static str, namespace: &str) -> Result<(), ConfigError> {
    if namespace.is_empty()
        || namespace.len() > 128
        || namespace
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':')))
    {
        return Err(ConfigError::InvalidCacheKeyNamespace {
            scope,
            namespace: namespace.to_owned(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheStaleErrorKind {
    Connect,
    Timeout,
    Read,
    Write,
    ConnectionClosed,
    HttpStatus,
    Protocol,
    Tls,
    Other,
}

fn default_cache_stale_if_error_on() -> Vec<CacheStaleErrorKind> {
    vec![
        CacheStaleErrorKind::Connect,
        CacheStaleErrorKind::Timeout,
        CacheStaleErrorKind::Read,
        CacheStaleErrorKind::Write,
        CacheStaleErrorKind::ConnectionClosed,
        CacheStaleErrorKind::HttpStatus,
        CacheStaleErrorKind::Protocol,
        CacheStaleErrorKind::Tls,
        CacheStaleErrorKind::Other,
    ]
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheLockConfig {
    #[serde(default = "default_cache_lock_enabled")]
    pub enabled: bool,
    #[serde(default = "default_cache_lock_age_timeout_secs")]
    pub age_timeout_secs: u64,
    #[serde(default = "default_cache_lock_wait_timeout_secs")]
    pub wait_timeout_secs: u64,
}

impl Default for CacheLockConfig {
    fn default() -> Self {
        Self {
            enabled: default_cache_lock_enabled(),
            age_timeout_secs: default_cache_lock_age_timeout_secs(),
            wait_timeout_secs: default_cache_lock_wait_timeout_secs(),
        }
    }
}

impl CacheLockConfig {
    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if self.age_timeout_secs == 0 {
            return Err(ConfigError::InvalidCacheLockTimeout {
                field: format!("{scope}.lock.age_timeout_secs"),
            });
        }
        if self.wait_timeout_secs == 0 {
            return Err(ConfigError::InvalidCacheLockTimeout {
                field: format!("{scope}.lock.wait_timeout_secs"),
            });
        }
        Ok(())
    }
}

const CACHE_PREDICTOR_MAX_CAPACITY: usize = 1_048_576;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePredictorConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_predictor_capacity")]
    pub capacity: usize,
}

impl Default for CachePredictorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            capacity: default_cache_predictor_capacity(),
        }
    }
}

impl CachePredictorConfig {
    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if self.enabled && (self.capacity == 0 || self.capacity > CACHE_PREDICTOR_MAX_CAPACITY) {
            return Err(ConfigError::InvalidCachePredictorCapacity { scope });
        }
        Ok(())
    }
}

fn default_cache_predictor_capacity() -> usize {
    65_536
}

const CACHE_PEER_FILL_MAX_PEERS: usize = 32;
const CACHE_PEER_FILL_MAX_CONCURRENT_REQUESTS: usize = 1024;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePeerFillConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub peers: Vec<CachePeerConfig>,
    #[serde(default = "default_cache_peer_fill_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_cache_peer_fill_read_timeout_secs")]
    pub read_timeout_secs: u64,
    #[serde(default)]
    pub max_object_bytes: Option<ByteSize>,
    #[serde(default = "default_cache_peer_fill_max_concurrent_requests")]
    pub max_concurrent_requests: usize,
    #[serde(default)]
    pub allow_insecure_http: bool,
    #[serde(default = "default_true")]
    pub fail_open: bool,
}

impl Default for CachePeerFillConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            peers: Vec::new(),
            connect_timeout_secs: default_cache_peer_fill_connect_timeout_secs(),
            read_timeout_secs: default_cache_peer_fill_read_timeout_secs(),
            max_object_bytes: None,
            max_concurrent_requests: default_cache_peer_fill_max_concurrent_requests(),
            allow_insecure_http: false,
            fail_open: true,
        }
    }
}

impl CachePeerFillConfig {
    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        #[cfg(not(feature = "cache"))]
        if self.enabled {
            return Err(ConfigError::CachePeerFillNotCompiled);
        }

        if !self.enabled {
            return Ok(());
        }

        if self.peers.is_empty() || self.peers.len() > CACHE_PEER_FILL_MAX_PEERS {
            return Err(ConfigError::InvalidCachePeerFillPolicy {
                scope,
                field: "peer_fill.peers",
                reason: "peer fill requires between 1 and 32 peers",
            });
        }
        if self.connect_timeout_secs == 0 || self.connect_timeout_secs > 300 {
            return Err(ConfigError::InvalidCachePeerFillPolicy {
                scope,
                field: "peer_fill.connect_timeout_secs",
                reason: "connect timeout must be between 1 and 300 seconds",
            });
        }
        if self.read_timeout_secs == 0 || self.read_timeout_secs > 3600 {
            return Err(ConfigError::InvalidCachePeerFillPolicy {
                scope,
                field: "peer_fill.read_timeout_secs",
                reason: "read timeout must be between 1 and 3600 seconds",
            });
        }
        if self.max_object_bytes.is_some_and(|size| size.as_u64() == 0) {
            return Err(ConfigError::InvalidCachePeerFillPolicy {
                scope,
                field: "peer_fill.max_object_bytes",
                reason: "max object bytes must be greater than zero",
            });
        }
        if self.max_concurrent_requests == 0
            || self.max_concurrent_requests > CACHE_PEER_FILL_MAX_CONCURRENT_REQUESTS
        {
            return Err(ConfigError::InvalidCachePeerFillPolicy {
                scope,
                field: "peer_fill.max_concurrent_requests",
                reason: "max concurrent requests must be between 1 and 1024",
            });
        }

        let mut seen_names = BTreeSet::new();
        let mut seen_urls = BTreeSet::new();
        for peer in &self.peers {
            peer.validate(scope, self.allow_insecure_http)?;
            if !seen_names.insert(peer.name.to_ascii_lowercase()) {
                return Err(ConfigError::DuplicateCachePeerFillPeerName {
                    scope,
                    name: peer.name.clone(),
                });
            }
            if !seen_urls.insert(peer.base_url.trim_end_matches('/').to_ascii_lowercase()) {
                return Err(ConfigError::DuplicateCachePeerFillPeerUrl {
                    scope,
                    url: peer.base_url.clone(),
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePeerConfig {
    pub name: String,
    pub base_url: String,
}

impl CachePeerConfig {
    fn validate(&self, scope: &'static str, allow_insecure_http: bool) -> Result<(), ConfigError> {
        validate_cache_peer_name(scope, &self.name)?;
        validate_cache_peer_base_url(scope, &self.name, &self.base_url, allow_insecure_http)
    }
}

fn default_cache_peer_fill_connect_timeout_secs() -> u64 {
    2
}

fn default_cache_peer_fill_read_timeout_secs() -> u64 {
    10
}

fn default_cache_peer_fill_max_concurrent_requests() -> usize {
    64
}

fn validate_cache_peer_name(scope: &'static str, name: &str) -> Result<(), ConfigError> {
    if name.is_empty()
        || name.len() > 64
        || name
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: name.to_owned(),
            reason: "peer name must be 1-64 ASCII letters, digits, dots, dashes, or underscores",
        });
    }
    Ok(())
}

fn validate_cache_peer_base_url(
    scope: &'static str,
    peer: &str,
    base_url: &str,
    allow_insecure_http: bool,
) -> Result<(), ConfigError> {
    let base_url = base_url.trim();
    let Some((scheme, rest)) = base_url.split_once("://") else {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: peer.to_owned(),
            reason: "peer base_url must start with https:// or http://",
        });
    };
    if !matches!(scheme, "https" | "http")
        || rest.is_empty()
        || base_url.len() > 2048
        || base_url.chars().any(char::is_whitespace)
        || base_url.chars().any(char::is_control)
        || base_url.contains('?')
        || base_url.contains('#')
    {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: peer.to_owned(),
            reason: "peer base_url must be a safe HTTP(S) origin URL without query or fragment",
        });
    }

    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.contains('@') || !valid_cache_peer_authority(authority) {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: peer.to_owned(),
            reason: "peer base_url authority must be a valid host:port or ip:port without userinfo",
        });
    }
    if !path.is_empty() && path != "/" {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: peer.to_owned(),
            reason: "peer base_url must not include a path yet",
        });
    }
    if scheme == "http" && !allow_insecure_http && !cache_peer_authority_is_loopback(authority) {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: peer.to_owned(),
            reason: "http peer base_url is allowed only for loopback peers unless allow_insecure_http = true",
        });
    }

    Ok(())
}

fn valid_cache_peer_authority(authority: &str) -> bool {
    if authority.starts_with('[') {
        let Some(end) = authority.find(']') else {
            return false;
        };
        let host = &authority[1..end];
        let tail = &authority[end + 1..];
        return !host.is_empty()
            && host.parse::<IpAddr>().is_ok()
            && tail
                .strip_prefix(':')
                .is_some_and(|port| port.parse::<u16>().is_ok_and(|port| port != 0));
    }

    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    port.parse::<u16>().is_ok_and(|port| port != 0)
        && (host.parse::<IpAddr>().is_ok() || valid_cache_peer_hostname(host))
}

fn valid_cache_peer_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn cache_peer_authority_is_loopback(authority: &str) -> bool {
    http_authority_is_loopback(authority)
}

fn http_authority_is_loopback(authority: &str) -> bool {
    if authority.contains('@') {
        return false;
    }
    let host = if authority.starts_with('[') {
        let Some(end) = authority.find(']') else {
            return false;
        };
        let tail = &authority[end + 1..];
        if !tail.is_empty() && !http_authority_valid_port_tail(tail) {
            return false;
        }
        &authority[1..end]
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => {
                if host.contains(':') || !valid_u16_port(port) {
                    return false;
                }
                host
            }
            None => authority,
        }
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn http_authority_valid_port_tail(tail: &str) -> bool {
    tail.strip_prefix(':').is_some_and(valid_u16_port)
}

fn valid_u16_port(port: &str) -> bool {
    port.parse::<u16>().is_ok_and(|port| port != 0)
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
    pub backend: CacheDiskBackend,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default = "default_cache_disk_max_size_bytes")]
    pub max_size_bytes: ByteSize,
    #[serde(default)]
    pub storage_bin: CacheDiskStorageBinConfig,
    #[serde(default)]
    pub encryption: CacheDiskEncryptionConfig,
}

#[derive(Debug, Clone, Copy, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheDiskBackend {
    #[default]
    Filesystem,
    StorageBin,
}

impl Default for CacheDiskConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: CacheDiskBackend::Filesystem,
            path: None,
            max_size_bytes: default_cache_disk_max_size_bytes(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        }
    }
}

impl CacheDiskConfig {
    fn validate(&self, scope: &'static str, max_object_bytes: ByteSize) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.backend == CacheDiskBackend::StorageBin {
            self.storage_bin
                .validate(scope, self.max_size_bytes, max_object_bytes)?;
        }
        self.encryption.validate(scope)?;

        let Some(path) = &self.path else {
            return Err(ConfigError::MissingCacheDiskPath { scope });
        };

        if path.as_os_str().is_empty() {
            return Err(ConfigError::EmptyCacheDiskPath { scope });
        }
        let path_field = format!("{scope}.disk.path");
        validate_path(path_field.clone(), Some(path))?;
        validate_non_world_writable_parent(path_field, Some(path))?;

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

#[derive(Debug, Clone, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskEncryptionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub provider: CacheDiskEncryptionProvider,
    #[serde(default)]
    pub algorithm: CacheDiskEncryptionAlgorithm,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    #[serde(default)]
    pub key_credential: Option<String>,
    #[serde(default)]
    pub openbao: CacheDiskEncryptionOpenBaoConfig,
}

#[derive(Debug, Clone, Copy, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheDiskEncryptionProvider {
    #[default]
    Local,
    OpenbaoTransit,
}

#[derive(Debug, Clone, Copy, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheDiskEncryptionAlgorithm {
    #[default]
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "xchacha20-poly1305")]
    XChaCha20Poly1305,
}

impl Default for CacheDiskEncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: CacheDiskEncryptionProvider::Local,
            algorithm: CacheDiskEncryptionAlgorithm::Aes256Gcm,
            key_id: None,
            key_file: None,
            key_credential: None,
            openbao: CacheDiskEncryptionOpenBaoConfig::default(),
        }
    }
}

impl CacheDiskEncryptionConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(key_file) = &mut self.key_file
            && key_file.is_relative()
        {
            *key_file = base_dir.join(&key_file);
        }
        self.openbao.resolve_relative_paths(base_dir);
    }

    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        let key_file_field = format!("{scope}.disk.encryption.key_file");
        validate_path(key_file_field.clone(), self.key_file.as_deref())?;
        validate_non_world_writable_parent(key_file_field, self.key_file.as_deref())?;

        if let Some(key_id) = self.key_id.as_deref() {
            validate_cache_encryption_label(scope, "key_id", key_id)?;
        }
        if let Some(credential) = self.key_credential.as_deref()
            && !valid_credential_name(credential)
        {
            return Err(ConfigError::InvalidCacheEncryptionCredentialName {
                scope,
                field: "key_credential",
                credential: credential.to_owned(),
            });
        }

        self.openbao.validate(scope)?;

        if !self.enabled {
            return Ok(());
        }

        match self.provider {
            CacheDiskEncryptionProvider::Local => {
                if self.algorithm != CacheDiskEncryptionAlgorithm::Aes256Gcm {
                    return Err(ConfigError::InvalidCacheEncryptionPolicy {
                        scope,
                        field: "disk.encryption.algorithm",
                        reason: "local provider currently supports only \"aes-256-gcm\"",
                    });
                }
                if self.openbao.is_configured() {
                    return Err(ConfigError::InvalidCacheEncryptionPolicy {
                        scope,
                        field: "disk.encryption.openbao",
                        reason: "openbao settings require provider = \"openbao-transit\"",
                    });
                }
                validate_cache_encryption_secret_choice(
                    scope,
                    "key",
                    self.key_file.as_ref(),
                    self.key_credential.as_deref(),
                )?;
            }
            CacheDiskEncryptionProvider::OpenbaoTransit => {
                if self.key_file.is_some() || self.key_credential.is_some() {
                    return Err(ConfigError::InvalidCacheEncryptionPolicy {
                        scope,
                        field: "disk.encryption.key",
                        reason: "local key sources require provider = \"local\"",
                    });
                }
                self.openbao.validate_enabled(scope)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskEncryptionOpenBaoConfig {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub mount: Option<String>,
    #[serde(default)]
    pub key_name: Option<String>,
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    #[serde(default)]
    pub token_credential: Option<String>,
}

impl CacheDiskEncryptionOpenBaoConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(token_file) = &mut self.token_file
            && token_file.is_relative()
        {
            *token_file = base_dir.join(&token_file);
        }
    }

    fn is_configured(&self) -> bool {
        self.address.is_some()
            || self.mount.is_some()
            || self.key_name.is_some()
            || self.token_file.is_some()
            || self.token_credential.is_some()
    }

    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if let Some(address) = self.address.as_deref()
            && invalid_cache_encryption_openbao_address(address)
        {
            return Err(ConfigError::InvalidCacheEncryptionPolicy {
                scope,
                field: "disk.encryption.openbao.address",
                reason: "must be an http://127.0.0.1, http://[::1], or https:// URL without credentials, query, or fragment",
            });
        }
        if let Some(mount) = self.mount.as_deref() {
            validate_cache_encryption_label(scope, "openbao.mount", mount)?;
        }
        if let Some(key_name) = self.key_name.as_deref() {
            validate_cache_encryption_label(scope, "openbao.key_name", key_name)?;
        }
        let token_file_field = format!("{scope}.disk.encryption.openbao.token_file");
        validate_path(token_file_field.clone(), self.token_file.as_deref())?;
        validate_non_world_writable_parent(token_file_field, self.token_file.as_deref())?;
        if let Some(credential) = self.token_credential.as_deref()
            && !valid_credential_name(credential)
        {
            return Err(ConfigError::InvalidCacheEncryptionCredentialName {
                scope,
                field: "openbao.token_credential",
                credential: credential.to_owned(),
            });
        }
        Ok(())
    }

    fn validate_enabled(&self, scope: &'static str) -> Result<(), ConfigError> {
        if self
            .address
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err(ConfigError::InvalidCacheEncryptionPolicy {
                scope,
                field: "disk.encryption.openbao.address",
                reason: "is required when provider = \"openbao-transit\"",
            });
        }
        if self
            .mount
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err(ConfigError::InvalidCacheEncryptionPolicy {
                scope,
                field: "disk.encryption.openbao.mount",
                reason: "is required when provider = \"openbao-transit\"",
            });
        }
        if self
            .key_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err(ConfigError::InvalidCacheEncryptionPolicy {
                scope,
                field: "disk.encryption.openbao.key_name",
                reason: "is required when provider = \"openbao-transit\"",
            });
        }
        validate_cache_encryption_secret_choice(
            scope,
            "openbao.token",
            self.token_file.as_ref(),
            self.token_credential.as_deref(),
        )
    }
}

fn validate_cache_encryption_secret_choice(
    scope: &'static str,
    field: &'static str,
    file: Option<&PathBuf>,
    credential: Option<&str>,
) -> Result<(), ConfigError> {
    let file = file.filter(|path| !path.as_os_str().is_empty());
    let credential = credential.map(str::trim).filter(|value| !value.is_empty());
    match (file.is_some(), credential.is_some()) {
        (true, false) | (false, true) => Ok(()),
        (false, false) => Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope,
            field,
            reason: "must be read from a file or systemd/container credential",
        }),
        (true, true) => Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope,
            field,
            reason: "cannot use more than one secret source",
        }),
    }
}

fn validate_cache_encryption_label(
    scope: &'static str,
    field: &'static str,
    value: &str,
) -> Result<(), ConfigError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('.')
        || value.contains("..")
        || value
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':')))
    {
        return Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope,
            field,
            reason: "must be 1-128 safe ASCII label characters",
        });
    }
    Ok(())
}

fn invalid_cache_encryption_openbao_address(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 2048
        || value.chars().any(char::is_whitespace)
        || value.contains('@')
        || value.contains('?')
        || value.contains('#')
    {
        return true;
    }
    if value.starts_with("https://") {
        let rest = value.trim_start_matches("https://");
        let authority = rest.split('/').next().unwrap_or_default();
        return authority.is_empty();
    }
    let Some(rest) = value.strip_prefix("http://") else {
        return true;
    };
    let authority = rest.split('/').next().unwrap_or_default();
    !openbao_plain_http_authority_is_loopback(authority)
}

fn openbao_plain_http_authority_is_loopback(authority: &str) -> bool {
    if authority.contains('@') {
        return false;
    }
    let host = if authority.starts_with('[') {
        let Some(end) = authority.find(']') else {
            return false;
        };
        let tail = &authority[end + 1..];
        if !tail.is_empty() && !http_authority_valid_port_tail(tail) {
            return false;
        }
        &authority[1..end]
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => {
                if host.contains(':') || !valid_u16_port(port) {
                    return false;
                }
                host
            }
            None => authority,
        }
    };
    host == "127.0.0.1" || host == "::1"
}

fn fips_allowed_local_openbao_endpoint(endpoint: &str) -> bool {
    let Some(rest) = endpoint.strip_prefix("http://") else {
        return false;
    };
    if rest.is_empty()
        || rest.contains('@')
        || rest.contains('?')
        || rest.contains('#')
        || rest
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return false;
    }
    let authority = rest
        .split_once('/')
        .map_or(rest, |(authority, _path)| authority);
    !authority.is_empty() && openbao_plain_http_authority_is_loopback(authority)
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskStorageBinConfig {
    #[serde(default = "default_cache_storage_bin_size_bytes")]
    pub bin_size_bytes: ByteSize,
    #[serde(default)]
    pub preallocate: bool,
    #[serde(default = "default_cache_storage_bin_max_open_bins")]
    pub max_open_bins: usize,
}

impl Default for CacheDiskStorageBinConfig {
    fn default() -> Self {
        Self {
            bin_size_bytes: default_cache_storage_bin_size_bytes(),
            preallocate: false,
            max_open_bins: default_cache_storage_bin_max_open_bins(),
        }
    }
}

impl CacheDiskStorageBinConfig {
    fn validate(
        &self,
        scope: &'static str,
        disk_max_size_bytes: ByteSize,
        max_object_bytes: ByteSize,
    ) -> Result<(), ConfigError> {
        let field = format!("{scope}.disk.storage_bin.bin_size_bytes");
        if self.bin_size_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidCacheTierMaxSize { field });
        }
        if self.bin_size_bytes < max_object_bytes {
            return Err(ConfigError::CacheStorageBinSmallerThanMaxObject { scope });
        }
        if self.bin_size_bytes > disk_max_size_bytes {
            return Err(ConfigError::CacheStorageBinLargerThanDiskTier { scope });
        }
        if self.max_open_bins == 0 {
            return Err(ConfigError::InvalidCacheStorageBinMaxOpenBins { scope });
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
    #[serde(default)]
    pub directory_listing: DirectoryListingConfig,
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
            directory_listing: DirectoryListingConfig::default(),
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
        self.directory_listing.validate()?;

        if self.index_files.is_empty() {
            return Err(ConfigError::EmptyIndexFiles);
        }
        validate_config_list_len(
            "web.index_files",
            self.index_files.len(),
            MAX_WEB_INDEX_FILES,
        )?;

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
    fn apply_preset_defaults(&mut self) {
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

    fn resolve_relative_paths(&mut self, base_dir: &Path) {
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

    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
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
const MAX_PHP_FPM_RETRY_METHODS: usize = 16;
const PHP_FPM_SAFE_RETRY_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "TRACE"];
const MAX_PHP_FPM_RETRY_STATUSES: usize = 100;
const MAX_PHP_FPM_TCP_UPSTREAMS: usize = 64;
const MAX_PHP_FPM_MANAGED_WORKERS: usize = 256;
const MAX_PHP_FPM_MANAGED_MAX_REQUESTS: usize = 1_000_000;
const MAX_PHP_FPM_MANAGED_MAX_SPAWN_RATE: usize = 1024;
const MAX_PHP_FPM_MANAGED_BACKLOG: i32 = 65_535;
const MAX_PHP_FPM_MANAGED_TIMEOUT_SECS: u64 = 86_400;
const MAX_PHP_FPM_SLOWLOG_TRACE_DEPTH: usize = 512;
const MAX_PHP_ALLOWED_EXTENSIONS: usize = 16;
const MAX_PHP_DENY_PATH_PREFIXES: usize = 128;
const MAX_PHP_ERROR_PAGES: usize = 64;
const MAX_PHP_HIDE_RESPONSE_HEADERS: usize = 64;
const MAX_PHP_INTERCEPT_ERROR_STATUSES: usize = 200;
const MAX_PHP_PARAMS: usize = 128;
const MAX_PHP_PARAM_NAME_BYTES: usize = 128;
const MAX_PHP_PARAM_VALUE_BYTES: usize = 16 * 1024;
const MAX_PHP_STDERR_FAILURE_PATTERNS: usize = 32;
const MAX_PHP_STDERR_FAILURE_PATTERN_BYTES: usize = 512;
const MAX_PHP_STDERR_LOG_BYTES: usize = 1024 * 1024;
const MAX_PHP_RESPONSE_CONFIG_BYTES: usize = 64 * 1024 * 1024;
const MAX_PHP_RESPONSE_HEADER_CONFIG_BYTES: usize = 1024 * 1024;

impl PhpFpmConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
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

    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
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

#[cfg(unix)]
fn validate_php_fpm_managed_config(
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

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryListingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub exact_size: bool,
    #[serde(default)]
    pub local_time: bool,
}

impl DirectoryListingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        Ok(())
    }
}

#[derive(Debug)]
pub enum ConfigLoadError {
    InvalidPath {
        path: PathBuf,
    },
    Read(std::io::Error),
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
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
            Self::Parse { path, source } => {
                write!(
                    formatter,
                    "failed to parse config {}: {source}",
                    path.display()
                )?;
                if let Some(hint) = config_parse_hint(source) {
                    write!(formatter, "\n{hint}")?;
                }
                Ok(())
            }
            Self::Validate(error) => write!(formatter, "invalid config: {error}"),
        }
    }
}

impl Error for ConfigLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidPath { .. } => None,
            Self::Read(error) => Some(error),
            Self::Parse { source, .. } => Some(source),
            Self::Validate(error) => Some(error),
        }
    }
}

fn config_parse_hint(error: &toml::de::Error) -> Option<&'static str> {
    let message = error.to_string();
    if message.contains("vhosts.proxy.error_pages.web") {
        return Some(
            "hint: proxy error pages are arrays; define [[vhosts.proxy.error_pages]] before [vhosts.proxy.error_pages.web]",
        );
    }
    if message.contains("vhosts.routes.proxy.error_pages.web") {
        return Some(
            "hint: route proxy error pages are arrays; define [[vhosts.routes.proxy.error_pages]] before [vhosts.routes.proxy.error_pages.web]",
        );
    }
    if message.contains("unknown field `vhost`") {
        return Some("hint: virtual hosts are configured with [[vhosts]], not [[vhost]]");
    }
    if message.contains("unknown field `action`") && message.contains("path_prefix") {
        return Some(
            "hint: routes select their action by defining one nested table: [vhosts.routes.proxy], [vhosts.routes.web], or [vhosts.routes.redirect]; do not set action = \"proxy\"",
        );
    }
    if message.contains("vhosts.routes.")
        && message.contains("invalid type: map, expected a sequence")
    {
        return Some(
            "hint: start each route with [[vhosts.routes]] before nested route tables such as [vhosts.routes.proxy] or [vhosts.routes.web]",
        );
    }
    if message.contains("invalid type: map, expected a sequence") {
        return Some(
            "hint: start each virtual host with [[vhosts]] before nested tables such as [vhosts.proxy]",
        );
    }
    if message.contains("[[vhosts.routes.") {
        return Some(
            "hint: route action/config tables use single-bracket tables such as [vhosts.routes.proxy], not arrays such as [[vhosts.routes.proxy]]",
        );
    }
    if message.contains("[[vhosts.proxy]]") {
        return Some(
            "hint: vhost proxy config uses [vhosts.proxy], not [[vhosts.proxy]]; proxy is a nested table inside one [[vhosts]] block",
        );
    }
    if message.contains("unknown field `certificates`") {
        return Some(
            "hint: vhost TLS uses [vhosts.tls.certificate] for one certificate pair; use global [[tls.certificates]] for additional listener certificates",
        );
    }
    None
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
    InvalidServerProxyProtocolPolicy {
        reason: &'static str,
    },
    InvalidConfigListLength {
        field: String,
        max: usize,
    },
    InvalidConfigNameLength {
        field: &'static str,
        max: usize,
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
    RemoteAdminRequiresSecureTransport {
        address: String,
    },
    UnauthenticatedAdminHealthNotLoopback {
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
    PathInspectionFailed {
        field: String,
        path: PathBuf,
        reason: String,
    },
    InvalidAdminSelfHealing {
        field: &'static str,
    },
    InvalidAdminAuthThrottle {
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
    MetricsOtlpExportNotCompiled,
    InvalidMetricsPolicy {
        field: &'static str,
        reason: &'static str,
    },
    TracingNotCompiled,
    OtlpTraceExportNotCompiled,
    InvalidTracingPolicy {
        field: &'static str,
        reason: &'static str,
    },
    InvalidCompliancePolicy {
        field: &'static str,
        reason: &'static str,
    },
    InvalidPhpConfig {
        field: &'static str,
        reason: &'static str,
    },
    PrivacyModeTracing,
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
    InvalidHeaderMutationLength {
        field: &'static str,
        operation: &'static str,
        max: usize,
    },
    InvalidHeaderTemplate {
        field: &'static str,
        name: String,
        variable: String,
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
    InvalidTlsPolicy {
        field: &'static str,
        reason: &'static str,
    },
    TlsListenerWithoutTls,
    TlsListenerWithoutStaticCertificate,
    MissingAcmeStorage,
    EmptyAcmeStorage,
    InvalidAcmeContactEmail,
    UnsupportedAcmeChallenge {
        challenge: AcmeChallenge,
    },
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
    InvalidAcmeEabCredentialName {
        issuer: String,
        field: &'static str,
        credential: String,
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
    DuplicateVhostAcmeDomain {
        scope: &'static str,
        domain: String,
    },
    MissingAcmeChallengeUpstream {
        vhost: String,
    },
    ConflictingAcmeChallengeUpstreams {
        vhost: String,
    },
    TooManyAcmeChallengeUpstreams {
        vhost: String,
        max: usize,
    },
    DuplicateAcmeChallengeUpstream {
        vhost: String,
        upstream: String,
    },
    InvalidUpstream {
        address: String,
    },
    ConflictingProxyUpstreams,
    TooManyProxyUpstreams {
        max: usize,
    },
    InvalidProxyUpstreamWeights {
        reason: &'static str,
    },
    InvalidProxyUpstreamPolicy {
        field: &'static str,
        reason: &'static str,
    },
    DuplicateProxyUpstream {
        upstream: String,
    },
    EmptyUpstreamSni,
    InvalidProxyTlsPolicy {
        reason: &'static str,
    },
    InvalidProxyTimeout {
        field: &'static str,
    },
    InvalidCompressionPolicy {
        field: &'static str,
    },
    TooManyProxyErrorPages {
        max: usize,
    },
    InvalidProxyErrorPageStatus {
        status: u16,
    },
    DuplicateProxyErrorPageStatus {
        status: u16,
    },
    InvalidProxyErrorPagePath {
        path: String,
    },
    MissingProxyErrorPageRoot {
        status: u16,
    },
    InvalidLoadBalanceMaxIterations,
    InvalidLoadBalanceSelection {
        reason: &'static str,
    },
    InvalidLoadBalanceHealthCheck {
        field: &'static str,
    },
    InvalidLoadBalancePassiveHealth {
        field: &'static str,
    },
    InvalidLoadBalanceSlowStart {
        field: &'static str,
    },
    InvalidLoadBalanceRetry {
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
    EmptyCacheContentTypes {
        scope: &'static str,
    },
    InvalidCacheContentType {
        scope: &'static str,
        content_type: String,
    },
    InvalidCacheMaxObjectBytes {
        scope: &'static str,
    },
    InvalidCacheStatusTtl {
        scope: &'static str,
        status: u16,
        ttl_secs: u32,
    },
    InvalidCacheDefaultStatusTtl {
        scope: &'static str,
    },
    InvalidCacheMinUses {
        scope: &'static str,
    },
    InvalidCacheRangePolicy {
        scope: &'static str,
        field: &'static str,
        reason: &'static str,
    },
    InvalidCacheBypassPath {
        scope: &'static str,
        path: String,
    },
    InvalidCacheBypassQueryParam {
        scope: &'static str,
        param: String,
    },
    InvalidCacheBypassQueryValue {
        scope: &'static str,
        param: String,
        value: String,
    },
    InvalidCacheBypassRequestHeaderValue {
        scope: &'static str,
        header: String,
        value: String,
    },
    InvalidCacheNoStoreResponseHeaderValue {
        scope: &'static str,
        header: String,
        value: String,
    },
    InvalidCacheBypassCookieName {
        scope: &'static str,
        name: String,
    },
    InvalidCacheBypassCookieValue {
        scope: &'static str,
        name: String,
        value: String,
    },
    InvalidCacheStaleIfErrorTtl {
        scope: &'static str,
    },
    InvalidCacheStaleWhileRevalidateTtl {
        scope: &'static str,
    },
    EmptyCacheStaleIfErrorOn {
        scope: &'static str,
    },
    InvalidCacheStaleIfErrorStatus {
        scope: &'static str,
        status: u16,
    },
    InvalidCacheVaryRequestHeader {
        scope: &'static str,
        header: String,
    },
    InvalidCacheListLength {
        scope: &'static str,
        field: &'static str,
        max: usize,
    },
    DuplicateCacheTagHeader {
        scope: &'static str,
        header: String,
    },
    InvalidCacheKeyNamespace {
        scope: &'static str,
        namespace: String,
    },
    EmptyCacheKeyParts {
        scope: &'static str,
    },
    DuplicateCacheKeyPart {
        scope: &'static str,
        part: CacheKeyPart,
    },
    MissingCacheKeyPath {
        scope: &'static str,
    },
    InvalidCacheLockTimeout {
        field: String,
    },
    InvalidCachePredictorCapacity {
        scope: &'static str,
    },
    InvalidCachePeerFillPolicy {
        scope: &'static str,
        field: &'static str,
        reason: &'static str,
    },
    InvalidCachePeerFillPeer {
        scope: &'static str,
        peer: String,
        reason: &'static str,
    },
    DuplicateCachePeerFillPeerName {
        scope: &'static str,
        name: String,
    },
    DuplicateCachePeerFillPeerUrl {
        scope: &'static str,
        url: String,
    },
    CachePeerFillNotCompiled,
    CacheEnabledWithoutStorageTier {
        scope: &'static str,
    },
    InvalidCacheTierMaxSize {
        field: String,
    },
    CacheTierSmallerThanMaxObject {
        tier: String,
    },
    CacheStorageBinLargerThanDiskTier {
        scope: &'static str,
    },
    CacheStorageBinSmallerThanMaxObject {
        scope: &'static str,
    },
    InvalidCacheStorageBinMaxOpenBins {
        scope: &'static str,
    },
    InvalidCacheEncryptionPolicy {
        scope: &'static str,
        field: &'static str,
        reason: &'static str,
    },
    InvalidCacheEncryptionCredentialName {
        scope: &'static str,
        field: &'static str,
        credential: String,
    },
    UnsupportedCacheDiskBackend {
        scope: &'static str,
        backend: &'static str,
    },
    CachePurgerNotCompiled,
    InvalidCachePurgerPolicy {
        field: &'static str,
        reason: &'static str,
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
    InvalidVhostLimit {
        vhost: String,
        field: &'static str,
    },
    InvalidAccessRule {
        field: &'static str,
        value: String,
    },
    DuplicateAccessRule {
        field: &'static str,
        value: String,
    },
    InvalidRateLimit {
        field: &'static str,
    },
    InvalidConcurrencyLimit {
        field: &'static str,
    },
    MissingVhostRedirectTarget {
        vhost: String,
    },
    VhostRedirectConflictsWithFallback {
        vhost: String,
    },
    EmptyRouteName {
        vhost: String,
    },
    InvalidRouteMatcher {
        vhost: String,
        route: String,
    },
    DuplicateFallbackRoute {
        vhost: String,
    },
    InvalidRouteStripPrefix {
        vhost: String,
        route: String,
    },
    InvalidRouteRewritePrefix {
        vhost: String,
        route: String,
    },
    InvalidRouteAction {
        vhost: String,
        route: String,
    },
    InvalidRouteLimit {
        vhost: String,
        route: String,
        field: &'static str,
    },
    InvalidRouteRedirectStatus {
        vhost: String,
        route: String,
        status: u16,
    },
    InvalidRouteRedirectTarget {
        vhost: String,
        route: String,
    },
    VhostSection {
        vhost: String,
        section: &'static str,
        source: Box<ConfigError>,
    },
    RouteSection {
        vhost: String,
        route: String,
        section: &'static str,
        source: Box<ConfigError>,
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
                    "server.default_vhost references unknown vhost {name:?}; if that vhost is defined in conf.d, set include_conf_d = true in the main config or validate the config directory instead of only the main file"
                )
            }
            Self::InvalidTrustedProxy { value } => write!(
                formatter,
                "server.trusted_proxies entries must be IP addresses or CIDR ranges, got {value:?}"
            ),
            Self::InvalidServerProxyProtocolPolicy { reason } => {
                write!(formatter, "server.proxy_protocol is invalid: {reason}")
            }
            Self::InvalidConfigListLength { field, max } => {
                write!(formatter, "{field} must contain at most {max} entries")
            }
            Self::InvalidConfigNameLength { field, max } => {
                write!(formatter, "{field} must be at most {max} bytes")
            }
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
            Self::RemoteAdminRequiresSecureTransport { address } => write!(
                formatter,
                "remote admin listener {address:?} requires admin.transport.mode = \"trusted_tls_terminator\"; keep admin.listen loopback or terminate TLS/mTLS in a trusted local sidecar"
            ),
            Self::UnauthenticatedAdminHealthNotLoopback { address } => write!(
                formatter,
                "admin.health.unauthenticated requires admin.listen to be loopback, got {address:?}"
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
                "{field} must be a safe filesystem path without parent-directory traversal, symlinked path components, or unsafe writable parents, got {}",
                path.display()
            ),
            Self::PathInspectionFailed {
                field,
                path,
                reason,
            } => write!(
                formatter,
                "{field} could not be inspected as a safe filesystem path: {} ({reason}); run the command as the Fluxheim service user or fix path permissions",
                path.display()
            ),
            Self::InvalidAdminSelfHealing { field } => {
                write!(formatter, "{field} must be within the allowed range")
            }
            Self::InvalidAdminAuthThrottle { field } => {
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
            Self::MetricsOtlpExportNotCompiled => write!(
                formatter,
                "metrics.otlp.enabled requires building Fluxheim with the metrics-otlp feature"
            ),
            Self::InvalidMetricsPolicy { field, reason } => {
                write!(formatter, "{field} is invalid: {reason}")
            }
            Self::TracingNotCompiled => write!(
                formatter,
                "tracing.enabled requires building Fluxheim with the otel-tracing feature"
            ),
            Self::OtlpTraceExportNotCompiled => write!(
                formatter,
                "tracing.otlp.enabled requires building Fluxheim with the otel-otlp feature"
            ),
            Self::InvalidTracingPolicy { field, reason } => {
                write!(formatter, "{field} is invalid: {reason}")
            }
            Self::InvalidCompliancePolicy { field, reason } => {
                write!(formatter, "{field} is invalid: {reason}")
            }
            Self::InvalidPhpConfig { field, reason } => {
                write!(formatter, "{field} is invalid: {reason}")
            }
            Self::PrivacyModeTracing => write!(
                formatter,
                "privacy-mode builds do not allow tracing.enabled = true"
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
            Self::InvalidHeaderMutationLength {
                field,
                operation,
                max,
            } => write!(
                formatter,
                "{field}.{operation} must contain at most {max} entries"
            ),
            Self::InvalidHeaderTemplate {
                field,
                name,
                variable,
            } => write!(
                formatter,
                "{field}.{name} contains unsupported dynamic header variable {{{variable}}}"
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
            Self::InvalidTlsPolicy { field, reason } => {
                write!(formatter, "{field} is invalid: {reason}")
            }
            Self::TlsListenerWithoutTls => {
                write!(formatter, "server.tls_listen requires tls.enabled = true")
            }
            Self::TlsListenerWithoutStaticCertificate => write!(
                formatter,
                "server.tls_listen requires a global certificate or a static/ACME certificate source on server.default_vhost"
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
            Self::UnsupportedAcmeChallenge { challenge } => write!(
                formatter,
                "tls.acme.challenge {challenge:?} is not supported for managed ACME yet; use \"http-01\" or \"tls-alpn-01\""
            ),
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
                "ACME issuer {issuer:?} EAB {field} must be read from an env var, file, or credential"
            ),
            Self::InvalidAcmeEabCredentialName {
                issuer,
                field,
                credential,
            } => write!(
                formatter,
                "ACME issuer {issuer:?} EAB {field} credential name {credential:?} must be a safe credential name"
            ),
            Self::ConflictingAcmeEabSecretSource { issuer, field } => write!(
                formatter,
                "ACME issuer {issuer:?} EAB {field} cannot use more than one secret source"
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
            Self::DuplicateVhostAcmeDomain { scope, domain } => write!(
                formatter,
                "{scope}.acme.domains contains duplicate domain {domain:?}"
            ),
            Self::MissingAcmeChallengeUpstream { vhost } => write!(
                formatter,
                "vhost {vhost:?} acme_challenge.enabled requires acme_challenge.upstream or acme_challenge.upstreams"
            ),
            Self::ConflictingAcmeChallengeUpstreams { vhost } => write!(
                formatter,
                "vhost {vhost:?} acme_challenge.upstream and acme_challenge.upstreams cannot both be configured"
            ),
            Self::TooManyAcmeChallengeUpstreams { vhost, max } => write!(
                formatter,
                "vhost {vhost:?} acme_challenge.upstreams must contain at most {max} entries"
            ),
            Self::DuplicateAcmeChallengeUpstream { vhost, upstream } => write!(
                formatter,
                "vhost {vhost:?} acme_challenge.upstreams contains duplicate upstream {upstream:?}"
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
            Self::TooManyProxyUpstreams { max } => write!(
                formatter,
                "proxy.upstreams must contain at most {max} entries"
            ),
            Self::InvalidProxyUpstreamWeights { reason } => {
                write!(formatter, "proxy.upstream_weights is invalid: {reason}")
            }
            Self::InvalidProxyUpstreamPolicy { field, reason } => {
                write!(formatter, "{field} is invalid: {reason}")
            }
            Self::DuplicateProxyUpstream { upstream } => write!(
                formatter,
                "proxy.upstreams contains duplicate upstream {upstream:?}"
            ),
            Self::EmptyUpstreamSni => write!(formatter, "upstream_sni cannot be empty"),
            Self::InvalidProxyTlsPolicy { reason } => {
                write!(formatter, "proxy upstream TLS policy is invalid: {reason}")
            }
            Self::InvalidProxyTimeout { field } => {
                write!(formatter, "{field} must be greater than zero")
            }
            Self::InvalidCompressionPolicy { field } => {
                write!(formatter, "{field} contains an invalid compression value")
            }
            Self::TooManyProxyErrorPages { max } => write!(
                formatter,
                "proxy.error_pages must contain at most {max} entries"
            ),
            Self::InvalidProxyErrorPageStatus { status } => write!(
                formatter,
                "proxy.error_pages.status must be an HTTP error status from 400 through 599, got {status}"
            ),
            Self::DuplicateProxyErrorPageStatus { status } => write!(
                formatter,
                "proxy.error_pages contains more than one page for status {status}"
            ),
            Self::InvalidProxyErrorPagePath { path } => write!(
                formatter,
                "proxy.error_pages.path must be an absolute internal request path, got {path:?}"
            ),
            Self::MissingProxyErrorPageRoot { status } => write!(
                formatter,
                "proxy.error_pages entry for status {status} requires web.root"
            ),
            Self::InvalidLoadBalanceMaxIterations => {
                write!(
                    formatter,
                    "proxy.load_balance.max_iterations must be greater than zero"
                )
            }
            Self::InvalidLoadBalanceSelection { reason } => {
                write!(
                    formatter,
                    "proxy.load_balance.selection is invalid: {reason}"
                )
            }
            Self::InvalidLoadBalanceHealthCheck { field } => {
                write!(formatter, "{field} must be greater than zero")
            }
            Self::InvalidLoadBalancePassiveHealth { field } => {
                write!(
                    formatter,
                    "{field} contains an invalid passive health value"
                )
            }
            Self::InvalidLoadBalanceSlowStart { field } => {
                write!(formatter, "{field} contains an invalid slow-start value")
            }
            Self::InvalidLoadBalanceRetry { field } => {
                write!(formatter, "{field} contains an invalid retry value")
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
            Self::EmptyCacheContentTypes { scope } => {
                write!(formatter, "{scope}.content_types cannot be empty")
            }
            Self::InvalidCacheContentType {
                scope,
                content_type,
            } => write!(
                formatter,
                "{scope}.content_types must contain media types such as \"image/*\" or \"text/css\", got {content_type:?}"
            ),
            Self::InvalidCacheMaxObjectBytes { scope } => {
                write!(
                    formatter,
                    "{scope}.max_object_bytes must be greater than zero"
                )
            }
            Self::InvalidCacheStatusTtl {
                scope,
                status,
                ttl_secs,
            } => write!(
                formatter,
                "{scope}.status_ttls[{status}] must use an HTTP status code from 100 to 599 and a positive TTL, got {ttl_secs}"
            ),
            Self::InvalidCacheDefaultStatusTtl { scope } => {
                write!(
                    formatter,
                    "{scope}.default_status_ttl_secs must be greater than zero"
                )
            }
            Self::InvalidCacheMinUses { scope } => {
                write!(formatter, "{scope}.min_uses must be greater than zero")
            }
            Self::InvalidCacheRangePolicy {
                scope,
                field,
                reason,
            } => write!(formatter, "{scope}.{field} is invalid: {reason}"),
            Self::InvalidCacheBypassPath { scope, path } => write!(
                formatter,
                "{scope}.bypass_path_prefixes and {scope}.bypass_path_exact must contain absolute normalized request paths, got {path:?}"
            ),
            Self::InvalidCacheBypassQueryParam { scope, param } => write!(
                formatter,
                "{scope}.bypass_query_params must contain raw query parameter names without whitespace, controls, '&', '=', '#', '?', or ';', got {param:?}"
            ),
            Self::InvalidCacheBypassQueryValue {
                scope,
                param,
                value,
            } => write!(
                formatter,
                "{scope}.bypass_query_values[{param:?}] must contain a non-empty safe raw query value without whitespace, controls, '&', '#', or ';', got {value:?}"
            ),
            Self::InvalidCacheBypassRequestHeaderValue {
                scope,
                header,
                value,
            } => write!(
                formatter,
                "{scope}.bypass_request_header_values[{header:?}] must contain a non-empty safe header value without controls, got {value:?}"
            ),
            Self::InvalidCacheNoStoreResponseHeaderValue {
                scope,
                header,
                value,
            } => write!(
                formatter,
                "{scope}.no_store_response_header_values[{header:?}] must contain a non-empty safe header value without controls, got {value:?}"
            ),
            Self::InvalidCacheBypassCookieName { scope, name } => write!(
                formatter,
                "{scope}.bypass_cookie_names must contain cookie name tokens without whitespace or separators, got {name:?}"
            ),
            Self::InvalidCacheBypassCookieValue { scope, name, value } => write!(
                formatter,
                "{scope}.bypass_cookie_values[{name:?}] must contain a safe cookie value without controls, ';', or ',', got {value:?}"
            ),
            Self::InvalidCacheStaleIfErrorTtl { scope } => {
                write!(
                    formatter,
                    "{scope}.stale_if_error_secs must be greater than zero"
                )
            }
            Self::InvalidCacheStaleWhileRevalidateTtl { scope } => {
                write!(
                    formatter,
                    "{scope}.stale_while_revalidate_secs must be greater than zero"
                )
            }
            Self::EmptyCacheStaleIfErrorOn { scope } => {
                write!(
                    formatter,
                    "{scope}.stale_if_error_on must not be empty when stale_if_error_secs is set"
                )
            }
            Self::InvalidCacheStaleIfErrorStatus { scope, status } => write!(
                formatter,
                "{scope}.stale_if_error_statuses must contain HTTP 5xx status codes, got {status}"
            ),
            Self::InvalidCacheVaryRequestHeader { scope, header } => write!(
                formatter,
                "{scope}.vary_request_headers must not include sensitive request header {header:?}; use bypass_request_headers for request-specific responses"
            ),
            Self::InvalidCacheListLength { scope, field, max } => write!(
                formatter,
                "{scope}.{field} must contain at most {max} entries"
            ),
            Self::DuplicateCacheTagHeader { scope, header } => write!(
                formatter,
                "{scope}.tag_headers must not contain duplicate response headers, got {header:?}"
            ),
            Self::InvalidCacheKeyNamespace { scope, namespace } => write!(
                formatter,
                "{scope}.key_namespace must be 1-128 characters and contain only ASCII letters, digits, '-', '_', '.', or ':', got {namespace:?}"
            ),
            Self::EmptyCacheKeyParts { scope } => {
                write!(formatter, "{scope}.key_parts must not be empty")
            }
            Self::DuplicateCacheKeyPart { scope, part } => write!(
                formatter,
                "{scope}.key_parts must not contain duplicate cache key part {part}"
            ),
            Self::MissingCacheKeyPath { scope } => {
                write!(formatter, "{scope}.key_parts must include path")
            }
            Self::InvalidCacheLockTimeout { field } => {
                write!(formatter, "{field} must be greater than zero")
            }
            Self::InvalidCachePredictorCapacity { scope } => write!(
                formatter,
                "{scope}.predictor.capacity must be between 1 and {CACHE_PREDICTOR_MAX_CAPACITY} when the predictor is enabled"
            ),
            Self::InvalidCachePeerFillPolicy {
                scope,
                field,
                reason,
            } => write!(formatter, "{scope}.{field} is invalid: {reason}"),
            Self::InvalidCachePeerFillPeer {
                scope,
                peer,
                reason,
            } => write!(
                formatter,
                "{scope}.peer_fill peer {peer:?} is invalid: {reason}"
            ),
            Self::DuplicateCachePeerFillPeerName { scope, name } => write!(
                formatter,
                "{scope}.peer_fill.peers contains duplicate peer name {name:?}"
            ),
            Self::DuplicateCachePeerFillPeerUrl { scope, url } => write!(
                formatter,
                "{scope}.peer_fill.peers contains duplicate peer base_url {url:?}"
            ),
            Self::CachePeerFillNotCompiled => write!(
                formatter,
                "cache peer_fill.enabled requires building Fluxheim with the cache feature"
            ),
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
            Self::CacheStorageBinLargerThanDiskTier { scope } => write!(
                formatter,
                "{scope}.disk.storage_bin.bin_size_bytes must not exceed {scope}.disk.max_size_bytes"
            ),
            Self::CacheStorageBinSmallerThanMaxObject { scope } => write!(
                formatter,
                "{scope}.disk.storage_bin.bin_size_bytes must be at least {scope}.max_object_bytes"
            ),
            Self::InvalidCacheStorageBinMaxOpenBins { scope } => write!(
                formatter,
                "{scope}.disk.storage_bin.max_open_bins must be greater than zero"
            ),
            Self::InvalidCacheEncryptionPolicy {
                scope,
                field,
                reason,
            } => write!(formatter, "{scope}.{field} is invalid: {reason}"),
            Self::InvalidCacheEncryptionCredentialName {
                scope,
                field,
                credential,
            } => write!(
                formatter,
                "{scope}.disk.encryption.{field} credential name {credential:?} must be a safe credential name"
            ),
            Self::UnsupportedCacheDiskBackend { scope, backend } => write!(
                formatter,
                "{scope}.disk.backend = {backend:?} is not supported by this build"
            ),
            Self::CachePurgerNotCompiled => write!(
                formatter,
                "cache_purger.enabled requires building Fluxheim with the cache feature"
            ),
            Self::InvalidCachePurgerPolicy { field, reason } => {
                write!(formatter, "{field} is invalid: {reason}")
            }
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
            Self::InvalidVhostLimit { vhost, field } => {
                write!(
                    formatter,
                    "vhost {vhost:?} {field} must be greater than zero"
                )
            }
            Self::InvalidAccessRule { field, value } => write!(
                formatter,
                "{field} entries must be IP addresses or CIDR ranges, got {value:?}"
            ),
            Self::DuplicateAccessRule { field, value } => {
                write!(formatter, "{field} contains duplicate entry {value:?}")
            }
            Self::InvalidRateLimit { field } => {
                write!(formatter, "{field} contains an invalid rate limit value")
            }
            Self::InvalidConcurrencyLimit { field } => {
                write!(
                    formatter,
                    "{field} contains an invalid concurrency limit value"
                )
            }
            Self::MissingVhostRedirectTarget { vhost } => write!(
                formatter,
                "vhost {vhost:?} redirect.enabled requires redirect.to"
            ),
            Self::VhostRedirectConflictsWithFallback { vhost } => write!(
                formatter,
                "vhost {vhost:?} redirect.enabled cannot be combined with an explicit fallback route"
            ),
            Self::EmptyRouteName { vhost } => {
                write!(
                    formatter,
                    "vhost {vhost:?} contains a route with an empty name"
                )
            }
            Self::InvalidRouteMatcher { vhost, route } => write!(
                formatter,
                "vhost {vhost:?} route {route:?} must define exactly one of path_exact, path_prefix, or fallback = true"
            ),
            Self::DuplicateFallbackRoute { vhost } => {
                write!(
                    formatter,
                    "vhost {vhost:?} defines more than one fallback route"
                )
            }
            Self::InvalidRouteStripPrefix { vhost, route } => write!(
                formatter,
                "vhost {vhost:?} route {route:?} strip_prefix must be an absolute path prefix attached to path_prefix"
            ),
            Self::InvalidRouteRewritePrefix { vhost, route } => write!(
                formatter,
                "vhost {vhost:?} route {route:?} rewrite_prefix must be an absolute path prefix attached to strip_prefix"
            ),
            Self::InvalidRouteAction { vhost, route } => write!(
                formatter,
                "vhost {vhost:?} route {route:?} must define exactly one action: redirect, proxy, or web"
            ),
            Self::InvalidRouteLimit {
                vhost,
                route,
                field,
            } => write!(
                formatter,
                "vhost {vhost:?} route {route:?} {field} must be greater than zero"
            ),
            Self::InvalidRouteRedirectStatus {
                vhost,
                route,
                status,
            } => write!(
                formatter,
                "vhost {vhost:?} route {route:?} redirect.status must be one of 301, 302, 307, or 308, got {status}"
            ),
            Self::InvalidRouteRedirectTarget { vhost, route } => write!(
                formatter,
                "vhost {vhost:?} route {route:?} redirect.to must be a safe absolute http(s) URL template"
            ),
            Self::VhostSection {
                vhost,
                section,
                source,
            } => write!(formatter, "vhost {vhost:?} {section}: {source}"),
            Self::RouteSection {
                vhost,
                route,
                section,
                source,
            } => write!(
                formatter,
                "vhost {vhost:?} route {route:?} {section}: {source}"
            ),
            Self::DuplicateVhostName { name } => write!(formatter, "duplicate vhost name {name:?}"),
            Self::DuplicateVhostHost { host } => write!(formatter, "duplicate vhost host {host:?}"),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::VhostSection { source, .. } | Self::RouteSection { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn default_listen() -> Vec<String> {
    vec!["127.0.0.1:8080".to_owned()]
}

fn default_admin_listen() -> String {
    "127.0.0.1:9090".to_owned()
}

fn default_admin_require_loopback() -> bool {
    true
}

fn default_admin_auth_throttle_enabled() -> bool {
    true
}

fn default_admin_auth_throttle_window_secs() -> u64 {
    60
}

fn default_admin_auth_throttle_per_source_failures() -> usize {
    10
}

fn default_admin_auth_throttle_global_failures() -> usize {
    100
}

fn default_admin_auth_throttle_base_lockout_secs() -> u64 {
    30
}

fn default_admin_auth_throttle_max_lockout_secs() -> u64 {
    900
}

fn default_admin_auth_throttle_max_sources() -> usize {
    4096
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

fn default_metrics_otlp_endpoint() -> String {
    "http://127.0.0.1:9090/api/v1/otlp/v1/metrics".to_owned()
}

fn default_metrics_otlp_service_name() -> String {
    "fluxheim".to_owned()
}

fn default_metrics_otlp_interval_secs() -> u64 {
    15
}

fn default_metrics_otlp_timeout_secs() -> u64 {
    2
}

fn default_otlp_trace_endpoint() -> String {
    "http://127.0.0.1:4318/v1/traces".to_owned()
}

fn default_otlp_service_name() -> String {
    "fluxheim".to_owned()
}

fn default_otlp_queue_size() -> usize {
    8192
}

fn default_otlp_timeout_secs() -> u64 {
    2
}

fn default_cache_purger_interval_secs() -> u64 {
    300
}

fn default_cache_purger_limit() -> usize {
    512
}

fn default_cache_purger_batches() -> usize {
    1
}

fn fips_allowed_local_otlp_endpoint(endpoint: &str) -> bool {
    let Some(rest) = endpoint.strip_prefix("http://") else {
        return false;
    };
    if rest.contains('@')
        || rest.contains('?')
        || rest.contains('#')
        || rest
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return false;
    }
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    !path.is_empty() && openbao_plain_http_authority_is_loopback(authority)
}

#[cfg(any(feature = "metrics-otlp", feature = "otel-otlp"))]
fn valid_http_otlp_endpoint(endpoint: &str) -> bool {
    let Some(rest) = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
    else {
        return false;
    };
    if rest.is_empty()
        || rest.contains('@')
        || rest.contains('?')
        || rest.contains('#')
        || rest
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return false;
    }
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    if authority.is_empty() || path.is_empty() {
        return false;
    }
    valid_http_authority(authority)
}

#[cfg(any(feature = "metrics-otlp", feature = "otel-otlp"))]
fn validate_otlp_ca_cert_path(field: &str, path: Option<&Path>) -> Result<(), &'static str> {
    let Some(path) = path else {
        return Ok(());
    };
    if path.as_os_str().is_empty() {
        return Err("path cannot be empty");
    }
    validate_path(field.to_owned(), Some(path)).map_err(
        |_| "path must be safe, without parent-directory traversal or symlinked components",
    )
}

#[cfg(any(feature = "metrics-otlp", feature = "otel-otlp"))]
fn warn_plaintext_remote_otlp_endpoint(field: &str, endpoint: &str) {
    if crate::otlp_http::plaintext_non_loopback_endpoint(endpoint) {
        log::warn!(
            "{field} uses plaintext HTTP to a non-loopback host; use https:// or restrict OTLP export to a local collector"
        );
    }
}

#[cfg(any(feature = "metrics-otlp", feature = "otel-otlp"))]
fn valid_http_authority(authority: &str) -> bool {
    if authority.starts_with('[') {
        let Some(end) = authority.find(']') else {
            return false;
        };
        if end <= 1 {
            return false;
        }
        let tail = &authority[end + 1..];
        return tail.is_empty() || valid_port_tail(tail);
    }

    let Some((host, port)) = authority.rsplit_once(':') else {
        return valid_http_host(authority);
    };
    valid_http_host(host) && valid_port(port)
}

#[cfg(any(feature = "metrics-otlp", feature = "otel-otlp"))]
fn valid_port_tail(tail: &str) -> bool {
    tail.strip_prefix(':').is_some_and(valid_port)
}

#[cfg(any(feature = "metrics-otlp", feature = "otel-otlp"))]
fn valid_port(port: &str) -> bool {
    port.parse::<u16>().is_ok_and(|port| port != 0)
}

#[cfg(any(feature = "metrics-otlp", feature = "otel-otlp"))]
fn valid_http_host(host: &str) -> bool {
    !host.is_empty()
        && !host.starts_with('-')
        && !host.ends_with('-')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

#[cfg(any(feature = "metrics-otlp", feature = "otel-otlp"))]
fn valid_service_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
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
                key_id_credential: None,
                hmac_key_env: Some("FLUXHEIM_ACTALIS_EAB_HMAC_KEY".to_owned()),
                hmac_key_file: None,
                hmac_key_credential: None,
            }),
        },
        AcmeIssuerConfig {
            name: "google-trust-services".to_owned(),
            directory_url: "https://dv.acme-v02.api.pki.goog/directory".to_owned(),
            eab: Some(AcmeExternalAccountBindingConfig {
                key_id_env: Some("FLUXHEIM_GTS_EAB_KID".to_owned()),
                key_id_file: None,
                key_id_credential: None,
                hmac_key_env: Some("FLUXHEIM_GTS_EAB_HMAC_KEY".to_owned()),
                hmac_key_file: None,
                hmac_key_credential: None,
            }),
        },
        AcmeIssuerConfig {
            name: "google-trust-services-staging".to_owned(),
            directory_url: "https://dv.acme-v02.test-api.pki.goog/directory".to_owned(),
            eab: Some(AcmeExternalAccountBindingConfig {
                key_id_env: Some("FLUXHEIM_GTS_STAGING_EAB_KID".to_owned()),
                key_id_file: None,
                key_id_credential: None,
                hmac_key_env: Some("FLUXHEIM_GTS_STAGING_EAB_HMAC_KEY".to_owned()),
                hmac_key_file: None,
                hmac_key_credential: None,
            }),
        },
    ]
}

fn default_upstream() -> String {
    "127.0.0.1:3000".to_owned()
}

fn disabled_proxy_config() -> ProxyConfig {
    ProxyConfig::disabled()
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

fn default_lb_health_check_path() -> String {
    "/".to_owned()
}

fn valid_health_check_path(path: &str) -> bool {
    path.len() <= 2048
        && path.starts_with('/')
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#')
}

fn valid_health_check_host(host: &str) -> bool {
    host.len() <= 255 && normalize_host(host).is_some()
}

fn default_cache_include_query() -> bool {
    true
}

fn default_cache_min_uses() -> u32 {
    1
}

fn default_cache_lock_enabled() -> bool {
    true
}

fn default_cache_lock_age_timeout_secs() -> u64 {
    30
}

fn default_cache_lock_wait_timeout_secs() -> u64 {
    30
}

fn default_cache_content_types() -> Vec<String> {
    [
        "image/*",
        "text/css",
        "text/javascript",
        "application/javascript",
        "application/wasm",
        "font/*",
        "application/font-woff",
        "application/vnd.ms-fontobject",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn default_cache_static_extensions() -> Vec<String> {
    [
        "avif", "css", "eot", "gif", "ico", "jpeg", "jpg", "js", "mjs", "otf", "png", "svg", "ttf",
        "wasm", "webp", "woff", "woff2",
    ]
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

fn default_cache_storage_bin_size_bytes() -> ByteSize {
    ByteSize::from_bytes(256 * 1024 * 1024)
}

fn default_cache_storage_bin_max_open_bins() -> usize {
    16
}

fn default_index_files() -> Vec<String> {
    vec!["index.html".to_owned()]
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

fn default_static_cache_control() -> String {
    "public, max-age=60".to_owned()
}

fn default_true() -> bool {
    true
}

fn default_hsts_max_age_secs() -> u64 {
    63_072_000
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
    vec!["x-powered-by".to_owned()]
}

fn canonical_config_source(path: &Path) -> Result<PathBuf, ConfigLoadError> {
    if existing_path_contains_symlink(path).map_err(ConfigLoadError::Read)? {
        return Err(ConfigLoadError::InvalidPath {
            path: path.to_path_buf(),
        });
    }

    let path = path.canonicalize().map_err(ConfigLoadError::Read)?;
    let metadata = fs::symlink_metadata(&path).map_err(ConfigLoadError::Read)?;
    if metadata.file_type().is_symlink() {
        return Err(ConfigLoadError::InvalidPath { path });
    }
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
        let file_type = entry.file_type().map_err(ConfigLoadError::Read)?;
        if file_type.is_symlink() || !file_type.is_file() {
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

fn config_directory_files(dir: &Path) -> Result<Vec<PathBuf>, ConfigLoadError> {
    let mut files = toml_files(dir)?;
    files.sort();

    let conf_dir = dir.join("conf.d");
    if conf_dir.try_exists().map_err(ConfigLoadError::Read)? {
        let metadata = fs::symlink_metadata(&conf_dir).map_err(ConfigLoadError::Read)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ConfigLoadError::InvalidPath { path: conf_dir });
        }

        let mut conf_files = toml_files(&conf_dir)?;
        conf_files.sort();
        files.extend(conf_files);
        if files.len() > MAX_CONFIG_DIRECTORY_FILES {
            return Err(ConfigLoadError::Read(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "config directory {} and conf.d contain more than {} TOML files",
                    dir.display(),
                    MAX_CONFIG_DIRECTORY_FILES
                ),
            )));
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
    #[cfg(unix)]
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
    valid_ip_matcher(value)
}

fn valid_ip_matcher(value: &str) -> bool {
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

fn validate_config_list_len(
    field: impl Into<String>,
    len: usize,
    max: usize,
) -> Result<(), ConfigError> {
    if len > max {
        return Err(ConfigError::InvalidConfigListLength {
            field: field.into(),
            max,
        });
    }
    Ok(())
}

fn validate_cache_list_len(
    scope: &'static str,
    field: &'static str,
    len: usize,
    max: usize,
) -> Result<(), ConfigError> {
    if len > max {
        return Err(ConfigError::InvalidCacheListLength { scope, field, max });
    }
    Ok(())
}

fn validate_optional_timeout_secs(
    field: &'static str,
    value: Option<u64>,
) -> Result<(), ConfigError> {
    if value.is_some_and(|seconds| seconds == 0) {
        return Err(ConfigError::InvalidProxyTimeout { field });
    }
    Ok(())
}

fn validate_required_timeout_secs(field: &'static str, value: u64) -> Result<(), ConfigError> {
    if value == 0 {
        return Err(ConfigError::InvalidProxyTimeout { field });
    }
    Ok(())
}

fn validate_route_path(
    _field: &'static str,
    value: &str,
    _prefix: bool,
) -> Result<(), ConfigError> {
    if !value.starts_with('/')
        || value.contains('\0')
        || value.contains('\\')
        || value.contains('?')
        || value.contains('#')
        || value.chars().any(char::is_control)
        || value.split('/').any(|segment| segment == "..")
    {
        return Err(ConfigError::InvalidRouteMatcher {
            vhost: String::new(),
            route: String::new(),
        });
    }
    Ok(())
}

fn validate_route_rewrite_prefix_path(value: &str) -> Result<(), ConfigError> {
    validate_route_path("vhosts.routes.rewrite_prefix", value, true)?;
    if value.contains('%') || value.chars().any(char::is_whitespace) {
        return Err(ConfigError::InvalidRouteMatcher {
            vhost: String::new(),
            route: String::new(),
        });
    }
    Ok(())
}

fn valid_redirect_target_template(value: &str) -> bool {
    let value = value.trim();
    if !(value.starts_with("https://") || value.starts_with("http://"))
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return false;
    }

    let expanded = value
        .replace("{uri}", "/")
        .replace("{path}", "/")
        .replace("{query}", "");
    if expanded.contains('{') || expanded.contains('}') {
        return false;
    }
    if expanded.contains("\\") {
        return false;
    }

    let Some(rest) = expanded
        .strip_prefix("https://")
        .or_else(|| expanded.strip_prefix("http://"))
    else {
        return false;
    };
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim_matches(['[', ']']);
    !authority.is_empty()
        && !authority.contains('@')
        && !authority.contains('\\')
        && !authority.chars().any(|character| {
            character.is_control() || character.is_whitespace() || matches!(character, '/' | '#')
        })
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
    credential: Option<&str>,
) -> Result<(), ConfigError> {
    let env = env.map(str::trim).filter(|value| !value.is_empty());
    let file = file.filter(|path| !path.as_os_str().is_empty());
    let credential = credential.map(str::trim).filter(|value| !value.is_empty());
    let file_field = format!("tls.acme.issuers.{issuer}.eab.{field}_file");
    validate_path(file_field.clone(), file.map(PathBuf::as_path))?;
    validate_non_world_writable_parent(file_field, file.map(PathBuf::as_path))?;

    if let Some(credential) = credential
        && !valid_credential_name(credential)
    {
        return Err(ConfigError::InvalidAcmeEabCredentialName {
            issuer: issuer.to_owned(),
            field,
            credential: credential.to_owned(),
        });
    }

    match (env.is_some(), file.is_some(), credential.is_some()) {
        (true, false, false) | (false, true, false) | (false, false, true) => Ok(()),
        (false, false, false) => Err(ConfigError::InvalidAcmeEabSecretSource {
            issuer: issuer.to_owned(),
            field,
        }),
        _ => Err(ConfigError::ConflictingAcmeEabSecretSource {
            issuer: issuer.to_owned(),
            field,
        }),
    }
}

fn valid_credential_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('.')
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
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

fn validate_php_index(index: &str) -> Result<(), ConfigError> {
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

fn validate_php_extensions(extensions: &[String]) -> Result<(), ConfigError> {
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

fn validate_php_deny_path_prefixes(prefixes: &[String]) -> Result<(), ConfigError> {
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

fn validate_php_stderr_failure_patterns(patterns: &[String]) -> Result<(), ConfigError> {
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

fn validate_php_hide_response_headers(headers: &[String]) -> Result<(), ConfigError> {
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

fn validate_php_params(params: &BTreeMap<String, String>) -> Result<(), ConfigError> {
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

fn validate_php_fpm_retry_methods(methods: &[String]) -> Result<(), ConfigError> {
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

fn validate_php_fpm_retry_statuses(statuses: &[u16]) -> Result<(), ConfigError> {
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

fn validate_php_intercept_error_statuses(statuses: &[u16]) -> Result<(), ConfigError> {
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

    match path_existing_prefix_contains_symlink(path) {
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

fn validate_non_world_writable_parent(
    field: impl Into<String>,
    path: Option<&Path>,
) -> Result<(), ConfigError> {
    let field = field.into();
    let Some(path) = path else {
        return Ok(());
    };

    #[cfg(unix)]
    match crate::fs_trust::existing_parent_has_insecure_write_permissions(path) {
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
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ConfigError::UnsafePath {
            field: field.to_owned(),
            path: path.to_path_buf(),
        });
    }
    match path_existing_prefix_contains_symlink(path) {
        Ok(true) => {
            return Err(ConfigError::UnsafePath {
                field: field.to_owned(),
                path: path.to_path_buf(),
            });
        }
        Ok(false) => {}
        Err(error) => {
            return Err(path_inspection_failed(field, path, error));
        }
    }
    #[cfg(unix)]
    match crate::fs_trust::existing_parent_has_insecure_write_permissions(path) {
        Ok(true) => {
            return Err(ConfigError::UnsafePath {
                field: field.to_owned(),
                path: path.to_path_buf(),
            });
        }
        Ok(false) => {}
        Err(error) => {
            return Err(path_inspection_failed(field, path, error));
        }
    }
    Ok(())
}

fn path_inspection_failed(
    field: impl Into<String>,
    path: &Path,
    error: std::io::Error,
) -> ConfigError {
    let reason = match error.kind() {
        std::io::ErrorKind::PermissionDenied => {
            format!("permission denied while checking path ownership and symlinks: {error}")
        }
        _ => format!("failed to check path ownership and symlinks: {error}"),
    };
    ConfigError::PathInspectionFailed {
        field: field.into(),
        path: path.to_path_buf(),
        reason,
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
    validate_header_mutation_len(field, "unset", unset.len(), MAX_HEADER_MUTATION_NAMES)?;
    validate_header_mutation_len(field, "set", set.len(), MAX_HEADER_MUTATION_NAMES)?;
    validate_header_mutation_len(field, "append", append.len(), MAX_HEADER_MUTATION_NAMES)?;

    for name in unset {
        validate_header_name(field, name)?;
    }
    for (name, value) in set {
        validate_header_name(field, name)?;
        validate_header_mutation_value(field, name, value)?;
    }
    for (name, values) in append {
        validate_header_name(field, name)?;
        validate_header_mutation_len(
            field,
            "append values",
            values.len(),
            MAX_HEADER_APPEND_VALUES,
        )?;
        for value in values.iter() {
            validate_header_mutation_value(field, name, value)?;
        }
    }

    Ok(())
}

fn validate_response_header_rewrite_rules(
    field: &'static str,
    header: &'static str,
    rules: &[ResponseHeaderRewriteRuleConfig],
) -> Result<(), ConfigError> {
    validate_header_mutation_len(
        field,
        header,
        rules.len(),
        MAX_RESPONSE_HEADER_REWRITE_RULES,
    )?;

    let mut seen = std::collections::BTreeSet::new();
    for rule in rules {
        validate_response_header_rewrite_endpoint(field, header, "from", &rule.from)?;
        validate_response_header_rewrite_endpoint(field, header, "to", &rule.to)?;
        if !seen.insert(rule.from.as_str()) {
            return Err(ConfigError::ConflictingHeaderAdd {
                field,
                name: format!("{header}.from"),
            });
        }
    }

    Ok(())
}

fn validate_response_header_rewrite_endpoint(
    field: &'static str,
    header: &'static str,
    side: &'static str,
    value: &str,
) -> Result<(), ConfigError> {
    let valid_prefix =
        value.starts_with("http://") || value.starts_with("https://") || value.starts_with('/');
    let valid_path_prefix = !value.starts_with("//");
    if value.is_empty()
        || value.len() > 2048
        || !valid_prefix
        || !valid_path_prefix
        || value.as_bytes().iter().any(|byte| {
            matches!(
                byte,
                0x00..=0x08 | 0x0a..=0x1f | 0x7f
            )
        })
    {
        return Err(ConfigError::InvalidHeaderValue {
            field,
            name: format!("{header}.{side}"),
        });
    }

    Ok(())
}

fn validate_cookie_domain_rewrite_rules(
    field: &'static str,
    rules: &[ResponseHeaderRewriteRuleConfig],
) -> Result<(), ConfigError> {
    validate_header_mutation_len(
        field,
        "cookie_domain",
        rules.len(),
        MAX_RESPONSE_HEADER_REWRITE_RULES,
    )?;

    let mut seen = std::collections::BTreeSet::new();
    for rule in rules {
        validate_cookie_domain_rewrite_endpoint(field, "from", &rule.from)?;
        validate_cookie_domain_rewrite_endpoint(field, "to", &rule.to)?;
        if !seen.insert(rule.from.to_ascii_lowercase()) {
            return Err(ConfigError::ConflictingHeaderAdd {
                field,
                name: "cookie_domain.from".to_owned(),
            });
        }
    }

    Ok(())
}

fn validate_cookie_domain_rewrite_endpoint(
    field: &'static str,
    side: &'static str,
    value: &str,
) -> Result<(), ConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed != value
        || value.len() > 255
        || value.starts_with('-')
        || value.ends_with('-')
        || value.contains("..")
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.')))
    {
        return Err(ConfigError::InvalidHeaderValue {
            field,
            name: format!("cookie_domain.{side}"),
        });
    }

    Ok(())
}

fn validate_cookie_path_rewrite_rules(
    field: &'static str,
    rules: &[ResponseHeaderRewriteRuleConfig],
) -> Result<(), ConfigError> {
    validate_header_mutation_len(
        field,
        "cookie_path",
        rules.len(),
        MAX_RESPONSE_HEADER_REWRITE_RULES,
    )?;

    let mut seen = std::collections::BTreeSet::new();
    for rule in rules {
        validate_cookie_path_rewrite_endpoint(field, "from", &rule.from)?;
        validate_cookie_path_rewrite_endpoint(field, "to", &rule.to)?;
        if !seen.insert(rule.from.as_str()) {
            return Err(ConfigError::ConflictingHeaderAdd {
                field,
                name: "cookie_path.from".to_owned(),
            });
        }
    }

    Ok(())
}

fn validate_cookie_path_rewrite_endpoint(
    field: &'static str,
    side: &'static str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 2048
        || !value.starts_with('/')
        || value.starts_with("//")
        || value
            .bytes()
            .any(|byte| matches!(byte, 0x00..=0x20 | 0x7f | b';'))
    {
        return Err(ConfigError::InvalidHeaderValue {
            field,
            name: format!("cookie_path.{side}"),
        });
    }

    Ok(())
}

fn validate_header_mutation_len(
    field: &'static str,
    operation: &'static str,
    len: usize,
    max: usize,
) -> Result<(), ConfigError> {
    if len > max {
        return Err(ConfigError::InvalidHeaderMutationLength {
            field,
            operation,
            max,
        });
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

    validate_dynamic_header_template(field, name, value)?;
    Ok(())
}

fn validate_dynamic_header_template(
    field: &'static str,
    name: &str,
    value: &str,
) -> Result<(), ConfigError> {
    let mut rest = value;
    while let Some(open) = rest.find('{') {
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            return Err(ConfigError::InvalidHeaderTemplate {
                field,
                name: name.to_owned(),
                variable: after_open.to_owned(),
            });
        };
        let variable = &after_open[..close];
        if !valid_dynamic_header_variable(variable) {
            return Err(ConfigError::InvalidHeaderTemplate {
                field,
                name: name.to_owned(),
                variable: variable.to_owned(),
            });
        }
        rest = &after_open[close + 1..];
    }

    if let Some(variable) = rest.split_once('}').map(|(before, _)| before) {
        return Err(ConfigError::InvalidHeaderTemplate {
            field,
            name: name.to_owned(),
            variable: variable.to_owned(),
        });
    }

    Ok(())
}

fn valid_dynamic_header_variable(variable: &str) -> bool {
    matches!(
        variable,
        "host" | "remote_addr" | "scheme" | "uri" | "path" | "query" | "request_id"
    ) || variable
        .strip_prefix("http.")
        .is_some_and(valid_http_header_name)
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
            candidate.trim_end_matches('.')
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

    use super::{
        AdminConfig, AdminHealthConfig, AdminHealthResponseMode, AdminRemoteTransportMode,
        AdminSelfHealingConfig, AdminTransportConfig, ByteSize, CacheConfig, CacheDiskBackend,
        CacheDiskEncryptionProvider, CacheKeyPart, CachePreset, CachePurgerConfig,
        CacheStaleErrorKind, CompressionConfig, Config, ConfigError, ConfigLoadError,
        DownstreamProxyProtocol, HeaderPolicyConfig, LoadBalanceHealthCheckProtocol, LoggingConfig,
        MetricsConfig, ProxyConfig, RateLimitMode, ServerConfig, ServerLimitsConfig,
        StaticCertificateConfig, TlsAlpnPolicy, TlsCipherSuite, TlsClientAuthMode,
        TlsCurvePreference, TlsPolicyProfile, TlsProtocolVersion, TracingConfig,
        UpstreamHttpVersion, UpstreamProxyProtocol, VhostConfig, VhostHeaderPolicyConfig,
        VhostTlsConfig, WebConfig, normalize_host, normalize_host_pattern,
        valid_dynamic_header_variable, validate_dynamic_header_template,
    };
    #[cfg(feature = "cache")]
    use super::{CachePeerConfig, CachePeerFillConfig};
    use crate::test_support::{safe_child_path, safe_relative_path, unique_temp_path};
    #[cfg(unix)]
    use crate::test_support::{unique_group_writable_child, unique_world_writable_child};
    use proptest::prelude::*;

    fn secure_test_dir(label: &str) -> PathBuf {
        let path = unique_temp_path(label);
        fs::create_dir_all(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    fn test_process_config_toml(label: &str) -> String {
        let root = secure_test_dir(label);
        format!(
            r#"
            [server.process]
            pid_file = "{}"
            upgrade_sock = "{}"
            certificate_reload_sock = "{}"
            "#,
            safe_child_path(&root, "fluxheim.pid").display(),
            safe_child_path(&root, "fluxheim-upgrade.sock").display(),
            safe_child_path(&root, "fluxheim-cert-reload.sock").display()
        )
    }

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
        assert_eq!(Config::default().headers.response.unset, ["x-powered-by"]);
        assert_eq!(Config::default().web.cache_control, "public, max-age=60");
        assert_eq!(Config::default().server.process.threads, 1);
        assert_eq!(Config::default().server.process.listener_tasks_per_fd, 1);
        assert_eq!(Config::default().server.process.max_retries, 16);
        assert!(!Config::default().compression.enabled);
        assert!(Config::default().compression.gzip);
        assert!(!Config::default().compression.zstd);
        assert!(!Config::default().compression.brotli);
        assert_eq!(
            Config::default().compression.max_output_bytes.as_u64(),
            super::DEFAULT_COMPRESSION_MAX_OUTPUT_BYTES
        );
        let default_issuers = Config::default().tls.acme.issuers;
        let issuer_names: Vec<&str> = default_issuers
            .iter()
            .map(|issuer| issuer.name.as_str())
            .collect();
        assert!(issuer_names.contains(&"google-trust-services"));
        assert!(issuer_names.contains(&"google-trust-services-staging"));
        let gts = default_issuers
            .iter()
            .find(|issuer| issuer.name == "google-trust-services")
            .unwrap();
        assert_eq!(
            gts.directory_url,
            "https://dv.acme-v02.api.pki.goog/directory"
        );
        assert_eq!(
            gts.eab.as_ref().unwrap().key_id_env.as_deref(),
            Some("FLUXHEIM_GTS_EAB_KID")
        );
        #[cfg(not(feature = "privacy-mode"))]
        assert!(Config::default().logging.access.enabled);
        #[cfg(feature = "privacy-mode")]
        assert!(!Config::default().logging.access.enabled);
    }

    #[test]
    fn compression_config_validates_bounds() {
        let config: Config = toml::from_str(
            r#"
            [compression]
            enabled = true
            gzip = true
            zstd = true
            brotli = true
            min_bytes = "2KiB"
            max_input_bytes = "4KiB"
            max_output_bytes = "8KiB"
            gzip_level = 6
            zstd_level = 5
            brotli_quality = 5
            "#,
        )
        .unwrap();

        assert_eq!(config.compression.min_bytes.as_u64(), 2048);
        assert_eq!(config.compression.max_output_bytes.as_u64(), 8192);
        assert!(config.compression.zstd);
        assert!(config.compression.brotli);
        assert_eq!(config.compression.zstd_level, 5);
        assert_eq!(config.compression.brotli_quality, 5);
        config.validate().unwrap();

        let invalid_level: Config = toml::from_str(
            r#"
            [compression]
            enabled = true
            gzip_level = 10
            "#,
        )
        .unwrap();
        assert!(matches!(
            invalid_level.validate(),
            Err(ConfigError::InvalidCompressionPolicy {
                field: "compression.gzip_level"
            })
        ));

        let invalid_zstd_level: Config = toml::from_str(
            r#"
            [compression]
            enabled = true
            zstd_level = 20
            "#,
        )
        .unwrap();
        assert!(matches!(
            invalid_zstd_level.validate(),
            Err(ConfigError::InvalidCompressionPolicy {
                field: "compression.zstd_level"
            })
        ));

        let invalid_brotli_quality: Config = toml::from_str(
            r#"
            [compression]
            enabled = true
            brotli_quality = 12
            "#,
        )
        .unwrap();
        assert!(matches!(
            invalid_brotli_quality.validate(),
            Err(ConfigError::InvalidCompressionPolicy {
                field: "compression.brotli_quality"
            })
        ));

        let invalid_bounds: Config = toml::from_str(
            r#"
            [compression]
            enabled = true
            min_bytes = "8KiB"
            max_input_bytes = "4KiB"
            "#,
        )
        .unwrap();
        assert!(matches!(
            invalid_bounds.validate(),
            Err(ConfigError::InvalidCompressionPolicy {
                field: "compression.min_bytes"
            })
        ));

        let invalid_output_bounds: Config = toml::from_str(
            r#"
            [compression]
            enabled = true
            min_bytes = "8KiB"
            max_input_bytes = "16KiB"
            max_output_bytes = "4KiB"
            "#,
        )
        .unwrap();
        assert!(matches!(
            invalid_output_bounds.validate(),
            Err(ConfigError::InvalidCompressionPolicy {
                field: "compression.max_output_bytes"
            })
        ));

        let vhost_override: Config = toml::from_str(
            r#"
            [compression]
            enabled = false

            [[vhosts]]
            name = "docs"
            hosts = ["docs.example"]

            [vhosts.compression]
            enabled = true
            gzip = false
            zstd = true
            min_bytes = "1KiB"
            max_input_bytes = "2MiB"
            "#,
        )
        .unwrap();
        vhost_override.validate().unwrap();
        let compression = vhost_override.vhosts[0].compression.as_ref().unwrap();
        assert!(compression.enabled);
        assert!(!compression.gzip);
        assert!(compression.zstd);

        let route_override: Config = toml::from_str(
            r#"
            [compression]
            enabled = false

            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [vhosts.compression]
            enabled = false

            [[vhosts.routes]]
            name = "uploads"
            path_prefix = "/wp-content/uploads/"

            [vhosts.routes.proxy]
            upstream = "127.0.0.1:8080"

            [vhosts.routes.compression]
            enabled = true
            gzip = true
            min_bytes = "1KiB"
            max_input_bytes = "2MiB"
            "#,
        )
        .unwrap();
        route_override.validate().unwrap();
        let route_compression = route_override.vhosts[0].routes[0]
            .compression
            .as_ref()
            .unwrap();
        assert!(route_compression.enabled);
        assert!(route_compression.gzip);
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
            downstream_write_timeout_secs = 20
            downstream_min_send_rate_bytes_per_sec = 8192
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
        assert_eq!(config.proxy.downstream_write_timeout_secs, Some(20));
        assert_eq!(
            config.proxy.downstream_min_send_rate_bytes_per_sec,
            Some(8192)
        );
    }

    #[test]
    fn parses_server_process_settings() {
        let root = unique_temp_path("config-process-settings");
        fs::create_dir(&root).unwrap();
        let error_log = safe_child_path(&root, "error.log");
        let pid_file = safe_child_path(&root, "fluxheim.pid");
        let upgrade_sock = safe_child_path(&root, "fluxheim-upgrade.sock");
        let certificate_reload_sock = safe_child_path(&root, "fluxheim-cert-reload.sock");
        let config: Config = toml::from_str(&format!(
            r#"
            [server.process]
            daemon = false
            error_log = "{}"
            pid_file = "{}"
            upgrade_sock = "{}"
            certificate_reload_sock = "{}"
            threads = 4
            listener_tasks_per_fd = 2
            work_stealing = false
            upstream_keepalive_pool_size = 512
            max_retries = 8
            grace_period_seconds = 10
            graceful_shutdown_timeout_seconds = 30
            "#,
            error_log.display(),
            pid_file.display(),
            upgrade_sock.display(),
            certificate_reload_sock.display()
        ))
        .unwrap();

        assert!(!config.server.process.daemon);
        assert_eq!(
            config.server.process.error_log.as_deref(),
            Some(error_log.as_path())
        );
        assert_eq!(config.server.process.pid_file, pid_file);
        assert_eq!(config.server.process.upgrade_sock, upgrade_sock);
        assert_eq!(
            config.server.process.certificate_reload_sock,
            certificate_reload_sock
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

            [web.directory_listing]
            enabled = true
            exact_size = true
            local_time = true
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
        assert!(config.web.directory_listing.enabled);
        assert!(config.web.directory_listing.exact_size);
        assert!(config.web.directory_listing.local_time);
    }

    #[test]
    fn parses_proxy_upstream_pool() {
        let config: Config = toml::from_str(
            r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_weights = [1, 3]
            backup_upstreams = ["127.0.0.1:3002"]
            connect_timeout_secs = 5
            upstream_total_connection_timeout_secs = 10
            upstream_idle_timeout_secs = 120
            upstream_tcp_keepalive_idle_secs = 30
            upstream_tcp_keepalive_interval_secs = 10
            upstream_tcp_keepalive_count = 3
            upstream_tcp_user_timeout_ms = 15000
            upstream_tcp_recv_buffer_bytes = "1MiB"
            upstream_dscp = 46
            upstream_tcp_fast_open = true
            read_timeout_secs = 60
            send_timeout_secs = 30
            upstream_tls = true
            upstream_sni = "origin.example.test"
            upstream_verify_cert = true
            upstream_verify_hostname = true
            upstream_alternative_cn = "fallback-origin.example.test"
            upstream_ca_path = "tests/fixtures/tls/localhost-cert.pem"
            upstream_client_cert_path = "tests/fixtures/tls/localhost-cert.pem"
            upstream_client_key_path = "tests/fixtures/tls/localhost-key.pem"
            upstream_proxy_protocol = "v2"
            upstream_http_version = "http1-and-http2"
            upstream_h2_max_streams = 64
            upstream_h2_ping_interval_secs = 30

            [proxy.load_balance]
            max_iterations = 16

            [proxy.load_balance.health_check]
            enabled = true
            protocol = "http"
            interval_secs = 2
            consecutive_success = 2
            consecutive_failure = 3
            parallel = true
            path = "/healthz"
            host = "app.internal"
            expected_statuses = [200, 204]
            reuse_connection = true
            port_override = 8081

            [proxy.load_balance.slow_start]
            enabled = true
            duration_secs = 45

            [[proxy.error_pages]]
            status = 502
            path = "/502.html"

            [proxy.error_pages.web]
            root = "/srv/fluxheim/errors"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.proxy.upstreams,
            ["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()]
        );
        assert_eq!(config.proxy.upstream_weights, [1, 3]);
        assert_eq!(config.proxy.backup_upstreams, ["127.0.0.1:3002"]);
        assert_eq!(config.proxy.connect_timeout_secs, Some(5));
        assert_eq!(
            config.proxy.upstream_total_connection_timeout_secs,
            Some(10)
        );
        assert_eq!(config.proxy.upstream_idle_timeout_secs, Some(120));
        assert_eq!(config.proxy.upstream_tcp_keepalive_idle_secs, Some(30));
        assert_eq!(config.proxy.upstream_tcp_keepalive_interval_secs, Some(10));
        assert_eq!(config.proxy.upstream_tcp_keepalive_count, Some(3));
        assert_eq!(config.proxy.upstream_tcp_user_timeout_ms, Some(15000));
        assert_eq!(
            config
                .proxy
                .upstream_tcp_recv_buffer_bytes
                .map(ByteSize::as_u64),
            Some(1024 * 1024)
        );
        assert_eq!(config.proxy.upstream_dscp, Some(46));
        assert!(config.proxy.upstream_tcp_fast_open);
        assert_eq!(config.proxy.read_timeout_secs, Some(60));
        assert_eq!(config.proxy.send_timeout_secs, Some(30));
        assert!(config.proxy.upstream_tls);
        assert_eq!(
            config.proxy.upstream_sni.as_deref(),
            Some("origin.example.test")
        );
        assert!(config.proxy.upstream_verify_cert);
        assert!(config.proxy.upstream_verify_hostname);
        assert_eq!(
            config.proxy.upstream_alternative_cn.as_deref(),
            Some("fallback-origin.example.test")
        );
        assert_eq!(
            config.proxy.upstream_ca_path.as_deref(),
            Some(Path::new("tests/fixtures/tls/localhost-cert.pem"))
        );
        assert_eq!(
            config.proxy.upstream_client_cert_path.as_deref(),
            Some(Path::new("tests/fixtures/tls/localhost-cert.pem"))
        );
        assert_eq!(
            config.proxy.upstream_client_key_path.as_deref(),
            Some(Path::new("tests/fixtures/tls/localhost-key.pem"))
        );
        assert_eq!(
            config.proxy.upstream_proxy_protocol,
            UpstreamProxyProtocol::V2
        );
        assert_eq!(
            config.proxy.upstream_http_version,
            UpstreamHttpVersion::Http1AndHttp2
        );
        assert_eq!(config.proxy.upstream_h2_max_streams, Some(64));
        assert_eq!(config.proxy.upstream_h2_ping_interval_secs, Some(30));
        assert_eq!(config.proxy.error_pages.len(), 1);
        assert_eq!(config.proxy.error_pages[0].status, 502);
        assert_eq!(config.proxy.error_pages[0].path, "/502.html");
        assert_eq!(config.proxy.load_balance.max_iterations, 16);
        assert!(config.proxy.load_balance.health_check.enabled);
        assert_eq!(
            config.proxy.load_balance.health_check.protocol,
            LoadBalanceHealthCheckProtocol::Http
        );
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
        assert_eq!(config.proxy.load_balance.health_check.path, "/healthz");
        assert_eq!(
            config.proxy.load_balance.health_check.host.as_deref(),
            Some("app.internal")
        );
        assert_eq!(
            config.proxy.load_balance.health_check.expected_statuses,
            vec![200, 204]
        );
        assert!(config.proxy.load_balance.health_check.reuse_connection);
        assert_eq!(
            config.proxy.load_balance.health_check.port_override,
            Some(8081)
        );
        assert!(config.proxy.load_balance.slow_start.enabled);
        assert_eq!(config.proxy.load_balance.slow_start.duration_secs, 45);
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
    fn rejects_invalid_proxy_upstream_weights() {
        let mismatch: Config = toml::from_str(
            r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_weights = [1]
            "#,
        )
        .unwrap();
        assert!(matches!(
            mismatch.validate(),
            Err(ConfigError::InvalidProxyUpstreamWeights { .. })
        ));

        let zero: Config = toml::from_str(
            r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_weights = [1, 0]
            "#,
        )
        .unwrap();
        assert!(matches!(
            zero.validate(),
            Err(ConfigError::InvalidProxyUpstreamWeights { .. })
        ));
    }

    #[test]
    fn rejects_invalid_proxy_upstream_tls_material_policy() {
        let without_tls: Config = toml::from_str(
            r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            upstream_ca_path = "tests/fixtures/tls/localhost-cert.pem"
            "#,
        )
        .unwrap();
        assert_eq!(
            without_tls.validate(),
            Err(ConfigError::InvalidProxyTlsPolicy {
                reason: "upstream TLS trust roots or client certificates require upstream_tls = true"
            })
        );

        let incomplete_mtls: Config = toml::from_str(
            r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            upstream_tls = true
            upstream_client_cert_path = "tests/fixtures/tls/localhost-cert.pem"
            "#,
        )
        .unwrap();
        assert_eq!(
            incomplete_mtls.validate(),
            Err(ConfigError::InvalidProxyTlsPolicy {
                reason: "upstream_client_cert_path and upstream_client_key_path must be configured together"
            })
        );
    }

    #[test]
    fn rejects_invalid_proxy_upstream_policy() {
        let unknown_backup: Config = toml::from_str(
            r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            backup_upstreams = ["127.0.0.1:3999"]
            "#,
        )
        .unwrap();
        assert!(matches!(
            unknown_backup.validate(),
            Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
        ));

        let overlapping_policy: Config = toml::from_str(
            r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            backup_upstreams = ["127.0.0.1:3002"]
            drain_upstreams = ["127.0.0.1:3002"]
            "#,
        )
        .unwrap();
        assert!(matches!(
            overlapping_policy.validate(),
            Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
        ));

        let no_primary: Config = toml::from_str(
            r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            backup_upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            "#,
        )
        .unwrap();
        assert!(matches!(
            no_primary.validate(),
            Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
        ));

        let h2_options_without_h2: Config = toml::from_str(
            r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_h2_max_streams = 64
            "#,
        )
        .unwrap();
        assert!(matches!(
            h2_options_without_h2.validate(),
            Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
        ));

        let too_many_h2_streams: Config = toml::from_str(
            r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_http_version = "http2"
            upstream_h2_max_streams = 1025
            "#,
        )
        .unwrap();
        assert!(matches!(
            too_many_h2_streams.validate(),
            Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
        ));

        let zero_h2_ping_interval: Config = toml::from_str(
            r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_http_version = "http2"
            upstream_h2_ping_interval_secs = 0
            "#,
        )
        .unwrap();
        assert!(matches!(
            zero_h2_ping_interval.validate(),
            Err(ConfigError::InvalidProxyTimeout { .. })
        ));

        let zero_upstream_total_connection_timeout: Config = toml::from_str(
            r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_total_connection_timeout_secs = 0
            "#,
        )
        .unwrap();
        assert!(matches!(
            zero_upstream_total_connection_timeout.validate(),
            Err(ConfigError::InvalidProxyTimeout { .. })
        ));

        let zero_upstream_idle_timeout: Config = toml::from_str(
            r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_idle_timeout_secs = 0
            "#,
        )
        .unwrap();
        assert!(matches!(
            zero_upstream_idle_timeout.validate(),
            Err(ConfigError::InvalidProxyTimeout { .. })
        ));

        let incomplete_tcp_keepalive: Config = toml::from_str(
            r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_tcp_keepalive_idle_secs = 30
            upstream_tcp_keepalive_count = 3
            "#,
        )
        .unwrap();
        assert!(matches!(
            incomplete_tcp_keepalive.validate(),
            Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
        ));

        let invalid_tcp_keepalive_count: Config = toml::from_str(
            r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_tcp_keepalive_idle_secs = 30
            upstream_tcp_keepalive_interval_secs = 10
            upstream_tcp_keepalive_count = 0
            "#,
        )
        .unwrap();
        assert!(matches!(
            invalid_tcp_keepalive_count.validate(),
            Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
        ));

        let invalid_tcp_recv_buffer: Config = toml::from_str(
            r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_tcp_recv_buffer_bytes = "512MiB"
            "#,
        )
        .unwrap();
        assert!(matches!(
            invalid_tcp_recv_buffer.validate(),
            Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
        ));

        let invalid_dscp: Config = toml::from_str(
            r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_dscp = 64
            "#,
        )
        .unwrap();
        assert!(matches!(
            invalid_dscp.validate(),
            Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
        ));
    }

    #[test]
    fn rejects_too_many_proxy_upstreams() {
        let upstreams = (0..=super::MAX_PROXY_UPSTREAMS)
            .map(|index| format!("\"origin-{index}.example.test:8080\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [proxy]
            upstreams = [{upstreams}]
            "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::TooManyProxyUpstreams {
                max: super::MAX_PROXY_UPSTREAMS
            })
        );
    }

    #[test]
    fn rejects_duplicate_proxy_upstreams() {
        let config: Config = toml::from_str(
            r#"
            [proxy]
            upstreams = ["origin.example.test:8080", "ORIGIN.example.test:8080"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::DuplicateProxyUpstream {
                upstream: "ORIGIN.example.test:8080".to_owned()
            })
        );
    }

    #[test]
    fn rejects_inconsistent_proxy_upstream_tls_verification_policy() {
        let config: Config = toml::from_str(
            r#"
            [proxy]
            upstream_tls = true
            upstream_verify_cert = false
            upstream_verify_hostname = true
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidProxyTlsPolicy {
                reason: "upstream_verify_hostname must be false when upstream_verify_cert = false"
            })
        );
    }

    #[test]
    fn rejects_invalid_proxy_upstream_alternative_cn() {
        let config: Config = toml::from_str(
            r#"
            [proxy]
            upstream_tls = true
            upstream_alternative_cn = "*.example.test"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidProxyTlsPolicy {
                reason: "upstream_alternative_cn must not contain wildcards"
            })
        );
    }

    #[test]
    fn vhost_without_proxy_does_not_inherit_legacy_default_upstream() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "static"
            hosts = ["static.example.test"]

            [vhosts.web]
            root = "/srv/static"
            "#,
        )
        .unwrap();

        assert!(!config.vhosts[0].proxy.has_configured_upstream());
        assert_eq!(config.proxy.primary_upstream(), "127.0.0.1:3000");
    }

    #[test]
    fn rejects_zero_proxy_timeouts() {
        let config: Config = toml::from_str(
            r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            read_timeout_secs = 0
            downstream_min_send_rate_bytes_per_sec = 1
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidProxyTimeout {
                field: "proxy.read_timeout_secs"
            })
        );

        let config: Config = toml::from_str(
            r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            downstream_write_timeout_secs = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidProxyTimeout {
                field: "proxy.downstream_write_timeout_secs"
            })
        );

        let config: Config = toml::from_str(
            r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            downstream_min_send_rate_bytes_per_sec = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidProxyTimeout {
                field: "proxy.downstream_min_send_rate_bytes_per_sec"
            })
        );
    }

    #[test]
    fn rejects_invalid_proxy_error_pages() {
        let config: Config = toml::from_str(
            r#"
            [[proxy.error_pages]]
            status = 302
            path = "/302.html"

            [proxy.error_pages.web]
            root = "/srv/fluxheim/errors"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidProxyErrorPageStatus { status: 302 })
        );

        let config: Config = toml::from_str(
            r#"
            [[proxy.error_pages]]
            status = 502
            path = "/502.html"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::MissingProxyErrorPageRoot { status: 502 })
        );
    }

    #[test]
    fn rejects_too_many_proxy_error_pages() {
        let error_pages = (0..=super::MAX_PROXY_ERROR_PAGES)
            .map(|index| super::ProxyErrorPageConfig {
                status: 400 + (index % 100) as u16,
                path: format!("/error-{index}.html"),
                web: WebConfig::default(),
            })
            .collect();
        let config = Config {
            proxy: ProxyConfig {
                error_pages,
                ..ProxyConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::TooManyProxyErrorPages {
                max: super::MAX_PROXY_ERROR_PAGES
            })
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
            x_real_ip = true
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
        assert!(policy.x_real_ip);
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
    fn validates_dynamic_request_header_values() {
        let config: Config = toml::from_str(
            r#"
            [headers.request.add]
            host = "{host}"
            x-real-ip = "{remote_addr}"
            x-forwarded-proto = "{scheme}"
            x-original-uri = "{uri}"
            x-original-path = "{path}"
            x-original-query = "{query}"
            x-request-id = "{request_id}"
            upgrade = "{http.upgrade}"
            "#,
        )
        .unwrap();

        config.validate().unwrap();

        let config: Config = toml::from_str(
            r#"
            [headers.request.add]
            x-bad = "{client_ip}"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHeaderTemplate {
                field: "headers.request",
                name: "x-bad".to_owned(),
                variable: "client_ip".to_owned(),
            })
        );
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
            Err(ConfigError::VhostSection {
                vhost: "api".to_owned(),
                section: "headers",
                source: Box::new(ConfigError::ConflictingHeaderAdd {
                    field: "vhosts.headers.request",
                    name: "x-route".to_owned()
                })
            })
        );
    }

    #[test]
    fn rejects_too_many_header_unset_operations() {
        let headers = (0..=super::MAX_HEADER_MUTATION_NAMES)
            .map(|index| format!("\"x-remove-{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [headers.request]
            remove = [{headers}]
            "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHeaderMutationLength {
                field: "headers.request",
                operation: "unset",
                max: super::MAX_HEADER_MUTATION_NAMES,
            })
        );
    }

    #[test]
    fn rejects_too_many_header_set_operations() {
        let headers = (0..=super::MAX_HEADER_MUTATION_NAMES)
            .map(|index| format!("\"x-set-{index}\" = \"value\""))
            .collect::<Vec<_>>()
            .join("\n");
        let config: Config = toml::from_str(&format!(
            r#"
            [headers.response.add]
            {headers}
            "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHeaderMutationLength {
                field: "headers.response",
                operation: "set",
                max: super::MAX_HEADER_MUTATION_NAMES,
            })
        );
    }

    #[test]
    fn rejects_too_many_header_append_operations() {
        let headers = (0..=super::MAX_HEADER_MUTATION_NAMES)
            .map(|index| format!("\"x-append-{index}\" = \"value\""))
            .collect::<Vec<_>>()
            .join("\n");
        let config: Config = toml::from_str(&format!(
            r#"
            [[vhosts]]
            name = "api"
            hosts = ["api.example.test"]

            [vhosts.headers.response.append]
            {headers}
            "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::VhostSection {
                vhost: "api".to_owned(),
                section: "headers",
                source: Box::new(ConfigError::InvalidHeaderMutationLength {
                    field: "vhosts.headers.response",
                    operation: "append",
                    max: super::MAX_HEADER_MUTATION_NAMES,
                })
            })
        );
    }

    #[test]
    fn rejects_too_many_header_append_values() {
        let values = (0..=super::MAX_HEADER_APPEND_VALUES)
            .map(|index| format!("\"value-{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [headers.response.append]
            vary = [{values}]
            "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHeaderMutationLength {
                field: "headers.response",
                operation: "append values",
                max: super::MAX_HEADER_APPEND_VALUES,
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

            [[headers.response.rewrite.location]]
            from = "http://backend.internal/"
            to = "https://example.test/"

            [[headers.response.rewrite.refresh]]
            from = "/legacy/"
            to = "/"

            [[headers.response.rewrite.cookie_domain]]
            from = "backend.internal"
            to = "example.test"

            [[headers.response.rewrite.cookie_path]]
            from = "/app/"
            to = "/"
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
        assert_eq!(
            policy.rewrite.location,
            [super::ResponseHeaderRewriteRuleConfig {
                from: "http://backend.internal/".to_owned(),
                to: "https://example.test/".to_owned()
            }]
        );
        assert_eq!(
            policy.rewrite.refresh,
            [super::ResponseHeaderRewriteRuleConfig {
                from: "/legacy/".to_owned(),
                to: "/".to_owned()
            }]
        );
        assert_eq!(
            policy.rewrite.cookie_domain,
            [super::ResponseHeaderRewriteRuleConfig {
                from: "backend.internal".to_owned(),
                to: "example.test".to_owned()
            }]
        );
        assert_eq!(
            policy.rewrite.cookie_path,
            [super::ResponseHeaderRewriteRuleConfig {
                from: "/app/".to_owned(),
                to: "/".to_owned()
            }]
        );
        config.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_response_header_rewrite_rules() {
        let config: Config = toml::from_str(
            r#"
            [[headers.response.rewrite.location]]
            from = "backend.internal/"
            to = "https://example.test/"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHeaderValue {
                field: "headers.response.rewrite",
                name: "location.from".to_owned()
            })
        );

        let config: Config = toml::from_str(
            r#"
            [[headers.response.rewrite.refresh]]
            from = "https://backend.internal/"
            to = "https://example.test/"

            [[headers.response.rewrite.refresh]]
            from = "https://backend.internal/"
            to = "https://example.test/other/"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::ConflictingHeaderAdd {
                field: "headers.response.rewrite",
                name: "refresh.from".to_owned()
            })
        );

        let config: Config = toml::from_str(
            r#"
            [[headers.response.rewrite.cookie_domain]]
            from = "bad domain"
            to = "example.test"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHeaderValue {
                field: "headers.response.rewrite",
                name: "cookie_domain.from".to_owned()
            })
        );

        let config: Config = toml::from_str(
            r#"
            [[headers.response.rewrite.cookie_path]]
            from = "//backend"
            to = "/"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHeaderValue {
                field: "headers.response.rewrite",
                name: "cookie_path.from".to_owned()
            })
        );
    }

    #[test]
    fn parses_structured_hsts_response_header_policy() {
        let config: Config = toml::from_str(
            r#"
            [headers.response.hsts]
            enabled = true
            max_age_secs = 63072000
            include_subdomains = true
            preload = true
            "#,
        )
        .unwrap();

        let hsts = config.headers.response.hsts.as_ref().unwrap();
        assert_eq!(
            hsts.header_value().as_deref(),
            Some("max-age=63072000; includeSubDomains; preload")
        );
        config.validate().unwrap();
    }

    #[test]
    fn rejects_conflicting_hsts_response_header_policy() {
        let config: Config = toml::from_str(
            r#"
            [headers.response]
            strict_transport_security = "max-age=31536000"

            [headers.response.hsts]
            max_age_secs = 63072000
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidResponseHeaderValue {
                field: "headers.response.hsts"
            })
        );
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
            let pid_file =
                unique_world_writable_child("config-process-world-writable", "fluxheim.pid");
            let config: Config = toml::from_str(&format!(
                r#"
                [server.process]
                pid_file = "{}"
                "#,
                pid_file.display()
            ))
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
    fn validates_load_balance_hash_selection() {
        let config: Config = toml::from_str(
            r#"
            [proxy.load_balance]
            selection = "consistent-header-hash"
            hash_header = "x-session"
            "#,
        )
        .unwrap();
        config.validate().unwrap();

        let missing_header: Config = toml::from_str(
            r#"
            [proxy.load_balance]
            selection = "header-hash"
            "#,
        )
        .unwrap();
        assert!(matches!(
            missing_header.validate(),
            Err(ConfigError::InvalidLoadBalanceSelection { .. })
        ));

        let unused_header: Config = toml::from_str(
            r#"
            [proxy.load_balance]
            selection = "source-hash"
            hash_header = "x-session"
            "#,
        )
        .unwrap();
        assert!(matches!(
            unused_header.validate(),
            Err(ConfigError::InvalidLoadBalanceSelection { .. })
        ));

        let cookie: Config = toml::from_str(
            r#"
            [proxy.load_balance]
            selection = "cookie-hash"
            hash_cookie = "session"
            "#,
        )
        .unwrap();
        cookie.validate().unwrap();

        let missing_cookie: Config = toml::from_str(
            r#"
            [proxy.load_balance]
            selection = "consistent-cookie-hash"
            "#,
        )
        .unwrap();
        assert!(matches!(
            missing_cookie.validate(),
            Err(ConfigError::InvalidLoadBalanceSelection { .. })
        ));

        let power_of_two: Config = toml::from_str(
            r#"
            [proxy.load_balance]
            selection = "power-of-two"
            "#,
        )
        .unwrap();
        power_of_two.validate().unwrap();
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
    fn rejects_invalid_http_load_balance_health_check() {
        let config: Config = toml::from_str(
            r#"
            [proxy.load_balance.health_check]
            protocol = "http"
            path = "relative"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.path"
            })
        );
    }

    #[test]
    fn validates_load_balance_passive_health() {
        let config: Config = toml::from_str(
            r#"
            [proxy.load_balance.passive_health]
            enabled = true
            consecutive_failure = 2
            ejection_secs = 10
            failure_statuses = [500, 502, 503]
            max_latency_ms = 250
            "#,
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.proxy.load_balance.passive_health.max_latency_ms, 250);

        let invalid_status: Config = toml::from_str(
            r#"
            [proxy.load_balance.passive_health]
            enabled = true
            failure_statuses = [404]
            "#,
        )
        .unwrap();
        assert_eq!(
            invalid_status.validate(),
            Err(ConfigError::InvalidLoadBalancePassiveHealth {
                field: "proxy.load_balance.passive_health.failure_statuses"
            })
        );

        let invalid_latency: Config = toml::from_str(
            r#"
            [proxy.load_balance.passive_health]
            max_latency_ms = 600001
            "#,
        )
        .unwrap();
        assert_eq!(
            invalid_latency.validate(),
            Err(ConfigError::InvalidLoadBalancePassiveHealth {
                field: "proxy.load_balance.passive_health.max_latency_ms"
            })
        );
    }

    #[test]
    fn rejects_invalid_load_balance_slow_start() {
        let config: Config = toml::from_str(
            r#"
            [proxy.load_balance.slow_start]
            enabled = true
            duration_secs = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidLoadBalanceSlowStart {
                field: "proxy.load_balance.slow_start.duration_secs"
            })
        );
    }

    #[test]
    fn validates_load_balance_retry_policy() {
        let config: Config = toml::from_str(
            r#"
            [proxy.load_balance.retry]
            enabled = true
            max_retries = 2
            methods = ["GET", "HEAD"]
            budget_per_window = 100
            budget_window_secs = 10
            "#,
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.proxy.load_balance.retry.budget_per_window, 100);
        assert_eq!(config.proxy.load_balance.retry.budget_window_secs, 10);

        let unsafe_method: Config = toml::from_str(
            r#"
            [proxy.load_balance.retry]
            enabled = true
            methods = ["POST"]
            "#,
        )
        .unwrap();
        assert_eq!(
            unsafe_method.validate(),
            Err(ConfigError::InvalidLoadBalanceRetry {
                field: "proxy.load_balance.retry.methods"
            })
        );

        let invalid_budget: Config = toml::from_str(
            r#"
            [proxy.load_balance.retry]
            budget_window_secs = 0
            "#,
        )
        .unwrap();
        assert_eq!(
            invalid_budget.validate(),
            Err(ConfigError::InvalidLoadBalanceRetry {
                field: "proxy.load_balance.retry.budget_window_secs"
            })
        );
    }

    #[test]
    fn parses_server_limits() {
        let config: Config = toml::from_str(
            r#"
            [server]
            trusted_proxies = ["127.0.0.1", "10.0.0.0/8", "2001:db8::/32"]
            proxy_protocol = "v2"

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
        assert_eq!(config.server.proxy_protocol, DownstreamProxyProtocol::V2);
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
    fn rejects_proxy_protocol_without_trusted_proxies() {
        let config: Config = toml::from_str(
            r#"
            [server]
            proxy_protocol = "v1"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidServerProxyProtocolPolicy {
                reason: "server.proxy_protocol requires server.trusted_proxies so client identity cannot be spoofed by direct peers"
            })
        );
    }

    #[test]
    fn parses_tls_acme_config_with_actalis_eab() {
        let storage = secure_test_dir("config-actalis-acme");
        let config: Config = toml::from_str(&format!(
            r#"
            [tls]
            enabled = true
            backend = "rustls"

            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            default_issuer = "actalis"
            challenge = "http-01"
            automation = "external"

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
            storage.display()
        ))
        .unwrap();

        assert!(config.tls.enabled);
        assert_eq!(config.tls.backend, super::TlsBackend::Rustls);
        assert!(config.tls.acme.enabled);
        assert_eq!(config.tls.acme.storage, Some(storage));
        assert_eq!(config.tls.acme.default_issuer, "actalis");
        assert_eq!(config.tls.acme.challenge, super::AcmeChallenge::Http01);
        assert_eq!(
            config.tls.acme.automation,
            super::AcmeAutomationMode::External
        );
        assert_eq!(config.tls.acme.renewal.renew_before_secs, 2_592_000);
        assert!(config.tls.acme.renewal.renew_after.is_some());
        config.validate().unwrap();
    }

    #[test]
    fn accepts_tls_alpn_acme_with_rustls_tls_listener() {
        let storage = secure_test_dir("config-tls-alpn-acme");
        let config: Config = toml::from_str(&format!(
            r#"
            [server]
            tls_listen = ["127.0.0.1:8443"]

            [tls]
            enabled = true
            backend = "rustls"

            [[tls.certificates]]
            cert_path = "tests/fixtures/tls/localhost-cert.pem"
            key_path = "tests/fixtures/tls/localhost-key.pem"

            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            challenge = "tls-alpn-01"
            "#,
            storage.display()
        ))
        .unwrap();

        assert_eq!(config.tls.acme.challenge, super::AcmeChallenge::TlsAlpn01);
        config.validate().unwrap();
    }

    #[test]
    fn rejects_tls_alpn_acme_without_tls_listener() {
        let storage = secure_test_dir("config-tls-alpn-no-listener");
        let config: Config = toml::from_str(&format!(
            r#"
            [tls]
            enabled = true
            backend = "rustls"

            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            challenge = "tls-alpn-01"
            "#,
            storage.display()
        ))
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidTlsPolicy {
                field: "tls.acme.challenge",
                ..
            })
        ));
    }

    #[test]
    fn parses_tls_policy_config() {
        let config: Config = toml::from_str(
            r#"
            [tls]
            enabled = true
            profile = "modern"
            min_protocol = "tls1.3"
            alpn = "http2"
            curve_preferences = ["X25519", "CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
            "#,
        )
        .unwrap();

        assert_eq!(config.tls.profile, TlsPolicyProfile::Modern);
        assert_eq!(
            config.tls.effective_min_protocol(),
            TlsProtocolVersion::Tls13
        );
        assert_eq!(config.tls.effective_alpn(), TlsAlpnPolicy::Http2);
        assert_eq!(
            config.tls.effective_curve_preferences(),
            [
                TlsCurvePreference::X25519,
                TlsCurvePreference::P256,
                TlsCurvePreference::P384
            ]
        );
        assert_eq!(
            config.tls.effective_cipher_suites(),
            [
                TlsCipherSuite::Tls13Aes256GcmSha384,
                TlsCipherSuite::Tls13Chacha20Poly1305Sha256
            ]
        );
        config.validate().unwrap();
    }

    #[test]
    fn parses_tls_fips_config_and_requires_fips_capable_build() {
        let config: Config = toml::from_str(
            r#"
            [tls]
            enabled = true
            backend = "openssl"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = [
              "TLS_AES_256_GCM_SHA384",
              "TLS_AES_128_GCM_SHA256",
              "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ]

            [tls.fips]
            required = true
            "#,
        )
        .unwrap();

        assert!(config.tls.fips.required);
        assert_eq!(config.tls.compliance_mode().label(), "FIPS 140-3");

        #[cfg(not(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips")))]
        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTlsPolicy {
                field: "tls.fips.required",
                reason: "FIPS-required mode requires a FIPS-capable TLS backend feature such as tls-rustls-fips or tls-openssl-fips; see docs/fips.md",
            })
        );

        #[cfg(feature = "tls-openssl-fips")]
        assert_eq!(config.validate(), Ok(()));

        #[cfg(all(feature = "tls-rustls-fips", not(feature = "tls-openssl-fips")))]
        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTlsPolicy {
                field: "tls.backend",
                reason: "tls.fips.required requires a configured backend supported by this FIPS-capable build",
            })
        );
    }

    #[test]
    fn parses_tls_iso19790_config_as_required_compliance_alias() {
        let config: Config = toml::from_str(
            r#"
            [tls]
            enabled = true
            backend = "openssl"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = [
              "TLS_AES_256_GCM_SHA384",
              "TLS_AES_128_GCM_SHA256",
              "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ]

            [tls.iso19790]
            required = true
            "#,
        )
        .unwrap();

        assert!(config.tls.iso19790.required);
        assert_eq!(config.tls.compliance_mode().label(), "ISO/IEC 19790");

        #[cfg(not(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips")))]
        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTlsPolicy {
                field: "tls.iso19790.required",
                reason: "ISO/IEC 19790-required mode requires a FIPS/ISO-capable TLS backend feature such as tls-rustls-fips, tls-openssl-fips, or tls-openssl-iso19790; see docs/fips.md",
            })
        );

        #[cfg(feature = "tls-openssl-fips")]
        assert_eq!(config.validate(), Ok(()));

        #[cfg(all(feature = "tls-rustls-fips", not(feature = "tls-openssl-fips")))]
        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTlsPolicy {
                field: "tls.backend",
                reason: "tls.iso19790.required requires a configured backend supported by this FIPS/ISO-capable build",
            })
        );
    }

    #[test]
    #[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
    fn rejects_tls_fips_policy_with_unsupported_backend_for_build() {
        #[cfg(feature = "tls-openssl-fips")]
        let backend = "rustls";
        #[cfg(all(feature = "tls-rustls-fips", not(feature = "tls-openssl-fips")))]
        let backend = "openssl";
        let config: Config = toml::from_str(&format!(
            r#"
            [tls]
            enabled = true
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true
            "#
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTlsPolicy {
                field: "tls.backend",
                reason: "tls.fips.required requires a configured backend supported by this FIPS-capable build",
            })
        );
    }

    #[test]
    fn rejects_tls_fips_policy_with_non_nist_group() {
        let config: Config = toml::from_str(
            r#"
            [tls]
            curve_preferences = ["X25519", "CurveP256"]

            [tls.fips]
            required = true
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTlsPolicy {
                field: "tls.curve_preferences",
                reason: "tls.fips.required rejects non-NIST or unproven hybrid groups; use CurveP256 and/or CurveP384 until a validated provider supports more",
            })
        );
    }

    #[test]
    fn rejects_tls_fips_policy_with_chacha20_cipher() {
        let config: Config = toml::from_str(
            r#"
            [tls]
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]

            [tls.fips]
            required = true
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTlsPolicy {
                field: "tls.cipher_suites",
                reason: "tls.fips.required rejects non-FIPS cipher suites such as ChaCha20; use AES-GCM/SHA-2 suites from the selected validated provider",
            })
        );
    }

    #[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
    fn fips_capable_backend_for_tests() -> &'static str {
        #[cfg(feature = "tls-openssl-fips")]
        {
            "openssl"
        }
        #[cfg(all(not(feature = "tls-openssl-fips"), feature = "tls-rustls-fips"))]
        {
            "rustls"
        }
    }

    #[test]
    #[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
    fn fips_required_accepts_provider_backed_admin_auth() {
        let snapshot_store = secure_test_dir("config-fips-admin-snapshot-store");
        let backend = fips_capable_backend_for_tests();
        let config: Config = toml::from_str(&format!(
            r#"
            [admin]
            enabled = true
            token_env = "FLUXHEIM_ADMIN_TOKEN"
            snapshot_store = "{}"

            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true
            "#,
            snapshot_store.display()
        ))
        .unwrap();

        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    #[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
    fn fips_required_rejects_managed_acme_internal_crypto() {
        let storage = secure_test_dir("config-fips-managed-acme");
        let backend = fips_capable_backend_for_tests();
        let config: Config = toml::from_str(&format!(
            r#"
            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true

            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            "#,
            storage.display()
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCompliancePolicy {
                field: "tls.acme.enabled",
                reason: "FIPS/ISO-required mode currently rejects managed ACME because account key generation, JWS account signing, EAB handling, outbound ACME HTTPS transport, and TLS-ALPN challenge certificate generation are not fully routed through the selected validated provider; use externally issued static certificates or an externally evidenced renewal process for the FIPS evidence boundary",
            })
        );
    }

    #[test]
    #[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
    fn fips_required_can_require_disk_cache_encryption() {
        let root = secure_test_dir("config-fips-require-disk-cache-encryption");
        let backend = fips_capable_backend_for_tests();
        let config: Config = toml::from_str(&format!(
            r#"
            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true
            require_disk_cache_encryption = true

            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"
            "#,
            root.display()
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCompliancePolicy {
                field: "cache",
                reason: "FIPS/ISO-required mode requires disk cache encryption because tls.fips.require_disk_cache_encryption or tls.iso19790.require_disk_cache_encryption is enabled",
            })
        );
    }

    #[test]
    #[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
    fn fips_required_rejects_local_cache_encryption() {
        let root = secure_test_dir("config-fips-local-cache-encryption");
        let backend = fips_capable_backend_for_tests();
        let config: Config = toml::from_str(&format!(
            r#"
            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true

            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            key_credential = "fluxheim-cache-key"
            "#,
            root.display()
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCompliancePolicy {
                field: "cache",
                reason: "FIPS/ISO-required mode rejects local cache encryption because it currently uses ring AES-GCM; use provider = \"openbao-transit\" with external validation evidence or disable cache encryption",
            })
        );
    }

    #[test]
    #[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
    fn fips_required_allows_openbao_transit_cache_encryption_boundary() {
        let root = secure_test_dir("config-fips-openbao-cache-encryption");
        let backend = fips_capable_backend_for_tests();
        let config: Config = toml::from_str(&format!(
            r#"
            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true

            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "openbao-transit"

            [cache.disk.encryption.openbao]
            address = "http://127.0.0.1:8200"
            mount = "transit"
            key_name = "fluxheim-cache"
            token_credential = "openbao-token"
            "#,
            root.display()
        ))
        .unwrap();

        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    #[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
    fn fips_required_rejects_remote_openbao_transit_cache_encryption_boundary() {
        let root = secure_test_dir("config-fips-remote-openbao-cache-encryption");
        let backend = fips_capable_backend_for_tests();
        let config: Config = toml::from_str(&format!(
            r#"
            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true

            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "openbao-transit"

            [cache.disk.encryption.openbao]
            address = "https://openbao.internal.example"
            mount = "transit"
            key_name = "fluxheim-cache"
            token_credential = "openbao-token"
            "#,
            root.display()
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCompliancePolicy {
                field: "cache",
                reason: "FIPS/ISO-required mode allows OpenBao Transit only through local http://127.0.0.1 or http://[::1] loopback; remote or HTTPS OpenBao transport needs provider-aligned outbound TLS evidence first",
            })
        );
    }

    #[test]
    fn fips_otlp_local_collector_exception_accepts_loopback_http_only() {
        assert!(super::fips_allowed_local_otlp_endpoint(
            "http://127.0.0.1:4318/v1/traces"
        ));
        assert!(!super::fips_allowed_local_otlp_endpoint(
            "http://localhost/v1/traces"
        ));
        assert!(super::fips_allowed_local_otlp_endpoint(
            "http://[::1]:4318/v1/traces"
        ));
        assert!(!super::fips_allowed_local_otlp_endpoint(
            "https://127.0.0.1:4318/v1/traces"
        ));
        assert!(!super::fips_allowed_local_otlp_endpoint(
            "http://collector.example.test/v1/traces"
        ));
        assert!(!super::fips_allowed_local_otlp_endpoint(
            "http://[::1]example.test/v1/traces"
        ));
        assert!(!super::fips_allowed_local_otlp_endpoint(
            "http://127.0.0.1:0/v1/traces"
        ));
        assert!(!super::fips_allowed_local_otlp_endpoint(
            "http://127.0.0.1:4318/v1/traces?debug=true"
        ));
        assert!(!super::fips_allowed_local_otlp_endpoint(
            "http://127.0.0.1:4318/v1/traces#fragment"
        ));
        assert!(!super::fips_allowed_local_otlp_endpoint(
            "http://127.0.0.1:4318/v1/traces\n"
        ));
    }

    #[test]
    fn fips_openbao_endpoint_accepts_numeric_loopback_http_only() {
        assert!(super::fips_allowed_local_openbao_endpoint(
            "http://127.0.0.1:8200"
        ));
        assert!(super::fips_allowed_local_openbao_endpoint(
            "http://[::1]:8200"
        ));
        assert!(!super::fips_allowed_local_openbao_endpoint(
            "http://localhost:8200"
        ));
        assert!(!super::fips_allowed_local_openbao_endpoint(
            "https://127.0.0.1:8200"
        ));
        assert!(!super::fips_allowed_local_openbao_endpoint(
            "https://openbao.internal.example"
        ));
        assert!(!super::fips_allowed_local_openbao_endpoint(
            "http://[::1]attacker.example.test"
        ));
    }

    #[test]
    fn rejects_too_many_tls_curve_preferences() {
        let curve_preferences = (0..=super::MAX_TLS_CURVE_PREFERENCES)
            .map(|_| "\"X25519\"")
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [tls]
            curve_preferences = [{curve_preferences}]
            "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidConfigListLength {
                field: "tls.curve_preferences".to_owned(),
                max: super::MAX_TLS_CURVE_PREFERENCES,
            })
        );
    }

    #[test]
    fn rejects_too_many_tls_cipher_suites() {
        let cipher_suites = (0..=super::MAX_TLS_CIPHER_SUITES)
            .map(|_| "\"TLS_AES_256_GCM_SHA384\"")
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [tls]
            cipher_suites = [{cipher_suites}]
            "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidConfigListLength {
                field: "tls.cipher_suites".to_owned(),
                max: super::MAX_TLS_CIPHER_SUITES,
            })
        );
    }

    #[test]
    fn rejects_too_many_tls_certificates() {
        let certificates = (0..=super::MAX_TLS_CERTIFICATES)
            .map(|index| {
                format!(
                    r#"
                    [[tls.certificates]]
                    cert_path = "tests/fixtures/tls/cert-{index}.pem"
                    key_path = "tests/fixtures/tls/key-{index}.pem"
                    "#
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let config: Config = toml::from_str(&certificates).unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidConfigListLength {
                field: "tls.certificates".to_owned(),
                max: super::MAX_TLS_CERTIFICATES,
            })
        );
    }

    #[test]
    fn accepts_tls_client_auth_required_with_ca_bundle() {
        let config: Config = toml::from_str(
            r#"
            [tls.client_auth]
            mode = "required"
            ca_path = "tests/fixtures/tls/localhost-cert.pem"
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(config.tls.client_auth.mode, TlsClientAuthMode::Required);
        assert_eq!(
            config.tls.client_auth.ca_path.as_deref(),
            Some(std::path::Path::new(
                "tests/fixtures/tls/localhost-cert.pem"
            ))
        );
    }

    #[test]
    fn rejects_tls_client_auth_without_ca_bundle() {
        let config: Config = toml::from_str(
            r#"
            [tls.client_auth]
            mode = "optional"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTlsPolicy {
                field: "tls.client_auth.ca_path",
                reason: "tls.client_auth.mode requires a client CA bundle path"
            })
        );
    }

    #[test]
    fn rejects_tls_client_auth_with_s2n_for_now() {
        let config: Config = toml::from_str(
            r#"
            [tls]
            backend = "s2n"

            [tls.client_auth]
            mode = "required"
            ca_path = "tests/fixtures/tls/localhost-cert.pem"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTlsPolicy {
                field: "tls.client_auth.mode",
                reason: "the s2n backend has mTLS primitives, but Fluxheim does not yet expose panic-free CA bundle loading for listener client auth; use rustls, OpenSSL, or BoringSSL for client certificate authentication"
            })
        );
    }

    #[test]
    fn rejects_too_many_acme_issuers() {
        let issuers = (0..=super::MAX_ACME_ISSUERS)
            .map(|index| {
                format!(
                    r#"
                    [[tls.acme.issuers]]
                    name = "issuer-{index}"
                    directory_url = "https://issuer-{index}.example.test/acme/directory"
                    "#
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let config: Config = toml::from_str(&issuers).unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidConfigListLength {
                field: "tls.acme.issuers".to_owned(),
                max: super::MAX_ACME_ISSUERS,
            })
        );
    }

    #[test]
    fn rejects_too_many_vhost_acme_domains() {
        let storage = secure_test_dir("config-vhost-acme-too-many-domains");
        let domains = (0..=super::MAX_VHOST_ACME_DOMAINS)
            .map(|index| format!("\"alias-{index}.example.test\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            default_issuer = "letsencrypt"

            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.tls.acme]
            enabled = true
            domains = [{domains}]
            "#,
            storage.display()
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::VhostSection {
                vhost: "gateway".to_owned(),
                section: "tls",
                source: Box::new(ConfigError::InvalidConfigListLength {
                    field: "vhosts.tls.acme.domains".to_owned(),
                    max: super::MAX_VHOST_ACME_DOMAINS,
                })
            })
        );
    }

    #[test]
    fn rejects_modern_tls_policy_with_tls12_override() {
        let config: Config = toml::from_str(
            r#"
            [tls]
            profile = "modern"
            min_protocol = "tls1.2"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTlsPolicy {
                field: "tls.min_protocol",
                reason: "tls.profile = \"modern\" requires min_protocol = \"tls1.3\""
            })
        );
    }

    #[test]
    fn rejects_tls12_cipher_suites_with_tls13_minimum() {
        let config: Config = toml::from_str(
            r#"
            [tls]
            min_protocol = "tls1.3"
            cipher_suites = ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTlsPolicy {
                field: "tls.cipher_suites",
                reason: "TLS 1.2 cipher suites cannot be used when min_protocol = \"tls1.3\""
            })
        );
    }

    #[test]
    fn rejects_boringssl_explicit_tls13_cipher_suites() {
        let config: Config = toml::from_str(
            r#"
            [tls]
            backend = "boringssl"
            cipher_suites = ["TLS_AES_256_GCM_SHA384"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTlsPolicy {
                field: "tls.cipher_suites",
                reason: "the BoringSSL backend does not expose Fluxheim-controlled TLS 1.3 cipher-suite allow-lists; omit TLS 1.3 cipher_suites or use the OpenSSL/rustls backend"
            })
        );
    }

    #[test]
    fn allows_intermediate_profile_with_tls13_minimum_when_ciphers_are_implicit() {
        let config: Config = toml::from_str(
            r#"
            [tls]
            profile = "intermediate"
            min_protocol = "VersionTLS13"
            "#,
        )
        .unwrap();

        assert_eq!(config.tls.profile, TlsPolicyProfile::Intermediate);
        assert_eq!(
            config.tls.effective_min_protocol(),
            TlsProtocolVersion::Tls13
        );
        config.validate().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_tls_certificate_paths_under_world_writable_parent() {
        let cert_path = unique_world_writable_child("config-tls-world-writable", "fullchain.pem");
        let key_path =
            safe_child_path(&secure_test_dir("config-tls-world-writable-key"), "key.pem");
        let config: Config = toml::from_str(&format!(
            r#"
            [tls]
            enabled = true

            [[tls.certificates]]
            cert_path = "{}"
            key_path = "{}"
            "#,
            cert_path.display(),
            key_path.display()
        ))
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsafePath { field, .. }) if field == "tls.certificates.cert_path"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_tls_certificate_paths_under_group_writable_parent() {
        let cert_path = unique_group_writable_child("config-tls-group-writable", "fullchain.pem");
        let key_path =
            safe_child_path(&secure_test_dir("config-tls-group-writable-key"), "key.pem");
        let config: Config = toml::from_str(&format!(
            r#"
            [tls]
            enabled = true

            [[tls.certificates]]
            cert_path = "{}"
            key_path = "{}"
            "#,
            cert_path.display(),
            key_path.display()
        ))
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsafePath { field, .. }) if field == "tls.certificates.cert_path"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_acme_paths_under_world_writable_parent() {
        let storage = unique_world_writable_child("config-acme-world-writable", "acme");
        let config: Config = toml::from_str(&format!(
            r#"
            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            default_issuer = "actalis"

            [[tls.acme.issuers]]
            name = "actalis"
            directory_url = "https://acme-api.actalis.com/acme/directory"

            [tls.acme.issuers.eab]
            key_id_env = "FLUXHEIM_ACTALIS_EAB_KID"
            hmac_key_env = "FLUXHEIM_ACTALIS_EAB_HMAC_KEY"
            "#,
            storage.display()
        ))
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsafePath { field, .. }) if field == "tls.acme.storage"
        ));
    }

    #[test]
    fn path_inspection_error_mentions_permissions_and_service_user() {
        let error = ConfigError::PathInspectionFailed {
            field: "tls.acme.storage".to_owned(),
            path: PathBuf::from("/var/lib/fluxheim/acme"),
            reason: "permission denied while checking path ownership and symlinks: Permission denied (os error 13)".to_owned(),
        };
        let message = error.to_string();
        assert!(message.contains("could not be inspected"));
        assert!(message.contains("permission denied"));
        assert!(message.contains("Fluxheim service user"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_acme_eab_secret_paths_under_world_writable_parent() {
        let storage = secure_test_dir("config-acme-eab-storage");
        let key_id_file = unique_world_writable_child("config-acme-eab-world-writable", "key-id");
        let config: Config = toml::from_str(&format!(
            r#"
            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            default_issuer = "actalis"

            [[tls.acme.issuers]]
            name = "actalis"
            directory_url = "https://acme-api.actalis.com/acme/directory"

            [tls.acme.issuers.eab]
            key_id_file = "{}"
            hmac_key_env = "FLUXHEIM_ACTALIS_EAB_HMAC_KEY"
            "#,
            storage.display(),
            key_id_file.display()
        ))
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsafePath { field, .. })
                if field == "tls.acme.issuers.actalis.eab.key_id_file"
        ));
    }

    #[test]
    fn accepts_acme_eab_credential_sources() {
        let storage = secure_test_dir("config-acme-eab-credentials");
        let config: Config = toml::from_str(&format!(
            r#"
            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            default_issuer = "actalis"

            [[tls.acme.issuers]]
            name = "actalis"
            directory_url = "https://acme-api.actalis.com/acme/directory"

            [tls.acme.issuers.eab]
            key_id_credential = "actalis-eab-kid"
            hmac_key_credential = "actalis-eab-hmac-key"
            "#,
            storage.display()
        ))
        .unwrap();

        let eab = config.tls.acme.issuers[0].eab.as_ref().unwrap();
        assert_eq!(eab.key_id_credential.as_deref(), Some("actalis-eab-kid"));
        assert_eq!(
            eab.hmac_key_credential.as_deref(),
            Some("actalis-eab-hmac-key")
        );
        config.validate().unwrap();
    }

    #[test]
    fn rejects_unsafe_acme_eab_credential_source() {
        let storage = secure_test_dir("config-acme-eab-unsafe-credential");
        let config: Config = toml::from_str(&format!(
            r#"
            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            default_issuer = "actalis"

            [[tls.acme.issuers]]
            name = "actalis"
            directory_url = "https://acme-api.actalis.com/acme/directory"

            [tls.acme.issuers.eab]
            key_id_credential = "../actalis-eab-kid"
            hmac_key_credential = "actalis-eab-hmac-key"
            "#,
            storage.display()
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidAcmeEabCredentialName {
                issuer: "actalis".to_owned(),
                field: "key_id",
                credential: "../actalis-eab-kid".to_owned(),
            })
        );
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
            Err(ConfigError::VhostSection {
                vhost: "example".to_owned(),
                section: "tls",
                source: Box::new(ConfigError::TlsEnabledWithoutCertificateSource {
                    scope: "vhosts.tls"
                })
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
            Err(ConfigError::VhostSection {
                vhost: "example".to_owned(),
                section: "tls",
                source: Box::new(ConfigError::VhostAcmeWithoutGlobalAcme {
                    scope: "vhosts.tls"
                })
            })
        );
    }

    #[test]
    fn accepts_vhost_acme_inheriting_exact_hosts() {
        let storage = secure_test_dir("config-vhost-acme-exact-hosts");
        let config: Config = toml::from_str(&format!(
            r#"
            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"

            [[vhosts]]
            name = "example"
            hosts = ["example.test", "*.example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.tls.acme]
            enabled = true
            "#,
            storage.display()
        ))
        .unwrap();

        config.validate().unwrap();
    }

    #[cfg(feature = "acme")]
    #[test]
    fn accepts_tls_alias_vhost_covered_by_managed_acme_san() {
        let storage = secure_test_dir("config-vhost-acme-san-alias");
        let config: Config = toml::from_str(&format!(
            r#"
            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"

            [[vhosts]]
            name = "apex"
            hosts = ["example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.tls.acme]
            enabled = true
            domains = ["example.test", "www.example.test"]

            [[vhosts]]
            name = "www"
            hosts = ["www.example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.redirect]
            enabled = true
            to = "https://example.test{{uri}}"
            "#,
            storage.display()
        ))
        .unwrap();

        config.validate().unwrap();
    }

    #[test]
    fn rejects_duplicate_vhost_acme_domains() {
        let storage = secure_test_dir("config-vhost-acme-duplicate-domains");
        let config: Config = toml::from_str(&format!(
            r#"
            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"

            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.tls.acme]
            enabled = true
            domains = ["Example.Test", "example.test"]
            "#,
            storage.display()
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::VhostSection {
                vhost: "example".to_owned(),
                section: "tls",
                source: Box::new(ConfigError::DuplicateVhostAcmeDomain {
                    scope: "vhosts.tls",
                    domain: "example.test".to_owned(),
                })
            })
        );
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
    fn parses_php_fpm_vhost_config() {
        let root = unique_temp_path("config-php-fpm-root");
        std::fs::create_dir_all(&root).unwrap();
        let spool_dir = unique_temp_path("config-php-fpm-spool");
        std::fs::create_dir_all(&spool_dir).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            preset = "wordpress"
            enabled = true
            runtime = "php-fpm"
            root = "{}"
            resolve_root_symlink = true
            fpm_root = "/app/public"
            index = "index.php"
            allowed_extensions = ["php"]
            deny_path_prefixes = ["/wp-content/uploads/", "/uploads"]
            try_files = "wordpress"
            pass_request_headers = false
            pass_request_body = false
            stderr_log = false
            stderr_log_level = "error"
            stderr_max_bytes = "4KiB"
            stderr_failure_patterns = ["PHP Fatal error:"]
            hide_response_headers = ["x-powered-by", "x-internal"]
            ignore_origin_cache_headers = true
            intercept_error_statuses = [404, 500, 502]
            request_timeout_secs = 30
            max_request_body_bytes = "16MiB"
            request_body_spool_threshold_bytes = "1MiB"
            request_body_spool_dir = "{}"
            max_response_bytes = "8MiB"
            max_response_header_bytes = "32KiB"
            path_info = "split"

            [[vhosts.php.error_pages]]
            status = 502
            path = "/502.html"

            [vhosts.php.error_pages.web]
            root = "{}"
            index_files = ["index.html"]

            [vhosts.php.params]
            APP_ENV = "production"
            PHP_VALUE = "memory_limit=256M"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            keepalive = true
            pool_max_idle = 4
            idle_timeout_secs = 45
            max_retries = 2
            retry_timeout_secs = 5
            retry_methods = ["GET", "HEAD"]
            retry_invalid_response = true
            retry_statuses = [500, 502, 503]
            "#,
            test_process_config_toml("config-php-fpm-process"),
            root.display(),
            spool_dir.display(),
            root.display()
        ))
        .unwrap();

        config.validate().unwrap();
        let php = &config.vhosts[0].php;
        assert_eq!(php.preset, super::PhpPreset::WordPress);
        assert!(php.enabled);
        assert_eq!(php.runtime, super::PhpRuntime::PhpFpm);
        assert_eq!(php.root.as_deref(), Some(root.as_path()));
        assert!(php.resolve_root_symlink);
        assert_eq!(
            php.fpm_root.as_deref(),
            Some(std::path::Path::new("/app/public"))
        );
        assert_eq!(
            php.deny_path_prefixes,
            ["/wp-content/uploads/".to_owned(), "/uploads".to_owned()]
        );
        assert_eq!(php.try_files, super::PhpTryFilesMode::WordPress);
        assert!(!php.pass_request_headers);
        assert!(!php.pass_request_body);
        assert!(!php.stderr_log);
        assert_eq!(php.stderr_log_level, super::PhpStderrLogLevel::Error);
        assert_eq!(php.stderr_max_bytes.as_u64(), 4 * 1024);
        assert_eq!(php.stderr_failure_patterns, ["PHP Fatal error:".to_owned()]);
        assert_eq!(
            php.hide_response_headers,
            ["x-powered-by".to_owned(), "x-internal".to_owned()]
        );
        assert!(php.ignore_origin_cache_headers);
        assert_eq!(php.intercept_error_statuses, [404, 500, 502]);
        assert_eq!(php.error_pages.len(), 1);
        assert_eq!(php.error_pages[0].status, 502);
        assert_eq!(php.error_pages[0].path, "/502.html");
        assert_eq!(php.allowed_extensions, ["php"]);
        assert_eq!(
            php.max_request_body_bytes.unwrap().as_u64(),
            16 * 1024 * 1024
        );
        assert_eq!(
            php.request_body_spool_threshold_bytes.unwrap().as_u64(),
            1024 * 1024
        );
        assert_eq!(
            php.request_body_spool_dir.as_deref(),
            Some(spool_dir.as_path())
        );
        assert_eq!(php.max_response_bytes.as_u64(), 8 * 1024 * 1024);
        assert_eq!(php.max_response_header_bytes.as_u64(), 32 * 1024);
        assert_eq!(php.path_info, super::PhpPathInfoMode::Split);
        assert_eq!(
            php.params.get("APP_ENV").map(String::as_str),
            Some("production")
        );
        assert_eq!(
            php.params.get("PHP_VALUE").map(String::as_str),
            Some("memory_limit=256M")
        );
        assert_eq!(php.fpm.tcp.as_deref(), Some("127.0.0.1:9000"));
        assert!(php.fpm.tcp_upstreams.is_empty());
        assert!(php.fpm.keepalive);
        assert_eq!(php.fpm.pool_max_idle, 4);
        assert_eq!(php.fpm.idle_timeout_secs, 45);
        assert_eq!(php.fpm.max_retries, 2);
        assert_eq!(php.fpm.retry_timeout_secs, Some(5));
        assert_eq!(php.fpm.retry_methods, ["GET", "HEAD"]);
        assert!(php.fpm.retry_invalid_response);
        assert_eq!(php.fpm.retry_statuses, [500, 502, 503]);

        let mut wordpress_php = php.clone();
        wordpress_php.apply_preset_defaults();
        assert_eq!(wordpress_php.try_files, super::PhpTryFilesMode::WordPress);
        assert!(
            wordpress_php
                .deny_path_prefixes
                .contains(&"/wp-content/uploads/".to_owned())
        );
        assert!(
            wordpress_php
                .deny_path_prefixes
                .contains(&"/files/".to_owned())
        );
    }

    #[test]
    fn parses_php_fpm_tcp_upstreams() {
        let root = unique_temp_path("config-php-fpm-upstreams-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp_upstreams = ["127.0.0.1:9000", "127.0.0.1:9001"]
            "#,
            test_process_config_toml("config-php-fpm-upstreams-process"),
            root.display()
        ))
        .unwrap();

        config.validate().unwrap();
        assert_eq!(
            config.vhosts[0].php.fpm.tcp_upstreams,
            ["127.0.0.1:9000".to_owned(), "127.0.0.1:9001".to_owned()]
        );
    }

    #[cfg(unix)]
    #[test]
    fn parses_managed_php_fpm_config() {
        let root = secure_test_dir("config-php-fpm-managed-root");
        let socket_dir = secure_test_dir("config-php-fpm-managed-socket");
        let session_dir = secure_test_dir("config-php-fpm-managed-session");
        let upload_dir = secure_test_dir("config-php-fpm-managed-upload");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            mode = "managed"
            php_fpm_binary = "/bin/sh"
            socket_dir = "{}"
            workers = 4
            max_requests_per_worker = 250
            process_manager = "dynamic"
            start_servers = 2
            min_spare_servers = 1
            max_spare_servers = 3
            max_spawn_rate = 8
            listen_backlog = 128
            listen_owner = "fluxheim"
            listen_group = "php"
            listen_mode = "0660"
            request_terminate_timeout_secs = 30
            request_terminate_timeout_track_finished = true
            request_slowlog_timeout_secs = 5
            request_slowlog_trace_depth = 16
            decorate_workers_output = false
            session_save_path = "{}"
            upload_tmp_dir = "{}"
            user = "fluxheim"
            group = "fluxheim"
            "#,
            test_process_config_toml("config-php-fpm-managed-process"),
            root.display(),
            socket_dir.display(),
            session_dir.display(),
            upload_dir.display()
        ))
        .unwrap();

        config.validate().unwrap();
        let php = &config.vhosts[0].php;
        assert_eq!(php.fpm.mode, super::PhpFpmMode::Managed);
        assert_eq!(
            php.fpm.php_fpm_binary.as_deref(),
            Some(Path::new("/bin/sh"))
        );
        assert_eq!(php.fpm.socket_dir.as_deref(), Some(socket_dir.as_path()));
        assert_eq!(php.fpm.workers, 4);
        assert_eq!(php.fpm.max_requests_per_worker, 250);
        assert_eq!(
            php.fpm.process_manager,
            super::PhpFpmProcessManager::Dynamic
        );
        assert_eq!(php.fpm.start_servers, Some(2));
        assert_eq!(php.fpm.min_spare_servers, Some(1));
        assert_eq!(php.fpm.max_spare_servers, Some(3));
        assert_eq!(php.fpm.max_spawn_rate, Some(8));
        assert_eq!(php.fpm.listen_backlog, Some(128));
        assert_eq!(php.fpm.listen_owner.as_deref(), Some("fluxheim"));
        assert_eq!(php.fpm.listen_group.as_deref(), Some("php"));
        assert_eq!(php.fpm.listen_mode.as_deref(), Some("0660"));
        assert_eq!(php.fpm.request_terminate_timeout_secs, Some(30));
        assert!(php.fpm.request_terminate_timeout_track_finished);
        assert_eq!(php.fpm.request_slowlog_timeout_secs, Some(5));
        assert_eq!(php.fpm.request_slowlog_trace_depth, 16);
        assert!(!php.fpm.decorate_workers_output);
        assert_eq!(
            php.fpm.session_save_path.as_deref(),
            Some(session_dir.as_path())
        );
        assert_eq!(
            php.fpm.upload_tmp_dir.as_deref(),
            Some(upload_dir.as_path())
        );
        assert_eq!(php.fpm.user.as_deref(), Some("fluxheim"));
        assert_eq!(php.fpm.group.as_deref(), Some("fluxheim"));
        assert!(php.fpm.socket.is_none());
        assert!(php.fpm.tcp.is_none());
        assert!(php.fpm.tcp_upstreams.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_managed_php_fpm_dynamic_without_spare_bounds() {
        let root = secure_test_dir("config-php-fpm-managed-dynamic-root");
        let socket_dir = secure_test_dir("config-php-fpm-managed-dynamic-socket");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            mode = "managed"
            php_fpm_binary = "/bin/sh"
            socket_dir = "{}"
            process_manager = "dynamic"
            "#,
            test_process_config_toml("config-php-fpm-managed-dynamic-process"),
            root.display(),
            socket_dir.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.fpm.min_spare_servers"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_managed_php_fpm_dynamic_inverted_spare_bounds() {
        let root = secure_test_dir("config-php-fpm-managed-dynamic-inverted-root");
        let socket_dir = secure_test_dir("config-php-fpm-managed-dynamic-inverted-socket");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            mode = "managed"
            php_fpm_binary = "/bin/sh"
            socket_dir = "{}"
            workers = 4
            process_manager = "dynamic"
            min_spare_servers = 3
            max_spare_servers = 2
            "#,
            test_process_config_toml("config-php-fpm-managed-dynamic-inverted-process"),
            root.display(),
            socket_dir.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.fpm.max_spare_servers"), "{error}");
        assert!(error.contains("min_spare_servers"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_managed_php_fpm_with_external_endpoint() {
        let root = secure_test_dir("config-php-fpm-managed-endpoint-root");
        let socket_dir = secure_test_dir("config-php-fpm-managed-endpoint-socket");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            mode = "managed"
            php_fpm_binary = "/bin/sh"
            socket_dir = "{}"
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-fpm-managed-endpoint-process"),
            root.display(),
            socket_dir.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.fpm.mode"), "{error}");
        assert!(error.contains("private socket"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_managed_php_fpm_user_without_group() {
        let root = secure_test_dir("config-php-fpm-managed-user-root");
        let socket_dir = secure_test_dir("config-php-fpm-managed-user-socket");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            mode = "managed"
            php_fpm_binary = "/bin/sh"
            socket_dir = "{}"
            user = "fluxheim"
            "#,
            test_process_config_toml("config-php-fpm-managed-user-process"),
            root.display(),
            socket_dir.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.fpm.user"), "{error}");
        assert!(error.contains("user and group"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_managed_php_fpm_listen_owner_without_group() {
        let root = secure_test_dir("config-php-fpm-managed-listen-owner-root");
        let socket_dir = secure_test_dir("config-php-fpm-managed-listen-owner-socket");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            mode = "managed"
            php_fpm_binary = "/bin/sh"
            socket_dir = "{}"
            listen_owner = "fluxheim"
            "#,
            test_process_config_toml("config-php-fpm-managed-listen-owner-process"),
            root.display(),
            socket_dir.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.fpm.listen_owner"), "{error}");
        assert!(error.contains("listen_owner and listen_group"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_managed_php_fpm_unsafe_listen_mode() {
        let root = secure_test_dir("config-php-fpm-managed-listen-mode-root");
        let socket_dir = secure_test_dir("config-php-fpm-managed-listen-mode-socket");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            mode = "managed"
            php_fpm_binary = "/bin/sh"
            socket_dir = "{}"
            listen_mode = "0666"
            "#,
            test_process_config_toml("config-php-fpm-managed-listen-mode-process"),
            root.display(),
            socket_dir.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.fpm.listen_mode"), "{error}");
        assert!(error.contains("0600"), "{error}");
    }

    #[test]
    fn rejects_external_php_fpm_with_managed_fields() {
        let root = secure_test_dir("config-php-fpm-external-managed-root");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            user = "fluxheim"
            "#,
            test_process_config_toml("config-php-fpm-external-managed-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.fpm.mode"), "{error}");
        assert!(error.contains("managed php-fpm fields"), "{error}");
    }

    #[test]
    fn rejects_too_many_php_fpm_tcp_upstreams() {
        let root = unique_temp_path("config-php-fpm-too-many-upstreams-root");
        std::fs::create_dir_all(&root).unwrap();
        let upstreams = (0..=super::MAX_PHP_FPM_TCP_UPSTREAMS)
            .map(|index| format!("\"127.0.0.1:{}\"", 9000 + index))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp_upstreams = [{}]
            "#,
            test_process_config_toml("config-php-fpm-too-many-upstreams-process"),
            root.display(),
            upstreams,
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.fpm.tcp_upstreams"), "{error}");
        assert!(error.contains("at most 64 upstreams"), "{error}");
    }

    #[test]
    fn rejects_duplicate_php_fpm_tcp_upstreams() {
        let root = unique_temp_path("config-php-fpm-duplicate-upstreams-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp_upstreams = ["php-fpm-a:9000", "PHP-FPM-A:9000"]
            "#,
            test_process_config_toml("config-php-fpm-duplicate-upstreams-process"),
            root.display(),
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.fpm.tcp_upstreams"), "{error}");
        assert!(error.contains("duplicate upstreams"), "{error}");
    }

    #[test]
    fn rejects_mixed_php_fpm_endpoint_modes() {
        let root = unique_temp_path("config-php-fpm-mixed-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            tcp_upstreams = ["127.0.0.1:9001"]
            "#,
            test_process_config_toml("config-php-fpm-mixed-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("socket, tcp, or tcp_upstreams"), "{error}");
    }

    #[test]
    fn rejects_incomplete_php_request_body_spool_config() {
        let root = unique_temp_path("config-php-incomplete-spool-root");
        let spool_dir = unique_temp_path("config-php-incomplete-spool-dir");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&spool_dir).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            request_body_spool_threshold_bytes = "1MiB"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-spool-threshold-without-dir-process"),
            root.display(),
        ))
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.request_body_spool_dir"), "{error}");

        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            request_body_spool_dir = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-spool-dir-without-threshold-process"),
            root.display(),
            spool_dir.display(),
        ))
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("php.request_body_spool_threshold_bytes"),
            "{error}"
        );
    }

    #[test]
    fn rejects_php_request_body_spool_threshold_at_or_above_body_limit() {
        let root = unique_temp_path("config-php-spool-threshold-over-limit-root");
        let spool_dir = unique_temp_path("config-php-spool-threshold-over-limit-dir");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&spool_dir).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            max_request_body_bytes = "8MiB"
            request_body_spool_threshold_bytes = "8MiB"
            request_body_spool_dir = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-spool-threshold-over-limit-process"),
            root.display(),
            spool_dir.display(),
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("php.request_body_spool_threshold_bytes"),
            "{error}"
        );
        assert!(
            error.contains("less than php.max_request_body_bytes"),
            "{error}"
        );
    }

    #[test]
    fn rejects_php_request_body_spool_path_that_is_not_directory() {
        let root = unique_temp_path("config-php-spool-file-root");
        let spool_path = unique_temp_path("config-php-spool-file");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&spool_path, b"not a directory").unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            request_body_spool_threshold_bytes = "1MiB"
            request_body_spool_dir = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-spool-file-process"),
            root.display(),
            spool_path.display(),
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.request_body_spool_dir"), "{error}");
        assert!(error.contains("must be a directory"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_php_request_body_spool_dir_with_insecure_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_temp_path("config-php-spool-insecure-root");
        let spool_dir = unique_temp_path("config-php-spool-insecure-dir");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&spool_dir).unwrap();
        std::fs::set_permissions(&spool_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            request_body_spool_threshold_bytes = "1MiB"
            request_body_spool_dir = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-spool-insecure-process"),
            root.display(),
            spool_dir.display(),
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.request_body_spool_dir"), "{error}");
    }

    #[test]
    fn rejects_zero_php_response_limit() {
        let root = unique_temp_path("config-php-zero-response-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            max_response_bytes = 0

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-zero-response-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.max_response_bytes"), "{error}");
    }

    #[test]
    fn rejects_excessive_php_response_limit() {
        let root = unique_temp_path("config-php-excessive-response-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            max_response_bytes = "65MiB"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-excessive-response-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.max_response_bytes"), "{error}");
        assert!(error.contains("less than or equal to 64MiB"), "{error}");
    }

    #[test]
    fn rejects_zero_php_response_header_limit() {
        let root = unique_temp_path("config-php-zero-response-header-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            max_response_header_bytes = 0

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-zero-response-header-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.max_response_header_bytes"), "{error}");
    }

    #[test]
    fn rejects_excessive_php_response_header_limit() {
        let root = unique_temp_path("config-php-excessive-response-header-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            max_response_header_bytes = "2MiB"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-excessive-response-header-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.max_response_header_bytes"), "{error}");
    }

    #[test]
    fn rejects_zero_php_stderr_limit() {
        let root = unique_temp_path("config-php-zero-stderr-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            stderr_max_bytes = 0

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-zero-stderr-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.stderr_max_bytes"), "{error}");
    }

    #[test]
    fn rejects_invalid_php_stderr_failure_pattern() {
        let root = unique_temp_path("config-php-bad-stderr-pattern-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            stderr_failure_patterns = ["PHP\nFatal"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-bad-stderr-pattern-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.stderr_failure_patterns"), "{error}");
    }

    #[test]
    fn rejects_too_many_php_stderr_failure_patterns() {
        let root = unique_temp_path("config-php-many-stderr-patterns-root");
        std::fs::create_dir_all(&root).unwrap();
        let patterns = (0..=super::MAX_PHP_STDERR_FAILURE_PATTERNS)
            .map(|index| format!("\"fatal-{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            stderr_failure_patterns = [{}]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-many-stderr-patterns-process"),
            root.display(),
            patterns,
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.stderr_failure_patterns"), "{error}");
        assert!(error.contains("at most 32 patterns"), "{error}");
    }

    #[test]
    fn rejects_invalid_php_hidden_response_header() {
        let root = unique_temp_path("config-php-bad-hidden-header-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            hide_response_headers = ["bad header"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-bad-hidden-header-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.hide_response_headers"), "{error}");
    }

    #[test]
    fn rejects_duplicate_php_hidden_response_header() {
        let root = unique_temp_path("config-php-duplicate-hidden-header-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            hide_response_headers = ["x-powered-by", "X-Powered-By"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-duplicate-hidden-header-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.hide_response_headers"), "{error}");
        assert!(error.contains("duplicate headers"), "{error}");
    }

    #[test]
    fn rejects_too_many_php_hidden_response_headers() {
        let root = unique_temp_path("config-php-many-hidden-headers-root");
        std::fs::create_dir_all(&root).unwrap();
        let headers = (0..=super::MAX_PHP_HIDE_RESPONSE_HEADERS)
            .map(|index| format!("\"x-hidden-{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            hide_response_headers = [{}]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-many-hidden-headers-process"),
            root.display(),
            headers,
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.hide_response_headers"), "{error}");
        assert!(error.contains("at most 64 headers"), "{error}");
    }

    #[test]
    fn rejects_invalid_php_intercept_error_status() {
        let root = unique_temp_path("config-php-bad-intercept-status-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            intercept_error_statuses = [302]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-bad-intercept-status-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.intercept_error_statuses"), "{error}");
    }

    #[test]
    fn rejects_duplicate_php_intercept_error_status() {
        let root = unique_temp_path("config-php-duplicate-intercept-status-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            intercept_error_statuses = [500, 500]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-duplicate-intercept-status-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.intercept_error_statuses"), "{error}");
    }

    #[test]
    fn rejects_too_many_php_intercept_error_statuses() {
        let root = unique_temp_path("config-php-many-intercept-statuses-root");
        std::fs::create_dir_all(&root).unwrap();
        let statuses = (0..=super::MAX_PHP_INTERCEPT_ERROR_STATUSES)
            .map(|index| (400 + index).to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            intercept_error_statuses = [{}]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-many-intercept-statuses-process"),
            root.display(),
            statuses,
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.intercept_error_statuses"), "{error}");
        assert!(error.contains("at most 200 statuses"), "{error}");
    }

    #[test]
    fn rejects_duplicate_php_error_page_status() {
        let root = unique_temp_path("config-php-duplicate-error-page-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [[vhosts.php.error_pages]]
            status = 502
            path = "/502.html"

            [vhosts.php.error_pages.web]
            root = "{}"

            [[vhosts.php.error_pages]]
            status = 502
            path = "/fallback.html"

            [vhosts.php.error_pages.web]
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-duplicate-error-page-process"),
            root.display(),
            root.display(),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.error_pages.status"), "{error}");
    }

    #[test]
    fn rejects_too_many_php_error_pages() {
        let root = unique_temp_path("config-php-many-error-pages-root");
        std::fs::create_dir_all(&root).unwrap();
        let error_pages = (0..=super::MAX_PHP_ERROR_PAGES)
            .map(|index| {
                format!(
                    r#"
            [[vhosts.php.error_pages]]
            status = {}
            path = "/{}.html"

            [vhosts.php.error_pages.web]
            root = "{}"
                    "#,
                    400 + index,
                    400 + index,
                    root.display()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            {}

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-many-error-pages-process"),
            root.display(),
            error_pages,
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.error_pages"), "{error}");
        assert!(error.contains("at most 64 error pages"), "{error}");
    }

    #[test]
    fn rejects_php_fpm_with_socket_and_tcp() {
        let root = unique_temp_path("config-php-fpm-conflict-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            socket = "/run/php/php-fpm.sock"
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-fpm-conflict-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("configure only one of socket, tcp, or tcp_upstreams"),
            "{error}"
        );
    }

    #[test]
    fn rejects_invalid_php_fpm_retry_policy() {
        let root = unique_temp_path("config-php-fpm-invalid-retries-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            max_retries = 11
            "#,
            test_process_config_toml("config-php-fpm-invalid-retries-process"),
            root.display()
        ))
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.fpm.max_retries"), "{error}");

        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            retry_methods = ["GET", "get"]
            "#,
            test_process_config_toml("config-php-fpm-invalid-retry-methods-process"),
            root.display()
        ))
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.fpm.retry_methods"), "{error}");

        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            server_port = 0

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-invalid-server-port-process"),
            root.display()
        ))
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.server_port"), "{error}");

        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.params]
            HTTP_AUTHORIZATION = "Bearer fixed"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-http-param-process"),
            root.display()
        ))
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("HTTP_* request header"), "{error}");

        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            retry_methods = ["GET", "POST"]
            "#,
            test_process_config_toml("config-php-fpm-unsafe-retry-method-process"),
            root.display()
        ))
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("safe HTTP methods"), "{error}");

        let retry_methods = (0..=super::MAX_PHP_FPM_RETRY_METHODS)
            .map(|index| format!("\"M{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            retry_methods = [{}]
            "#,
            test_process_config_toml("config-php-fpm-too-many-retry-methods-process"),
            root.display(),
            retry_methods,
        ))
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.fpm.retry_methods"), "{error}");
        assert!(error.contains("at most 16 methods"), "{error}");

        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            retry_timeout_secs = 0
            "#,
            test_process_config_toml("config-php-fpm-invalid-retry-timeout-process"),
            root.display()
        ))
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.fpm.retry_timeout_secs"), "{error}");

        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            retry_statuses = [404]
            "#,
            test_process_config_toml("config-php-fpm-invalid-retry-status-process"),
            root.display()
        ))
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.fpm.retry_statuses"), "{error}");

        let retry_statuses = (0..=super::MAX_PHP_FPM_RETRY_STATUSES)
            .map(|index| (500 + index).to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            retry_statuses = [{}]
            "#,
            test_process_config_toml("config-php-fpm-too-many-retry-statuses-process"),
            root.display(),
            retry_statuses,
        ))
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.fpm.retry_statuses"), "{error}");
        assert!(error.contains("at most 100 statuses"), "{error}");

        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            retry_statuses = [500, 500]
            "#,
            test_process_config_toml("config-php-fpm-duplicate-retry-status-process"),
            root.display()
        ))
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.fpm.retry_statuses"), "{error}");
    }

    #[test]
    fn rejects_php_fpm_keepalive_without_idle_capacity() {
        let root = unique_temp_path("config-php-fpm-keepalive-zero-pool");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            keepalive = true
            pool_max_idle = 0
            "#,
            test_process_config_toml("config-php-fpm-keepalive-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.fpm.pool_max_idle"), "{error}");
    }

    #[test]
    fn rejects_php_param_that_overrides_script_filename() {
        let root = unique_temp_path("config-php-param-protected");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.params]
            SCRIPT_FILENAME = "/tmp/other.php"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-param-protected-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.params"), "{error}");
        assert!(error.contains("managed by Fluxheim"), "{error}");
    }

    #[test]
    fn rejects_php_param_control_character_value() {
        let root = unique_temp_path("config-php-param-control");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.params]
            APP_ENV = "production\u000a"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-param-control-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("control characters"), "{error}");
    }

    #[test]
    fn rejects_too_many_php_params() {
        let root = unique_temp_path("config-php-many-params");
        std::fs::create_dir_all(&root).unwrap();
        let params = (0..=super::MAX_PHP_PARAMS)
            .map(|index| format!("PARAM_{index} = \"value\""))
            .collect::<Vec<_>>()
            .join("\n");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.params]
            {}

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-many-params-process"),
            root.display(),
            params,
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.params"), "{error}");
        assert!(error.contains("at most 128 parameters"), "{error}");
    }

    #[test]
    fn rejects_php_extension_with_leading_dot() {
        let root = unique_temp_path("config-php-extension-dot-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            allowed_extensions = [".php"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-extension-dot-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("extensions must be plain extension names"),
            "{error}"
        );
    }

    #[test]
    fn rejects_duplicate_php_allowed_extension() {
        let root = unique_temp_path("config-php-duplicate-extension-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            allowed_extensions = ["php", "PHP"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-duplicate-extension-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.allowed_extensions"), "{error}");
        assert!(error.contains("duplicate extensions"), "{error}");
    }

    #[test]
    fn rejects_too_many_php_allowed_extensions() {
        let root = unique_temp_path("config-php-many-extensions-root");
        std::fs::create_dir_all(&root).unwrap();
        let extensions = (0..=super::MAX_PHP_ALLOWED_EXTENSIONS)
            .map(|index| format!("\"php{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            allowed_extensions = [{}]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-many-extensions-process"),
            root.display(),
            extensions,
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.allowed_extensions"), "{error}");
        assert!(error.contains("at most 16 extensions"), "{error}");
    }

    #[test]
    fn rejects_invalid_php_deny_path_prefix() {
        let root = unique_temp_path("config-php-bad-deny-prefix-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            deny_path_prefixes = ["uploads/../secret"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-bad-deny-prefix-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.deny_path_prefixes"), "{error}");
    }

    #[test]
    fn rejects_duplicate_php_deny_path_prefix() {
        let root = unique_temp_path("config-php-duplicate-deny-prefix-root");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            deny_path_prefixes = ["/uploads", "/uploads"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-duplicate-deny-prefix-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.deny_path_prefixes"), "{error}");
    }

    #[test]
    fn rejects_too_many_php_deny_path_prefixes() {
        let root = unique_temp_path("config-php-many-deny-prefixes-root");
        std::fs::create_dir_all(&root).unwrap();
        let prefixes = (0..=super::MAX_PHP_DENY_PATH_PREFIXES)
            .map(|index| format!("\"/upload-{index}/\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            deny_path_prefixes = [{}]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
            test_process_config_toml("config-php-many-deny-prefixes-process"),
            root.display(),
            prefixes,
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.deny_path_prefixes"), "{error}");
        assert!(error.contains("at most 128 prefixes"), "{error}");
    }

    #[test]
    fn parses_cache_config() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            preset = "wordpress"
            enabled = true
            local_static = true
            status_header = "X-Cache-Status"
            status_reason_header = "X-Cache-Reason"
            hide_response_headers = ["set-cookie"]
            tag_headers = ["Surrogate-Key", "X-App-Cache-Tags"]
            no_store_response_headers = ["x-fluxheim-no-store"]
            no_store_response_header_values = { x-app-cache = "private" }
            bypass_path_prefixes = ["/private/"]
            bypass_path_exact = ["/login"]
            bypass_request_headers = ["cookie", "authorization"]
            bypass_request_header_values = { x-preview-mode = "1" }
            bypass_cookie_names = ["sessionid", "wordpress_logged_in"]
            bypass_cookie_name_prefixes = ["wordpress_sec_"]
            bypass_cookie_values = { preview = "1" }
            bypass_query_params = ["preview", "token"]
            bypass_query_values = { mode = "private" }
            bypass_query = false
            allow_client_cache_refresh = true
            vary_request_headers = ["accept-encoding", "accept-language"]
            ignore_origin_cache_headers = true
            key_namespace = "repoheim-assets-v1"
            key_parts = ["method", "host", "path"]
            min_uses = 2
            pass_uncacheable_after = 3
            status_ttls = { "200" = 3600, "404" = 60 }
            default_status_ttl_secs = 15
            stale_while_revalidate_secs = 30
            stale_if_error_secs = 120
            stale_if_error_on = ["connect", "timeout", "connection-closed", "http-status"]
            stale_if_error_statuses = [500, 502, 503, 504]
            include_query = false
            content_types = ["image/*", "text/css"]
            extensions = ["jpg", "webp", "css"]
            methods = ["GET"]
            max_object_bytes = "4MiB"

            [cache.range]
            enabled = true
            max_bytes = "1MiB"

            [cache.range.slice]
            enabled = true
            size_bytes = "256KiB"
            max_slices = 4
            fill_missing = false

            [cache.memory]
            enabled = true
            max_size_bytes = "1GiB"

            [cache.disk]
            enabled = true
            path = "/var/cache/fluxheim"
            max_size_bytes = "10GiB"

            [cache.lock]
            enabled = false
            age_timeout_secs = 45
            wait_timeout_secs = 10

            [cache.predictor]
            enabled = true
            capacity = 8192
            "#,
        )
        .unwrap();

        assert!(config.cache.enabled);
        assert_eq!(config.cache.preset, CachePreset::WordPress);
        assert!(config.cache.local_static);
        assert_eq!(
            config.cache.status_header,
            Some("X-Cache-Status".to_owned())
        );
        assert_eq!(
            config.cache.status_reason_header,
            Some("X-Cache-Reason".to_owned())
        );
        assert_eq!(
            config.cache.hide_response_headers,
            ["set-cookie".to_owned()]
        );
        assert_eq!(
            config.cache.tag_headers,
            ["Surrogate-Key".to_owned(), "X-App-Cache-Tags".to_owned()]
        );
        assert_eq!(
            config.cache.no_store_response_headers,
            ["x-fluxheim-no-store".to_owned()]
        );
        assert_eq!(
            config
                .cache
                .no_store_response_header_values
                .get("x-app-cache"),
            Some(&"private".to_owned())
        );
        assert_eq!(config.cache.bypass_path_prefixes, ["/private/".to_owned()]);
        assert_eq!(config.cache.bypass_path_exact, ["/login".to_owned()]);
        assert_eq!(
            config.cache.bypass_request_headers,
            ["cookie".to_owned(), "authorization".to_owned()]
        );
        assert_eq!(
            config
                .cache
                .bypass_request_header_values
                .get("x-preview-mode"),
            Some(&"1".to_owned())
        );
        assert_eq!(
            config.cache.bypass_cookie_names,
            ["sessionid".to_owned(), "wordpress_logged_in".to_owned()]
        );
        assert_eq!(
            config.cache.bypass_cookie_name_prefixes,
            ["wordpress_sec_".to_owned()]
        );
        assert_eq!(
            config.cache.bypass_cookie_values.get("preview"),
            Some(&"1".to_owned())
        );
        assert_eq!(
            config.cache.bypass_query_params,
            ["preview".to_owned(), "token".to_owned()]
        );
        assert_eq!(
            config.cache.bypass_query_values.get("mode"),
            Some(&"private".to_owned())
        );
        assert!(!config.cache.bypass_query);
        assert!(config.cache.allow_client_cache_refresh);
        assert_eq!(
            config.cache.vary_request_headers,
            ["accept-encoding".to_owned(), "accept-language".to_owned()]
        );
        assert!(config.cache.ignore_origin_cache_headers);
        assert_eq!(
            config.cache.key_namespace,
            Some("repoheim-assets-v1".to_owned())
        );
        assert_eq!(
            config.cache.key_parts,
            [CacheKeyPart::Method, CacheKeyPart::Host, CacheKeyPart::Path]
        );
        assert_eq!(config.cache.min_uses, 2);
        assert_eq!(config.cache.pass_uncacheable_after, 3);
        assert_eq!(config.cache.status_ttls.get(&200), Some(&3600));
        assert_eq!(config.cache.status_ttls.get(&404), Some(&60));
        assert_eq!(config.cache.default_status_ttl_secs, Some(15));
        assert_eq!(config.cache.stale_while_revalidate_secs, Some(30));
        assert_eq!(config.cache.stale_if_error_secs, Some(120));
        assert_eq!(
            config.cache.stale_if_error_on,
            [
                CacheStaleErrorKind::Connect,
                CacheStaleErrorKind::Timeout,
                CacheStaleErrorKind::ConnectionClosed,
                CacheStaleErrorKind::HttpStatus
            ]
        );
        assert_eq!(config.cache.stale_if_error_statuses, [500, 502, 503, 504]);
        assert!(!config.cache.include_query);
        assert_eq!(
            config.cache.content_types,
            ["image/*".to_owned(), "text/css".to_owned()]
        );
        assert_eq!(
            config.cache.image_extensions,
            ["jpg".to_owned(), "webp".to_owned(), "css".to_owned()]
        );
        assert_eq!(config.cache.methods, ["GET".to_owned()]);
        let wordpress_cache = config.cache.with_presets();
        assert!(
            wordpress_cache
                .bypass_path_prefixes
                .contains(&"/wp-admin/".to_owned())
        );
        for path in [
            "/wp-login.php",
            "/wp-register.php",
            "/wp-mail.php",
            "/index.php",
            "/sitemap.xml",
            "/sitemap_index.xml",
        ] {
            assert!(
                wordpress_cache.bypass_path_exact.contains(&path.to_owned()),
                "missing WordPress bypass path {path}"
            );
        }
        assert!(
            wordpress_cache
                .bypass_cookie_name_prefixes
                .contains(&"wordpress_logged_in_".to_owned())
        );
        assert!(wordpress_cache.bypass_query);
        assert_eq!(
            config.cache.max_object_bytes,
            ByteSize::from_bytes(4 * 1024 * 1024)
        );
        assert!(config.cache.range.enabled);
        assert_eq!(
            config.cache.range.max_bytes,
            ByteSize::from_bytes(1024 * 1024)
        );
        assert!(config.cache.range.slice.enabled);
        assert_eq!(
            config.cache.range.slice.size_bytes,
            ByteSize::from_bytes(256 * 1024)
        );
        assert_eq!(config.cache.range.slice.max_slices, 4);
        assert!(!config.cache.range.slice.fill_missing);
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
        assert!(!config.cache.lock.enabled);
        assert_eq!(config.cache.lock.age_timeout_secs, 45);
        assert_eq!(config.cache.lock.wait_timeout_secs, 10);
        assert!(config.cache.predictor.enabled);
        assert_eq!(config.cache.predictor.capacity, 8192);
        config.cache.validate("cache").unwrap();
    }

    #[test]
    fn rejects_invalid_cache_status_header_name() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            status_header = "bad header"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHeaderName {
                field: "cache",
                name: "bad header".to_owned()
            })
        );
    }

    #[test]
    fn rejects_invalid_cache_status_reason_header_name() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            status_reason_header = "bad header"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHeaderName {
                field: "cache",
                name: "bad header".to_owned()
            })
        );
    }

    #[test]
    fn rejects_invalid_cache_hidden_response_header_name() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            hide_response_headers = ["bad header"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHeaderName {
                field: "cache",
                name: "bad header".to_owned()
            })
        );
    }

    #[test]
    fn rejects_invalid_cache_bypass_request_header_name() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            bypass_request_headers = ["bad header"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHeaderName {
                field: "cache",
                name: "bad header".to_owned()
            })
        );
    }

    #[test]
    fn rejects_invalid_cache_bypass_request_header_value() {
        for value in ["", " ", "bad\nvalue"] {
            let config: Config = toml::from_str(&format!(
                r#"
                [cache]
                bypass_request_header_values = {{ x-preview-mode = {value:?} }}
                "#,
            ))
            .unwrap();

            assert_eq!(
                config.validate(),
                Err(ConfigError::InvalidCacheBypassRequestHeaderValue {
                    scope: "cache",
                    header: "x-preview-mode".to_owned(),
                    value: value.to_owned()
                })
            );
        }
    }

    #[test]
    fn rejects_invalid_cache_no_store_response_header_name() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            no_store_response_headers = ["bad header"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHeaderName {
                field: "cache",
                name: "bad header".to_owned()
            })
        );
    }

    #[test]
    fn rejects_invalid_cache_no_store_response_header_value() {
        for value in ["", " ", "bad\nvalue"] {
            let config: Config = toml::from_str(&format!(
                r#"
                [cache]
                no_store_response_header_values = {{ x-app-cache = {value:?} }}
                "#,
            ))
            .unwrap();

            assert_eq!(
                config.validate(),
                Err(ConfigError::InvalidCacheNoStoreResponseHeaderValue {
                    scope: "cache",
                    header: "x-app-cache".to_owned(),
                    value: value.to_owned()
                })
            );
        }
    }

    #[test]
    fn rejects_invalid_cache_bypass_query_param() {
        for param in ["", "bad param", "token=value", "a&b", "a?b"] {
            let config: Config = toml::from_str(&format!(
                r#"
                [cache]
                bypass_query_params = [{param:?}]
                "#,
            ))
            .unwrap();

            assert_eq!(
                config.validate(),
                Err(ConfigError::InvalidCacheBypassQueryParam {
                    scope: "cache",
                    param: param.to_owned()
                })
            );
        }
    }

    #[test]
    fn rejects_invalid_cache_bypass_query_value() {
        for value in ["", " ", "bad value", "bad&value", "bad\nvalue"] {
            let config: Config = toml::from_str(&format!(
                r#"
                [cache]
                bypass_query_values = {{ mode = {value:?} }}
                "#,
            ))
            .unwrap();

            assert_eq!(
                config.validate(),
                Err(ConfigError::InvalidCacheBypassQueryValue {
                    scope: "cache",
                    param: "mode".to_owned(),
                    value: value.to_owned()
                })
            );
        }
    }

    #[test]
    fn rejects_invalid_cache_bypass_cookie_name() {
        for name in ["", "bad name", "session=value", "a;b", "a,b"] {
            let config: Config = toml::from_str(&format!(
                r#"
                [cache]
                bypass_cookie_names = [{name:?}]
                "#,
            ))
            .unwrap();

            assert_eq!(
                config.validate(),
                Err(ConfigError::InvalidCacheBypassCookieName {
                    scope: "cache",
                    name: name.to_owned()
                })
            );
        }
    }

    #[test]
    fn rejects_invalid_cache_bypass_cookie_value() {
        for value in ["bad;value", "bad,value", "bad\nvalue"] {
            let config: Config = toml::from_str(&format!(
                r#"
                [cache]
                bypass_cookie_values = {{ preview = {value:?} }}
                "#,
            ))
            .unwrap();

            assert_eq!(
                config.validate(),
                Err(ConfigError::InvalidCacheBypassCookieValue {
                    scope: "cache",
                    name: "preview".to_owned(),
                    value: value.to_owned()
                })
            );
        }
    }

    #[test]
    fn rejects_invalid_cache_vary_request_header_name() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            vary_request_headers = ["bad header"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidHeaderName {
                field: "cache",
                name: "bad header".to_owned()
            })
        );
    }

    #[test]
    fn rejects_sensitive_cache_vary_request_header() {
        for header in ["cookie", "authorization", "proxy-authorization"] {
            let config: Config = toml::from_str(&format!(
                r#"
                [cache]
                vary_request_headers = [{header:?}]
                "#
            ))
            .unwrap();

            assert_eq!(
                config.validate(),
                Err(ConfigError::InvalidCacheVaryRequestHeader {
                    scope: "cache",
                    header: header.to_owned(),
                }),
                "{header}"
            );
        }
    }

    #[test]
    fn rejects_too_many_cache_bypass_paths() {
        let prefixes = (0..=super::MAX_CACHE_BYPASS_PATHS)
            .map(|index| format!("\"/private-{index}/\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            bypass_path_prefixes = [{prefixes}]
            "#,
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("cache.bypass_path_prefixes"), "{error}");
        assert!(error.contains("at most 128 entries"), "{error}");
    }

    #[test]
    fn rejects_too_many_cache_bypass_cookies() {
        let cookies = (0..=super::MAX_CACHE_BYPASS_COOKIES)
            .map(|index| format!("\"cookie_{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            bypass_cookie_name_prefixes = [{cookies}]
            "#,
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("cache.bypass_cookie_name_prefixes"),
            "{error}"
        );
        assert!(error.contains("at most 128 entries"), "{error}");
    }

    #[test]
    fn rejects_too_many_cache_vary_headers() {
        let headers = (0..=super::MAX_CACHE_VARY_REQUEST_HEADERS)
            .map(|index| format!("\"x-vary-{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            vary_request_headers = [{headers}]
            "#,
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("cache.vary_request_headers"), "{error}");
        assert!(error.contains("at most 32 entries"), "{error}");
    }

    #[test]
    fn rejects_too_many_cache_status_ttls() {
        let status_ttls = (0..=super::MAX_CACHE_STATUS_TTLS)
            .map(|index| format!("\"{}\" = 60", 100 + index))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            status_ttls = {{ {status_ttls} }}
            "#,
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("cache.status_ttls"), "{error}");
        assert!(error.contains("at most 128 entries"), "{error}");
    }

    #[test]
    fn rejects_too_many_cache_content_types_extensions_and_methods() {
        let content_types = (0..=super::MAX_CACHE_CONTENT_TYPES)
            .map(|index| format!("\"application/x-{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            content_types = [{content_types}]
            "#,
        ))
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("cache.content_types"), "{error}");
        assert!(error.contains("at most 64 entries"), "{error}");

        let extensions = (0..=super::MAX_CACHE_IMAGE_EXTENSIONS)
            .map(|index| format!("\"ext{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            image_extensions = [{extensions}]
            "#,
        ))
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("cache.image_extensions"), "{error}");
        assert!(error.contains("at most 128 entries"), "{error}");

        let methods = (0..=super::MAX_CACHE_METHODS)
            .map(|index| format!("\"M{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            methods = [{methods}]
            "#,
        ))
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("cache.methods"), "{error}");
        assert!(error.contains("at most 16 entries"), "{error}");
    }

    #[test]
    fn rejects_invalid_cache_key_namespace() {
        for namespace in ["", "bad namespace", "bad/namespace", "bad;namespace"]
            .into_iter()
            .map(str::to_owned)
            .chain(std::iter::once("x".repeat(129)))
        {
            let config: Config = toml::from_str(&format!(
                r#"
                [cache]
                key_namespace = {namespace:?}
                "#
            ))
            .unwrap();

            assert_eq!(
                config.validate(),
                Err(ConfigError::InvalidCacheKeyNamespace {
                    scope: "cache",
                    namespace: namespace.to_owned(),
                }),
                "{namespace:?}"
            );
        }
    }

    #[test]
    fn rejects_empty_cache_key_parts() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            key_parts = []
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::EmptyCacheKeyParts { scope: "cache" })
        );
    }

    #[test]
    fn rejects_too_many_cache_key_parts() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            key_parts = ["method", "host", "path", "query", "path"]
            "#,
        )
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("cache.key_parts"), "{error}");
        assert!(error.contains("at most 4 entries"), "{error}");
    }

    #[test]
    fn route_cache_wraps_too_many_key_parts() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [[vhosts.routes]]
            name = "assets"
            path_prefix = "/assets/"

            [vhosts.routes.proxy]
            upstream = "127.0.0.1:3000"

            [vhosts.routes.cache]
            key_parts = ["method", "host", "path", "query", "path"]
            "#,
        )
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("vhost \"gateway\" route \"assets\" cache:"),
            "{error}"
        );
        assert!(error.contains("vhosts.routes.cache.key_parts"), "{error}");
        assert!(error.contains("at most 4 entries"), "{error}");
    }

    #[test]
    fn rejects_duplicate_cache_key_parts() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            key_parts = ["method", "path", "path"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::DuplicateCacheKeyPart {
                scope: "cache",
                part: CacheKeyPart::Path,
            })
        );
    }

    #[test]
    fn rejects_cache_key_parts_without_path() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            key_parts = ["method", "host"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::MissingCacheKeyPath { scope: "cache" })
        );
    }

    #[test]
    fn rejects_invalid_cache_status_ttl() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            status_ttls = { "99" = 60 }
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheStatusTtl {
                scope: "cache",
                status: 99,
                ttl_secs: 60,
            })
        );

        let config: Config = toml::from_str(
            r#"
            [cache]
            status_ttls = { "200" = 0 }
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheStatusTtl {
                scope: "cache",
                status: 200,
                ttl_secs: 0,
            })
        );
    }

    #[test]
    fn rejects_invalid_cache_min_uses() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            min_uses = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheMinUses { scope: "cache" })
        );
    }

    #[test]
    fn rejects_zero_cache_range_max_bytes() {
        let config: Config = toml::from_str(
            r#"
            [cache.range]
            max_bytes = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheRangePolicy {
                scope: "cache",
                field: "range.max_bytes",
                reason: "max bytes must be greater than zero",
            })
        );
    }

    #[test]
    fn rejects_cache_range_larger_than_cache_object_limit() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            max_object_bytes = "1MiB"

            [cache.range]
            enabled = true
            max_bytes = "2MiB"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheRangePolicy {
                scope: "cache",
                field: "range.max_bytes",
                reason: "max bytes must not exceed max_object_bytes",
            })
        );
    }

    #[test]
    fn rejects_invalid_cache_default_status_ttl() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            default_status_ttl_secs = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheDefaultStatusTtl { scope: "cache" })
        );
    }

    #[test]
    fn rejects_invalid_cache_stale_if_error_ttl() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            stale_if_error_secs = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheStaleIfErrorTtl { scope: "cache" })
        );
    }

    #[test]
    fn rejects_empty_cache_stale_if_error_on_when_error_stale_is_enabled() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            stale_if_error_secs = 30
            stale_if_error_on = []
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::EmptyCacheStaleIfErrorOn { scope: "cache" })
        );
    }

    #[test]
    fn rejects_invalid_cache_stale_if_error_statuses() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            stale_if_error_statuses = [404]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheStaleIfErrorStatus {
                scope: "cache",
                status: 404,
            })
        );
    }

    #[test]
    fn rejects_invalid_cache_stale_while_revalidate_ttl() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            stale_while_revalidate_secs = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheStaleWhileRevalidateTtl { scope: "cache" })
        );
    }

    #[test]
    fn rejects_duplicate_cache_tag_headers() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            tag_headers = ["Surrogate-Key", "surrogate-key"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::DuplicateCacheTagHeader {
                scope: "cache",
                header: "surrogate-key".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_invalid_cache_content_type() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            content_types = []
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::EmptyCacheContentTypes { scope: "cache" })
        );

        for content_type in ["image", "*/json", "image/p*ng", "text/html; charset=utf-8"] {
            let config: Config = toml::from_str(&format!(
                r#"
                [cache]
                content_types = [{content_type:?}]
                "#
            ))
            .unwrap();

            assert_eq!(
                config.validate(),
                Err(ConfigError::InvalidCacheContentType {
                    scope: "cache",
                    content_type: content_type.to_owned(),
                }),
                "{content_type}"
            );
        }
    }

    #[test]
    fn rejects_invalid_cache_lock_timeout() {
        let config: Config = toml::from_str(
            r#"
            [cache.lock]
            age_timeout_secs = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheLockTimeout {
                field: "cache.lock.age_timeout_secs".to_owned()
            })
        );

        let config: Config = toml::from_str(
            r#"
            [cache.lock]
            wait_timeout_secs = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheLockTimeout {
                field: "cache.lock.wait_timeout_secs".to_owned()
            })
        );
    }

    #[test]
    fn rejects_invalid_cache_predictor_capacity() {
        let config: Config = toml::from_str(
            r#"
            [cache.predictor]
            enabled = true
            capacity = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCachePredictorCapacity { scope: "cache" })
        );
    }

    #[test]
    #[cfg(feature = "cache")]
    fn parses_cache_peer_fill_config() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "/var/cache/fluxheim/example"

            [cache.peer_fill]
            enabled = true
            connect_timeout_secs = 3
            read_timeout_secs = 12
            max_object_bytes = "64MiB"
            max_concurrent_requests = 32
            fail_open = false

            [[cache.peer_fill.peers]]
            name = "node-a"
            base_url = "https://node-a.example.internal:8443"

            [[cache.peer_fill.peers]]
            name = "local"
            base_url = "http://127.0.0.1:8080"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.cache.peer_fill,
            CachePeerFillConfig {
                enabled: true,
                peers: vec![
                    CachePeerConfig {
                        name: "node-a".to_owned(),
                        base_url: "https://node-a.example.internal:8443".to_owned(),
                    },
                    CachePeerConfig {
                        name: "local".to_owned(),
                        base_url: "http://127.0.0.1:8080".to_owned(),
                    },
                ],
                connect_timeout_secs: 3,
                read_timeout_secs: 12,
                max_object_bytes: Some(ByteSize(64 * 1024 * 1024)),
                max_concurrent_requests: 32,
                allow_insecure_http: false,
                fail_open: false,
            }
        );
    }

    #[test]
    #[cfg(feature = "cache")]
    fn rejects_cache_peer_fill_without_enabled_cache_policy() {
        let config: Config = toml::from_str(
            r#"
            [cache.peer_fill]
            enabled = true

            [[cache.peer_fill.peers]]
            name = "node-a"
            base_url = "https://node-a.example.internal:8443"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCachePeerFillPolicy {
                scope: "cache",
                field: "peer_fill.enabled",
                reason: "peer fill requires the cache policy to be enabled",
            })
        );
    }

    #[test]
    #[cfg(feature = "cache")]
    fn rejects_unsafe_cache_peer_fill_peers() {
        let config: Config = toml::from_str(
            r#"
            [cache]
            enabled = true

            [cache.memory]
            enabled = true

            [cache.peer_fill]
            enabled = true

            [[cache.peer_fill.peers]]
            name = "node-a"
            base_url = "http://node-a.example.internal:8080"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCachePeerFillPeer {
                scope: "cache",
                peer: "node-a".to_owned(),
                reason: "http peer base_url is allowed only for loopback peers unless allow_insecure_http = true",
            })
        );

        let config: Config = toml::from_str(
            r#"
            [cache]
            enabled = true

            [cache.memory]
            enabled = true

            [cache.peer_fill]
            enabled = true
            allow_insecure_http = true

            [[cache.peer_fill.peers]]
            name = "node-a"
            base_url = "http://node-a.example.internal:8080"

            [[cache.peer_fill.peers]]
            name = "node-a"
            base_url = "https://node-b.example.internal:8443"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::DuplicateCachePeerFillPeerName {
                scope: "cache",
                name: "node-a".to_owned(),
            })
        );
    }

    #[test]
    #[cfg(feature = "cache")]
    fn parses_cache_purger_config() {
        let config: Config = toml::from_str(
            r#"
            [cache_purger]
            enabled = true
            interval_secs = 60
            limit = 1000
            batches = 4
            "#,
        )
        .unwrap();

        assert_eq!(
            config.cache_purger,
            CachePurgerConfig {
                enabled: true,
                interval_secs: 60,
                limit: 1000,
                batches: 4,
            }
        );
        config.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_cache_purger_limits() {
        let config: Config = toml::from_str(
            r#"
            [cache_purger]
            interval_secs = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCachePurgerPolicy {
                field: "cache_purger.interval_secs",
                reason: "interval must be between 1 and 86400 seconds",
            })
        );

        let config: Config = toml::from_str(
            r#"
            [cache_purger]
            limit = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCachePurgerPolicy {
                field: "cache_purger.limit",
                reason: "limit must be between 1 and 100000 indexed entries",
            })
        );

        let config: Config = toml::from_str(
            r#"
            [cache_purger]
            batches = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCachePurgerPolicy {
                field: "cache_purger.batches",
                reason: "batches must be between 1 and 100",
            })
        );
    }

    #[test]
    #[cfg(not(feature = "cache"))]
    fn rejects_enabled_cache_purger_without_cache_feature() {
        let config: Config = toml::from_str(
            r#"
            [cache_purger]
            enabled = true
            "#,
        )
        .unwrap();

        assert_eq!(config.validate(), Err(ConfigError::CachePurgerNotCompiled));
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

    #[test]
    fn parses_filesystem_disk_cache_backend() {
        let root = unique_temp_path("config-cache-filesystem-backend");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            backend = "filesystem"
            path = "{}"
            "#,
            root.display()
        ))
        .unwrap();

        assert_eq!(config.cache.disk.backend, CacheDiskBackend::Filesystem);
        assert_eq!(config.validate(), Ok(()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn accepts_storage_bin_backend() {
        let root = unique_temp_path("config-cache-storage-bin-backend");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            backend = "storage-bin"
            path = "{}"
            "#,
            root.display()
        ))
        .unwrap();

        assert_eq!(config.cache.disk.backend, CacheDiskBackend::StorageBin);
        assert_eq!(config.validate(), Ok(()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn parses_reserved_storage_bin_backend_options() {
        let root = unique_temp_path("config-cache-storage-bin-options");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            enabled = true
            max_object_bytes = "32MiB"

            [cache.disk]
            enabled = true
            backend = "storage-bin"
            path = "{}"
            max_size_bytes = "2GiB"

            [cache.disk.storage_bin]
            bin_size_bytes = "512MiB"
            preallocate = true
            max_open_bins = 8
            "#,
            root.display()
        ))
        .unwrap();

        assert_eq!(config.cache.disk.backend, CacheDiskBackend::StorageBin);
        assert_eq!(
            config.cache.disk.storage_bin.bin_size_bytes,
            ByteSize::from_bytes(512 * 1024 * 1024)
        );
        assert!(config.cache.disk.storage_bin.preallocate);
        assert_eq!(config.cache.disk.storage_bin.max_open_bins, 8);
        assert_eq!(config.validate(), Ok(()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_storage_bin_smaller_than_cache_object_limit() {
        let root = unique_temp_path("config-cache-storage-bin-too-small");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            enabled = true
            max_object_bytes = "64MiB"

            [cache.disk]
            enabled = true
            backend = "storage-bin"
            path = "{}"
            max_size_bytes = "2GiB"

            [cache.disk.storage_bin]
            bin_size_bytes = "32MiB"
            "#,
            root.display()
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::CacheStorageBinSmallerThanMaxObject { scope: "cache" })
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_zero_storage_bin_max_open_bins() {
        let root = unique_temp_path("config-cache-storage-bin-open-bins");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            backend = "storage-bin"
            path = "{}"
            max_size_bytes = "2GiB"

            [cache.disk.storage_bin]
            max_open_bins = 0
            "#,
            root.display()
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheStorageBinMaxOpenBins { scope: "cache" })
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn accepts_cache_disk_encryption_local_file() {
        let root = unique_temp_path("config-cache-encryption-local");
        let secrets = root.join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}/cache"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            algorithm = "aes-256-gcm"
            key_id = "cache-v1"
            key_file = "{}/cache-key"
            "#,
            root.display(),
            secrets.display()
        ))
        .unwrap();

        assert!(config.cache.disk.encryption.enabled);
        assert_eq!(
            config.cache.disk.encryption.provider,
            CacheDiskEncryptionProvider::Local
        );
        assert_eq!(config.validate(), Ok(()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn accepts_cache_disk_encryption_local_credential() {
        let root = unique_temp_path("config-cache-encryption-credential");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            key_credential = "fluxheim-cache-key"
            "#,
            root.display()
        ))
        .unwrap();

        assert_eq!(config.validate(), Ok(()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_enabled_cache_disk_encryption_without_secret_source() {
        let root = unique_temp_path("config-cache-encryption-missing-key");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            "#,
            root.display()
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheEncryptionPolicy {
                scope: "cache",
                field: "key",
                reason: "must be read from a file or systemd/container credential",
            })
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_conflicting_cache_disk_encryption_secret_sources() {
        let root = unique_temp_path("config-cache-encryption-conflict");
        let secrets = root.join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}/cache"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            key_file = "{}/cache-key"
            key_credential = "fluxheim-cache-key"
            "#,
            root.display(),
            secrets.display()
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheEncryptionPolicy {
                scope: "cache",
                field: "key",
                reason: "cannot use more than one secret source",
            })
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_unimplemented_local_cache_disk_encryption_algorithm() {
        let root = unique_temp_path("config-cache-encryption-local-algorithm");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            algorithm = "xchacha20-poly1305"
            key_credential = "fluxheim-cache-key"
            "#,
            root.display()
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheEncryptionPolicy {
                scope: "cache",
                field: "disk.encryption.algorithm",
                reason: "local provider currently supports only \"aes-256-gcm\"",
            })
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn accepts_cache_disk_encryption_openbao_transit_provider() {
        let root = unique_temp_path("config-cache-encryption-openbao");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "openbao-transit"
            algorithm = "xchacha20-poly1305"

            [cache.disk.encryption.openbao]
            address = "https://openbao.internal.example"
            mount = "transit"
            key_name = "fluxheim-cache"
            token_credential = "openbao-token"
            "#,
            root.display()
        ))
        .unwrap();

        assert_eq!(
            config.cache.disk.encryption.provider,
            CacheDiskEncryptionProvider::OpenbaoTransit
        );
        assert_eq!(config.validate(), Ok(()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_plain_http_openbao_non_loopback_address() {
        let root = unique_temp_path("config-cache-encryption-openbao-http");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "openbao-transit"

            [cache.disk.encryption.openbao]
            address = "http://openbao.internal.example"
            mount = "transit"
            key_name = "fluxheim-cache"
            token_credential = "openbao-token"
            "#,
            root.display()
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheEncryptionPolicy {
                scope: "cache",
                field: "disk.encryption.openbao.address",
                reason: "must be an http://127.0.0.1, http://[::1], or https:// URL without credentials, query, or fragment",
            })
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_plain_http_openbao_malformed_ipv6_loopback_authority() {
        let root = unique_temp_path("config-cache-encryption-openbao-ipv6-tail");
        std::fs::create_dir_all(&root).unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "openbao-transit"

            [cache.disk.encryption.openbao]
            address = "http://[::1]attacker.example.test/v1"
            mount = "transit"
            key_name = "fluxheim-cache"
            token_credential = "openbao-token"
            "#,
            root.display()
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheEncryptionPolicy {
                scope: "cache",
                field: "disk.encryption.openbao.address",
                reason: "must be an http://127.0.0.1, http://[::1], or https:// URL without credentials, query, or fragment",
            })
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_disk_cache_under_world_writable_parent() {
        let path = unique_world_writable_child("config-cache-world-writable", "cache");
        let config: Config = toml::from_str(&format!(
            r#"
            [cache.disk]
            enabled = true
            path = "{}"
            "#,
            path.display()
        ))
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
            tracing: TracingConfig::default(),
            logging: LoggingConfig::default(),
            headers: HeaderPolicyConfig::default(),
            tls: super::TlsConfig::default(),
            proxy: ProxyConfig::default(),
            compression: CompressionConfig::default(),
            cache: CacheConfig::default(),
            cache_purger: CachePurgerConfig::default(),
            web: WebConfig::default(),
            vhosts: vec![],
        };

        assert_eq!(config.validate(), Err(ConfigError::EmptyListeners));
    }

    #[test]
    fn parses_strict_host_routing_mode() {
        let config: Config = toml::from_str(
            r#"
            [server.host_routing]
            strict = true
            "#,
        )
        .unwrap();

        assert!(config.server.host_routing.strict);
        config.validate().unwrap();
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
        let snapshot_store = secure_test_dir("config-admin-self-healing-snapshots");
        let config: Config = toml::from_str(&format!(
            r#"
            [admin]
            enabled = true
            listen = "127.0.0.1:9090"
            token_env = "FLUXHEIM_ADMIN_TOKEN"
            snapshot_store = "{}"

            [admin.transport]
            mode = "local_only"

            [admin.health]
            unauthenticated = false
            response = "minimal"

            [admin.auth_throttle]
            enabled = true
            window_secs = 30
            per_source_failures = 3
            global_failures = 50
            base_lockout_secs = 10
            max_lockout_secs = 120
            max_sources = 1024

            [admin.self_healing]
            enabled = true
            validation_window_secs = 45
            health_path = "/_fluxheim/health"
            min_successful_checks = 2
            max_error_rate_per_mille = 50
            "#,
            snapshot_store.display()
        ))
        .unwrap();

        config.validate().unwrap();
        assert!(config.admin.enabled);
        assert!(config.admin.self_healing.enabled);
        assert_eq!(
            config.admin.snapshot_store.as_deref(),
            Some(snapshot_store.as_path())
        );
        assert_eq!(
            config.admin.health.response,
            AdminHealthResponseMode::Minimal
        );
        assert_eq!(
            config.admin.transport.mode,
            AdminRemoteTransportMode::LocalOnly
        );
        assert_eq!(config.admin.auth_throttle.per_source_failures, 3);
        assert_eq!(config.admin.auth_throttle.global_failures, 50);
    }

    #[test]
    fn rejects_remote_unauthenticated_admin_health() {
        let snapshot_store = secure_test_dir("config-admin-remote-health-snapshots");
        let config = Config {
            admin: AdminConfig {
                enabled: true,
                listen: "0.0.0.0:9090".to_owned(),
                require_loopback: false,
                token_env: Some("FLUXHEIM_ADMIN_TOKEN".to_owned()),
                snapshot_store: Some(snapshot_store),
                transport: AdminTransportConfig {
                    mode: AdminRemoteTransportMode::TrustedTlsTerminator,
                },
                health: AdminHealthConfig {
                    unauthenticated: true,
                    ..AdminHealthConfig::default()
                },
                ..AdminConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::UnauthenticatedAdminHealthNotLoopback {
                address: "0.0.0.0:9090".to_owned()
            })
        );
    }

    #[test]
    fn rejects_invalid_admin_auth_throttle() {
        let config: Config = toml::from_str(
            r#"
            [admin.auth_throttle]
            enabled = true
            max_lockout_secs = 1
            base_lockout_secs = 2
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidAdminAuthThrottle {
                field: "admin.auth_throttle.max_lockout_secs"
            })
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

    #[cfg(feature = "metrics-otlp")]
    #[test]
    fn parses_otlp_metrics_export_config() {
        let config: Config = toml::from_str(
            r#"
            [metrics]
            enabled = true

            [metrics.otlp]
            enabled = true
            endpoint = "http://127.0.0.1:9090/api/v1/otlp/v1/metrics"
            service_name = "fluxheim-smoke"
            interval_secs = 1
            timeout_secs = 1
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.metrics.otlp.enabled);
        assert_eq!(
            config.metrics.otlp.endpoint,
            "http://127.0.0.1:9090/api/v1/otlp/v1/metrics"
        );
        assert_eq!(config.metrics.otlp.service_name, "fluxheim-smoke");
        assert_eq!(config.metrics.otlp.interval_secs, 1);
    }

    #[cfg(feature = "metrics-otlp")]
    #[test]
    fn accepts_https_otlp_metrics_endpoint() {
        let config: Config = toml::from_str(
            r#"
            [metrics]
            enabled = true

            [metrics.otlp]
            enabled = true
            endpoint = "https://collector.example.test/v1/metrics"
            tls_ca_cert_path = "fixtures/private-ca.pem"
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(
            config.metrics.otlp.endpoint,
            "https://collector.example.test/v1/metrics"
        );
        assert_eq!(
            config.metrics.otlp.tls_ca_cert_path.as_deref(),
            Some(Path::new("fixtures/private-ca.pem"))
        );
    }

    #[cfg(not(feature = "metrics-otlp"))]
    #[test]
    fn rejects_otlp_metrics_export_without_feature() {
        let config: Config = toml::from_str(
            r#"
            [metrics]
            enabled = true

            [metrics.otlp]
            enabled = true
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::MetricsOtlpExportNotCompiled)
        );
    }

    #[cfg(feature = "otel-tracing")]
    #[test]
    fn parses_trace_context_config() {
        let config: Config = toml::from_str(
            r#"
            [tracing]
            enabled = true
            mode = "propagate_only"
            traceparent = true
            log_trace_id = true
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.tracing.enabled);
        assert_eq!(config.tracing.mode, super::TracingMode::PropagateOnly);
    }

    #[cfg(all(feature = "otel-tracing", feature = "otel-otlp"))]
    #[test]
    fn parses_otlp_trace_export_config() {
        let config: Config = toml::from_str(
            r#"
            [tracing]
            enabled = true
            mode = "propagate_only"

            [tracing.otlp]
            enabled = true
            endpoint = "http://127.0.0.1:4318/v1/traces"
            service_name = "fluxheim-smoke"
            queue_size = 64
            timeout_secs = 1
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.tracing.otlp.enabled);
        assert_eq!(
            config.tracing.otlp.endpoint,
            "http://127.0.0.1:4318/v1/traces"
        );
        assert_eq!(config.tracing.otlp.service_name, "fluxheim-smoke");
        assert_eq!(config.tracing.otlp.queue_size, 64);
    }

    #[cfg(all(feature = "otel-tracing", feature = "otel-otlp"))]
    #[test]
    fn accepts_https_otlp_trace_endpoint() {
        let config: Config = toml::from_str(
            r#"
            [tracing]
            enabled = true

            [tracing.otlp]
            enabled = true
            endpoint = "https://collector.example.test/v1/traces"
            tls_ca_cert_path = "fixtures/private-ca.pem"
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(
            config.tracing.otlp.endpoint,
            "https://collector.example.test/v1/traces"
        );
        assert_eq!(
            config.tracing.otlp.tls_ca_cert_path.as_deref(),
            Some(Path::new("fixtures/private-ca.pem"))
        );
    }

    #[cfg(all(feature = "otel-tracing", not(feature = "otel-otlp")))]
    #[test]
    fn rejects_otlp_trace_export_without_feature() {
        let config: Config = toml::from_str(
            r#"
            [tracing]
            enabled = true

            [tracing.otlp]
            enabled = true
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::OtlpTraceExportNotCompiled)
        );
    }

    #[cfg(not(feature = "otel-tracing"))]
    #[test]
    fn rejects_enabled_tracing_without_feature() {
        let config: Config = toml::from_str(
            r#"
            [tracing]
            enabled = true
            "#,
        )
        .unwrap();

        assert_eq!(config.validate(), Err(ConfigError::TracingNotCompiled));
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
            include_client_ip = false
            include_path = false
            include_route = false
            include_upstream = false
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
        assert!(!config.logging.access.include_client_ip);
        assert!(!config.logging.access.include_path);
        assert!(!config.logging.access.include_route);
        assert!(!config.logging.access.include_upstream);
        assert!(!config.logging.access.request_id);
        assert_eq!(config.logging.access.request_id_header, "x-correlation-id");
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn parses_file_logging_config() {
        let log_path = unique_temp_path("config-file-logging").join("fluxheim.log");
        let config: Config = toml::from_str(&format!(
            r#"
            [logging.file]
            enabled = true
            path = "{}"
            append = false
            "#,
            log_path.display()
        ))
        .unwrap();

        config.validate().unwrap();
        assert!(config.logging.file.enabled);
        assert_eq!(
            config.logging.file.path.as_deref(),
            Some(log_path.as_path())
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
        let path = unique_world_writable_child("config-log-world-writable", "fluxheim.log");
        let config: Config = toml::from_str(&format!(
            r#"
            [logging.file]
            path = "{}"
            "#,
            path.display()
        ))
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
            path = "/var/log/fluxheim.log"
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
        let snapshot_store = secure_test_dir("config-admin-missing-auth-snapshots");
        let config = Config {
            admin: AdminConfig {
                enabled: true,
                snapshot_store: Some(snapshot_store),
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
        let snapshot_store = secure_test_dir("config-admin-remote-default-snapshots");
        let config = Config {
            admin: AdminConfig {
                enabled: true,
                listen: "0.0.0.0:9090".to_owned(),
                token_env: Some("FLUXHEIM_ADMIN_TOKEN".to_owned()),
                snapshot_store: Some(snapshot_store),
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

    #[test]
    fn rejects_remote_admin_without_trusted_tls_terminator() {
        let snapshot_store = secure_test_dir("config-admin-remote-insecure-snapshots");
        let config = Config {
            admin: AdminConfig {
                enabled: true,
                listen: "0.0.0.0:9090".to_owned(),
                require_loopback: false,
                token_env: Some("FLUXHEIM_ADMIN_TOKEN".to_owned()),
                snapshot_store: Some(snapshot_store),
                ..AdminConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::RemoteAdminRequiresSecureTransport {
                address: "0.0.0.0:9090".to_owned()
            })
        );
    }

    #[test]
    fn accepts_remote_admin_when_trusted_tls_terminator_is_explicit() {
        let snapshot_store = secure_test_dir("config-admin-remote-trusted-snapshots");
        let config = Config {
            admin: AdminConfig {
                enabled: true,
                listen: "0.0.0.0:9090".to_owned(),
                require_loopback: false,
                token_env: Some("FLUXHEIM_ADMIN_TOKEN".to_owned()),
                snapshot_store: Some(snapshot_store),
                transport: AdminTransportConfig {
                    mode: AdminRemoteTransportMode::TrustedTlsTerminator,
                },
                ..AdminConfig::default()
            },
            ..Config::default()
        };

        config.validate().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_admin_paths_under_world_writable_parent() {
        let token_file = unique_world_writable_child("config-admin-token-world-writable", "token");
        let token_config = Config {
            admin: AdminConfig {
                token_file: Some(token_file),
                ..AdminConfig::default()
            },
            ..Config::default()
        };
        assert!(matches!(
            token_config.validate(),
            Err(ConfigError::UnsafePath { field, .. }) if field == "admin.token_file"
        ));

        let snapshot_store =
            unique_world_writable_child("config-admin-snapshot-world-writable", "snapshots");
        let snapshot_config = Config {
            admin: AdminConfig {
                snapshot_store: Some(snapshot_store),
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
    fn accepts_tls_listener_with_default_vhost_static_certificate() {
        let certificate = StaticCertificateConfig {
            cert_path: PathBuf::from("fullchain.pem"),
            key_path: PathBuf::from("key.pem"),
        };
        let config = Config {
            server: ServerConfig {
                tls_listen: vec!["127.0.0.1:8443".to_owned()],
                default_vhost: Some("example".to_owned()),
                ..ServerConfig::default()
            },
            tls: super::TlsConfig {
                enabled: true,
                ..super::TlsConfig::default()
            },
            vhosts: vec![VhostConfig {
                name: "example".to_owned(),
                hosts: vec!["example.test".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                tls: VhostTlsConfig {
                    enabled: true,
                    certificate: Some(certificate),
                    ..VhostTlsConfig::default()
                },
                acme_challenge: super::VhostAcmeChallengeConfig::default(),
                redirect: super::VhostRedirectConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };

        config.validate().unwrap();
    }

    #[cfg(feature = "acme")]
    #[test]
    fn accepts_tls_listener_with_default_vhost_acme_certificate_source() {
        let storage = secure_test_dir("config-default-vhost-acme-source");
        let config = Config {
            server: ServerConfig {
                tls_listen: vec!["127.0.0.1:8443".to_owned()],
                default_vhost: Some("example".to_owned()),
                ..ServerConfig::default()
            },
            tls: super::TlsConfig {
                enabled: true,
                acme: super::AcmeConfig {
                    enabled: true,
                    storage: Some(storage),
                    contact_email: Some("admin@example.test".to_owned()),
                    ..super::AcmeConfig::default()
                },
                ..super::TlsConfig::default()
            },
            vhosts: vec![VhostConfig {
                name: "example".to_owned(),
                hosts: vec!["example.test".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                tls: VhostTlsConfig {
                    enabled: true,
                    acme: super::VhostAcmeConfig {
                        enabled: true,
                        issuer: None,
                        domains: Vec::new(),
                    },
                    ..VhostTlsConfig::default()
                },
                acme_challenge: super::VhostAcmeChallengeConfig::default(),
                redirect: super::VhostRedirectConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
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
            tracing: TracingConfig::default(),
            logging: LoggingConfig::default(),
            headers: HeaderPolicyConfig::default(),
            tls: super::TlsConfig::default(),
            proxy: ProxyConfig {
                upstream: Some("https://origin.example.test".to_owned()),
                upstream_tls: true,
                upstream_sni: None,
                ..ProxyConfig::default()
            },
            compression: CompressionConfig::default(),
            cache: CacheConfig::default(),
            cache_purger: CachePurgerConfig::default(),
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
    fn vhost_section_errors_include_vhost_context() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [vhosts.proxy]
            upstream = "https://origin.example.test"
            "#,
        )
        .unwrap();

        let error = config.validate().unwrap_err();
        assert!(matches!(
            &error,
            ConfigError::VhostSection {
                vhost,
                section: "proxy",
                source,
            } if vhost == "gateway"
                && matches!(source.as_ref(), ConfigError::InvalidUpstream { .. })
        ));
        assert!(
            error
                .to_string()
                .contains("vhost \"gateway\" proxy: upstream must be host:port")
        );
    }

    #[test]
    fn route_section_errors_include_vhost_and_route_context() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "api"
            path_prefix = "/api/"

            [vhosts.routes.proxy]
            upstream = "https://api.example.test"
            "#,
        )
        .unwrap();

        let error = config.validate().unwrap_err();
        assert!(matches!(
            &error,
            ConfigError::RouteSection {
                vhost,
                route,
                section: "proxy",
                source,
            } if vhost == "gateway"
                && route == "api"
                && matches!(source.as_ref(), ConfigError::InvalidUpstream { .. })
        ));
        assert!(
            error
                .to_string()
                .contains("vhost \"gateway\" route \"api\" proxy: upstream must be host:port")
        );
    }

    #[test]
    fn rejects_empty_index_files() {
        let config = Config {
            server: ServerConfig::default(),
            admin: AdminConfig::default(),
            metrics: MetricsConfig::default(),
            tracing: TracingConfig::default(),
            logging: LoggingConfig::default(),
            headers: HeaderPolicyConfig::default(),
            tls: super::TlsConfig::default(),
            proxy: ProxyConfig::default(),
            compression: CompressionConfig::default(),
            cache: CacheConfig::default(),
            cache_purger: CachePurgerConfig::default(),
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
    fn rejects_too_many_index_files() {
        let index_files = (0..=super::MAX_WEB_INDEX_FILES)
            .map(|index| format!("index-{index}.html"))
            .collect::<Vec<_>>();
        let config = Config {
            server: ServerConfig::default(),
            admin: AdminConfig::default(),
            metrics: MetricsConfig::default(),
            tracing: TracingConfig::default(),
            logging: LoggingConfig::default(),
            headers: HeaderPolicyConfig::default(),
            tls: super::TlsConfig::default(),
            proxy: ProxyConfig::default(),
            compression: CompressionConfig::default(),
            cache: CacheConfig::default(),
            cache_purger: CachePurgerConfig::default(),
            web: WebConfig {
                root: Some(PathBuf::from("public")),
                index_files,
                deny_dotfiles: true,
                ..WebConfig::default()
            },
            vhosts: vec![],
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidConfigListLength {
                field: "web.index_files".to_owned(),
                max: super::MAX_WEB_INDEX_FILES,
            })
        );
    }

    #[test]
    fn route_web_wraps_too_many_index_files() {
        let index_files = (0..=super::MAX_WEB_INDEX_FILES)
            .map(|index| format!("\"index-{index}.html\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [[vhosts.routes]]
            name = "static"
            path_prefix = "/static/"

            [vhosts.routes.web]
            root = "public"
            index_files = [{index_files}]
            "#
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::RouteSection {
                vhost: "gateway".to_owned(),
                route: "static".to_owned(),
                section: "web",
                source: Box::new(ConfigError::InvalidConfigListLength {
                    field: "web.index_files".to_owned(),
                    max: super::MAX_WEB_INDEX_FILES,
                })
            })
        );
    }

    #[test]
    fn rejects_nested_index_files() {
        let config = Config {
            server: ServerConfig::default(),
            admin: AdminConfig::default(),
            metrics: MetricsConfig::default(),
            tracing: TracingConfig::default(),
            logging: LoggingConfig::default(),
            headers: HeaderPolicyConfig::default(),
            tls: super::TlsConfig::default(),
            proxy: ProxyConfig::default(),
            compression: CompressionConfig::default(),
            cache: CacheConfig::default(),
            cache_purger: CachePurgerConfig::default(),
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
            normalize_host("Example.COM.:443"),
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

    fn host_candidate() -> impl Strategy<Value = String> {
        prop::string::string_regex("[A-Za-z0-9.-]{1,64}").expect("valid host candidate regex")
    }

    fn header_template_fragment() -> impl Strategy<Value = String> {
        prop::string::string_regex("[A-Za-z0-9 _./:;=,?&-]{0,32}")
            .expect("valid header template fragment regex")
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn normalized_hosts_are_lowercase_and_idempotent(
            candidate in host_candidate(),
            port in prop::option::of(1u16..=u16::MAX),
        ) {
            let input = match port {
                Some(port) => format!("{candidate}:{port}"),
                None => candidate,
            };

            if let Some(normalized) = normalize_host(&input) {
                prop_assert!(!normalized.is_empty());
                let lowercase = normalized.to_ascii_lowercase();
                prop_assert_eq!(normalized.as_str(), lowercase.as_str());
                prop_assert!(!normalized.ends_with('.'));
                prop_assert!(!normalized.contains('*'));
                prop_assert!(!normalized.contains('/'));
                prop_assert!(!normalized.contains('\\'));
                prop_assert!(!normalized.contains('?'));
                prop_assert!(!normalized.contains('#'));
                prop_assert!(!normalized.contains('@'));
                let normalized_again = normalize_host(&normalized);
                prop_assert_eq!(normalized_again.as_deref(), Some(normalized.as_str()));
            }
        }

        #[test]
        fn host_normalization_rejects_forbidden_delimiters(
            prefix in host_candidate(),
            suffix in host_candidate(),
            delimiter in prop_oneof![
                Just('/'),
                Just('\\'),
                Just('?'),
                Just('#'),
                Just('@'),
                Just('*'),
                Just(' '),
            ],
        ) {
            let input = format!("{prefix}{delimiter}{suffix}");

            prop_assert_eq!(normalize_host(&input), None);
        }

        #[test]
        fn dynamic_header_templates_accept_supported_variables(
            prefix in header_template_fragment(),
            suffix in header_template_fragment(),
            variable in prop::sample::select(vec![
                "host",
                "remote_addr",
                "scheme",
                "uri",
                "path",
                "query",
                "request_id",
                "http.upgrade",
                "http.x-forwarded-host",
            ]),
        ) {
            let template = format!("{prefix}{{{variable}}}{suffix}");

            prop_assert!(
                validate_dynamic_header_template("headers.request", "x-test", &template).is_ok()
            );
        }

        #[test]
        fn dynamic_header_templates_reject_unknown_variables(
            prefix in header_template_fragment(),
            variable in "[a-z_]{1,16}",
            suffix in header_template_fragment(),
        ) {
            prop_assume!(!valid_dynamic_header_variable(&variable));
            let template = format!("{prefix}{{{variable}}}{suffix}");
            let result = validate_dynamic_header_template("headers.request", "x-test", &template);

            prop_assert!(result.is_err());
        }
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
    fn parses_vhost_and_route_access_policy() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.access]
            allow = ["10.0.0.0/8", "2001:db8::/32"]
            deny = ["10.9.0.0/16"]

            [vhosts.rate_limit]
            enabled = true
            requests_per_second = 10
            burst = 20
            mode = "delay"
            max_delay_ms = 250

            [vhosts.concurrency]
            enabled = true
            max_in_flight = 100
            queue_timeout_ms = 100

            [[vhosts.routes]]
            name = "admin"
            path_prefix = "/admin/"

            [vhosts.routes.access]
            allow = ["10.1.2.3"]

            [vhosts.routes.rate_limit]
            enabled = true
            requests_per_second = 2
            burst = 4
            status = 429

            [vhosts.routes.concurrency]
            enabled = true
            max_in_flight = 10
            queue_timeout_ms = 50

            [vhosts.routes.proxy]
            upstream = "127.0.0.1:3000"
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(
            config.vhosts[0].access.allow,
            ["10.0.0.0/8", "2001:db8::/32"]
        );
        assert_eq!(config.vhosts[0].access.deny, ["10.9.0.0/16"]);
        assert_eq!(config.vhosts[0].routes[0].access.allow, ["10.1.2.3"]);
        assert_eq!(config.vhosts[0].rate_limit.requests_per_second, 10);
        assert_eq!(config.vhosts[0].rate_limit.mode, RateLimitMode::Delay);
        assert_eq!(config.vhosts[0].rate_limit.max_delay_ms, 250);
        assert_eq!(config.vhosts[0].routes[0].rate_limit.burst, 4);
        assert_eq!(config.vhosts[0].concurrency.max_in_flight, 100);
        assert_eq!(config.vhosts[0].concurrency.queue_timeout_ms, 100);
        assert_eq!(config.vhosts[0].routes[0].concurrency.max_in_flight, 10);
        assert_eq!(config.vhosts[0].routes[0].concurrency.queue_timeout_ms, 50);
    }

    #[test]
    fn rejects_invalid_vhost_access_rule() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.access]
            allow = ["10.0.0.0/99"]

            [vhosts.proxy]
            upstream = "127.0.0.1:3000"
            "#,
        )
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("vhosts.access.allow"), "{error}");
    }

    #[test]
    fn rejects_invalid_vhost_rate_limit() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.rate_limit]
            enabled = true
            requests_per_second = 0

            [vhosts.proxy]
            upstream = "127.0.0.1:3000"
            "#,
        )
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("vhosts.rate_limit.requests_per_second"),
            "{error}"
        );
    }

    #[test]
    fn rejects_invalid_vhost_concurrency_limit() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.concurrency]
            enabled = true
            max_in_flight = 0

            [vhosts.proxy]
            upstream = "127.0.0.1:3000"
            "#,
        )
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("vhosts.concurrency.max_in_flight"),
            "{error}"
        );
    }

    #[test]
    fn parses_vhost_routes() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]
            max_request_body_bytes = "128MiB"

            [vhosts.acme_challenge]
            enabled = true
            upstreams = ["127.0.0.1:8080"]

            [[vhosts.routes]]
            name = "chat"
            path_prefix = "/chat/"
            https_redirect_exempt = true
            strip_prefix = "/chat/"
            rewrite_prefix = "/backend/chat/"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            connect_timeout_secs = 5
            read_timeout_secs = 600
            send_timeout_secs = 600

            [[vhosts.routes]]
            name = "repo"
            path_prefix = "/repo"
            strip_prefix = "/repo"

            [vhosts.routes.web]
            root = "/srv/repo"

            [[vhosts.routes]]
            name = "fallback"
            fallback = true

            [vhosts.routes.redirect]
            to = "https://gateway.example{uri}"
            status = 308
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(config.vhosts[0].routes.len(), 3);
        assert_eq!(
            config.vhosts[0].max_request_body_bytes,
            Some(ByteSize::from_bytes(128 * 1024 * 1024))
        );
        assert!(config.vhosts[0].acme_challenge.enabled);
        assert_eq!(
            config.vhosts[0].acme_challenge.upstreams,
            ["127.0.0.1:8080"]
        );
        assert_eq!(config.vhosts[0].routes[0].name, "chat");
        assert!(config.vhosts[0].routes[0].https_redirect_exempt);
        assert_eq!(
            config.vhosts[0].routes[0].rewrite_prefix.as_deref(),
            Some("/backend/chat/")
        );
        assert_eq!(
            config.vhosts[0].routes[0]
                .proxy
                .as_ref()
                .unwrap()
                .primary_upstream(),
            "127.0.0.1:6012"
        );
        assert_eq!(
            config.vhosts[0].routes[0]
                .proxy
                .as_ref()
                .unwrap()
                .read_timeout_secs,
            Some(600)
        );
        assert_eq!(
            config.vhosts[0].routes[2].redirect.as_ref().unwrap().status,
            308
        );
    }

    #[test]
    fn rejects_invalid_vhost_body_limit() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]
            max_request_body_bytes = "0B"

            [vhosts.proxy]
            upstreams = ["127.0.0.1:6010"]
            "#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidVhostLimit {
                vhost,
                field: "max_request_body_bytes"
            }) if vhost == "gateway"
        ));
    }

    #[test]
    fn rejects_too_many_server_listeners() {
        let listen = (0..=super::MAX_SERVER_LISTENERS)
            .map(|index| format!("\"127.0.0.1:{}\"", 10_000 + index))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [server]
            listen = [{listen}]
            "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidConfigListLength {
                field: "server.listen".to_owned(),
                max: super::MAX_SERVER_LISTENERS,
            })
        );
    }

    #[test]
    fn rejects_too_many_tls_listeners() {
        let tls_listen = (0..=super::MAX_SERVER_LISTENERS)
            .map(|index| format!("\"127.0.0.1:{}\"", 20_000 + index))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [server]
            tls_listen = [{tls_listen}]
            "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidConfigListLength {
                field: "server.tls_listen".to_owned(),
                max: super::MAX_SERVER_LISTENERS,
            })
        );
    }

    #[test]
    fn rejects_too_many_trusted_proxies() {
        let trusted_proxies = (0..=super::MAX_TRUSTED_PROXIES)
            .map(|index| format!("\"10.{}.0.0/16\"", index % 256))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [server]
            trusted_proxies = [{trusted_proxies}]
            "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidConfigListLength {
                field: "server.trusted_proxies".to_owned(),
                max: super::MAX_TRUSTED_PROXIES,
            })
        );
    }

    #[test]
    fn rejects_too_many_vhosts() {
        let vhosts = (0..=super::MAX_VHOSTS)
            .map(|index| {
                format!(
                    r#"
                    [[vhosts]]
                    name = "site-{index}"
                    hosts = ["site-{index}.example.test"]
                    "#
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let config: Config = toml::from_str(&vhosts).unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidConfigListLength {
                field: "vhosts".to_owned(),
                max: super::MAX_VHOSTS,
            })
        );
    }

    #[test]
    fn rejects_oversized_vhost_name() {
        let name = "v".repeat(super::MAX_VHOST_NAME_BYTES + 1);
        let config: Config = toml::from_str(&format!(
            r#"
            [[vhosts]]
            name = {name:?}
            hosts = ["gateway.example.test"]
            "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidConfigNameLength {
                field: "vhosts.name",
                max: super::MAX_VHOST_NAME_BYTES,
            })
        );
    }

    #[test]
    fn rejects_too_many_vhost_hosts() {
        let hosts = (0..=super::MAX_VHOST_HOSTS)
            .map(|index| format!("\"alias-{index}.example.test\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = [{hosts}]
            "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidConfigListLength {
                field: "vhost \"gateway\".hosts".to_owned(),
                max: super::MAX_VHOST_HOSTS,
            })
        );
    }

    #[test]
    fn rejects_too_many_vhost_routes() {
        let routes = (0..=super::MAX_VHOST_ROUTES)
            .map(|index| {
                format!(
                    r#"
                    [[vhosts.routes]]
                    name = "route-{index}"
                    path_prefix = "/route-{index}/"
                    "#
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let config: Config = toml::from_str(&format!(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]
            {routes}
            "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidConfigListLength {
                field: "vhost \"gateway\".routes".to_owned(),
                max: super::MAX_VHOST_ROUTES,
            })
        );
    }

    #[test]
    fn rejects_oversized_route_name() {
        let route_name = "r".repeat(super::MAX_ROUTE_NAME_BYTES + 1);
        let config: Config = toml::from_str(&format!(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [[vhosts.routes]]
            name = {route_name:?}
            path_prefix = "/assets/"

            [vhosts.routes.web]
            root = "/srv/assets"
            "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidConfigNameLength {
                field: "vhosts.routes.name",
                max: super::MAX_ROUTE_NAME_BYTES,
            })
        );
    }

    #[test]
    fn rejects_enabled_acme_challenge_without_upstream() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [vhosts.acme_challenge]
            enabled = true
            "#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::MissingAcmeChallengeUpstream { vhost }) if vhost == "gateway"
        ));
    }

    #[test]
    fn rejects_too_many_acme_challenge_upstreams() {
        let upstreams = (0..=super::MAX_ACME_CHALLENGE_UPSTREAMS)
            .map(|index| format!("\"acme-{index}.example.test:8080\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config: Config = toml::from_str(&format!(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [vhosts.acme_challenge]
            enabled = true
            upstreams = [{upstreams}]
            "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::TooManyAcmeChallengeUpstreams {
                vhost: "gateway".to_owned(),
                max: super::MAX_ACME_CHALLENGE_UPSTREAMS,
            })
        );
    }

    #[test]
    fn rejects_duplicate_acme_challenge_upstreams() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [vhosts.acme_challenge]
            enabled = true
            upstreams = ["acme.example.test:8080", "ACME.example.test:8080"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::DuplicateAcmeChallengeUpstream {
                vhost: "gateway".to_owned(),
                upstream: "ACME.example.test:8080".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_enabled_vhost_redirect_without_target() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "www"
            hosts = ["www.example.test"]

            [vhosts.redirect]
            enabled = true
            "#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::MissingVhostRedirectTarget { vhost }) if vhost == "www"
        ));
    }

    #[test]
    fn rejects_vhost_redirect_with_explicit_fallback_route() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "www"
            hosts = ["www.example.test"]

            [vhosts.redirect]
            enabled = true
            to = "https://example.test{uri}"

            [[vhosts.routes]]
            name = "fallback"
            fallback = true

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:3000"]
            "#,
        )
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::VhostRedirectConflictsWithFallback { vhost }) if vhost == "www"
        ));
    }

    #[test]
    fn rejects_invalid_vhost_routes() {
        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_exact = "/one"
            path_prefix = "/one/"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidRouteMatcher {
                vhost: "gateway".to_owned(),
                route: "bad".to_owned(),
            })
        );

        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_prefix = "/one/"

            [vhosts.routes.redirect]
            to = "https://gateway.example{uri}"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidRouteAction {
                vhost: "gateway".to_owned(),
                route: "bad".to_owned(),
            })
        );

        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_prefix = "/one/"
            rewrite_prefix = "/upstream/"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidRouteRewritePrefix {
                vhost: "gateway".to_owned(),
                route: "bad".to_owned(),
            })
        );

        let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_prefix = "/one/"
            strip_prefix = "/one/"
            rewrite_prefix = "/upstream/%2e%2e/"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
        )
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidRouteRewritePrefix {
                vhost: "gateway".to_owned(),
                route: "bad".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_duplicate_vhost_hosts() {
        let config = Config {
            server: ServerConfig::default(),
            admin: AdminConfig::default(),
            metrics: MetricsConfig::default(),
            tracing: TracingConfig::default(),
            logging: LoggingConfig::default(),
            headers: HeaderPolicyConfig::default(),
            tls: super::TlsConfig::default(),
            proxy: ProxyConfig::default(),
            compression: CompressionConfig::default(),
            cache: CacheConfig::default(),
            cache_purger: CachePurgerConfig::default(),
            web: WebConfig::default(),
            vhosts: vec![
                VhostConfig {
                    name: "first.example".to_owned(),
                    hosts: vec!["Example.com".to_owned()],
                    max_request_body_bytes: None,
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: super::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    compression: None,
                    headers: VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
                VhostConfig {
                    name: "second.example".to_owned(),
                    hosts: vec!["example.com:443".to_owned()],
                    max_request_body_bytes: None,
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: super::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    compression: None,
                    headers: VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
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
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: super::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::UnknownDefaultVhost {
                name: "missing".to_owned()
            })
        );
        let message = config.validate().unwrap_err().to_string();
        assert!(message.contains("include_conf_d = true"));
        assert!(message.contains("validate the config directory"));
    }

    #[test]
    fn accepts_wildcard_vhost_host() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "wild".to_owned(),
                hosts: vec!["*.example.com".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: super::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
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
        fs::create_dir_all(dir.child("site")).unwrap();
        fs::write(
            dir.child("00-server.toml"),
            r#"
            [server]
            listen = ["127.0.0.1:19090"]
            default_vhost = "example"
            "#,
        )
        .unwrap();
        fs::write(
            dir.child("10-vhost.toml"),
            r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.web]
            root = "site"
            "#,
        )
        .unwrap();
        fs::write(dir.child(".ignored.toml"), "this is not toml").unwrap();
        fs::write(dir.child("ignored.txt"), "ignored").unwrap();

        let config = Config::load(Some(dir.path())).unwrap();

        assert_eq!(config.server.listen, ["127.0.0.1:19090"]);
        assert_eq!(config.server.default_vhost, Some("example".to_owned()));
        assert_eq!(config.vhosts.len(), 1);
        assert_eq!(config.vhosts[0].web.root, Some(dir.child("site")));
    }

    #[test]
    fn loading_main_config_file_also_loads_sibling_conf_d() {
        let dir = TestDir::new("config-file-with-conf-d");
        fs::create_dir_all(dir.child("conf.d")).unwrap();
        fs::create_dir_all(dir.child("conf.d/site")).unwrap();
        fs::write(
            dir.child("fluxheim.toml"),
            r#"
            include_conf_d = true

            [server]
            listen = ["127.0.0.1:19090"]
            default_vhost = "example"
            "#,
        )
        .unwrap();
        fs::write(
            dir.child("conf.d/10-vhost.toml"),
            r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.web]
            root = "site"
            "#,
        )
        .unwrap();

        let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

        assert_eq!(config.server.default_vhost, Some("example".to_owned()));
        assert_eq!(config.vhosts.len(), 1);
        assert_eq!(config.vhosts[0].web.root, Some(dir.child("conf.d/site")));
    }

    #[test]
    fn conf_d_parse_error_reports_source_file() {
        let dir = TestDir::new("config-file-with-bad-conf-d");
        fs::create_dir_all(dir.child("conf.d")).unwrap();
        fs::write(
            dir.child("fluxheim.toml"),
            r#"
            include_conf_d = true

            [server]
            listen = ["127.0.0.1:19090"]
            "#,
        )
        .unwrap();
        let bad_config = dir.child("conf.d/10-bad.toml");
        fs::write(
            &bad_config,
            "[vhosts.proxy.error_pages.web]\nroot = \"/tmp\"\n",
        )
        .unwrap();

        let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();
        let message = error.to_string();

        assert!(message.contains(&bad_config.display().to_string()));
        assert!(message.contains("failed to parse config"));
        assert!(message.contains("define [[vhosts.proxy.error_pages]]"));
    }

    #[test]
    fn config_parse_error_hints_route_proxy_error_page_array() {
        let dir = TestDir::new("config-route-proxy-error-page-table");
        let config = dir.child("fluxheim.toml");
        fs::write(
            &config,
            r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [[vhosts.routes]]
            name = "app"
            path_prefix = "/"

            [vhosts.routes.proxy.error_pages.web]
            root = "/srv/fluxheim/errors"
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&config)).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("failed to parse config"), "{message}");
        assert!(
            message.contains("define [[vhosts.routes.proxy.error_pages]]"),
            "{message}"
        );
    }

    #[test]
    fn config_parse_error_hints_singular_vhost_typo() {
        let dir = TestDir::new("config-singular-vhost-typo");
        let config = dir.child("fluxheim.toml");
        fs::write(
            &config,
            r#"
            [[vhost]]
            name = "bad"
            hosts = ["bad.example"]
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&config)).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("failed to parse config"));
        assert!(message.contains("hint: virtual hosts are configured with [[vhosts]]"));
    }

    #[test]
    fn config_parse_error_hints_vhost_table_before_array() {
        let dir = TestDir::new("config-vhost-table-before-array");
        let config = dir.child("fluxheim.toml");
        fs::write(
            &config,
            r#"
            [vhosts.proxy]
            upstreams = ["127.0.0.1:3000"]
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&config)).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("failed to parse config"), "{message}");
        assert!(
            message.contains("start each virtual host with [[vhosts]]"),
            "{message}"
        );
    }

    #[test]
    fn config_parse_error_hints_proxy_array_table() {
        let dir = TestDir::new("config-vhost-proxy-array-table");
        let config = dir.child("fluxheim.toml");
        fs::write(
            &config,
            r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [[vhosts.proxy]]
            upstreams = ["127.0.0.1:3000"]
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&config)).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("failed to parse config"), "{message}");
        assert!(
            message.contains("uses [vhosts.proxy], not [[vhosts.proxy]]"),
            "{message}"
        );
    }

    #[test]
    fn config_parse_error_hints_route_action_field() {
        let dir = TestDir::new("config-route-action-field");
        let config = dir.child("fluxheim.toml");
        fs::write(
            &config,
            r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [[vhosts.routes]]
            name = "app"
            path_prefix = "/"
            action = "proxy"
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&config)).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("failed to parse config"), "{message}");
        assert!(
            message.contains("routes select their action by defining one nested table"),
            "{message}"
        );
    }

    #[test]
    fn config_parse_error_hints_route_table_before_array() {
        let dir = TestDir::new("config-route-table-before-array");
        let config = dir.child("fluxheim.toml");
        fs::write(
            &config,
            r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:3000"]
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&config)).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("failed to parse config"), "{message}");
        assert!(
            message.contains("start each route with [[vhosts.routes]]"),
            "{message}"
        );
    }

    #[test]
    fn config_parse_error_hints_route_web_table_before_array() {
        let dir = TestDir::new("config-route-web-table-before-array");
        let config = dir.child("fluxheim.toml");
        fs::write(
            &config,
            r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [vhosts.routes.web]
            root = "/srv/sites/site"
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&config)).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("failed to parse config"), "{message}");
        assert!(
            message.contains("start each route with [[vhosts.routes]]"),
            "{message}"
        );
    }

    #[test]
    fn config_parse_error_hints_route_proxy_array_table() {
        let dir = TestDir::new("config-route-proxy-array-table");
        let config = dir.child("fluxheim.toml");
        fs::write(
            &config,
            r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [[vhosts.routes]]
            name = "app"
            path_prefix = "/"

            [[vhosts.routes.proxy]]
            upstreams = ["127.0.0.1:3000"]
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&config)).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("failed to parse config"), "{message}");
        assert!(
            message.contains("route action/config tables use single-bracket tables"),
            "{message}"
        );
    }

    #[test]
    fn config_parse_error_hints_route_web_array_table() {
        let dir = TestDir::new("config-route-web-array-table");
        let config = dir.child("fluxheim.toml");
        fs::write(
            &config,
            r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [[vhosts.routes]]
            name = "assets"
            path_prefix = "/assets/"

            [[vhosts.routes.web]]
            root = "/srv/sites/site/assets"
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&config)).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("failed to parse config"), "{message}");
        assert!(
            message.contains("route action/config tables use single-bracket tables"),
            "{message}"
        );
    }

    #[test]
    fn config_parse_error_hints_plural_vhost_tls_certificate_table() {
        let dir = TestDir::new("config-plural-vhost-tls-certificates");
        let config = dir.child("fluxheim.toml");
        fs::write(
            &config,
            r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [vhosts.tls]
            enabled = true

            [[vhosts.tls.certificates]]
            cert_path = "/etc/fluxheim/tls/site/fullchain.pem"
            key_path = "/etc/fluxheim/tls/site/privkey.pem"
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&config)).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("failed to parse config"));
        assert!(message.contains("hint: vhost TLS uses [vhosts.tls.certificate]"));
    }

    #[test]
    fn conf_d_tls_acme_fragment_preserves_main_tls_settings() {
        let dir = TestDir::new("config-file-with-tls-acme-conf-d");
        fs::create_dir_all(dir.child("conf.d")).unwrap();
        fs::create_dir_all(dir.child("site")).unwrap();
        fs::write(dir.child("site/index.html"), "ok").unwrap();
        fs::write(
            dir.child("fluxheim.toml"),
            r#"
            include_conf_d = true

            [server]
            listen = ["127.0.0.1:19090"]
            default_vhost = "example"

            [tls]
            enabled = true
            backend = "rustls"
            "#,
        )
        .unwrap();
        fs::write(
            dir.child("conf.d/acme.toml"),
            format!(
                r#"
                [tls.acme]
                enabled = true
                storage = "{}"
                contact_email = "admin@example.test"
                default_issuer = "letsencrypt"
                challenge = "http-01"
                "#,
                dir.child("acme").display()
            ),
        )
        .unwrap();
        fs::write(
            dir.child("conf.d/vhost.toml"),
            format!(
                r#"
                [[vhosts]]
                name = "example"
                hosts = ["example.test"]

                [vhosts.tls]
                enabled = true

                [vhosts.tls.acme]
                enabled = true
                domains = ["example.test"]

                [vhosts.web]
                root = "{}"
                "#,
                dir.child("site").display()
            ),
        )
        .unwrap();

        let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

        assert!(config.tls.enabled);
        assert!(config.tls.acme.enabled);
        assert_eq!(config.vhosts.len(), 1);
        assert!(config.vhosts[0].tls.enabled);
        assert!(config.vhosts[0].tls.acme.enabled);
        #[cfg(feature = "acme")]
        assert_eq!(crate::acme::renewal_targets(&config).len(), 1);
    }

    #[test]
    fn loading_main_config_file_does_not_load_conf_d_without_opt_in() {
        let dir = TestDir::new("config-file-with-conf-d-no-opt-in");
        fs::create_dir_all(dir.child("conf.d")).unwrap();
        fs::write(
            dir.child("fluxheim.toml"),
            r#"
            [server]
            listen = ["127.0.0.1:19090"]
            "#,
        )
        .unwrap();
        fs::write(
            dir.child("conf.d/10-vhost.toml"),
            r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]
            "#,
        )
        .unwrap();

        let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

        assert!(config.vhosts.is_empty());
    }

    #[test]
    fn loading_config_directory_also_loads_conf_d_after_top_level_files() {
        let dir = TestDir::new("config-dir-with-conf-d");
        fs::create_dir_all(dir.child("conf.d/site")).unwrap();
        fs::write(
            dir.child("00-server.toml"),
            r#"
            [server]
            listen = ["127.0.0.1:19090"]
            default_vhost = "example"
            "#,
        )
        .unwrap();
        fs::write(
            dir.child("conf.d/10-vhost.toml"),
            r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.web]
            root = "site"
            "#,
        )
        .unwrap();

        let config = Config::load(Some(dir.path())).unwrap();

        assert_eq!(config.server.default_vhost, Some("example".to_owned()));
        assert_eq!(config.vhosts.len(), 1);
        assert_eq!(config.vhosts[0].web.root, Some(dir.child("conf.d/site")));
    }

    #[test]
    fn rejects_config_directory_with_too_many_toml_files() {
        let dir = TestDir::new("config-dir-too-many-files");
        for index in 0..=super::MAX_CONFIG_DIRECTORY_FILES {
            fs::write(dir.child(&format!("{index:03}.toml")), "[server]\n").unwrap();
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
            dir.child("fluxheim.toml"),
            r#"
            [cache.disk]
            enabled = true
            path = "cache"
            max_size_bytes = "1GiB"
            "#,
        )
        .unwrap();

        let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

        assert_eq!(config.cache.disk.path, Some(dir.child("cache")));
    }

    #[test]
    fn resolves_relative_server_process_paths_from_config_file() {
        let dir = TestDir::new("server-process-paths");
        fs::write(
            dir.child("fluxheim.toml"),
            r#"
            [server.process]
            error_log = "logs/error.log"
            pid_file = "run/fluxheim.pid"
            upgrade_sock = "run/fluxheim-upgrade.sock"
            "#,
        )
        .unwrap();

        let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

        assert_eq!(
            config.server.process.error_log,
            Some(dir.child("logs/error.log"))
        );
        assert_eq!(
            config.server.process.pid_file,
            dir.child("run/fluxheim.pid")
        );
        assert_eq!(
            config.server.process.upgrade_sock,
            dir.child("run/fluxheim-upgrade.sock")
        );
    }

    #[test]
    fn resolves_relative_logging_file_path_from_config_file() {
        let dir = TestDir::new("logging-file-path");
        fs::write(
            dir.child("fluxheim.toml"),
            r#"
            [logging.file]
            path = "logs/fluxheim.log"
            "#,
        )
        .unwrap();

        let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

        assert_eq!(
            config.logging.file.path,
            Some(dir.child("logs/fluxheim.log"))
        );
    }

    #[test]
    fn resolves_relative_tls_paths_from_config_file() {
        let dir = TestDir::new("tls-paths");
        fs::write(
            dir.child("fluxheim.toml"),
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

        let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

        assert_eq!(
            config.tls.certificates[0].cert_path,
            dir.child("tls/fullchain.pem")
        );
        assert_eq!(config.tls.acme.storage, Some(dir.child("acme")));
        assert_eq!(
            config.vhosts[0].tls.certificate.as_ref().unwrap().key_path,
            dir.child("vhosts/example/key.pem")
        );
    }

    #[test]
    fn rejects_config_relative_paths_with_parent_traversal() {
        let dir = TestDir::new("unsafe-paths");
        fs::write(
            dir.child("fluxheim.toml"),
            r#"
            [web]
            root = "../outside"
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();

        assert!(matches!(
            error,
            ConfigLoadError::Validate(ConfigError::UnsafePath { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_runtime_path_below_symlinked_directory() {
        let dir = TestDir::new("runtime-path-parent-symlink");
        let real_dir = dir.child("real");
        let symlink_dir = dir.child("linked");
        fs::create_dir_all(safe_child_path(&real_dir, "public")).unwrap();
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();
        fs::write(
            dir.child("fluxheim.toml"),
            r#"
            [web]
            root = "linked/public"
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();

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
        let real_root = dir.child("public-real");
        let symlink_root = dir.child("public");
        fs::create_dir(&real_root).unwrap();
        std::os::unix::fs::symlink(&real_root, &symlink_root).unwrap();
        fs::write(
            dir.child("fluxheim.toml"),
            r#"
            [web]
            root = "public"
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();

        assert!(matches!(
            error,
            ConfigLoadError::Validate(ConfigError::UnsafePath { field, .. })
                if field == "web.root"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn accepts_final_php_root_symlink_when_enabled() {
        let dir = TestDir::new("php-root-final-symlink");
        let real_root = dir.child("releases/current");
        let symlink_root = dir.child("public");
        fs::create_dir_all(&real_root).unwrap();
        std::os::unix::fs::symlink(&real_root, &symlink_root).unwrap();
        fs::write(
            dir.child("fluxheim.toml"),
            r#"
            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "public"
            resolve_root_symlink = true

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        )
        .unwrap();

        let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

        assert_eq!(
            config.vhosts[0].php.root.as_deref(),
            Some(symlink_root.as_path())
        );
        assert!(config.vhosts[0].php.resolve_root_symlink);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_existing_php_fpm_root_symlink() {
        let dir = TestDir::new("php-fpm-root-symlink");
        let local_root = dir.child("local-public");
        let fpm_real_root = dir.child("fpm-real-public");
        let fpm_symlink_root = dir.child("fpm-public");
        fs::create_dir_all(&local_root).unwrap();
        fs::create_dir_all(&fpm_real_root).unwrap();
        std::os::unix::fs::symlink(&fpm_real_root, &fpm_symlink_root).unwrap();
        fs::write(
            dir.child("fluxheim.toml"),
            r#"
            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "local-public"
            fpm_root = "fpm-public"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();

        assert!(matches!(
            error,
            ConfigLoadError::Validate(ConfigError::VhostSection {
                vhost,
                section: "php",
                source,
            }) if vhost == "php"
                && matches!(
                    *source,
                    ConfigError::UnsafePath { ref field, .. } if field == "vhosts.php.fpm_root"
                )
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_php_root_below_symlinked_parent_when_final_symlink_enabled() {
        let dir = TestDir::new("php-root-parent-symlink");
        let real_dir = dir.child("real");
        let symlink_dir = dir.child("linked");
        fs::create_dir_all(safe_child_path(&real_dir, "public")).unwrap();
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();
        fs::write(
            dir.child("fluxheim.toml"),
            r#"
            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "linked/public"
            resolve_root_symlink = true

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        )
        .unwrap();

        let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();

        assert!(matches!(
            error,
            ConfigLoadError::Validate(ConfigError::VhostSection {
                vhost,
                section: "php",
                source,
            }) if vhost == "php"
                && matches!(
                    *source,
                    ConfigError::UnsafePath { ref field, .. } if field == "vhosts.php.root"
                )
        ));
    }

    #[test]
    fn rejects_non_toml_config_file() {
        let dir = TestDir::new("non-toml-config");
        let path = dir.child("fluxheim.txt");
        fs::write(&path, "[server]\n").unwrap();

        let error = Config::load(Some(&path)).unwrap_err();

        assert!(matches!(error, ConfigLoadError::InvalidPath { .. }));
    }

    #[test]
    fn rejects_oversized_config_file() {
        let dir = TestDir::new("oversized-config");
        let path = dir.child("fluxheim.toml");
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
        let real_path = dir.child("real.toml");
        let symlink_path = dir.child("fluxheim.toml");
        fs::write(&real_path, "[server]\n").unwrap();
        std::os::unix::fs::symlink(&real_path, &symlink_path).unwrap();

        let error = Config::load(Some(&symlink_path)).unwrap_err();

        assert!(matches!(error, ConfigLoadError::InvalidPath { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_config_directory_source() {
        let dir = TestDir::new("config-dir-symlink");
        let real_dir = dir.child("real");
        let symlink_dir = dir.child("linked");
        fs::create_dir(&real_dir).unwrap();
        fs::write(safe_child_path(&real_dir, "fluxheim.toml"), "[server]\n").unwrap();
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

        let error = Config::load(Some(&symlink_dir)).unwrap_err();

        assert!(matches!(error, ConfigLoadError::InvalidPath { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_config_source_below_symlinked_directory() {
        let dir = TestDir::new("config-dir-parent-symlink");
        let real_dir = dir.child("real");
        let symlink_dir = dir.child("linked");
        fs::create_dir(&real_dir).unwrap();
        fs::write(safe_child_path(&real_dir, "fluxheim.toml"), "[server]\n").unwrap();
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

        let error =
            Config::load(Some(&safe_child_path(&symlink_dir, "fluxheim.toml"))).unwrap_err();

        assert!(matches!(error, ConfigLoadError::InvalidPath { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn ignores_symlinked_config_directory_entries() {
        let dir = TestDir::new("config-dir-entry-symlink");
        let outside_dir = TestDir::new("config-dir-entry-symlink-outside");
        let outside = outside_dir.child("outside.toml");
        fs::write(
            dir.child("00-server.toml"),
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
        std::os::unix::fs::symlink(&outside, dir.child("10-linked.toml")).unwrap();

        let config = Config::load(Some(dir.path())).unwrap();

        assert_eq!(config.server.listen, ["127.0.0.1:19090"]);
        assert!(config.vhosts.is_empty());
    }

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let path = unique_temp_path(label);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn child(&self, name: &str) -> PathBuf {
            safe_relative_path(&self.path, name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
