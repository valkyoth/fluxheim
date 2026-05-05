use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use toml::value::{Datetime, Offset};

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
            Some(path) if path.is_dir() => Self::load_dir(path)?,
            Some(path) => Self::load_file(path)?,
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
        let raw = fs::read_to_string(path).map_err(ConfigLoadError::Read)?;
        toml::from_str(&raw).map_err(ConfigLoadError::Parse)
    }

    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(tls) = &mut self.tls {
            tls.resolve_relative_paths(base_dir);
        }
        if let Some(admin) = &mut self.admin {
            admin.resolve_relative_paths(base_dir);
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
    pub limits: ServerLimitsConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            tls_listen: Vec::new(),
            default_vhost: None,
            limits: ServerLimitsConfig::default(),
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
        if let Some(limits) = fragment.limits {
            self.limits = limits;
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

        if let Some(default_vhost) = &self.default_vhost
            && default_vhost.trim().is_empty()
        {
            return Err(ConfigError::EmptyDefaultVhost);
        }

        self.limits.validate()?;
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
    limits: Option<ServerLimitsConfig>,
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
            || self.health_path.contains(' ')
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
    #[serde(default = "default_upstream")]
    pub upstream: String,
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
            upstream: default_upstream(),
            upstreams: Vec::new(),
            upstream_tls: false,
            upstream_sni: None,
            load_balance: LoadBalanceConfig::default(),
        }
    }
}

impl ProxyConfig {
    pub fn upstream_sni(&self) -> String {
        self.upstream_sni
            .clone()
            .unwrap_or_else(|| upstream_host(&self.upstream).unwrap_or_default())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !valid_authority(&self.upstream) {
            return Err(ConfigError::InvalidUpstream {
                address: self.upstream.clone(),
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
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            root: None,
            index_files: default_index_files(),
            deny_dotfiles: true,
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

        Ok(())
    }
}

#[derive(Debug)]
pub enum ConfigLoadError {
    Read(std::io::Error),
    Parse(toml::de::Error),
    Validate(ConfigError),
}

impl Display for ConfigLoadError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "failed to read config: {error}"),
            Self::Parse(error) => write!(formatter, "failed to parse config: {error}"),
            Self::Validate(error) => write!(formatter, "invalid config: {error}"),
        }
    }
}

impl Error for ConfigLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
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
            Self::InvalidAdminSelfHealing { field } => {
                write!(formatter, "{field} must be within the allowed range")
            }
            Self::InvalidAdminHealthPath { path } => write!(
                formatter,
                "admin.self_healing.health_path must be an absolute path without spaces, got {path:?}"
            ),
            Self::InvalidMetricsListenAddress { address } => write!(
                formatter,
                "metrics.listen must be an ip:port listener address, got {address:?}"
            ),
            Self::MetricsListenNotLoopback { address } => write!(
                formatter,
                "metrics.listen must be loopback when metrics.require_loopback = true, got {address:?}"
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
    "/_fluxheim/health".to_owned()
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

fn default_true() -> bool {
    true
}

fn toml_files(dir: &Path) -> Result<Vec<PathBuf>, ConfigLoadError> {
    let entries = fs::read_dir(dir).map_err(ConfigLoadError::Read)?;
    let mut files = Vec::new();

    for entry in entries {
        let entry = entry.map_err(ConfigLoadError::Read)?;
        let path = entry.path();
        if path.is_file() && is_visible_toml_file(&path) {
            files.push(path);
        }
    }

    Ok(files)
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

pub fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty()
        || host.contains('*')
        || host.contains('/')
        || host.contains('\\')
        || host.chars().any(char::is_whitespace)
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
        MetricsConfig, ProxyConfig, ServerConfig, ServerLimitsConfig, VhostConfig, WebConfig,
        normalize_host, normalize_host_pattern,
    };

    #[test]
    fn default_config_is_valid() {
        Config::default().validate().unwrap();
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
        assert_eq!(config.proxy.upstream, "origin.example.test:443");
        assert!(config.proxy.upstream_tls);
        assert_eq!(config.proxy.upstream_sni(), "origin.example.test");
    }

    #[test]
    fn parses_proxy_upstream_pool() {
        let config: Config = toml::from_str(
            r#"
            [proxy]
            upstream = "127.0.0.1:3000"
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
        config.validate().unwrap();
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
                limits: ServerLimitsConfig::default(),
            },
            admin: AdminConfig::default(),
            metrics: MetricsConfig::default(),
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
            tls: super::TlsConfig::default(),
            proxy: ProxyConfig {
                upstream: "https://origin.example.test".to_owned(),
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
            tls: super::TlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            web: WebConfig {
                root: Some(PathBuf::from("public")),
                index_files: vec![],
                deny_dotfiles: true,
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
            tls: super::TlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            web: WebConfig {
                root: Some(PathBuf::from("public")),
                index_files: vec!["pages/index.html".to_owned()],
                deny_dotfiles: true,
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
                    web: WebConfig::default(),
                },
                VhostConfig {
                    name: "second.example".to_owned(),
                    hosts: vec!["example.com:443".to_owned()],
                    tls: super::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
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
                limits: ServerLimitsConfig::default(),
            },
            vhosts: vec![VhostConfig {
                name: "known".to_owned(),
                hosts: vec!["known.example".to_owned()],
                tls: super::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
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
