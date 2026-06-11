use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

pub use crate::config_access::{
    AccessPolicyConfig, ConcurrencyLimitConfig, RateLimitConfig, RateLimitMode,
};
pub use crate::config_acme::{
    AcmeAutomationMode, AcmeChallenge, AcmeConfig, AcmeExternalAccountBindingConfig,
    AcmeIssuerConfig, AcmeRenewalConfig, VhostAcmeChallengeConfig, VhostAcmeConfig,
};
#[cfg(test)]
pub(crate) use crate::config_acme::{
    MAX_ACME_CHALLENGE_UPSTREAMS, MAX_ACME_ISSUERS, MAX_VHOST_ACME_DOMAINS,
};
pub(crate) use crate::config_admin::MAX_ADMIN_HEALTH_PATH_BYTES;
pub use crate::config_admin::{
    AdminAuthThrottleConfig, AdminClientCertificateConfig, AdminConfig, AdminHealthConfig,
    AdminHealthResponseMode, AdminOpsSocketConfig, AdminRemoteTransportMode,
    AdminSelfHealingConfig, AdminTransportConfig,
};
pub(crate) use crate::config_cache::{
    CACHE_PREDICTOR_MAX_CAPACITY, extend_unique, validate_cache_compliance_internal_crypto,
};
pub use crate::config_cache::{
    CacheConfig, CacheDiskBackend, CacheDiskConfig, CacheDiskEncryptionAlgorithm,
    CacheDiskEncryptionConfig, CacheDiskEncryptionOpenBaoConfig, CacheDiskEncryptionProvider,
    CacheDiskStorageBinConfig, CacheKeyPart, CacheLockConfig, CacheMemoryConfig, CachePeerConfig,
    CachePeerFillConfig, CachePredictorConfig, CachePreset, CachePurgerConfig, CacheRangeConfig,
    CacheRangeSliceConfig, CacheStaleErrorKind,
};
#[cfg(test)]
pub(crate) use crate::config_cache::{
    MAX_CACHE_BYPASS_COOKIES, MAX_CACHE_BYPASS_PATHS, MAX_CACHE_CONTENT_TYPES,
    MAX_CACHE_IMAGE_EXTENSIONS, MAX_CACHE_METHODS, MAX_CACHE_STATUS_TTLS,
    MAX_CACHE_VARY_REQUEST_HEADERS, fips_allowed_local_openbao_endpoint,
};
pub use crate::config_compression::CompressionConfig;
#[cfg(test)]
pub(crate) use crate::config_compression::DEFAULT_COMPRESSION_MAX_OUTPUT_BYTES;
pub use crate::config_geoip::{GeoIpConfig, GeoIpDatabaseConfig, GeoIpProvider};
pub use crate::config_header::{
    ForwardedClientIpHeaderMode, HeaderOperationsConfig, HeaderPolicyConfig, HeaderValues,
    RequestHeaderPolicyConfig, RequestHeaderPolicyOverlayConfig, ResponseHeaderPolicyConfig,
    ResponseHeaderPolicyOverlayConfig, ResponseHeaderRewriteConfig,
    ResponseHeaderRewriteRuleConfig, ResponseHstsConfig, VhostHeaderPolicyConfig,
};
#[cfg(test)]
pub(crate) use crate::config_header::{MAX_HEADER_APPEND_VALUES, MAX_HEADER_MUTATION_NAMES};
#[cfg(test)]
use crate::config_header::{valid_dynamic_header_variable, validate_dynamic_header_template};
use crate::config_http::{
    fips_allowed_local_auth_request_endpoint, fips_allowed_local_mirror_endpoint,
    fips_allowed_local_otlp_endpoint,
};
pub use crate::config_load_balance::{
    LoadBalanceConfig, LoadBalanceHealthCheckConfig, LoadBalanceHealthCheckExpectedHeader,
    LoadBalanceHealthCheckExpectedJson, LoadBalanceHealthCheckExpectedStatusRange,
    LoadBalanceHealthCheckProtocol, LoadBalanceHealthCheckRequestHeader,
    LoadBalanceManagedCookieSameSite, LoadBalancePassiveHealthConfig, LoadBalancePersistenceConfig,
    LoadBalancePersistenceMode, LoadBalanceQueueConfig, LoadBalanceRetryConfig,
    LoadBalanceSelection, LoadBalanceSlowStartConfig,
};
pub use crate::config_loader::ConfigLoadError;
#[cfg(feature = "load-balancer")]
pub(crate) use crate::config_loader::read_proxy_upstreams_file;
use crate::config_loader::{
    canonical_config_source, config_directory_files, read_regular_config_file_to_string,
    regular_visible_toml_file, toml_files,
};
pub use crate::config_logging::{
    AccessLoggingConfig, LoggingConfig, LoggingFileConfig, LoggingFormat, LoggingLevel,
    LoggingTarget,
};
pub use crate::config_net::{normalize_host, normalize_host_pattern};
pub use crate::config_observability::{
    MetricsConfig, MetricsOtlpExportConfig, OtlpTraceExportConfig, TracingConfig, TracingMode,
};
#[cfg(feature = "php-fpm")]
pub(crate) use crate::config_php::protected_php_param_name;
#[cfg(test)]
pub(crate) use crate::config_php::{
    MAX_PHP_ALLOWED_EXTENSIONS, MAX_PHP_DENY_PATH_PREFIXES, MAX_PHP_ERROR_PAGES,
    MAX_PHP_FPM_RETRY_METHODS, MAX_PHP_FPM_RETRY_STATUSES, MAX_PHP_FPM_TCP_UPSTREAMS,
    MAX_PHP_HIDE_RESPONSE_HEADERS, MAX_PHP_INTERCEPT_ERROR_STATUSES, MAX_PHP_PARAMS,
    MAX_PHP_STDERR_FAILURE_PATTERNS,
};
pub use crate::config_php::{
    PhpConfig, PhpFpmConfig, PhpFpmMode, PhpFpmProcessManager, PhpPathInfoMode, PhpPreset,
    PhpRuntime, PhpStderrLogLevel, PhpTryFilesMode,
};
pub use crate::config_proxy::{
    AuthRequestConfig, ProxyConfig, ProxyErrorPageConfig, TrafficMirrorConfig, UpstreamHttpVersion,
    UpstreamProxyProtocol,
};
#[cfg(test)]
pub(crate) use crate::config_proxy::{MAX_PROXY_ERROR_PAGES, MAX_PROXY_UPSTREAMS};
pub use crate::config_route::{
    GrpcRouteConfig, RouteConfig, RouteRedirectConfig, VhostRedirectConfig,
};
use crate::config_server::ServerConfigFragment;
pub use crate::config_server::{
    DownstreamProxyProtocol, HostRoutingConfig, HttpsRedirectConfig, ServerConfig,
    ServerLimitsConfig, ServerProcessConfig,
};
#[cfg(test)]
pub(crate) use crate::config_server::{MAX_SERVER_LISTENERS, MAX_TRUSTED_PROXIES};
pub use crate::config_stream::{StreamConfig, StreamRouteConfig};
use crate::config_tls::TlsConfigFragment;
#[cfg(test)]
pub(crate) use crate::config_tls::{
    MAX_TLS_CERTIFICATES, MAX_TLS_CIPHER_SUITES, MAX_TLS_CURVE_PREFERENCES,
};
pub use crate::config_tls::{
    StaticCertificateConfig, TlsAlpnPolicy, TlsBackend, TlsCipherSuite, TlsClientAuthConfig,
    TlsClientAuthMode, TlsComplianceMode, TlsConfig, TlsCurvePreference, TlsFipsConfig,
    TlsIso19790Config, TlsPolicyProfile, TlsProtocolVersion, VhostTlsConfig,
};
pub use crate::config_types::{ByteSize, ByteSizeParseError};
pub use crate::config_udp::{UdpConfig, UdpRouteConfig, UdpRouteMode};
#[cfg(test)]
pub(crate) use crate::config_web::MAX_WEB_INDEX_FILES;
pub use crate::config_web::{DirectoryListingConfig, WebConfig};
use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::config_loader::{MAX_CONFIG_DIRECTORY_FILES, MAX_CONFIG_FILE_BYTES};

const MAX_VHOSTS: usize = 1024;
const MAX_VHOST_NAME_BYTES: usize = 128;
const MAX_VHOST_HOSTS: usize = 64;
const MAX_VHOST_ROUTES: usize = 256;
pub(crate) const MAX_ROUTE_NAME_BYTES: usize = 128;
pub(crate) const MAX_ROUTE_REGEX_CAPTURE_VALUES: usize = 16;
pub(crate) const MAX_ROUTE_REGEX_CAPTURE_NAME_BYTES: usize = 64;
pub(crate) const MAX_ROUTE_REGEX_PROGRAM_BYTES: usize = 1024 * 1024;

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
    pub geoip: GeoIpConfig,
    #[serde(default)]
    pub stream: StreamConfig,
    #[serde(default)]
    pub udp: UdpConfig,
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
        if let Some(geoip) = fragment.geoip {
            self.geoip = geoip;
        }
        if let Some(stream) = fragment.stream {
            self.stream = stream;
        }
        if let Some(udp) = fragment.udp {
            self.udp = udp;
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
        self.server.validate_with_runtime_path_validation(
            validate_runtime_paths,
            self.stream.enabled || self.udp.enabled,
        )?;
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
        self.geoip.validate()?;
        self.stream.validate()?;
        self.udp.validate()?;
        self.validate_vhosts()?;
        self.validate_geoip_policy()?;
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
        validate_auth_request_compliance_internal_crypto(&self.proxy, "proxy.auth_request")?;
        validate_traffic_mirror_compliance_internal_crypto(&self.proxy, "proxy.mirror")?;

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
            validate_auth_request_compliance_internal_crypto(
                &vhost.proxy,
                "vhosts.proxy.auth_request",
            )
            .map_err(|source| ConfigError::VhostSection {
                vhost: vhost.name.clone(),
                section: "proxy",
                source: Box::new(source),
            })?;
            validate_traffic_mirror_compliance_internal_crypto(&vhost.proxy, "vhosts.proxy.mirror")
                .map_err(|source| ConfigError::VhostSection {
                    vhost: vhost.name.clone(),
                    section: "proxy",
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
                if let Some(proxy) = &route.proxy {
                    validate_auth_request_compliance_internal_crypto(
                        proxy,
                        "vhosts.routes.proxy.auth_request",
                    )
                    .map_err(|source| ConfigError::RouteSection {
                        vhost: vhost.name.clone(),
                        route: route.name.clone(),
                        section: "proxy",
                        source: Box::new(source),
                    })?;
                    validate_traffic_mirror_compliance_internal_crypto(
                        proxy,
                        "vhosts.routes.proxy.mirror",
                    )
                    .map_err(|source| ConfigError::RouteSection {
                        vhost: vhost.name.clone(),
                        route: route.name.clone(),
                        section: "proxy",
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
            vhost.validate(self.server.regex_enabled)?;
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

    fn validate_geoip_policy(&self) -> Result<(), ConfigError> {
        if self.geoip.enabled {
            return Ok(());
        }
        for vhost in &self.vhosts {
            if vhost.access.requires_geoip() {
                return Err(ConfigError::InvalidGeoIpPolicy {
                    field: "vhosts.access",
                    reason: "GeoIP access rules require geoip.enabled = true",
                });
            }
            for route in &vhost.routes {
                if route.access.requires_geoip() {
                    return Err(ConfigError::InvalidGeoIpPolicy {
                        field: "vhosts.routes.access",
                        reason: "GeoIP access rules require geoip.enabled = true",
                    });
                }
            }
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
    geoip: Option<GeoIpConfig>,
    #[serde(default)]
    stream: Option<StreamConfig>,
    #[serde(default)]
    udp: Option<UdpConfig>,
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

    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
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
        if let Some(geoip) = &mut self.geoip {
            geoip.resolve_relative_paths(base_dir);
        }
        if let Some(stream) = &mut self.stream {
            stream.resolve_relative_paths(base_dir);
        }
        for vhost in &mut self.vhosts {
            vhost.resolve_relative_paths(base_dir);
        }
    }
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

    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        self.tls.resolve_relative_paths(base_dir);
        self.proxy.resolve_relative_paths(base_dir);
        self.cache.resolve_relative_paths(base_dir);
        self.php.resolve_relative_paths(base_dir);
        self.web.resolve_relative_paths(base_dir);
        for route in &mut self.routes {
            route.resolve_relative_paths(base_dir);
        }
    }

    fn validate(&self, regex_enabled: bool) -> Result<(), ConfigError> {
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
        self.validate_routes(regex_enabled)?;
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

    fn validate_routes(&self, regex_enabled: bool) -> Result<(), ConfigError> {
        let mut fallback_seen = false;
        for route in &self.routes {
            route.validate(&self.name, regex_enabled)?;
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

fn validate_auth_request_compliance_internal_crypto(
    proxy: &ProxyConfig,
    scope: &'static str,
) -> Result<(), ConfigError> {
    if !proxy.auth_request.enabled {
        return Ok(());
    }
    let Some(url) = proxy.auth_request.url.as_deref() else {
        return Ok(());
    };
    if fips_allowed_local_auth_request_endpoint(url) {
        return Ok(());
    }
    Err(ConfigError::InvalidCompliancePolicy {
        field: scope,
        reason: "FIPS/ISO-required mode allows auth_request only to a numeric local http://127.0.0.1 or http://[::1] loopback endpoint; remote or HTTPS auth subrequests need provider-aligned outbound TLS evidence first",
    })
}

fn validate_traffic_mirror_compliance_internal_crypto(
    proxy: &ProxyConfig,
    scope: &'static str,
) -> Result<(), ConfigError> {
    if !proxy.mirror.enabled {
        return Ok(());
    }
    let Some(base_url) = proxy.mirror.base_url.as_deref() else {
        return Ok(());
    };
    if fips_allowed_local_mirror_endpoint(base_url) {
        return Ok(());
    }
    Err(ConfigError::InvalidCompliancePolicy {
        field: scope,
        reason: "FIPS/ISO-required mode allows traffic mirroring only to a numeric local http://127.0.0.1 or http://[::1] loopback endpoint; remote or HTTPS mirror export needs provider-aligned outbound TLS evidence first",
    })
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
    InvalidAdminOpsSocket {
        field: &'static str,
        reason: &'static str,
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
    GeoIpNotCompiled,
    InvalidGeoIpPolicy {
        field: &'static str,
        reason: &'static str,
    },
    StreamProxyNotCompiled,
    InvalidStreamListenAddress {
        address: String,
    },
    InvalidStreamUpstream {
        address: String,
    },
    InvalidStreamProxyPolicy {
        field: &'static str,
        reason: &'static str,
    },
    DuplicateStreamRouteName {
        name: String,
    },
    DuplicateStreamListener {
        listen: String,
    },
    DuplicateStreamUpstream {
        upstream: String,
    },
    UdpProxyNotCompiled,
    InvalidUdpListenAddress {
        address: String,
    },
    InvalidUdpUpstream {
        address: String,
    },
    InvalidUdpProxyPolicy {
        field: &'static str,
        reason: &'static str,
    },
    DuplicateUdpRouteName {
        name: String,
    },
    DuplicateUdpListener {
        listen: String,
    },
    DuplicateUdpUpstream {
        upstream: String,
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
    UnsafeTlsHeaderAppend {
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
    RouteRegexDisabled {
        vhost: String,
        route: String,
    },
    InvalidRouteRegex {
        vhost: String,
        route: String,
    },
    InvalidRouteMethods {
        vhost: String,
        route: String,
        reason: &'static str,
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
    InvalidRouteRewriteTemplate {
        vhost: String,
        route: String,
    },
    InvalidRouteAction {
        vhost: String,
        route: String,
    },
    InvalidRouteGrpcPolicy {
        vhost: String,
        route: String,
        reason: &'static str,
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
            Self::InvalidAdminOpsSocket { field, reason } => {
                write!(formatter, "{field} is invalid: {reason}")
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
            Self::GeoIpNotCompiled => write!(
                formatter,
                "geoip.enabled requires building Fluxheim with the geoip feature"
            ),
            Self::InvalidGeoIpPolicy { field, reason } => {
                write!(formatter, "{field} is invalid: {reason}")
            }
            Self::StreamProxyNotCompiled => write!(
                formatter,
                "stream.enabled requires building Fluxheim with the stream-proxy feature"
            ),
            Self::InvalidStreamListenAddress { address } => write!(
                formatter,
                "stream.routes.listen entries must be ip:port listener addresses, got {address:?}"
            ),
            Self::InvalidStreamUpstream { address } => write!(
                formatter,
                "stream upstreams must be host:port or ip:port, got {address:?}"
            ),
            Self::InvalidStreamProxyPolicy { field, reason } => {
                write!(formatter, "{field} is invalid: {reason}")
            }
            Self::DuplicateStreamRouteName { name } => {
                write!(
                    formatter,
                    "stream.routes contains duplicate route name {name:?}"
                )
            }
            Self::DuplicateStreamListener { listen } => write!(
                formatter,
                "stream.routes contains duplicate listener {listen:?}"
            ),
            Self::DuplicateStreamUpstream { upstream } => write!(
                formatter,
                "stream.routes.upstreams contains duplicate upstream {upstream:?}"
            ),
            Self::UdpProxyNotCompiled => write!(
                formatter,
                "udp.enabled requires building Fluxheim with the udp-proxy feature"
            ),
            Self::InvalidUdpListenAddress { address } => write!(
                formatter,
                "udp.routes.listen entries must be ip:port listener addresses, got {address:?}"
            ),
            Self::InvalidUdpUpstream { address } => write!(
                formatter,
                "UDP upstreams must be host:port or ip:port, got {address:?}"
            ),
            Self::InvalidUdpProxyPolicy { field, reason } => {
                write!(formatter, "{field} is invalid: {reason}")
            }
            Self::DuplicateUdpRouteName { name } => {
                write!(
                    formatter,
                    "udp.routes contains duplicate route name {name:?}"
                )
            }
            Self::DuplicateUdpListener { listen } => {
                write!(
                    formatter,
                    "udp.routes contains duplicate listener {listen:?}"
                )
            }
            Self::DuplicateUdpUpstream { upstream } => write!(
                formatter,
                "udp.routes.upstreams contains duplicate upstream {upstream:?}"
            ),
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
            Self::UnsafeTlsHeaderAppend { field, name } => write!(
                formatter,
                "{field}.append.{name} cannot use tls.* template variables; use set/add so inbound spoofed headers are removed before Fluxheim forwards TLS identity"
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
                "proxy.upstream, proxy.upstreams, and proxy.upstreams_file are mutually exclusive; use proxy.upstreams for static pools or proxy.upstreams_file for file-refreshed pools"
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
                "vhost {vhost:?} route {route:?} must define exactly one of path_exact, path_prefix, path_regex, or fallback = true"
            ),
            Self::RouteRegexDisabled { vhost, route } => write!(
                formatter,
                "vhost {vhost:?} route {route:?} uses path_regex but server.regex_enabled is false"
            ),
            Self::InvalidRouteRegex { vhost, route } => write!(
                formatter,
                "vhost {vhost:?} route {route:?} path_regex must be a valid bounded Rust regex for request paths"
            ),
            Self::InvalidRouteMethods {
                vhost,
                route,
                reason,
            } => write!(
                formatter,
                "vhost {vhost:?} route {route:?} methods policy is invalid: {reason}"
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
            Self::InvalidRouteRewriteTemplate { vhost, route } => write!(
                formatter,
                "vhost {vhost:?} route {route:?} rewrite_template must be an absolute path template attached to path_regex and cannot be combined with strip_prefix or rewrite_prefix"
            ),
            Self::InvalidRouteAction { vhost, route } => write!(
                formatter,
                "vhost {vhost:?} route {route:?} must define exactly one action: redirect, proxy, or web"
            ),
            Self::InvalidRouteGrpcPolicy {
                vhost,
                route,
                reason,
            } => write!(
                formatter,
                "vhost {vhost:?} route {route:?} grpc policy is invalid: {reason}"
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

fn disabled_proxy_config() -> ProxyConfig {
    ProxyConfig::disabled()
}

pub(crate) fn valid_http_token(value: &str) -> bool {
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

pub(crate) fn validate_config_list_len(
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

pub(crate) fn validate_optional_timeout_secs(
    field: &'static str,
    value: Option<u64>,
) -> Result<(), ConfigError> {
    if value.is_some_and(|seconds| seconds == 0) {
        return Err(ConfigError::InvalidProxyTimeout { field });
    }
    Ok(())
}

pub(crate) fn validate_required_timeout_secs(
    field: &'static str,
    value: u64,
) -> Result<(), ConfigError> {
    if value == 0 {
        return Err(ConfigError::InvalidProxyTimeout { field });
    }
    Ok(())
}

pub(crate) fn valid_credential_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('.')
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
