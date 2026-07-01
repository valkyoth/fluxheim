use std::fs;
use std::path::Path;

pub use crate::config_access::{
    AccessPolicyConfig, ConcurrencyLimitConfig, RateLimitConfig, RateLimitMode,
};
pub use crate::config_acme::{
    AcmeAutomationMode, AcmeChallenge, AcmeConfig, AcmeExternalAccountBindingConfig,
    AcmeIssuerConfig, AcmeRenewalConfig, VhostAcmeChallengeConfig, VhostAcmeConfig,
};
#[cfg(test)]
pub use crate::config_acme::{
    MAX_ACME_CHALLENGE_UPSTREAMS, MAX_ACME_ISSUERS, MAX_VHOST_ACME_DOMAINS,
};
use crate::config_admin::AdminConfigFragment;
pub use crate::config_admin::MAX_ADMIN_HEALTH_PATH_BYTES;
pub use crate::config_admin::{
    AdminAuthThrottleConfig, AdminClientCertificateConfig, AdminConfig, AdminHealthConfig,
    AdminHealthResponseMode, AdminOpsSocketConfig, AdminRemoteTransportMode,
    AdminSelfHealingConfig, AdminTransportConfig,
};
use crate::config_cache::CacheConfigFragment;
pub use crate::config_cache::validate_cache_compliance_internal_crypto;
pub use crate::config_cache::{CacheConfig, CachePreset};
pub use crate::config_cache_controls::CACHE_PREDICTOR_MAX_CAPACITY;
pub use crate::config_cache_controls::{
    CacheLockConfig, CacheOriginProtectionConfig, CachePredictorConfig,
};
pub use crate::config_cache_disk::{CacheDiskBackend, CacheDiskConfig};
#[cfg(test)]
pub use crate::config_cache_encryption::fips_allowed_local_openbao_endpoint;
pub use crate::config_cache_encryption::{
    CacheDiskEncryptionAlgorithm, CacheDiskEncryptionConfig, CacheDiskEncryptionOpenBaoConfig,
    CacheDiskEncryptionProvider,
};
pub use crate::config_cache_memory::CacheMemoryConfig;
pub use crate::config_cache_peer::{CachePeerConfig, CachePeerFillConfig};
pub use crate::config_cache_policy::{CacheKeyPart, CacheStaleErrorKind, extend_unique};
pub use crate::config_cache_purger::CachePurgerConfig;
use crate::config_cache_purger::CachePurgerConfigFragment;
pub use crate::config_cache_range::{CacheRangeConfig, CacheRangeSliceConfig};
pub use crate::config_cache_storage_bin::CacheDiskStorageBinConfig;
#[cfg(test)]
pub use crate::config_cache_validate::{
    MAX_CACHE_BYPASS_COOKIES, MAX_CACHE_BYPASS_PATHS, MAX_CACHE_CONTENT_TYPES,
    MAX_CACHE_IMAGE_EXTENSIONS, MAX_CACHE_METHODS, MAX_CACHE_STATUS_TTLS,
    MAX_CACHE_VARY_REQUEST_HEADERS,
};
pub use crate::config_compression::CompressionConfig;
use crate::config_compression::CompressionConfigFragment;
#[cfg(test)]
pub use crate::config_compression::DEFAULT_COMPRESSION_MAX_OUTPUT_BYTES;
pub use crate::config_error::ConfigError;
pub use crate::config_geoip::{GeoIpConfig, GeoIpDatabaseConfig, GeoIpProvider};
pub use crate::config_header::{
    ForwardedClientIpHeaderMode, HeaderOperationsConfig, HeaderPolicyConfig, HeaderValues,
    RequestHeaderPolicyConfig, RequestHeaderPolicyOverlayConfig, ResponseHeaderPolicyConfig,
    ResponseHeaderPolicyOverlayConfig, ResponseHeaderRewriteConfig,
    ResponseHeaderRewriteRuleConfig, ResponseHstsConfig, VhostHeaderPolicyConfig,
};
#[cfg(test)]
pub use crate::config_header::{MAX_HEADER_APPEND_VALUES, MAX_HEADER_MUTATION_NAMES};
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
pub use crate::config_loader::read_proxy_upstreams_file;
use crate::config_loader::{
    canonical_config_source, config_directory_files, read_regular_config_file_to_string,
    regular_visible_toml_file, toml_files,
};
pub use crate::config_logging::{
    AccessLoggingConfig, LoggingConfig, LoggingFileConfig, LoggingFormat, LoggingLevel,
    LoggingTarget,
};
pub use crate::config_metrics_summary::{
    CacheConfigStats, LoadBalancerConfigStats, cache_config_stats, load_balancer_config_stats,
};
pub use crate::config_net::{normalize_host, normalize_host_pattern};
pub use crate::config_observability::{
    MetricsConfig, MetricsOtlpExportConfig, OtlpTraceExportConfig, TracingConfig, TracingMode,
};
#[cfg(feature = "php-fpm")]
pub use crate::config_php::protected_php_param_name;
#[cfg(test)]
pub use crate::config_php::{
    MAX_PHP_ALLOWED_EXTENSIONS, MAX_PHP_DENY_PATH_PREFIXES, MAX_PHP_ERROR_PAGES,
    MAX_PHP_FPM_RETRY_METHODS, MAX_PHP_FPM_RETRY_STATUSES, MAX_PHP_FPM_TCP_UPSTREAMS,
    MAX_PHP_HIDE_RESPONSE_HEADERS, MAX_PHP_INTERCEPT_ERROR_STATUSES, MAX_PHP_PARAMS,
    MAX_PHP_STDERR_FAILURE_PATTERNS,
};
pub use crate::config_php::{
    PhpConfig, PhpFpmConfig, PhpFpmMode, PhpFpmProcessManager, PhpPathInfoMode, PhpPreset,
    PhpRuntime, PhpStderrLogLevel, PhpTryFilesMode,
};
use crate::config_proxy::ProxyConfigFragment;
pub use crate::config_proxy::{
    AuthRequestConfig, ProxyConfig, ProxyErrorPageConfig, TrafficMirrorConfig, UpstreamHttpVersion,
    UpstreamProxyProtocol,
};
#[cfg(test)]
pub use crate::config_proxy::{MAX_PROXY_ERROR_PAGES, MAX_PROXY_UPSTREAMS};
pub use crate::config_route::{
    GrpcRouteConfig, RouteConfig, RouteRedirectConfig, VhostRedirectConfig,
};
use crate::config_server::ServerConfigFragment;
pub use crate::config_server::{
    DownstreamProxyProtocol, HostRoutingConfig, HttpsRedirectConfig, ServerConfig,
    ServerLimitsConfig, ServerProcessConfig,
};
#[cfg(test)]
pub use crate::config_server::{MAX_SERVER_LISTENERS, MAX_TRUSTED_PROXIES};
use crate::config_stream::StreamConfigFragment;
pub use crate::config_stream::{StreamConfig, StreamRouteConfig};
use crate::config_tls::TlsConfigFragment;
#[cfg(test)]
pub use crate::config_tls::{
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
pub use crate::config_web::MAX_WEB_INDEX_FILES;
use crate::config_web::WebConfigFragment;
pub use crate::config_web::{DirectoryListingConfig, WebConfig};
use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::config_loader::{MAX_CONFIG_DIRECTORY_FILES, MAX_CONFIG_FILE_BYTES};

const MAX_VHOSTS: usize = 1024;
const MAX_VHOST_NAME_BYTES: usize = 128;
const MAX_VHOST_HOSTS: usize = 64;
const MAX_VHOST_ROUTES: usize = 256;
pub const MAX_ROUTE_NAME_BYTES: usize = 128;
pub const MAX_ROUTE_REGEX_CAPTURE_VALUES: usize = 16;
pub const MAX_ROUTE_REGEX_CAPTURE_NAME_BYTES: usize = 64;
pub const MAX_ROUTE_REGEX_PROGRAM_BYTES: usize = 1024 * 1024;

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
        config.merge(fragment)?;
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
            config.merge(fragment)?;
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
            self.merge(fragment)?;
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

    fn merge(&mut self, fragment: ConfigFragment) -> Result<(), ConfigLoadError> {
        if let Some(server) = fragment.server {
            self.server.merge(server);
        }
        if let Some(admin) = fragment.admin {
            self.admin.merge(admin);
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
            if proxy.has_conflicting_upstream_sources() {
                return Err(ConfigLoadError::Validate(
                    ConfigError::ConflictingProxyUpstreams,
                ));
            }
            self.proxy.merge(proxy);
        }
        if let Some(compression) = fragment.compression {
            self.compression.merge(compression);
        }
        if let Some(cache) = fragment.cache {
            self.cache.merge(cache);
        }
        if let Some(cache_purger) = fragment.cache_purger {
            self.cache_purger.merge(cache_purger);
        }
        if let Some(web) = fragment.web {
            self.web.merge(web);
        }
        if let Some(geoip) = fragment.geoip {
            self.geoip = geoip;
        }
        if let Some(stream) = fragment.stream {
            self.stream.merge(stream);
        }
        if let Some(udp) = fragment.udp {
            self.udp = udp;
        }
        self.vhosts.extend(fragment.vhosts);
        Ok(())
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
    admin: Option<AdminConfigFragment>,
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
    proxy: Option<ProxyConfigFragment>,
    #[serde(default)]
    compression: Option<CompressionConfigFragment>,
    #[serde(default)]
    cache: Option<CacheConfigFragment>,
    #[serde(default)]
    cache_purger: Option<CachePurgerConfigFragment>,
    #[serde(default)]
    web: Option<WebConfigFragment>,
    #[serde(default)]
    geoip: Option<GeoIpConfig>,
    #[serde(default)]
    stream: Option<StreamConfigFragment>,
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

    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
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

    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
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

fn disabled_proxy_config() -> ProxyConfig {
    ProxyConfig::disabled()
}

pub fn valid_http_token(value: &str) -> bool {
    fluxheim_protocol::http_token_valid(value)
}

const MAX_TIMEOUT_SECS: u64 = 24 * 60 * 60;

pub fn validate_config_list_len(
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

pub fn validate_optional_timeout_secs(
    field: &'static str,
    value: Option<u64>,
) -> Result<(), ConfigError> {
    if value.is_some_and(|seconds| seconds == 0 || seconds > MAX_TIMEOUT_SECS) {
        return Err(ConfigError::InvalidProxyTimeout { field });
    }
    Ok(())
}

pub fn validate_required_timeout_secs(field: &'static str, value: u64) -> Result<(), ConfigError> {
    if value == 0 || value > MAX_TIMEOUT_SECS {
        return Err(ConfigError::InvalidProxyTimeout { field });
    }
    Ok(())
}

pub fn valid_credential_name(value: &str) -> bool {
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
