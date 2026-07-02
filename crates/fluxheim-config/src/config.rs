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
pub use crate::config_admin::MAX_ADMIN_HEALTH_PATH_BYTES;
pub use crate::config_admin::{
    AdminAuthThrottleConfig, AdminClientCertificateConfig, AdminConfig, AdminHealthConfig,
    AdminHealthResponseMode, AdminOpsSocketConfig, AdminRemoteTransportMode,
    AdminSelfHealingConfig, AdminTransportConfig,
};
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
pub use crate::config_cache_range::{CacheRangeConfig, CacheRangeSliceConfig};
pub use crate::config_cache_storage_bin::CacheDiskStorageBinConfig;
#[cfg(test)]
pub use crate::config_cache_validate::{
    MAX_CACHE_BYPASS_COOKIES, MAX_CACHE_BYPASS_PATHS, MAX_CACHE_CONTENT_TYPES,
    MAX_CACHE_IMAGE_EXTENSIONS, MAX_CACHE_METHODS, MAX_CACHE_STATUS_TTLS,
    MAX_CACHE_VARY_REQUEST_HEADERS,
};
pub use crate::config_compression::CompressionConfig;
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
#[cfg(test)]
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
pub use crate::config_proxy::{
    AuthRequestConfig, ProxyConfig, ProxyErrorPageConfig, TrafficMirrorConfig, UpstreamHttpVersion,
    UpstreamProxyProtocol,
};
#[cfg(test)]
pub use crate::config_proxy::{MAX_PROXY_ERROR_PAGES, MAX_PROXY_UPSTREAMS};
pub use crate::config_route::{
    GrpcRouteConfig, RouteConfig, RouteRedirectConfig, VhostRedirectConfig,
};
pub use crate::config_server::{
    DownstreamProxyProtocol, HostRoutingConfig, HttpsRedirectConfig, ServerConfig,
    ServerLimitsConfig, ServerProcessConfig,
};
#[cfg(test)]
pub use crate::config_server::{MAX_SERVER_LISTENERS, MAX_TRUSTED_PROXIES};
pub use crate::config_stream::{StreamConfig, StreamRouteConfig};
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
pub use crate::config_vhost::VhostConfig;
#[cfg(test)]
pub use crate::config_web::MAX_WEB_INDEX_FILES;
pub use crate::config_web::{DirectoryListingConfig, WebConfig};
use serde::{Deserialize, Serialize};

pub(crate) const MAX_VHOSTS: usize = 1024;
pub(crate) const MAX_VHOST_NAME_BYTES: usize = 128;
pub(crate) const MAX_VHOST_HOSTS: usize = 64;
pub(crate) const MAX_VHOST_ROUTES: usize = 256;
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
