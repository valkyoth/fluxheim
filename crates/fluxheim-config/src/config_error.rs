use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;

use crate::config_acme::AcmeChallenge;
use crate::config_admin::MAX_ADMIN_HEALTH_PATH_BYTES;
use crate::config_cache_controls::CACHE_PREDICTOR_MAX_CAPACITY;
use crate::config_cache_policy::CacheKeyPart;

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
    InvalidCacheOriginProtectionPolicy {
        scope: &'static str,
        field: &'static str,
        reason: &'static str,
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
            Self::InvalidCacheOriginProtectionPolicy {
                scope,
                field,
                reason,
            } => write!(formatter, "{scope}.{field} is invalid: {reason}"),
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
