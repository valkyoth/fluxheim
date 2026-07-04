use std::path::PathBuf;

use crate::config_acme::AcmeChallenge;
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
    InvalidWasmPolicy {
        scope: String,
        field: &'static str,
        reason: &'static str,
    },
    DuplicateWasmPluginName {
        name: String,
    },
    UnknownWasmPlugin {
        scope: String,
        plugin: String,
    },
    DuplicateWasmAttachment {
        scope: String,
        plugin: String,
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
