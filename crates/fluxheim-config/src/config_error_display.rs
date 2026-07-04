use std::error::Error;
use std::fmt::{Display, Formatter};

use super::kind::ConfigError;
use crate::config_admin::MAX_ADMIN_HEALTH_PATH_BYTES;

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
            Self::InvalidWasmPolicy {
                scope,
                field,
                reason,
            } => {
                write!(formatter, "{scope} {field} is invalid: {reason}")
            }
            Self::DuplicateWasmPluginName { name } => {
                write!(
                    formatter,
                    "wasm.plugins contains duplicate plugin name {name:?}"
                )
            }
            Self::UnknownWasmPlugin { scope, plugin } => {
                write!(
                    formatter,
                    "{scope} references unknown wasm plugin {plugin:?}"
                )
            }
            Self::DuplicateWasmAttachment { scope, plugin } => {
                write!(
                    formatter,
                    "{scope} contains duplicate wasm attachment for plugin {plugin:?}"
                )
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
            Self::EmptyTlsCertificatePath { .. }
            | Self::EmptyTlsKeyPath { .. }
            | Self::TlsEnabledWithoutCertificateSource { .. }
            | Self::InvalidTlsPolicy { .. }
            | Self::TlsListenerWithoutTls
            | Self::TlsListenerWithoutStaticCertificate
            | Self::MissingAcmeStorage
            | Self::EmptyAcmeStorage
            | Self::InvalidAcmeContactEmail
            | Self::UnsupportedAcmeChallenge { .. }
            | Self::InvalidAcmeRenewalDuration { .. }
            | Self::InvalidAcmeRenewAfterDatetime
            | Self::AcmeRenewalRetryInitialExceedsMax
            | Self::EmptyAcmeIssuerName { .. }
            | Self::DuplicateAcmeIssuerName { .. }
            | Self::UnknownAcmeIssuer { .. }
            | Self::InvalidAcmeDirectoryUrl { .. }
            | Self::InvalidAcmeEabSecretSource { .. }
            | Self::InvalidAcmeEabCredentialName { .. }
            | Self::ConflictingAcmeEabSecretSource { .. }
            | Self::VhostAcmeWithoutGlobalAcme { .. }
            | Self::EmptyVhostAcmeDomains { .. }
            | Self::InvalidVhostAcmeDomain { .. }
            | Self::DuplicateVhostAcmeDomain { .. }
            | Self::MissingAcmeChallengeUpstream { .. }
            | Self::ConflictingAcmeChallengeUpstreams { .. }
            | Self::TooManyAcmeChallengeUpstreams { .. }
            | Self::DuplicateAcmeChallengeUpstream { .. } => {
                super::display_tls::format_tls_error(self, formatter)
            }
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
            Self::EmptyCacheImageExtensions { .. }
            | Self::InvalidCacheImageExtension { .. }
            | Self::EmptyCacheMethods { .. }
            | Self::InvalidCacheMethod { .. }
            | Self::EmptyCacheContentTypes { .. }
            | Self::InvalidCacheContentType { .. }
            | Self::InvalidCacheMaxObjectBytes { .. }
            | Self::InvalidCacheStatusTtl { .. }
            | Self::InvalidCacheDefaultStatusTtl { .. }
            | Self::InvalidCacheMinUses { .. }
            | Self::InvalidCacheRangePolicy { .. }
            | Self::InvalidCacheBypassPath { .. }
            | Self::InvalidCacheBypassQueryParam { .. }
            | Self::InvalidCacheBypassQueryValue { .. }
            | Self::InvalidCacheBypassRequestHeaderValue { .. }
            | Self::InvalidCacheNoStoreResponseHeaderValue { .. }
            | Self::InvalidCacheBypassCookieName { .. }
            | Self::InvalidCacheBypassCookieValue { .. }
            | Self::InvalidCacheStaleIfErrorTtl { .. }
            | Self::InvalidCacheStaleWhileRevalidateTtl { .. }
            | Self::EmptyCacheStaleIfErrorOn { .. }
            | Self::InvalidCacheStaleIfErrorStatus { .. }
            | Self::InvalidCacheVaryRequestHeader { .. }
            | Self::InvalidCacheListLength { .. }
            | Self::DuplicateCacheTagHeader { .. }
            | Self::InvalidCacheKeyNamespace { .. }
            | Self::EmptyCacheKeyParts { .. }
            | Self::DuplicateCacheKeyPart { .. }
            | Self::MissingCacheKeyPath { .. }
            | Self::InvalidCacheLockTimeout { .. }
            | Self::InvalidCachePredictorCapacity { .. }
            | Self::InvalidCacheOriginProtectionPolicy { .. }
            | Self::InvalidCachePeerFillPolicy { .. }
            | Self::InvalidCachePeerFillPeer { .. }
            | Self::DuplicateCachePeerFillPeerName { .. }
            | Self::DuplicateCachePeerFillPeerUrl { .. }
            | Self::CachePeerFillNotCompiled
            | Self::CacheEnabledWithoutStorageTier { .. }
            | Self::InvalidCacheTierMaxSize { .. }
            | Self::CacheTierSmallerThanMaxObject { .. }
            | Self::CacheStorageBinLargerThanDiskTier { .. }
            | Self::CacheStorageBinSmallerThanMaxObject { .. }
            | Self::InvalidCacheStorageBinMaxOpenBins { .. }
            | Self::InvalidCacheEncryptionPolicy { .. }
            | Self::InvalidCacheEncryptionCredentialName { .. }
            | Self::UnsupportedCacheDiskBackend { .. }
            | Self::CachePurgerNotCompiled
            | Self::InvalidCachePurgerPolicy { .. }
            | Self::MissingCacheDiskPath { .. }
            | Self::EmptyCacheDiskPath { .. } => {
                super::display_cache::format_cache_error(self, formatter)
            }
            Self::EmptyWebRoot
            | Self::EmptyIndexFiles
            | Self::InvalidIndexFile { .. }
            | Self::EmptyVhostName
            | Self::EmptyVhostHosts { .. }
            | Self::InvalidVhostHost { .. }
            | Self::InvalidVhostLimit { .. }
            | Self::InvalidAccessRule { .. }
            | Self::DuplicateAccessRule { .. }
            | Self::InvalidRateLimit { .. }
            | Self::InvalidConcurrencyLimit { .. }
            | Self::MissingVhostRedirectTarget { .. }
            | Self::VhostRedirectConflictsWithFallback { .. }
            | Self::EmptyRouteName { .. }
            | Self::InvalidRouteMatcher { .. }
            | Self::RouteRegexDisabled { .. }
            | Self::InvalidRouteRegex { .. }
            | Self::InvalidRouteMethods { .. }
            | Self::DuplicateFallbackRoute { .. }
            | Self::InvalidRouteStripPrefix { .. }
            | Self::InvalidRouteRewritePrefix { .. }
            | Self::InvalidRouteRewriteTemplate { .. }
            | Self::InvalidRouteAction { .. }
            | Self::InvalidRouteGrpcPolicy { .. }
            | Self::InvalidRouteLimit { .. }
            | Self::InvalidRouteRedirectStatus { .. }
            | Self::InvalidRouteRedirectTarget { .. }
            | Self::VhostSection { .. }
            | Self::RouteSection { .. }
            | Self::DuplicateVhostName { .. }
            | Self::DuplicateVhostHost { .. } => {
                super::display_route::format_route_error(self, formatter)
            }
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
