use std::collections::{HashMap, VecDeque};
use std::future::Future;
#[cfg(feature = "php-fpm")]
use std::io;
use std::net::{IpAddr, Ipv6Addr};
#[cfg(feature = "php-fpm")]
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
use bytes::Bytes;
use fluxheim_common::path_safety::safe_forward_path;
#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
use fluxheim_compression::{
    ResponseCompressionEncoder, cache_control_directive_blocks_compression,
    content_encoding_value_is_active, content_type_is_compressible,
    input_length_within_compression_bounds, parse_accept_encoding_qvalue,
};
#[cfg(not(feature = "privacy-mode"))]
use fluxheim_config::ForwardedClientIpHeaderMode;
use fluxheim_config::{
    AccessPolicyConfig, GrpcRouteConfig, HeaderPolicyConfig, HeaderValues, HttpsRedirectConfig,
    RateLimitMode, RequestHeaderPolicyConfig, ResponseHeaderPolicyConfig,
    ResponseHeaderPolicyOverlayConfig, ResponseHeaderRewriteConfig, normalize_host,
};
#[cfg(feature = "acme")]
use fluxheim_config::{AcmeChallenge, Config};
use fluxheim_headers::{
    SPOOFABLE_CLIENT_IP_HEADERS, rewrite_header_prefix, rewrite_refresh_url,
    rewrite_set_cookie_value,
};
#[cfg(not(feature = "privacy-mode"))]
use fluxheim_headers::{build_forwarded_header, effective_client_ip};
use fluxheim_protocol::{
    Http1RequestTarget, http1_request_target, route_method_matches, route_prefix_matches_path,
    route_strip_prefix_suffix,
};

#[cfg(feature = "php-fpm")]
use crate::native_http1_php::{
    NativePhpResponsePlan, NativePhpScriptResolve, native_php_execute_fpm, native_php_request_body,
    native_php_request_plan,
};
use crate::{
    DownstreamHttp1Policy, NativeHttp1ConnectionStream, NativeHttp1Error, NativeHttp1Handler,
    NativeHttp1Proxy, NativeHttp1ProxyConfigError, NativeHttp1Request, NativeHttp1Response,
    NativeHttp1StaticWeb, ProxyProtocolTrustedSource,
};
#[cfg(feature = "acme")]
use crate::{NativeHttp1AcmeHttp01Store, native_http1_acme::http_01_token_from_path};
use tokio::io::AsyncWriteExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAX_ROUTE_REGEX_CAPTURE_VALUES: usize = 16;
const MAX_ROUTE_REGEX_CAPTURE_VALUE_BYTES: usize = 256;
const NATIVE_RATE_LIMIT_MIN_PRUNE_INTERVAL: Duration = Duration::from_secs(1);
const NATIVE_RATE_LIMIT_PRUNE_SCAN_LIMIT: usize = 128;
const NATIVE_RATE_LIMIT_SHARDS: usize = 16;
const NATIVE_RATE_LIMIT_SHARD_HASH_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const NATIVE_RATE_LIMIT_SHARD_HASH_PRIME: u64 = 0x0000_0100_0000_01b3;
static NATIVE_RATE_LIMIT_SHARD_SEED: OnceLock<u64> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1RouteProxy {
    routes: Vec<NativeHttp1RouteProxyRoute>,
    fallback: Option<NativeHttp1Proxy>,
    fallback_web: Option<NativeHttp1StaticWeb>,
    #[cfg(feature = "php-fpm")]
    fallback_php: Option<NativePhpFpmRoute>,
    fallback_response_headers: NativeRouteResponseHeaderPolicy,
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    fallback_compression: Option<fluxheim_config::CompressionConfig>,
    access: NativeIpAccessPolicy,
    rate_limit: NativeRateLimit,
    concurrency: NativeConcurrencyLimit,
    max_request_body_bytes: Option<u64>,
    https_redirect: HttpsRedirectConfig,
    #[cfg(not(feature = "privacy-mode"))]
    trusted_sources: Vec<ProxyProtocolTrustedSource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1RouteProxyRoute {
    methods: Vec<String>,
    matcher: NativeHttp1RouteMatcher,
    strip_prefix: Option<String>,
    rewrite_prefix: Option<String>,
    rewrite_template: Option<String>,
    max_request_body_bytes: Option<u64>,
    https_redirect_exempt: bool,
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    compression: Option<fluxheim_config::CompressionConfig>,
    request_headers: NativeRouteRequestHeaderPolicy,
    response_headers: NativeRouteResponseHeaderPolicy,
    access: NativeIpAccessPolicy,
    rate_limit: NativeRateLimit,
    concurrency: NativeConcurrencyLimit,
    grpc: GrpcRouteConfig,
    action: NativeHttp1RouteAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NativeHttp1RouteMatcher {
    Exact(String),
    Prefix(String),
    Regex(NativeRegexRouteMatcher),
    Fallback,
}

#[derive(Clone)]
struct NativeRegexRouteMatcher {
    pattern: String,
    regex: regex::Regex,
}

impl std::fmt::Debug for NativeRegexRouteMatcher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeRegexRouteMatcher")
            .field("pattern", &self.pattern)
            .finish_non_exhaustive()
    }
}

impl PartialEq for NativeRegexRouteMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for NativeRegexRouteMatcher {}

impl NativeRegexRouteMatcher {
    fn from_pattern(pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            pattern: pattern.to_owned(),
            regex: regex::RegexBuilder::new(pattern)
                .size_limit(fluxheim_config::MAX_ROUTE_REGEX_PROGRAM_BYTES)
                .dfa_size_limit(fluxheim_config::MAX_ROUTE_REGEX_PROGRAM_BYTES)
                .build()?,
        })
    }

    fn is_match(&self, path: &str) -> bool {
        self.regex.is_match(path)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NativeHttp1RouteAction {
    #[cfg(feature = "acme")]
    AcmeHttp01(NativeHttp1AcmeHttp01Store),
    #[cfg(feature = "php-fpm")]
    PhpFpm(Box<NativePhpFpmRoute>),
    Proxy(Box<NativeHttp1Proxy>),
    Redirect(NativeHttp1RouteRedirect),
    StaticWeb(Box<NativeHttp1StaticWeb>),
}

#[cfg(feature = "php-fpm")]
#[derive(Clone, Debug)]
struct NativePhpFpmRoute {
    config: fluxheim_config::PhpConfig,
    root: PathBuf,
    fpm_root: PathBuf,
    files: NativeHttp1StaticWeb,
    error_pages: Vec<NativePhpErrorPage>,
    vhost_name: String,
    _managed_fpm: Option<Arc<fluxheim_php_fpm::ManagedPhpFpmProcess>>,
    pools: Vec<Arc<fluxheim_php_fpm::PhpFpmPool>>,
    next_endpoint: Arc<AtomicUsize>,
    in_flight: Arc<Semaphore>,
}

#[cfg(feature = "php-fpm")]
impl PartialEq for NativePhpFpmRoute {
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
            && self.root == other.root
            && self.fpm_root == other.fpm_root
            && self.files == other.files
            && self.error_pages == other.error_pages
            && self.vhost_name == other.vhost_name
    }
}

#[cfg(feature = "php-fpm")]
impl Eq for NativePhpFpmRoute {}

#[cfg(feature = "php-fpm")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct NativePhpErrorPage {
    status: u16,
    path: String,
    web: NativeHttp1StaticWeb,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeHttp1RouteRedirect {
    to: String,
    status: u16,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NativeRouteRequestHeaderPolicy {
    enabled: bool,
    strip_inbound_client_ip_headers: bool,
    #[cfg(not(feature = "privacy-mode"))]
    x_forwarded_for: ForwardedClientIpHeaderMode,
    #[cfg(not(feature = "privacy-mode"))]
    x_real_ip: bool,
    #[cfg(not(feature = "privacy-mode"))]
    x_forwarded_host: bool,
    #[cfg(not(feature = "privacy-mode"))]
    x_forwarded_proto: bool,
    #[cfg(not(feature = "privacy-mode"))]
    forwarded: bool,
    #[cfg(not(feature = "privacy-mode"))]
    trusted_sources: Vec<ProxyProtocolTrustedSource>,
    unset: Vec<String>,
    set: Vec<(String, String)>,
    append: Vec<(String, String)>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NativeRequestHeaderTemplateContext {
    route_regex_captures: Vec<(String, String)>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NativeRouteResponseHeaderPolicy {
    enabled: bool,
    unset: Vec<String>,
    set: Vec<(String, String)>,
    append: Vec<(String, String)>,
    rewrite: ResponseHeaderRewriteConfig,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct NativeIpAccessPolicy {
    enabled: bool,
    allow: Vec<ProxyProtocolTrustedSource>,
    deny: Vec<ProxyProtocolTrustedSource>,
    require_client_cert: bool,
    allow_client_cert_sha256: Vec<String>,
    deny_client_cert_sha256: Vec<String>,
    allow_countries: Vec<String>,
    deny_countries: Vec<String>,
    allow_asns: Vec<u32>,
    deny_asns: Vec<u32>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum NativeRateLimitKey {
    Ip(IpAddr),
    Indeterminate,
}

impl From<Option<IpAddr>> for NativeRateLimitKey {
    fn from(value: Option<IpAddr>) -> Self {
        value.map(Self::Ip).unwrap_or(Self::Indeterminate)
    }
}

#[derive(Clone, Copy, Debug)]
struct NativeRateLimitBucket {
    tokens: f64,
    updated_at: Instant,
    last_seen: Instant,
}

#[derive(Debug)]
struct NativeRateLimitState {
    shards: Box<[Mutex<NativeRateLimitBuckets>]>,
}

#[derive(Debug)]
struct NativeRateLimitBuckets {
    entries: HashMap<NativeRateLimitKey, NativeRateLimitBucket>,
    prune_queue: VecDeque<NativeRateLimitKey>,
    last_pruned_at: Option<Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum NativeRateLimitDecision {
    Allow,
    Delay(Duration),
    Reject(u16),
}

#[derive(Clone, Debug)]
struct NativeRateLimit {
    enabled: bool,
    requests_per_second: f64,
    burst: f64,
    status: u16,
    table_max_entries: usize,
    entry_ttl: Duration,
    mode: RateLimitMode,
    max_delay: Duration,
    reject_indeterminate: bool,
    state: Arc<NativeRateLimitState>,
}

impl PartialEq for NativeRateLimit {
    fn eq(&self, other: &Self) -> bool {
        self.enabled == other.enabled
            && self.requests_per_second == other.requests_per_second
            && self.burst == other.burst
            && self.status == other.status
            && self.table_max_entries == other.table_max_entries
            && self.entry_ttl == other.entry_ttl
            && self.mode == other.mode
            && self.max_delay == other.max_delay
            && self.reject_indeterminate == other.reject_indeterminate
    }
}

impl Eq for NativeRateLimit {}

#[derive(Debug)]
struct NativeConcurrencyPermit {
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for NativeConcurrencyPermit {
    fn drop(&mut self) {
        let _ = self.permit.take();
    }
}

#[derive(Debug)]
struct NativeQueuedConcurrencyWaiter {
    queued: Arc<AtomicUsize>,
}

impl Drop for NativeQueuedConcurrencyWaiter {
    fn drop(&mut self) {
        self.queued.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Debug)]
struct NativeConcurrencyLimit {
    enabled: bool,
    max_in_flight: usize,
    max_queue: usize,
    status: u16,
    queue_timeout: Duration,
    semaphore: Arc<Semaphore>,
    queued: Arc<AtomicUsize>,
}

impl PartialEq for NativeConcurrencyLimit {
    fn eq(&self, other: &Self) -> bool {
        self.enabled == other.enabled
            && self.max_in_flight == other.max_in_flight
            && self.max_queue == other.max_queue
            && self.status == other.status
            && self.queue_timeout == other.queue_timeout
    }
}

impl Eq for NativeConcurrencyLimit {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHttp1RouteProxyConfigError {
    AccessPolicy,
    #[cfg(feature = "acme")]
    AcmeStorage,
    MissingRouteAction,
    Proxy(NativeHttp1ProxyConfigError),
    RegexRoute,
    StaticWeb,
}

impl std::fmt::Display for NativeHttp1RouteProxyConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessPolicy => {
                formatter.write_str("native route proxy access policy configuration error")
            }
            #[cfg(feature = "acme")]
            Self::AcmeStorage => {
                formatter.write_str("native route proxy ACME storage is not configured")
            }
            Self::MissingRouteAction => {
                formatter.write_str("native route proxy requires an action")
            }
            Self::Proxy(error) => write!(formatter, "{error}"),
            Self::RegexRoute => {
                formatter.write_str("native route proxy regex route configuration error")
            }
            Self::StaticWeb => formatter.write_str("native route static web config is invalid"),
        }
    }
}

impl std::error::Error for NativeHttp1RouteProxyConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Proxy(error) => Some(error),
            Self::AccessPolicy | Self::MissingRouteAction | Self::RegexRoute | Self::StaticWeb => {
                None
            }
            #[cfg(feature = "acme")]
            Self::AcmeStorage => None,
        }
    }
}

impl NativeIpAccessPolicy {
    fn from_config(access: &AccessPolicyConfig) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        if !access.enabled {
            return Ok(Self::default());
        }
        Ok(Self {
            enabled: true,
            allow: parse_native_access_sources(&access.allow)?,
            deny: parse_native_access_sources(&access.deny)?,
            require_client_cert: access.require_client_cert,
            allow_client_cert_sha256: normalized_access_strings(&access.allow_client_cert_sha256),
            deny_client_cert_sha256: normalized_access_strings(&access.deny_client_cert_sha256),
            allow_countries: normalized_access_strings(&access.allow_countries),
            deny_countries: normalized_access_strings(&access.deny_countries),
            allow_asns: access.allow_asns.clone(),
            deny_asns: access.deny_asns.clone(),
        })
    }

    fn allows(
        &self,
        client_ip: Option<IpAddr>,
        tls_identity: Option<&crate::NativeHttp1TlsClientIdentity>,
        geo_context: Option<&crate::NativeHttp1GeoContext>,
    ) -> bool {
        if !self.enabled {
            return true;
        }
        let ip_restrictive = !self.allow.is_empty() || !self.deny.is_empty();
        if let Some(client_ip) = client_ip {
            if self.deny.iter().any(|source| source.contains(client_ip)) {
                return false;
            }
            if !self.allow.is_empty() && !self.allow.iter().any(|source| source.contains(client_ip))
            {
                return false;
            }
        } else if ip_restrictive {
            return false;
        }
        self.allows_client_certificate(tls_identity) && self.allows_geo(geo_context)
    }

    fn allows_client_certificate(
        &self,
        tls_identity: Option<&crate::NativeHttp1TlsClientIdentity>,
    ) -> bool {
        let cert_sha256 = tls_identity
            .and_then(|identity| identity.cert_sha256.as_deref())
            .map(str::to_ascii_lowercase);
        if self.require_client_cert && cert_sha256.is_none() {
            return false;
        }
        let Some(cert_sha256) = cert_sha256.as_deref() else {
            return self.allow_client_cert_sha256.is_empty();
        };
        if self
            .deny_client_cert_sha256
            .iter()
            .any(|denied| denied == cert_sha256)
        {
            return false;
        }
        self.allow_client_cert_sha256.is_empty()
            || self
                .allow_client_cert_sha256
                .iter()
                .any(|allowed| allowed == cert_sha256)
    }

    fn allows_geo(&self, geo_context: Option<&crate::NativeHttp1GeoContext>) -> bool {
        let has_allow = !self.allow_countries.is_empty() || !self.allow_asns.is_empty();
        let has_deny = !self.deny_countries.is_empty() || !self.deny_asns.is_empty();
        if !has_allow && !has_deny {
            return true;
        }
        let Some(geo_context) = geo_context else {
            return !has_allow;
        };
        let country = geo_context
            .country_iso
            .as_deref()
            .map(str::to_ascii_lowercase);
        if country
            .as_deref()
            .is_some_and(|country| self.deny_countries.iter().any(|denied| denied == country))
        {
            return false;
        }
        if !self.allow_countries.is_empty()
            && !country.as_deref().is_some_and(|country| {
                self.allow_countries
                    .iter()
                    .any(|allowed| allowed == country)
            })
        {
            return false;
        }
        if geo_context
            .asn
            .is_some_and(|asn| self.deny_asns.contains(&asn))
        {
            return false;
        }
        self.allow_asns.is_empty()
            || geo_context
                .asn
                .is_some_and(|asn| self.allow_asns.contains(&asn))
    }
}

fn normalized_access_strings(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn parse_native_access_sources(
    values: &[String],
) -> Result<Vec<ProxyProtocolTrustedSource>, NativeHttp1RouteProxyConfigError> {
    values
        .iter()
        .map(
            |value| match fluxheim_protocol::parse_proxy_protocol_trusted_source(value) {
                Ok(fluxheim_protocol::ProxyProtocolTrustedSource::Ip(address)) => {
                    Ok(ProxyProtocolTrustedSource::Ip(address))
                }
                Ok(fluxheim_protocol::ProxyProtocolTrustedSource::Cidr { network, prefix }) => {
                    Ok(ProxyProtocolTrustedSource::Cidr { network, prefix })
                }
                Err(_) => Err(NativeHttp1RouteProxyConfigError::AccessPolicy),
            },
        )
        .collect()
}

impl Default for NativeRateLimit {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_second: 0.0,
            burst: 0.0,
            status: 429,
            table_max_entries: 0,
            entry_ttl: Duration::from_secs(300),
            mode: RateLimitMode::Nodelay,
            max_delay: Duration::from_millis(1000),
            reject_indeterminate: false,
            state: Arc::new(NativeRateLimitState {
                shards: native_rate_limit_shards(),
            }),
        }
    }
}

impl NativeRateLimit {
    fn from_config(config: &fluxheim_config::RateLimitConfig) -> Self {
        let burst = if config.burst == 0 {
            config.requests_per_second.max(1)
        } else {
            config.burst
        };
        Self {
            enabled: config.enabled,
            requests_per_second: f64::from(config.requests_per_second),
            burst: f64::from(burst),
            status: config.status,
            table_max_entries: config.table_max_entries,
            entry_ttl: Duration::from_secs(config.entry_ttl_secs),
            mode: config.mode,
            max_delay: Duration::from_millis(config.max_delay_ms),
            reject_indeterminate: config.reject_indeterminate,
            state: Arc::new(NativeRateLimitState {
                shards: native_rate_limit_shards(),
            }),
        }
    }

    fn check(&self, client_ip: Option<IpAddr>) -> NativeRateLimitDecision {
        if !self.enabled {
            return NativeRateLimitDecision::Allow;
        }

        let now = Instant::now();
        let key = NativeRateLimitKey::from(client_ip);
        if matches!(key, NativeRateLimitKey::Indeterminate) && self.reject_indeterminate {
            return NativeRateLimitDecision::Reject(self.status);
        }
        let shard = native_rate_limit_shard(key);
        let max_entries = self
            .table_max_entries
            .div_ceil(NATIVE_RATE_LIMIT_SHARDS)
            .max(1);
        let mut buckets = match self.state.shards[shard].lock() {
            Ok(guard) => guard,
            Err(_) => {
                log::error!(
                    target: "fluxheim::security",
                    "native rate-limit bucket lock poisoned; aborting to avoid inconsistent edge limits"
                );
                std::process::abort();
            }
        };
        if !buckets.entries.contains_key(&key) && buckets.entries.len() >= max_entries {
            let should_prune = buckets.last_pruned_at.is_none_or(|last_pruned_at| {
                now.saturating_duration_since(last_pruned_at)
                    >= NATIVE_RATE_LIMIT_MIN_PRUNE_INTERVAL
            });
            if should_prune {
                prune_native_rate_limit_entries(
                    &mut buckets,
                    now,
                    self.entry_ttl,
                    NATIVE_RATE_LIMIT_PRUNE_SCAN_LIMIT,
                );
                buckets.last_pruned_at = Some(now);
            }
            if buckets.entries.len() >= max_entries {
                return NativeRateLimitDecision::Reject(self.status);
            }
        }

        if !buckets.entries.contains_key(&key) {
            buckets.prune_queue.push_back(key);
            buckets.entries.insert(
                key,
                NativeRateLimitBucket {
                    tokens: self.burst,
                    updated_at: now,
                    last_seen: now,
                },
            );
        }
        let bucket = buckets.entries.get_mut(&key).unwrap_or_else(|| {
            log::error!(
                target: "fluxheim::security",
                "native rate-limit bucket vanished during locked update; aborting to avoid inconsistent edge limits"
            );
            std::process::abort();
        });
        let elapsed = now
            .saturating_duration_since(bucket.updated_at)
            .as_secs_f64();
        bucket.tokens = self
            .burst
            .min(bucket.tokens + elapsed * self.requests_per_second);
        bucket.updated_at = now;
        bucket.last_seen = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return NativeRateLimitDecision::Allow;
        }

        if !matches!(self.mode, RateLimitMode::Delay) || bucket.tokens <= -self.burst {
            return NativeRateLimitDecision::Reject(self.status);
        }

        if !self.requests_per_second.is_finite() || self.requests_per_second <= 0.0 {
            return NativeRateLimitDecision::Reject(self.status);
        }
        let wait = Duration::from_secs_f64((1.0 - bucket.tokens) / self.requests_per_second);
        if wait > self.max_delay {
            return NativeRateLimitDecision::Reject(self.status);
        }

        bucket.tokens -= 1.0;
        NativeRateLimitDecision::Delay(wait)
    }
}

fn native_rate_limit_shards() -> Box<[Mutex<NativeRateLimitBuckets>]> {
    (0..NATIVE_RATE_LIMIT_SHARDS)
        .map(|_| {
            Mutex::new(NativeRateLimitBuckets {
                entries: HashMap::new(),
                prune_queue: VecDeque::new(),
                last_pruned_at: None,
            })
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

fn prune_native_rate_limit_entries(
    buckets: &mut NativeRateLimitBuckets,
    now: Instant,
    ttl: Duration,
    scan_limit: usize,
) {
    let scans = scan_limit.min(buckets.prune_queue.len());
    for _ in 0..scans {
        let Some(key) = buckets.prune_queue.pop_front() else {
            return;
        };
        let Some(bucket) = buckets.entries.get(&key) else {
            continue;
        };
        if now.saturating_duration_since(bucket.last_seen) > ttl {
            buckets.entries.remove(&key);
        } else {
            buckets.prune_queue.push_back(key);
        }
    }
}

fn native_rate_limit_shard(key: NativeRateLimitKey) -> usize {
    match key {
        NativeRateLimitKey::Ip(IpAddr::V4(address)) => {
            native_rate_limit_shard_hash(&address.octets()) & (NATIVE_RATE_LIMIT_SHARDS - 1)
        }
        NativeRateLimitKey::Ip(IpAddr::V6(address)) => {
            native_rate_limit_shard_hash(&address.octets()) & (NATIVE_RATE_LIMIT_SHARDS - 1)
        }
        NativeRateLimitKey::Indeterminate => {
            native_rate_limit_shard_hash(b"indeterminate") & (NATIVE_RATE_LIMIT_SHARDS - 1)
        }
    }
}

fn native_rate_limit_shard_hash(bytes: &[u8]) -> usize {
    let mut hash = native_rate_limit_shard_seed();
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(NATIVE_RATE_LIMIT_SHARD_HASH_PRIME);
    }
    hash as usize
}

fn native_rate_limit_shard_seed() -> u64 {
    *NATIVE_RATE_LIMIT_SHARD_SEED.get_or_init(|| {
        let mut bytes = [0_u8; 8];
        if let Err(error) = getrandom::fill(&mut bytes) {
            log::error!(
                target: "fluxheim::security",
                "native rate-limit shard seed generation failed: {error}; aborting"
            );
            std::process::abort();
        }
        u64::from_le_bytes(bytes) ^ NATIVE_RATE_LIMIT_SHARD_HASH_OFFSET
    })
}

impl Default for NativeConcurrencyLimit {
    fn default() -> Self {
        Self {
            enabled: false,
            max_in_flight: 0,
            max_queue: 0,
            status: 503,
            queue_timeout: Duration::ZERO,
            semaphore: Arc::new(Semaphore::new(0)),
            queued: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl NativeConcurrencyLimit {
    fn from_config(config: &fluxheim_config::ConcurrencyLimitConfig) -> Self {
        let max_queue = if config.max_queue == 0 {
            config
                .max_in_flight
                .saturating_mul(4)
                .max(config.max_in_flight)
                .min(1_000_000)
        } else {
            config.max_queue
        };
        Self {
            enabled: config.enabled,
            max_in_flight: config.max_in_flight,
            max_queue,
            status: config.status,
            queue_timeout: Duration::from_millis(config.queue_timeout_ms),
            semaphore: Arc::new(Semaphore::new(config.max_in_flight)),
            queued: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn acquire(&self) -> Result<Option<NativeConcurrencyPermit>, u16> {
        if !self.enabled {
            return Ok(None);
        }

        match Arc::clone(&self.semaphore).try_acquire_owned() {
            Ok(permit) => {
                return Ok(Some(NativeConcurrencyPermit {
                    permit: Some(permit),
                }));
            }
            Err(_) if self.queue_timeout.is_zero() => return Err(self.status),
            Err(_) => {}
        }

        if !self.try_enter_queue() {
            return Err(self.status);
        }
        let queued = NativeQueuedConcurrencyWaiter {
            queued: Arc::clone(&self.queued),
        };
        let result = tokio::time::timeout(
            self.queue_timeout,
            Arc::clone(&self.semaphore).acquire_owned(),
        )
        .await;
        drop(queued);

        match result {
            Ok(Ok(permit)) => Ok(Some(NativeConcurrencyPermit {
                permit: Some(permit),
            })),
            Ok(Err(_)) | Err(_) => Err(self.status),
        }
    }

    fn try_enter_queue(&self) -> bool {
        let mut current = self.queued.load(Ordering::Acquire);
        loop {
            if current >= self.max_queue {
                return false;
            }
            let Some(next) = current.checked_add(1) else {
                return false;
            };
            match self.queued.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }
}

impl NativeHttp1RouteProxy {
    pub fn new(
        routes: Vec<NativeHttp1RouteProxyRoute>,
        fallback: Option<NativeHttp1Proxy>,
    ) -> Self {
        Self {
            routes,
            fallback,
            fallback_web: None,
            #[cfg(feature = "php-fpm")]
            fallback_php: None,
            fallback_response_headers: NativeRouteResponseHeaderPolicy::default(),
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            fallback_compression: None,
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            max_request_body_bytes: None,
            https_redirect: HttpsRedirectConfig::default(),
            #[cfg(not(feature = "privacy-mode"))]
            trusted_sources: Vec::new(),
        }
    }

    pub fn from_root_config(
        config: &fluxheim_config::Config,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        Self::from_root_config_with_load_balancer_services(
            config,
            policy,
            pool_max_idle,
            #[cfg(feature = "load-balancer")]
            None,
        )
    }

    pub(crate) fn from_root_config_with_load_balancer_services(
        config: &fluxheim_config::Config,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
        #[cfg(feature = "load-balancer")] load_balancer_services: Option<
            &mut Vec<fluxheim_load_balancer::UpstreamLoadBalancerService>,
        >,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        if native_cache_policy_enabled(&config.cache) && !root_native_cache_supported(config) {
            return Err(NativeHttp1RouteProxyConfigError::Proxy(
                NativeHttp1ProxyConfigError::CachePolicy,
            ));
        }
        let fallback_web = if config.web.enabled() {
            let cache =
                NativeHttp1StaticWeb::cache_supported(&config.cache).then_some(&config.cache);
            NativeHttp1StaticWeb::from_config_with_cache(&config.web, cache)
                .map_err(|_| NativeHttp1RouteProxyConfigError::StaticWeb)?
        } else {
            None
        };
        let fallback = native_proxy_from_config_collecting_load_balancer(
            "root proxy",
            "root",
            None,
            &config.proxy,
            policy,
            pool_max_idle,
            #[cfg(feature = "load-balancer")]
            load_balancer_services,
        )?
        .map(|proxy| {
            let proxy = proxy.with_header_policy(&config.headers);
            if NativeHttp1Proxy::proxy_cache_supported_for_proxy(&config.cache, &config.proxy) {
                proxy.with_proxy_cache_config(&config.cache)
            } else {
                proxy
            }
        });
        if fallback_web.is_none() && fallback.is_none() {
            return Err(NativeHttp1RouteProxyConfigError::MissingRouteAction);
        }
        let mut proxy = Self::new(Vec::new(), fallback);
        proxy.fallback_web = fallback_web;
        proxy.https_redirect = config.server.https_redirect;
        proxy.fallback_response_headers =
            NativeRouteResponseHeaderPolicy::from_policy(&config.headers.response);
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        if config.compression.enabled {
            proxy.fallback_compression = Some(config.compression.clone());
        }
        Ok(proxy)
    }

    pub fn routes(&self) -> &[NativeHttp1RouteProxyRoute] {
        &self.routes
    }

    pub fn fallback(&self) -> Option<&NativeHttp1Proxy> {
        self.fallback.as_ref()
    }

    pub(crate) fn with_https_redirect(mut self, https_redirect: HttpsRedirectConfig) -> Self {
        self.https_redirect = https_redirect;
        self
    }

    #[cfg(feature = "acme")]
    pub fn from_config(
        config: &Config,
        vhost: &fluxheim_config::VhostConfig,
        base_headers: &HeaderPolicyConfig,
        inherited_compression: Option<&fluxheim_config::CompressionConfig>,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        Self::from_config_with_trusted_sources(
            config,
            vhost,
            base_headers,
            inherited_compression,
            policy,
            pool_max_idle,
            &[],
        )
    }

    #[cfg(feature = "acme")]
    pub fn from_config_with_trusted_sources(
        config: &Config,
        vhost: &fluxheim_config::VhostConfig,
        base_headers: &HeaderPolicyConfig,
        inherited_compression: Option<&fluxheim_config::CompressionConfig>,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
        #[cfg_attr(feature = "privacy-mode", allow(unused_variables))]
        trusted_sources: &[ProxyProtocolTrustedSource],
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        Self::from_config_with_trusted_sources_and_load_balancer_services(
            config,
            vhost,
            base_headers,
            inherited_compression,
            policy,
            pool_max_idle,
            trusted_sources,
            #[cfg(feature = "load-balancer")]
            None,
        )
    }

    #[cfg(feature = "acme")]
    #[allow(clippy::too_many_arguments)]
    pub fn from_config_with_trusted_sources_and_load_balancer_services(
        config: &Config,
        vhost: &fluxheim_config::VhostConfig,
        base_headers: &HeaderPolicyConfig,
        inherited_compression: Option<&fluxheim_config::CompressionConfig>,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
        #[cfg_attr(feature = "privacy-mode", allow(unused_variables))]
        trusted_sources: &[ProxyProtocolTrustedSource],
        #[cfg(feature = "load-balancer")] load_balancer_services: Option<
            &mut Vec<fluxheim_load_balancer::UpstreamLoadBalancerService>,
        >,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        let mut proxy = Self::from_vhost_config_with_trusted_sources_and_load_balancer_services(
            vhost,
            base_headers,
            inherited_compression,
            policy,
            pool_max_idle,
            trusted_sources,
            #[cfg(feature = "load-balancer")]
            load_balancer_services,
        )?;
        proxy.https_redirect = config.server.https_redirect;
        if let Some(route) = native_managed_http_01_route(config, vhost, base_headers)? {
            proxy.routes.insert(0, route);
        }
        Ok(proxy)
    }

    pub fn from_vhost_config(
        vhost: &fluxheim_config::VhostConfig,
        base_headers: &HeaderPolicyConfig,
        inherited_compression: Option<&fluxheim_config::CompressionConfig>,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        Self::from_vhost_config_with_trusted_sources(
            vhost,
            base_headers,
            inherited_compression,
            policy,
            pool_max_idle,
            &[],
        )
    }

    pub fn from_vhost_config_with_trusted_sources(
        vhost: &fluxheim_config::VhostConfig,
        base_headers: &HeaderPolicyConfig,
        inherited_compression: Option<&fluxheim_config::CompressionConfig>,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
        #[cfg_attr(feature = "privacy-mode", allow(unused_variables))]
        trusted_sources: &[ProxyProtocolTrustedSource],
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        Self::from_vhost_config_with_trusted_sources_and_load_balancer_services(
            vhost,
            base_headers,
            inherited_compression,
            policy,
            pool_max_idle,
            trusted_sources,
            #[cfg(feature = "load-balancer")]
            None,
        )
    }

    pub fn from_vhost_config_with_trusted_sources_and_load_balancer_services(
        vhost: &fluxheim_config::VhostConfig,
        base_headers: &HeaderPolicyConfig,
        inherited_compression: Option<&fluxheim_config::CompressionConfig>,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
        #[cfg_attr(feature = "privacy-mode", allow(unused_variables))]
        trusted_sources: &[ProxyProtocolTrustedSource],
        #[cfg(feature = "load-balancer")] mut load_balancer_services: Option<
            &mut Vec<fluxheim_load_balancer::UpstreamLoadBalancerService>,
        >,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        if native_vhost_cache_policy_blocked(vhost) {
            return Err(NativeHttp1RouteProxyConfigError::Proxy(
                NativeHttp1ProxyConfigError::CachePolicy,
            ));
        }
        let headers = base_headers.with_vhost_overlay(&vhost.headers);
        let inherited_compression = vhost.compression.as_ref().or(inherited_compression);
        let fallback_web = if vhost.web.enabled() {
            let cache = NativeHttp1StaticWeb::cache_supported(&vhost.cache).then_some(&vhost.cache);
            NativeHttp1StaticWeb::from_config_with_cache(&vhost.web, cache)
                .map_err(|_| NativeHttp1RouteProxyConfigError::StaticWeb)?
        } else {
            None
        };
        #[cfg(feature = "php-fpm")]
        let fallback_php = NativePhpFpmRoute::from_config(
            format!("vhost {}", vhost.name),
            &vhost.name,
            "default",
            &vhost.php,
        )?;
        #[cfg(not(feature = "php-fpm"))]
        if vhost.php.enabled {
            return Err(NativeHttp1RouteProxyConfigError::Proxy(
                NativeHttp1ProxyConfigError::PhpFpm,
            ));
        }
        let access = NativeIpAccessPolicy::from_config(&vhost.access)?;
        let rate_limit = NativeRateLimit::from_config(&vhost.rate_limit);
        let concurrency = NativeConcurrencyLimit::from_config(&vhost.concurrency);
        let fallback = native_proxy_from_config_collecting_load_balancer(
            &vhost.name,
            &vhost.name,
            None,
            &vhost.proxy,
            policy,
            pool_max_idle,
            #[cfg(feature = "load-balancer")]
            native_load_balancer_services_reborrow(&mut load_balancer_services),
        )?;
        let fallback = fallback.map(|proxy| {
            let proxy = proxy.with_header_policy(&headers);
            if NativeHttp1Proxy::proxy_cache_supported_for_proxy(&vhost.cache, &vhost.proxy) {
                proxy.with_proxy_cache_config(&vhost.cache)
            } else {
                proxy
            }
        });
        #[cfg(not(feature = "privacy-mode"))]
        let fallback = fallback.map(|proxy| proxy.with_trusted_sources(trusted_sources));
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        let fallback = fallback.map(|proxy| {
            if let Some(compression) = inherited_compression.cloned() {
                proxy.with_compression_config(compression)
            } else {
                proxy
            }
        });

        let mut routes = Vec::new();
        for route in vhost
            .acme_challenge
            .route_config()
            .into_iter()
            .chain(vhost.routes.iter().cloned())
            .chain(vhost.redirect.route_config())
        {
            let proxy = if let Some(proxy_config) = route.proxy.as_ref() {
                let proxy = native_proxy_from_config_collecting_load_balancer(
                    &format!("{} route {}", vhost.name, route.name),
                    &vhost.name,
                    Some(&route.name),
                    proxy_config,
                    policy,
                    pool_max_idle,
                    #[cfg(feature = "load-balancer")]
                    native_load_balancer_services_reborrow(&mut load_balancer_services),
                )?;
                #[cfg(not(feature = "privacy-mode"))]
                let proxy = proxy.map(|proxy| proxy.with_trusted_sources(trusted_sources));
                proxy.map(|proxy| {
                    if let Some(cache) = route.cache.as_ref().filter(|cache| {
                        NativeHttp1Proxy::proxy_cache_supported_for_proxy(cache, proxy_config)
                    }) {
                        proxy.with_proxy_cache_config(cache)
                    } else {
                        proxy
                    }
                })
            } else {
                None
            };
            let route = NativeHttp1RouteProxyRoute::from_config_with_inherited(
                &route,
                proxy,
                &headers,
                inherited_compression,
                &vhost.name,
            )?;
            #[cfg(not(feature = "privacy-mode"))]
            let route = route.with_trusted_sources(trusted_sources);
            routes.push(route);
        }

        Ok(Self {
            routes,
            fallback,
            fallback_web,
            #[cfg(feature = "php-fpm")]
            fallback_php,
            fallback_response_headers: NativeRouteResponseHeaderPolicy::from_policy(
                &headers.response,
            ),
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            fallback_compression: inherited_compression.cloned(),
            access,
            rate_limit,
            concurrency,
            max_request_body_bytes: vhost.max_request_body_bytes.map(|bytes| bytes.as_u64()),
            https_redirect: HttpsRedirectConfig::default(),
            #[cfg(not(feature = "privacy-mode"))]
            trusted_sources: trusted_sources.to_vec(),
        })
    }
}

fn native_proxy_from_config_collecting_load_balancer(
    name: &str,
    vhost: &str,
    route: Option<&str>,
    proxy: &fluxheim_config::ProxyConfig,
    policy: DownstreamHttp1Policy,
    pool_max_idle: usize,
    #[cfg(feature = "load-balancer")] load_balancer_services: Option<
        &mut Vec<fluxheim_load_balancer::UpstreamLoadBalancerService>,
    >,
) -> Result<Option<NativeHttp1Proxy>, NativeHttp1RouteProxyConfigError> {
    #[cfg(feature = "load-balancer")]
    {
        let result = NativeHttp1Proxy::from_proxy_config_with_native_load_balancer(
            name,
            vhost,
            route,
            proxy,
            policy,
            pool_max_idle,
        )
        .map_err(NativeHttp1RouteProxyConfigError::Proxy)?;
        let Some((proxy, service)) = result else {
            return Ok(None);
        };
        if let (Some(services), Some(service)) = (load_balancer_services, service) {
            services.push(service);
        }
        Ok(Some(proxy))
    }
    #[cfg(not(feature = "load-balancer"))]
    {
        let _ = (name, vhost, route);
        NativeHttp1Proxy::from_proxy_config_with_pool_size(proxy, policy, pool_max_idle)
            .map_err(NativeHttp1RouteProxyConfigError::Proxy)
    }
}

#[cfg(feature = "load-balancer")]
#[allow(clippy::option_as_ref_deref)]
fn native_load_balancer_services_reborrow<'a>(
    services: &'a mut Option<&mut Vec<fluxheim_load_balancer::UpstreamLoadBalancerService>>,
) -> Option<&'a mut Vec<fluxheim_load_balancer::UpstreamLoadBalancerService>> {
    services.as_mut().map(|services| &mut **services)
}

#[cfg(feature = "acme")]
fn native_managed_http_01_route(
    config: &Config,
    vhost: &fluxheim_config::VhostConfig,
    base_headers: &HeaderPolicyConfig,
) -> Result<Option<NativeHttp1RouteProxyRoute>, NativeHttp1RouteProxyConfigError> {
    if vhost.acme_challenge.enabled
        || !config.tls.acme.enabled
        || config.tls.acme.challenge != AcmeChallenge::Http01
    {
        return Ok(None);
    }

    let Some(storage) = config.tls.acme.storage.as_deref() else {
        return Err(NativeHttp1RouteProxyConfigError::AcmeStorage);
    };
    let Some(owner) = native_managed_http_01_owner_vhost(config, vhost) else {
        return Ok(None);
    };

    Ok(Some(NativeHttp1RouteProxyRoute::acme_http_01(
        owner,
        storage,
        base_headers,
    )))
}

#[cfg(feature = "acme")]
fn native_managed_http_01_owner_vhost<'a>(
    config: &'a Config,
    request_vhost: &'a fluxheim_config::VhostConfig,
) -> Option<&'a str> {
    if request_vhost.tls.enabled && request_vhost.tls.acme.enabled {
        return Some(&request_vhost.name);
    }

    let request_hosts: std::collections::HashSet<String> = request_vhost
        .hosts
        .iter()
        .filter_map(|host| fluxheim_config::config_net::normalize_host(host))
        .collect();
    if request_hosts.is_empty() {
        return None;
    }

    config.vhosts.iter().find_map(|candidate| {
        if !candidate.tls.enabled || !candidate.tls.acme.enabled {
            return None;
        }

        let domains: Box<dyn Iterator<Item = &str> + '_> = if candidate.tls.acme.domains.is_empty()
        {
            Box::new(candidate.hosts.iter().map(String::as_str))
        } else {
            Box::new(candidate.tls.acme.domains.iter().map(String::as_str))
        };

        for domain in domains {
            let Some(domain) = fluxheim_config::config_net::normalize_host(domain) else {
                continue;
            };
            if request_hosts.contains(&domain) {
                return Some(candidate.name.as_str());
            }
        }

        None
    })
}

impl NativeHttp1RouteProxyRoute {
    pub fn exact(path: impl Into<String>, methods: Vec<String>, proxy: NativeHttp1Proxy) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Exact(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::Proxy(Box::new(proxy.without_header_policy())),
        }
    }

    pub fn prefix(path: impl Into<String>, methods: Vec<String>, proxy: NativeHttp1Proxy) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Prefix(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::Proxy(Box::new(proxy.without_header_policy())),
        }
    }

    pub fn fallback(proxy: NativeHttp1Proxy) -> Self {
        Self {
            methods: Vec::new(),
            matcher: NativeHttp1RouteMatcher::Fallback,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::Proxy(Box::new(proxy.without_header_policy())),
        }
    }

    pub fn exact_redirect(
        path: impl Into<String>,
        methods: Vec<String>,
        to: impl Into<String>,
        status: u16,
    ) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Exact(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::Redirect(NativeHttp1RouteRedirect {
                to: to.into(),
                status,
            }),
        }
    }

    pub fn prefix_redirect(
        path: impl Into<String>,
        methods: Vec<String>,
        to: impl Into<String>,
        status: u16,
    ) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Prefix(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::Redirect(NativeHttp1RouteRedirect {
                to: to.into(),
                status,
            }),
        }
    }

    pub fn prefix_static_web(
        path: impl Into<String>,
        methods: Vec<String>,
        web: NativeHttp1StaticWeb,
    ) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Prefix(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::StaticWeb(Box::new(web)),
        }
    }

    #[cfg(feature = "acme")]
    fn acme_http_01(
        vhost_name: &str,
        storage: &std::path::Path,
        base_headers: &HeaderPolicyConfig,
    ) -> Self {
        Self {
            methods: Vec::new(),
            matcher: NativeHttp1RouteMatcher::Prefix("/.well-known/acme-challenge/".to_owned()),
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: true,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: NativeRouteRequestHeaderPolicy::from_policy(&base_headers.request),
            response_headers: NativeRouteResponseHeaderPolicy::from_policy(&base_headers.response),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::AcmeHttp01(NativeHttp1AcmeHttp01Store::new(
                storage, vhost_name,
            )),
        }
    }

    pub fn from_config(
        route: &fluxheim_config::RouteConfig,
        proxy: Option<NativeHttp1Proxy>,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        Self::from_config_with_inherited(route, proxy, &HeaderPolicyConfig::default(), None, "")
    }

    pub fn from_config_with_inherited(
        route: &fluxheim_config::RouteConfig,
        proxy: Option<NativeHttp1Proxy>,
        base_headers: &HeaderPolicyConfig,
        inherited_compression: Option<&fluxheim_config::CompressionConfig>,
        #[cfg_attr(not(feature = "php-fpm"), allow(unused_variables))] vhost_name: &str,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        if native_route_cache_policy_blocked(route) {
            return Err(NativeHttp1RouteProxyConfigError::Proxy(
                NativeHttp1ProxyConfigError::CachePolicy,
            ));
        }
        #[cfg(not(feature = "php-fpm"))]
        if route.php.as_ref().is_some_and(|php| php.enabled) {
            return Err(NativeHttp1RouteProxyConfigError::Proxy(
                NativeHttp1ProxyConfigError::PhpFpm,
            ));
        }
        #[cfg(not(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        )))]
        let _ = inherited_compression;
        let matcher = if let Some(path) = &route.path_exact {
            NativeHttp1RouteMatcher::Exact(path.clone())
        } else if let Some(path) = &route.path_prefix {
            NativeHttp1RouteMatcher::Prefix(path.clone())
        } else if let Some(pattern) = &route.path_regex {
            NativeHttp1RouteMatcher::Regex(
                NativeRegexRouteMatcher::from_pattern(pattern)
                    .map_err(|_| NativeHttp1RouteProxyConfigError::RegexRoute)?,
            )
        } else if route.fallback {
            NativeHttp1RouteMatcher::Fallback
        } else {
            return Err(NativeHttp1RouteProxyConfigError::MissingRouteAction);
        };
        let action = if let Some(redirect) = &route.redirect {
            NativeHttp1RouteAction::Redirect(NativeHttp1RouteRedirect {
                to: redirect.to.clone(),
                status: redirect.status,
            })
        } else if let Some(php) = route.php.as_ref().filter(|php| php.enabled) {
            #[cfg(feature = "php-fpm")]
            {
                NativeHttp1RouteAction::PhpFpm(Box::new(
                    NativePhpFpmRoute::from_config(
                        format!("route {}", route.name),
                        vhost_name,
                        &route.name,
                        php,
                    )?
                    .ok_or(NativeHttp1RouteProxyConfigError::MissingRouteAction)?,
                ))
            }
            #[cfg(not(feature = "php-fpm"))]
            {
                let _ = php;
                return Err(NativeHttp1RouteProxyConfigError::Proxy(
                    NativeHttp1ProxyConfigError::PhpFpm,
                ));
            }
        } else if let Some(web) = route.web.as_ref().filter(|web| web.enabled()) {
            NativeHttp1RouteAction::StaticWeb(Box::new(
                NativeHttp1StaticWeb::from_config_with_cache(web, route.cache.as_ref())
                    .map_err(|_| NativeHttp1RouteProxyConfigError::StaticWeb)?
                    .ok_or(NativeHttp1RouteProxyConfigError::MissingRouteAction)?,
            ))
        } else {
            NativeHttp1RouteAction::Proxy(Box::new(
                proxy
                    .ok_or(NativeHttp1RouteProxyConfigError::MissingRouteAction)?
                    .without_header_policy(),
            ))
        };
        let headers = base_headers.with_vhost_overlay(&route.headers);
        Ok(Self {
            methods: route.methods.clone(),
            matcher,
            strip_prefix: route.strip_prefix.clone(),
            rewrite_prefix: route.rewrite_prefix.clone(),
            rewrite_template: route.rewrite_template.clone(),
            max_request_body_bytes: route.max_request_body_bytes.map(|bytes| bytes.as_u64()),
            https_redirect_exempt: route.https_redirect_exempt,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: route
                .compression
                .clone()
                .or_else(|| inherited_compression.cloned()),
            request_headers: NativeRouteRequestHeaderPolicy::from_policy(&headers.request),
            response_headers: NativeRouteResponseHeaderPolicy::from_policy(&headers.response),
            access: NativeIpAccessPolicy::from_config(&route.access)?,
            rate_limit: NativeRateLimit::from_config(&route.rate_limit),
            concurrency: NativeConcurrencyLimit::from_config(&route.concurrency),
            grpc: route.grpc,
            action,
        })
    }

    pub fn with_strip_prefix(mut self, strip_prefix: impl Into<String>) -> Self {
        self.strip_prefix = Some(strip_prefix.into());
        self
    }

    pub fn with_rewrite_prefix(mut self, rewrite_prefix: impl Into<String>) -> Self {
        self.rewrite_prefix = Some(rewrite_prefix.into());
        self
    }

    pub const fn with_max_request_body_bytes(mut self, max_request_body_bytes: u64) -> Self {
        self.max_request_body_bytes = Some(max_request_body_bytes);
        self
    }

    #[cfg(test)]
    pub const fn with_grpc_policy(mut self, grpc: GrpcRouteConfig) -> Self {
        self.grpc = grpc;
        self
    }

    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    pub fn with_compression_config(
        mut self,
        compression: fluxheim_config::CompressionConfig,
    ) -> Self {
        self.compression = Some(compression);
        self
    }

    pub fn with_response_header_policy(
        mut self,
        response_headers: &ResponseHeaderPolicyOverlayConfig,
    ) -> Self {
        // Programmatic builders apply overlays over the safe default response
        // policy. Config-built routes should use from_config_with_inherited()
        // when root/vhost policy inheritance is required.
        self.response_headers = NativeRouteResponseHeaderPolicy::from_overlay(response_headers);
        self
    }

    #[cfg(not(feature = "privacy-mode"))]
    pub fn with_trusted_sources(mut self, trusted_sources: &[ProxyProtocolTrustedSource]) -> Self {
        self.request_headers
            .set_trusted_sources(trusted_sources.to_vec());
        self
    }

    pub fn with_request_header_policy(
        mut self,
        request_headers: &fluxheim_config::RequestHeaderPolicyOverlayConfig,
    ) -> Self {
        // Programmatic builders apply overlays over the safe default request
        // policy. Config-built routes should use from_config_with_inherited()
        // when root/vhost policy inheritance is required.
        self.request_headers = NativeRouteRequestHeaderPolicy::from_overlay(request_headers);
        self
    }

    pub fn proxy(&self) -> Option<&NativeHttp1Proxy> {
        match &self.action {
            NativeHttp1RouteAction::Proxy(proxy) => Some(proxy.as_ref()),
            #[cfg(feature = "acme")]
            NativeHttp1RouteAction::AcmeHttp01(_) => None,
            #[cfg(feature = "php-fpm")]
            NativeHttp1RouteAction::PhpFpm(_) => None,
            NativeHttp1RouteAction::Redirect(_) | NativeHttp1RouteAction::StaticWeb(_) => None,
        }
    }

    pub fn is_redirect(&self) -> bool {
        matches!(self.action, NativeHttp1RouteAction::Redirect(_))
    }

    fn https_redirect_exempt_or_redirect(&self) -> bool {
        if self.https_redirect_exempt || self.is_redirect() {
            return true;
        }
        #[cfg(feature = "acme")]
        if matches!(self.action, NativeHttp1RouteAction::AcmeHttp01(_)) {
            return true;
        }
        false
    }

    pub fn is_static_web(&self) -> bool {
        matches!(self.action, NativeHttp1RouteAction::StaticWeb(_))
    }
}

#[cfg(feature = "php-fpm")]
impl NativePhpFpmRoute {
    fn from_config(
        scope: impl std::fmt::Display,
        vhost_name: &str,
        metric_pool: &str,
        config: &fluxheim_config::PhpConfig,
    ) -> Result<Option<Self>, NativeHttp1RouteProxyConfigError> {
        if !config.enabled {
            return Ok(None);
        }
        let scope = scope.to_string();
        let root = native_php_root(&scope, config).map_err(|_| {
            NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::PhpFpm)
        })?;
        let fpm_root = native_php_fpm_root(&scope, config, &root).map_err(|_| {
            NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::PhpFpm)
        })?;
        let files = NativeHttp1StaticWeb::from_config(&fluxheim_config::WebConfig {
            root: Some(root.clone()),
            index_files: vec![config.index.clone()],
            deny_dotfiles: true,
            directory_listing: fluxheim_config::DirectoryListingConfig::default(),
            cache_control: "private, no-store".to_owned(),
            expires: None,
        })
        .map_err(|_| NativeHttp1RouteProxyConfigError::StaticWeb)?
        .ok_or(NativeHttp1RouteProxyConfigError::StaticWeb)?;
        let error_pages = native_php_error_pages_from_config(config).map_err(|_| {
            NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::PhpFpm)
        })?;
        let mut runtime_config = config.clone();
        let managed_fpm =
            fluxheim_php_fpm::managed_php_fpm_from_config(&scope, metric_pool, &mut runtime_config)
                .map_err(|_| {
                    NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::PhpFpm)
                })?;
        let pools = fluxheim_php_fpm::php_fpm_keepalive_pools_from_config(
            &runtime_config,
            vhost_name,
            metric_pool,
            fluxheim_php_fpm::PhpFpmPoolMetrics::default(),
        );
        runtime_config.fpm.mode = fluxheim_config::PhpFpmMode::External;
        Ok(Some(Self {
            config: runtime_config,
            root,
            fpm_root,
            files,
            error_pages,
            vhost_name: vhost_name.to_owned(),
            _managed_fpm: managed_fpm,
            pools,
            next_endpoint: Arc::new(AtomicUsize::new(0)),
            in_flight: Arc::new(Semaphore::new(config.max_in_flight)),
        }))
    }

    async fn handle(&self, request: NativeHttp1Request) -> NativeHttp1Response {
        if !native_php_method_allowed(&request.method) {
            return NativeHttp1Response::new(405, "Method Not Allowed", b"method not allowed\n")
                .with_header("allow", "GET, HEAD, POST")
                .close_connection();
        }
        let Some((path, _)) = request_path_and_query(&request) else {
            return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                .close_connection();
        };
        let script = match self.files.resolve_php_script(&self.config, &path, true) {
            Ok(NativePhpScriptResolve::Execute(script)) => script,
            Ok(NativePhpScriptResolve::RedirectDirectorySlash) => {
                return NativeHttp1Response::new(308, "Permanent Redirect", Vec::new())
                    .with_header("location", format!("{path}/"))
                    .close_connection();
            }
            Ok(NativePhpScriptResolve::Decline | NativePhpScriptResolve::NotFound) => {
                return NativeHttp1Response::new(404, "Not Found", b"not found\n")
                    .close_connection();
            }
            Ok(NativePhpScriptResolve::Forbidden) => {
                return NativeHttp1Response::new(403, "Forbidden", b"forbidden\n")
                    .close_connection();
            }
            Err(error) => {
                log::warn!(
                    target: "fluxheim::native_http1",
                    "native php-fpm script resolution failed: {error}"
                );
                return NativeHttp1Response::new(500, "Internal Server Error", b"internal error\n")
                    .close_connection();
            }
        };
        let Ok(_permit) = Arc::clone(&self.in_flight).try_acquire_owned() else {
            return NativeHttp1Response::new(503, "Service Unavailable", b"php busy\n")
                .close_connection();
        };
        let body = match native_php_request_body(&request, &self.config).await {
            Ok(body) if self.config.pass_request_body => body,
            Ok(_) => fluxheim_php_fpm::PhpRequestBody::memory(Vec::new()),
            Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                return NativeHttp1Response::new(413, "Payload Too Large", b"payload too large\n")
                    .close_connection();
            }
            Err(error) => {
                log::warn!(
                    target: "fluxheim::native_http1",
                    "native php-fpm request body planning failed: {error}"
                );
                return NativeHttp1Response::new(502, "Bad Gateway", b"php-fpm failed\n")
                    .close_connection();
            }
        };
        let server_port = native_php_server_port(&self.config, &request);
        let plan = match native_php_request_plan(
            &request,
            &self.config,
            &self.root,
            &self.fpm_root,
            &script.local_path,
            &self.vhost_name,
            &server_port,
        ) {
            Ok(plan) => plan,
            Err(error) => {
                log::debug!(
                    target: "fluxheim::native_http1",
                    "native php-fpm request plan rejected request: {error}"
                );
                return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                    .close_connection();
            }
        };
        match native_php_execute_fpm(
            &self.config,
            &plan,
            body,
            &self.pools,
            self.next_endpoint.as_ref(),
        )
        .await
        {
            Ok(NativePhpResponsePlan {
                response,
                intercept_status: None,
            }) => response,
            Ok(NativePhpResponsePlan {
                response,
                intercept_status: Some(status),
            }) => self
                .error_page_response(&request, status)
                .unwrap_or(response),
            Err(error) => {
                log::warn!(target: "fluxheim::native_http1", "native php-fpm request failed: {error}");
                NativeHttp1Response::new(502, "Bad Gateway", b"php-fpm failed\n").close_connection()
            }
        }
    }

    fn error_page_response(
        &self,
        request: &NativeHttp1Request,
        status: u16,
    ) -> Option<NativeHttp1Response> {
        self.error_pages
            .iter()
            .find(|page| page.status == status)
            .and_then(|page| page.web.handle_error_page(request, &page.path, status))
            .map(NativeHttp1Response::close_connection)
    }
}

#[cfg(feature = "php-fpm")]
fn native_php_error_pages_from_config(
    config: &fluxheim_config::PhpConfig,
) -> Result<Vec<NativePhpErrorPage>, NativeHttp1ProxyConfigError> {
    let mut pages = Vec::with_capacity(config.error_pages.len());
    for page in &config.error_pages {
        let web = NativeHttp1StaticWeb::from_config(&page.web)
            .map_err(|_| NativeHttp1ProxyConfigError::ErrorPages)?
            .ok_or(NativeHttp1ProxyConfigError::ErrorPages)?;
        pages.push(NativePhpErrorPage {
            status: page.status,
            path: page.path.clone(),
            web,
        });
    }
    Ok(pages)
}

#[cfg(feature = "php-fpm")]
fn native_php_root(scope: &str, config: &fluxheim_config::PhpConfig) -> io::Result<PathBuf> {
    let configured_root = config.root.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{scope}: enabled PHP requires php.root"),
        )
    })?;
    let root_metadata = std::fs::symlink_metadata(configured_root).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("{scope}: php root {}: {error}", configured_root.display()),
        )
    })?;
    if root_metadata.file_type().is_symlink() && !config.resolve_root_symlink {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{scope}: php root is not a real directory: {}",
                configured_root.display()
            ),
        ));
    }
    if !root_metadata.file_type().is_symlink() && !root_metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{scope}: php root is not a real directory: {}",
                configured_root.display()
            ),
        ));
    }
    let root = configured_root.canonicalize().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("{scope}: php root {}: {error}", configured_root.display()),
        )
    })?;
    let resolved_metadata = std::fs::metadata(&root).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("{scope}: php root {}: {error}", root.display()),
        )
    })?;
    if !resolved_metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{scope}: php root does not resolve to a directory: {}",
                configured_root.display()
            ),
        ));
    }
    Ok(root)
}

#[cfg(feature = "php-fpm")]
fn native_php_fpm_root(
    scope: &str,
    config: &fluxheim_config::PhpConfig,
    root: &Path,
) -> io::Result<PathBuf> {
    let Some(configured_fpm_root) = &config.fpm_root else {
        return Ok(root.to_path_buf());
    };
    match configured_fpm_root.canonicalize() {
        Ok(resolved) => Ok(resolved),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(configured_fpm_root.clone()),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!(
                "{scope}: php fpm_root {}: {error}",
                configured_fpm_root.display()
            ),
        )),
    }
}

#[cfg(feature = "php-fpm")]
fn native_php_method_allowed(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "POST")
}

#[cfg(feature = "php-fpm")]
fn native_php_server_port(
    config: &fluxheim_config::PhpConfig,
    request: &NativeHttp1Request,
) -> String {
    config
        .server_port
        .or_else(|| native_php_request_host(request).and_then(native_php_explicit_authority_port))
        .unwrap_or(if request.downstream_tls { 443 } else { 80 })
        .to_string()
}

#[cfg(feature = "php-fpm")]
fn native_php_request_host(request: &NativeHttp1Request) -> Option<&str> {
    request.headers.iter().find_map(|(name, value)| {
        name.eq_ignore_ascii_case("host")
            .then_some(value.trim())
            .filter(|value| !value.is_empty())
    })
}

#[cfg(feature = "php-fpm")]
fn native_php_explicit_authority_port(authority: &str) -> Option<u16> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (_, after_host) = rest.split_once(']')?;
        return after_host.strip_prefix(':')?.parse().ok();
    }
    let (_, port) = authority.rsplit_once(':')?;
    port.parse().ok()
}

fn native_cache_policy_enabled(cache: &fluxheim_config::CacheConfig) -> bool {
    cache.enabled || cache.local_static
}

fn native_vhost_cache_policy_blocked(vhost: &fluxheim_config::VhostConfig) -> bool {
    if !native_cache_policy_enabled(&vhost.cache) {
        return false;
    }
    !vhost_native_cache_supported(vhost)
}

fn native_route_cache_policy_blocked(route: &fluxheim_config::RouteConfig) -> bool {
    route.cache.as_ref().is_some_and(|cache| {
        if !native_cache_policy_enabled(cache) {
            return false;
        }
        !route_native_cache_supported(route, cache)
    })
}

fn root_native_cache_supported(config: &fluxheim_config::Config) -> bool {
    (config.web.enabled() && NativeHttp1StaticWeb::cache_supported(&config.cache))
        || (config.proxy.has_configured_upstream()
            && NativeHttp1Proxy::proxy_cache_supported_for_proxy(&config.cache, &config.proxy))
}

fn vhost_native_cache_supported(vhost: &fluxheim_config::VhostConfig) -> bool {
    (vhost.web.enabled() && NativeHttp1StaticWeb::cache_supported(&vhost.cache))
        || (vhost.proxy.has_configured_upstream()
            && NativeHttp1Proxy::proxy_cache_supported_for_proxy(&vhost.cache, &vhost.proxy))
}

fn route_native_cache_supported(
    route: &fluxheim_config::RouteConfig,
    cache: &fluxheim_config::CacheConfig,
) -> bool {
    route
        .web
        .as_ref()
        .is_some_and(|web| web.enabled() && NativeHttp1StaticWeb::cache_supported(cache))
        || route.proxy.as_ref().is_some_and(|proxy| {
            proxy.has_configured_upstream()
                && NativeHttp1Proxy::proxy_cache_supported_for_proxy(cache, proxy)
        })
}

impl NativeHttp1Handler for NativeHttp1RouteProxy {
    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp1Response> + Send + 'a>> {
        Box::pin(async move {
            let Some((path, query)) = request_path_and_query(&request) else {
                return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                    .close_connection();
            };
            let selected_route = self.select_route(&request.method, &path);
            let decoded_policy_route = self.select_decoded_policy_route(&request.method, &path);
            if selected_route.is_none()
                && self.fallback_web.is_none()
                && self.fallback.is_none()
                && {
                    #[cfg(feature = "php-fpm")]
                    {
                        self.fallback_php.is_none()
                    }
                    #[cfg(not(feature = "php-fpm"))]
                    {
                        true
                    }
                }
            {
                return NativeHttp1Response::new(404, "Not Found", b"not found\n")
                    .close_connection();
            }
            let client_ip = self.access_client_ip(&request);
            let tls_identity = request.tls_identity.as_ref();
            let geo_context = request.geo_context.as_ref();
            if !self.access.allows(client_ip, tls_identity, geo_context)
                || selected_route
                    .is_some_and(|route| !route.access.allows(client_ip, tls_identity, geo_context))
                || decoded_policy_route
                    .is_some_and(|route| !route.access.allows(client_ip, tls_identity, geo_context))
            {
                return NativeHttp1Response::new(403, "Forbidden", b"forbidden\n")
                    .close_connection();
            }
            if let Some(response) = self.https_redirect_response(&request, selected_route) {
                return response;
            }
            let concurrency_route = decoded_policy_route.or(selected_route);
            // Delay-mode rate limiting sleeps are still live downstream work.
            // Count them against concurrency so an attacker cannot park
            // unlimited delayed tasks outside the configured vhost/route cap.
            let _concurrency_permits =
                match self.acquire_concurrency_permits(concurrency_route).await {
                    Ok(permits) => permits,
                    Err(status) => {
                        return NativeHttp1Response::new(
                            status,
                            "Too Many Requests",
                            b"too many requests\n",
                        )
                        .close_connection();
                    }
                };
            match self.check_rate_limits(concurrency_route, client_ip) {
                NativeRateLimitDecision::Allow => {}
                NativeRateLimitDecision::Delay(delay) => {
                    tokio::time::sleep(delay).await;
                }
                NativeRateLimitDecision::Reject(status) => {
                    return NativeHttp1Response::new(
                        status,
                        "Too Many Requests",
                        b"rate limited\n",
                    )
                    .close_connection();
                }
            }
            if let Some(route) = selected_route {
                if let Some(response) = native_grpc_rejection_response(&route.grpc, &request) {
                    return response;
                }
                let mut request =
                    match rewrite_route_request(request, route, &path, query.as_deref()) {
                        Some(request) => request,
                        None => {
                            return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                                .close_connection();
                        }
                    };
                if route
                    .max_request_body_bytes
                    .or(self.max_request_body_bytes)
                    .is_some_and(|limit| (request.body.len() as u64) > limit)
                {
                    return NativeHttp1Response::new(
                        413,
                        "Payload Too Large",
                        b"payload too large\n",
                    )
                    .close_connection();
                }
                let header_context = NativeRequestHeaderTemplateContext::from_route(route, &path);
                route
                    .request_headers
                    .apply(&mut request, Some(&header_context));
                return route.handle(request).await;
            }
            if let Some(response) = self.fallback_web_response(&request, &path) {
                return response;
            }
            #[cfg(feature = "php-fpm")]
            if let Some(php) = &self.fallback_php {
                return php.handle(request).await;
            }
            if let Some(proxy) = &self.fallback {
                return proxy.handle(request).await;
            }
            NativeHttp1Response::new(404, "Not Found", b"not found\n").close_connection()
        })
    }

    fn request_body_timeout(&self, request: &NativeHttp1Request) -> Option<Duration> {
        let (path, _) = request_path_and_query(request)?;
        if let Some(route) = self.select_route(&request.method, &path) {
            return route.request_body_timeout();
        }
        #[cfg(feature = "php-fpm")]
        if let Some(php) = &self.fallback_php {
            return Some(Duration::from_secs(php.config.request_timeout_secs));
        }
        self.fallback
            .as_ref()
            .and_then(NativeHttp1Proxy::request_body_timeout)
    }

    fn handles_connection_takeover(&self, request: &NativeHttp1Request) -> bool {
        let Some((path, _)) = request_path_and_query(request) else {
            return false;
        };
        if let Some(route) = self.select_route(&request.method, &path) {
            return route.handles_connection_takeover(request);
        }
        self.fallback
            .as_ref()
            .is_some_and(|proxy| proxy.handles_connection_takeover(request))
    }

    fn handle_connection_takeover<'a>(
        &'a self,
        request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        stream: NativeHttp1ConnectionStream,
    ) -> Pin<Box<dyn Future<Output = Result<(), NativeHttp1Error>> + Send + 'a>> {
        Box::pin(async move {
            self.handle_connection_takeover_inner(request, prebuffered, stream)
                .await
        })
    }
}

impl NativeHttp1RouteProxy {
    fn https_redirect_response(
        &self,
        request: &NativeHttp1Request,
        selected_route: Option<&NativeHttp1RouteProxyRoute>,
    ) -> Option<NativeHttp1Response> {
        if !self.https_redirect.enabled || request.downstream_tls {
            return None;
        }
        if selected_route.is_some_and(NativeHttp1RouteProxyRoute::https_redirect_exempt_or_redirect)
        {
            return None;
        }
        let Some(location) = https_redirect_location(request, &self.https_redirect) else {
            return Some(
                NativeHttp1Response::new(400, "Bad Request", b"missing or invalid host\n")
                    .close_connection(),
            );
        };
        let mut response = NativeHttp1Response::new(
            self.https_redirect.status,
            redirect_reason(self.https_redirect.status),
            Vec::new(),
        )
        .with_header("location", location)
        .with_header("content-length", "0");
        self.fallback_response_headers.apply(&mut response);
        Some(response)
    }
}

impl NativeHttp1RouteProxy {
    async fn handle_connection_takeover_inner(
        &self,
        request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        mut stream: NativeHttp1ConnectionStream,
    ) -> Result<(), NativeHttp1Error> {
        let Some((path, query)) = request_path_and_query(&request) else {
            return write_takeover_rejection(&mut stream, 400, "Bad Request", b"bad request\n")
                .await;
        };
        let selected_route = self.select_route(&request.method, &path);
        let decoded_policy_route = self.select_decoded_policy_route(&request.method, &path);
        if selected_route.is_none() && self.fallback.is_none() && {
            #[cfg(feature = "php-fpm")]
            {
                self.fallback_php.is_none()
            }
            #[cfg(not(feature = "php-fpm"))]
            {
                true
            }
        } {
            return write_takeover_rejection(&mut stream, 404, "Not Found", b"not found\n").await;
        }
        let client_ip = self.access_client_ip(&request);
        let tls_identity = request.tls_identity.as_ref();
        let geo_context = request.geo_context.as_ref();
        if !self.access.allows(client_ip, tls_identity, geo_context)
            || selected_route
                .is_some_and(|route| !route.access.allows(client_ip, tls_identity, geo_context))
            || decoded_policy_route
                .is_some_and(|route| !route.access.allows(client_ip, tls_identity, geo_context))
        {
            return write_takeover_rejection(&mut stream, 403, "Forbidden", b"forbidden\n").await;
        }
        let concurrency_route = decoded_policy_route.or(selected_route);
        let concurrency_permits = match self.acquire_concurrency_permits(concurrency_route).await {
            Ok(permits) => permits,
            Err(status) => {
                return write_takeover_rejection(
                    &mut stream,
                    status,
                    "Too Many Requests",
                    b"too many requests\n",
                )
                .await;
            }
        };
        match self.check_rate_limits(concurrency_route, client_ip) {
            NativeRateLimitDecision::Allow => {}
            NativeRateLimitDecision::Delay(delay) => tokio::time::sleep(delay).await,
            NativeRateLimitDecision::Reject(status) => {
                return write_takeover_rejection(
                    &mut stream,
                    status,
                    "Too Many Requests",
                    b"rate limited\n",
                )
                .await;
            }
        }
        drop(concurrency_permits);
        if let Some(route) = selected_route {
            let mut request = match rewrite_route_request(request, route, &path, query.as_deref()) {
                Some(request) => request,
                None => {
                    return write_takeover_rejection(
                        &mut stream,
                        400,
                        "Bad Request",
                        b"bad request\n",
                    )
                    .await;
                }
            };
            if route
                .max_request_body_bytes
                .or(self.max_request_body_bytes)
                .is_some_and(|limit| (request.body.len() as u64) > limit)
            {
                return write_takeover_rejection(
                    &mut stream,
                    413,
                    "Payload Too Large",
                    b"payload too large\n",
                )
                .await;
            }
            let header_context = NativeRequestHeaderTemplateContext::from_route(route, &path);
            route
                .request_headers
                .apply(&mut request, Some(&header_context));
            return route
                .handle_connection_takeover(request, prebuffered, stream)
                .await;
        }
        if let Some(proxy) = &self.fallback {
            return proxy
                .handle_connection_takeover(request, prebuffered, stream)
                .await;
        }
        #[cfg(feature = "php-fpm")]
        if self.fallback_php.is_some() {
            return write_takeover_rejection(
                &mut stream,
                400,
                "Bad Request",
                b"unsupported upgrade target\n",
            )
            .await;
        }
        write_takeover_rejection(&mut stream, 404, "Not Found", b"not found\n").await
    }

    fn fallback_web_response(
        &self,
        request: &NativeHttp1Request,
        path: &str,
    ) -> Option<NativeHttp1Response> {
        let web = self.fallback_web.as_ref()?;
        let mut response = web.handle_optional(request, path)?;
        self.fallback_response_headers.apply(&mut response);
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        if let Some(compression) = &self.fallback_compression {
            apply_native_response_compression(request, &mut response, compression);
        }
        Some(response)
    }
}

impl NativeHttp1RouteProxy {
    fn select_route(&self, method: &str, path: &str) -> Option<&NativeHttp1RouteProxyRoute> {
        self.select_route_with_fallback(method, path, true)
    }

    fn select_decoded_policy_route(
        &self,
        method: &str,
        path: &str,
    ) -> Option<&NativeHttp1RouteProxyRoute> {
        decoded_route_policy_path(path)
            .as_deref()
            .and_then(|decoded_path| self.select_route_with_fallback(method, decoded_path, false))
    }

    fn select_route_with_fallback(
        &self,
        method: &str,
        path: &str,
        include_fallback: bool,
    ) -> Option<&NativeHttp1RouteProxyRoute> {
        let mut fallback = None;
        let mut best_prefix = None;
        let mut first_regex = None;
        for route in &self.routes {
            if !route_method_matches(&route.methods, method) {
                continue;
            }
            match &route.matcher {
                NativeHttp1RouteMatcher::Exact(exact) if path == exact => return Some(route),
                NativeHttp1RouteMatcher::Prefix(prefix)
                    if route_prefix_matches_path(prefix, path) =>
                {
                    if best_prefix
                        .map(|best: &NativeHttp1RouteProxyRoute| {
                            route.prefix_len() > best.prefix_len()
                        })
                        .unwrap_or(true)
                    {
                        best_prefix = Some(route);
                    }
                }
                NativeHttp1RouteMatcher::Regex(regex)
                    if first_regex.is_none() && regex.is_match(path) =>
                {
                    first_regex = Some(route);
                }
                NativeHttp1RouteMatcher::Fallback if include_fallback => fallback = Some(route),
                _ => {}
            }
        }
        best_prefix.or(first_regex).or(fallback)
    }

    fn access_client_ip(&self, request: &NativeHttp1Request) -> Option<IpAddr> {
        if let Some(addr) = request.effective_client_addr {
            return Some(addr.ip());
        }
        let direct_ip = request.peer_addr.map(|addr| addr.ip());
        #[cfg(not(feature = "privacy-mode"))]
        {
            let original_x_forwarded_for = joined_header_value(request, "x-forwarded-for");
            let trusted_direct_peer = direct_ip.is_some_and(|ip| self.trusted_source_contains(ip));
            let trusted_proxy_matcher = |ip| self.trusted_source_contains(ip);
            direct_ip.map(|ip| {
                effective_client_ip(
                    ip,
                    trusted_direct_peer,
                    original_x_forwarded_for.as_deref(),
                    Some(&trusted_proxy_matcher),
                )
            })
        }
        #[cfg(feature = "privacy-mode")]
        {
            direct_ip
        }
    }

    #[cfg(not(feature = "privacy-mode"))]
    fn trusted_source_contains(&self, address: IpAddr) -> bool {
        self.trusted_sources
            .iter()
            .any(|source| source.contains(address))
    }

    fn check_rate_limits(
        &self,
        route: Option<&NativeHttp1RouteProxyRoute>,
        client_ip: Option<IpAddr>,
    ) -> NativeRateLimitDecision {
        let mut delay = None;
        match self.rate_limit.check(client_ip) {
            NativeRateLimitDecision::Allow => {}
            NativeRateLimitDecision::Delay(vhost_delay) => delay = Some(vhost_delay),
            decision => return decision,
        }
        if let Some(route) = route {
            match route.rate_limit.check(client_ip) {
                NativeRateLimitDecision::Allow => {}
                NativeRateLimitDecision::Delay(route_delay) => {
                    delay = Some(
                        delay.map_or(route_delay, |current: Duration| current.max(route_delay)),
                    );
                }
                decision => return decision,
            }
        }

        delay
            .map(NativeRateLimitDecision::Delay)
            .unwrap_or(NativeRateLimitDecision::Allow)
    }

    async fn acquire_concurrency_permits(
        &self,
        route: Option<&NativeHttp1RouteProxyRoute>,
    ) -> Result<Vec<NativeConcurrencyPermit>, u16> {
        let mut permits = Vec::with_capacity(2);
        if let Some(permit) = self.concurrency.acquire().await? {
            permits.push(permit);
        }
        if let Some(route) = route
            && let Some(permit) = route.concurrency.acquire().await?
        {
            permits.push(permit);
        }
        Ok(permits)
    }
}

fn decoded_route_policy_path(path: &str) -> Option<String> {
    // One decode pass mirrors the compatibility access-policy path check. This
    // catches ordinary encoded route aliases such as /%61dmin while avoiding a
    // second, independent route-normalization model for double-encoded input.
    if !path.as_bytes().contains(&b'%') {
        return None;
    }
    let decoded = percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .ok()?;
    if decoded == path || decoded.contains('\0') || !decoded.starts_with('/') {
        return None;
    }
    Some(decoded.into_owned())
}

fn native_grpc_rejection_response(
    grpc: &GrpcRouteConfig,
    request: &NativeHttp1Request,
) -> Option<NativeHttp1Response> {
    if !grpc.enabled {
        return None;
    }
    if request.method != "POST" {
        return Some(
            NativeHttp1Response::new(405, "Method Not Allowed", b"method not allowed\n")
                .with_header("Allow", "POST")
                .with_header("grpc-status", "12")
                .with_header("grpc-message", "method not allowed; gRPC requires POST")
                .close_connection(),
        );
    }
    if grpc.require_content_type {
        let mut content_types = native_request_header_values(request, "content-type");
        let Some(content_type) = content_types.next() else {
            return Some(native_grpc_unsupported_media_type_response());
        };
        if content_types.next().is_some() || !native_grpc_content_type(content_type) {
            return Some(native_grpc_unsupported_media_type_response());
        }
    }
    None
}

fn native_grpc_unsupported_media_type_response() -> NativeHttp1Response {
    NativeHttp1Response::new(415, "Unsupported Media Type", b"unsupported media type\n")
        .with_header("grpc-status", "3")
        .with_header("grpc-message", "content-type must be application/grpc")
        .close_connection()
}

fn native_grpc_content_type(value: &str) -> bool {
    let media_type = value
        .split_once(';')
        .map(|(media_type, _)| media_type)
        .unwrap_or(value)
        .trim();
    media_type.eq_ignore_ascii_case("application/grpc")
        || media_type
            .get(.."application/grpc+".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("application/grpc+"))
}

fn native_request_header_values<'a>(
    request: &'a NativeHttp1Request,
    name: &'a str,
) -> impl Iterator<Item = &'a str> {
    request
        .headers
        .iter()
        .filter(move |(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

impl NativeHttp1RouteProxyRoute {
    fn request_body_timeout(&self) -> Option<Duration> {
        match &self.action {
            #[cfg(feature = "acme")]
            NativeHttp1RouteAction::AcmeHttp01(_) => None,
            NativeHttp1RouteAction::Proxy(proxy) => proxy.request_body_timeout(),
            #[cfg(feature = "php-fpm")]
            NativeHttp1RouteAction::PhpFpm(php) => {
                Some(Duration::from_secs(php.config.request_timeout_secs))
            }
            NativeHttp1RouteAction::Redirect(_) | NativeHttp1RouteAction::StaticWeb(_) => None,
        }
    }

    fn prefix_len(&self) -> usize {
        match &self.matcher {
            NativeHttp1RouteMatcher::Prefix(prefix) => prefix.len(),
            _ => 0,
        }
    }

    async fn handle(&self, request: NativeHttp1Request) -> NativeHttp1Response {
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        let compression_request = self.compression.as_ref().map(|_| request.clone());
        let mut response = match &self.action {
            #[cfg(feature = "acme")]
            NativeHttp1RouteAction::AcmeHttp01(store) => {
                native_acme_http_01_response(&request, store).await
            }
            NativeHttp1RouteAction::Proxy(proxy) => proxy.handle(request).await,
            #[cfg(feature = "php-fpm")]
            NativeHttp1RouteAction::PhpFpm(php) => php.handle(request).await,
            NativeHttp1RouteAction::Redirect(redirect) => redirect_response(&request, redirect),
            NativeHttp1RouteAction::StaticWeb(web) => {
                let Some((path, _)) = request_path_and_query(&request) else {
                    return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                        .close_connection();
                };
                web.handle(&request, &path)
            }
        };
        self.response_headers.apply(&mut response);
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        if let Some(compression) = &self.compression
            && let Some(compression_request) = compression_request.as_ref()
        {
            apply_route_compression(compression_request, &mut response, compression);
        }
        response
    }

    fn handles_connection_takeover(&self, request: &NativeHttp1Request) -> bool {
        match &self.action {
            NativeHttp1RouteAction::Proxy(proxy) => proxy.handles_connection_takeover(request),
            #[cfg(feature = "acme")]
            NativeHttp1RouteAction::AcmeHttp01(_) => false,
            #[cfg(feature = "php-fpm")]
            NativeHttp1RouteAction::PhpFpm(_) => false,
            NativeHttp1RouteAction::Redirect(_) | NativeHttp1RouteAction::StaticWeb(_) => false,
        }
    }

    async fn handle_connection_takeover(
        &self,
        request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        stream: NativeHttp1ConnectionStream,
    ) -> Result<(), NativeHttp1Error> {
        match &self.action {
            NativeHttp1RouteAction::Proxy(proxy) => {
                proxy
                    .handle_connection_takeover(request, prebuffered, stream)
                    .await
            }
            #[cfg(feature = "acme")]
            NativeHttp1RouteAction::AcmeHttp01(_) => {
                let mut stream = stream;
                write_takeover_rejection(
                    &mut stream,
                    400,
                    "Bad Request",
                    b"unsupported upgrade target\n",
                )
                .await
            }
            #[cfg(feature = "php-fpm")]
            NativeHttp1RouteAction::PhpFpm(_) => {
                let mut stream = stream;
                write_takeover_rejection(
                    &mut stream,
                    400,
                    "Bad Request",
                    b"unsupported upgrade target\n",
                )
                .await
            }
            NativeHttp1RouteAction::Redirect(_) | NativeHttp1RouteAction::StaticWeb(_) => {
                let mut stream = stream;
                write_takeover_rejection(
                    &mut stream,
                    400,
                    "Bad Request",
                    b"unsupported upgrade target\n",
                )
                .await
            }
        }
    }
}

async fn write_takeover_rejection<S>(
    stream: &mut S,
    status: u16,
    reason: &str,
    body: &[u8],
) -> Result<(), NativeHttp1Error>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status} {reason}\r\n\
                 Connection: close\r\n\
                 Content-Length: {}\r\n\
                 Content-Type: text/plain\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(feature = "acme")]
async fn native_acme_http_01_response(
    request: &NativeHttp1Request,
    store: &NativeHttp1AcmeHttp01Store,
) -> NativeHttp1Response {
    if request.method != "GET" && request.method != "HEAD" {
        return NativeHttp1Response::new(405, "Method Not Allowed", Vec::new())
            .with_header("Allow", "GET, HEAD")
            .with_content_length(0);
    }

    let Some((path, _)) = request_path_and_query(request) else {
        return NativeHttp1Response::new(400, "Bad Request", b"bad request\n").close_connection();
    };
    let Some(token) = http_01_token_from_path(&path).map(str::to_owned) else {
        return NativeHttp1Response::new(404, "Not Found", b"not found\n").close_connection();
    };

    let store = store.clone();
    let key_authorization =
        match tokio::task::spawn_blocking(move || store.load_key_authorization(&token)).await {
            Ok(Ok(Some(value))) => value,
            Ok(Ok(None)) => {
                return NativeHttp1Response::new(404, "Not Found", b"not found\n")
                    .close_connection();
            }
            Ok(Err(error)) => {
                log::error!("failed to load ACME HTTP-01 challenge token: {error}");
                return NativeHttp1Response::new(
                    500,
                    "Internal Server Error",
                    b"internal server error\n",
                )
                .close_connection();
            }
            Err(error) => {
                log::error!("ACME HTTP-01 challenge token loader failed: {error}");
                return NativeHttp1Response::new(
                    500,
                    "Internal Server Error",
                    b"internal server error\n",
                )
                .close_connection();
            }
        };

    let content_length = key_authorization.len() as u64;
    let body = if request.method == "HEAD" {
        Vec::new()
    } else {
        key_authorization.into_bytes()
    };

    NativeHttp1Response::new(200, "OK", body)
        .with_header("content-type", "text/plain")
        .with_header("cache-control", "no-store")
        .with_content_length(content_length)
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn apply_route_compression(
    request: &NativeHttp1Request,
    response: &mut NativeHttp1Response,
    config: &fluxheim_config::CompressionConfig,
) {
    apply_native_response_compression(request, response, config);
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
pub(crate) fn apply_native_response_compression(
    request: &NativeHttp1Request,
    response: &mut NativeHttp1Response,
    config: &fluxheim_config::CompressionConfig,
) {
    let Some(mut encoder) = selected_route_compression(request, response, config) else {
        return;
    };
    let input = Bytes::copy_from_slice(response.body());
    match encoder.encode_chunk(Some(&input), true) {
        Ok(encoded) => {
            response.remove_header("content-encoding");
            response.remove_header("content-length");
            response.remove_header("etag");
            response.push_header("content-encoding", encoder.encoding);
            append_vary_accept_encoding(response);
            response.replace_body(encoded.to_vec());
        }
        Err(error) => {
            log::debug!(
                target: "fluxheim::native",
                "native route response compression skipped: {error}"
            );
        }
    }
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn selected_route_compression(
    request: &NativeHttp1Request,
    response: &NativeHttp1Response,
    config: &fluxheim_config::CompressionConfig,
) -> Option<ResponseCompressionEncoder> {
    if !(config.enabled
        && request.method == "GET"
        && response.status() == 200
        && !response_has_content_encoding(response)
        && !response_has_header(response, "content-range")
        && !response_has_header(response, "set-cookie")
        && !request_has_header(request, "authorization")
        && !request_has_header(request, "cookie")
        && !response_cache_control_blocks_compression(response)
        && response_content_type_is_compressible(response)
        && response_content_length_in_compression_bounds(response, config))
    {
        return None;
    }

    let mut candidates = Vec::new();
    #[cfg(feature = "compression-brotli")]
    if config.brotli
        && let Some(quality) = request_accept_encoding_quality(request, "br")
    {
        candidates.push((quality, 0u8, "br"));
    }
    #[cfg(feature = "compression-zstd")]
    if config.zstd
        && let Some(quality) = request_accept_encoding_quality(request, "zstd")
    {
        candidates.push((quality, 1u8, "zstd"));
    }
    #[cfg(feature = "compression-gzip")]
    if config.gzip
        && let Some(quality) = request_accept_encoding_quality(request, "gzip")
    {
        candidates.push((quality, 2u8, "gzip"));
    }
    candidates.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));

    for (_, _, encoding) in candidates {
        if let Some(encoder) = route_compression_encoder(encoding, config) {
            return Some(encoder);
        }
    }

    None
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn route_compression_encoder(
    encoding: &str,
    config: &fluxheim_config::CompressionConfig,
) -> Option<ResponseCompressionEncoder> {
    match encoding {
        #[cfg(feature = "compression-brotli")]
        "br" => Some(ResponseCompressionEncoder::brotli(
            config.brotli_quality,
            compression_max_output_bytes(config),
        )),
        #[cfg(feature = "compression-zstd")]
        "zstd" => ResponseCompressionEncoder::zstd(
            config.zstd_level,
            compression_max_output_bytes(config),
        )
        .ok(),
        #[cfg(feature = "compression-gzip")]
        "gzip" => Some(ResponseCompressionEncoder::gzip(
            config.gzip_level,
            compression_max_output_bytes(config),
        )),
        _ => None,
    }
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn compression_max_output_bytes(config: &fluxheim_config::CompressionConfig) -> usize {
    usize::try_from(config.max_output_bytes.as_u64()).unwrap_or(usize::MAX)
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn request_accept_encoding_quality(request: &NativeHttp1Request, expected: &str) -> Option<u16> {
    let mut wildcard_quality = None;
    for token in request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
        .flat_map(|(_, value)| value.split(','))
    {
        let Some((coding, quality)) = accept_encoding_token_quality(token) else {
            continue;
        };
        if coding.eq_ignore_ascii_case(expected) {
            return (quality > 0).then_some(quality);
        }
        if coding == "*" && quality > 0 {
            wildcard_quality = Some(wildcard_quality.unwrap_or(0).max(quality));
        }
    }
    wildcard_quality
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn accept_encoding_token_quality(token: &str) -> Option<(&str, u16)> {
    let mut parts = token.split(';');
    let coding = parts.next().unwrap_or_default().trim();
    if coding.is_empty() {
        return None;
    }
    let mut quality = 1000u16;
    for (name, value) in parts
        .map(str::trim)
        .filter_map(|parameter| parameter.split_once('='))
    {
        if !name.trim().eq_ignore_ascii_case("q") {
            continue;
        }
        quality = parse_accept_encoding_qvalue(value.trim())?;
        break;
    }
    Some((coding, quality))
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn response_has_content_encoding(response: &NativeHttp1Response) -> bool {
    response
        .headers()
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .any(|(_, value)| content_encoding_value_is_active(value))
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn request_has_header(request: &NativeHttp1Request, name: &str) -> bool {
    request
        .headers
        .iter()
        .any(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn response_has_header(response: &NativeHttp1Response, name: &str) -> bool {
    response
        .headers()
        .iter()
        .any(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn response_cache_control_blocks_compression(response: &NativeHttp1Response) -> bool {
    response
        .headers()
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("cache-control"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .any(cache_control_directive_blocks_compression)
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn response_content_type_is_compressible(response: &NativeHttp1Response) -> bool {
    response
        .headers()
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .is_some_and(|(_, value)| content_type_is_compressible(value))
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn response_content_length_in_compression_bounds(
    response: &NativeHttp1Response,
    config: &fluxheim_config::CompressionConfig,
) -> bool {
    let length = response
        .content_length()
        .unwrap_or_else(|| response.body().len() as u64);
    input_length_within_compression_bounds(
        length,
        config.min_bytes.as_u64(),
        config.max_input_bytes.as_u64(),
    )
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn append_vary_accept_encoding(response: &mut NativeHttp1Response) {
    let has_accept_encoding = response
        .headers()
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("vary"))
        .flat_map(|(_, value)| value.split(','))
        .any(|field| field.trim().eq_ignore_ascii_case("accept-encoding"));
    if !has_accept_encoding {
        response.push_header("vary", "accept-encoding");
    }
}

fn request_path_and_query(request: &NativeHttp1Request) -> Option<(String, Option<String>)> {
    match http1_request_target(&request.method, &request.target).ok()? {
        Http1RequestTarget::Origin { path, query, .. } => {
            Some((path.to_owned(), query.map(str::to_owned)))
        }
        Http1RequestTarget::AbsoluteUri { path, query, .. } => {
            Some((path.unwrap_or("/").to_owned(), query.map(str::to_owned)))
        }
        Http1RequestTarget::Authority { .. } | Http1RequestTarget::Asterisk => None,
    }
}

fn rewrite_route_request(
    mut request: NativeHttp1Request,
    route: &NativeHttp1RouteProxyRoute,
    path: &str,
    query: Option<&str>,
) -> Option<NativeHttp1Request> {
    if let Some(template) = route.rewrite_template.as_deref() {
        let rewritten_path = route_rewrite_template_path(path, &route.matcher, template)?;
        if !safe_forward_path(&rewritten_path) {
            return None;
        }
        request.target = query
            .map(|query| format!("{rewritten_path}?{query}"))
            .unwrap_or(rewritten_path);
        return Some(request);
    }

    let Some(strip_prefix) = route.strip_prefix.as_deref() else {
        return Some(request);
    };
    let suffix = route_strip_prefix_suffix(strip_prefix, path)?;
    let rewritten_path = if let Some(rewrite_prefix) = route.rewrite_prefix.as_deref() {
        join_route_rewrite_prefix(rewrite_prefix, suffix)?
    } else if suffix.is_empty() {
        "/".to_owned()
    } else if suffix.starts_with('/') {
        suffix.to_owned()
    } else {
        format!("/{suffix}")
    };
    if !safe_forward_path(&rewritten_path) {
        return None;
    }
    request.target = query
        .map(|query| format!("{rewritten_path}?{query}"))
        .unwrap_or(rewritten_path);
    Some(request)
}

fn route_rewrite_template_path(
    path: &str,
    matcher: &NativeHttp1RouteMatcher,
    template: &str,
) -> Option<String> {
    let NativeHttp1RouteMatcher::Regex(regex_matcher) = matcher else {
        return None;
    };
    let captures = regex_matcher.regex.captures(path)?;
    let mut rewritten = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        rewritten.push_str(&rest[..open]);
        let after_open = &rest[open + 1..];
        let close = after_open.find('}')?;
        let variable = &after_open[..close];
        if let Some(value) = route_regex_capture_value(&regex_matcher.regex, &captures, variable) {
            append_route_regex_capture_value(&mut rewritten, value);
        }
        rest = &after_open[close + 1..];
    }
    rewritten.push_str(rest);
    if rewritten.contains('{') || rewritten.contains('}') {
        return None;
    }
    Some(rewritten)
}

fn route_regex_header_captures(
    path: &str,
    matcher: &NativeHttp1RouteMatcher,
) -> Vec<(String, String)> {
    let NativeHttp1RouteMatcher::Regex(regex_matcher) = matcher else {
        return Vec::new();
    };
    let Some(captures) = regex_matcher.regex.captures(path) else {
        return Vec::new();
    };
    let mut values = Vec::new();
    for index in 1..captures.len() {
        if let Some(value) = captures.get(index) {
            values.push((format!("route.regex.{index}"), value.as_str().to_owned()));
        }
    }
    for name in regex_matcher.regex.capture_names().flatten() {
        if let Some(value) = captures.name(name) {
            values.push((format!("route.regex.{name}"), value.as_str().to_owned()));
        }
    }
    values
}

fn route_regex_capture_value<'a>(
    regex: &regex::Regex,
    captures: &'a regex::Captures<'a>,
    variable: &str,
) -> Option<&'a str> {
    let key = variable.strip_prefix("route.regex.")?;
    let value = if key.bytes().all(|byte| byte.is_ascii_digit()) {
        let index = key.parse::<usize>().ok()?;
        if index >= MAX_ROUTE_REGEX_CAPTURE_VALUES {
            return None;
        }
        captures.get(index)?.as_str()
    } else {
        let index = regex
            .capture_names()
            .enumerate()
            .take(MAX_ROUTE_REGEX_CAPTURE_VALUES)
            .find_map(|(index, name)| (name == Some(key)).then_some(index))?;
        captures.get(index)?.as_str()
    };
    (value.len() <= MAX_ROUTE_REGEX_CAPTURE_VALUE_BYTES).then_some(value)
}

fn append_route_regex_capture_value(rewritten: &mut String, value: &str) {
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            rewritten.push(char::from(byte));
        } else {
            static HEX: &[u8; 16] = b"0123456789ABCDEF";
            rewritten.push('%');
            rewritten.push(char::from(HEX[usize::from(byte >> 4)]));
            rewritten.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
}

fn join_route_rewrite_prefix(rewrite_prefix: &str, suffix: &str) -> Option<String> {
    if rewrite_prefix == "/" {
        return Some(if suffix.is_empty() {
            "/".to_owned()
        } else if suffix.starts_with('/') {
            suffix.to_owned()
        } else {
            format!("/{suffix}")
        });
    }

    let rewritten_path = if suffix.is_empty() {
        rewrite_prefix.to_owned()
    } else if rewrite_prefix.ends_with('/') && suffix.starts_with('/') {
        format!("{}{}", rewrite_prefix, &suffix[1..])
    } else if rewrite_prefix.ends_with('/') || suffix.starts_with('/') {
        format!("{rewrite_prefix}{suffix}")
    } else {
        format!("{rewrite_prefix}/{suffix}")
    };

    safe_forward_path(&rewritten_path).then_some(rewritten_path)
}

fn redirect_response(
    request: &NativeHttp1Request,
    redirect: &NativeHttp1RouteRedirect,
) -> NativeHttp1Response {
    let Some(location) = route_redirect_location(request, redirect) else {
        return NativeHttp1Response::new(400, "Bad Request", b"invalid redirect target\n")
            .close_connection();
    };
    NativeHttp1Response::new(
        redirect.status,
        redirect_reason(redirect.status),
        Vec::new(),
    )
    .with_header("location", location)
}

fn redirect_reason(status: u16) -> &'static str {
    match status {
        301 => "Moved Permanently",
        302 => "Found",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        _ => "Redirect",
    }
}

fn https_redirect_location(
    request: &NativeHttp1Request,
    config: &HttpsRedirectConfig,
) -> Option<String> {
    let host = request_header_value(request, "host")?;
    let normalized_host = normalize_host(host)?;
    let authority = redirect_authority(&normalized_host, config.target_port)?;
    let target = request.target.as_str();
    if !target.starts_with('/') || target.chars().any(char::is_control) {
        return None;
    }
    Some(format!("https://{authority}{target}"))
}

fn redirect_authority(host: &str, target_port: Option<u16>) -> Option<String> {
    let host = if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    };

    match target_port {
        Some(443) | None => Some(host),
        Some(0) => None,
        Some(port) => Some(format!("{host}:{port}")),
    }
}

fn route_redirect_location(
    request: &NativeHttp1Request,
    redirect: &NativeHttp1RouteRedirect,
) -> Option<String> {
    let (path, query) = request_path_and_query(request)?;
    let uri = query
        .as_deref()
        .map(|query| format!("{path}?{query}"))
        .unwrap_or_else(|| path.clone());
    if !safe_forward_path(&path) || uri.chars().any(char::is_control) {
        return None;
    }
    if redirect_template_substitutes_query_into_path(&redirect.to)
        && !redirect_query_path_expansion_safe(query.as_deref().unwrap_or_default())
    {
        return None;
    }

    let location = redirect
        .to
        .replace("{uri}", &uri)
        .replace("{path}", &path)
        .replace("{query}", query.as_deref().unwrap_or_default());
    valid_redirect_location(&location).then_some(location)
}

fn redirect_template_substitutes_query_into_path(template: &str) -> bool {
    let Some(query_token) = template.find("{query}") else {
        return false;
    };
    let query_tail = template.find(['?', '#']).unwrap_or(template.len());
    query_token < query_tail
}

fn redirect_query_path_expansion_safe(query: &str) -> bool {
    if query.is_empty() || query.chars().any(char::is_control) {
        return query.is_empty();
    }
    safe_forward_path(&format!("/{query}"))
}

fn valid_redirect_location(location: &str) -> bool {
    if !(location.starts_with("https://") || location.starts_with("http://"))
        || !redirect_location_path_safe(location)
    {
        return false;
    }
    !location.contains('{')
        && !location.contains('}')
        && !location.contains('\\')
        && !location
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn redirect_location_path_safe(location: &str) -> bool {
    let Some(rest) = location
        .strip_prefix("https://")
        .or_else(|| location.strip_prefix("http://"))
    else {
        return false;
    };
    let path_and_tail = rest
        .find('/')
        .map(|path_start| &rest[path_start..])
        .unwrap_or_default();
    let path_end = path_and_tail
        .find(['?', '#'])
        .unwrap_or(path_and_tail.len());
    let path = &path_and_tail[..path_end];
    path.is_empty() || safe_forward_path(path)
}

fn request_header_value<'a>(request: &'a NativeHttp1Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(header_name, value)| {
            header_name.eq_ignore_ascii_case(name) && !value.trim().is_empty()
        })
        .map(|(_, value)| value.trim())
}

#[cfg(not(feature = "privacy-mode"))]
fn header_value<'a>(request: &'a NativeHttp1Request, name: &str) -> Option<&'a str> {
    request_header_value(request, name)
}

#[cfg(not(feature = "privacy-mode"))]
fn joined_header_value(request: &NativeHttp1Request, name: &str) -> Option<String> {
    let mut values = request
        .headers
        .iter()
        .filter(|(header_name, value)| {
            header_name.eq_ignore_ascii_case(name) && !value.trim().is_empty()
        })
        .map(|(_, value)| value.trim());
    let first = values.next()?.to_owned();
    Some(values.fold(first, |mut joined, value| {
        joined.push_str(", ");
        joined.push_str(value);
        joined
    }))
}

fn strip_spoofable_client_ip_headers(request: &mut NativeHttp1Request) {
    request.headers.retain(|(header_name, _)| {
        !SPOOFABLE_CLIENT_IP_HEADERS
            .iter()
            .any(|blocked| header_name.eq_ignore_ascii_case(blocked))
    });
}

#[cfg(not(feature = "privacy-mode"))]
fn remove_request_header(request: &mut NativeHttp1Request, name: &str) {
    request
        .headers
        .retain(|(header_name, _)| !header_name.eq_ignore_ascii_case(name));
}

#[cfg(not(feature = "privacy-mode"))]
fn replace_request_header(
    request: &mut NativeHttp1Request,
    name: impl Into<String>,
    value: impl Into<String>,
) {
    let name = name.into();
    remove_request_header(request, &name);
    request.headers.push((name, value.into()));
}

fn render_native_request_header_template(
    value: &str,
    request: &NativeHttp1Request,
    context: Option<&NativeRequestHeaderTemplateContext>,
) -> String {
    let mut rendered = String::with_capacity(value.len());
    let mut rest = value;

    while let Some(open) = rest.find('{') {
        rendered.push_str(&rest[..open]);
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            rendered.push_str(&rest[open..]);
            return rendered;
        };
        let variable = &after_open[..close];
        if let Some(value) = native_request_header_template_variable(variable, request, context) {
            rendered.extend(value.chars().filter(|character| !character.is_control()));
        }
        rest = &after_open[close + 1..];
    }

    rendered.push_str(rest);
    rendered
}

fn native_request_header_template_variable(
    variable: &str,
    request: &NativeHttp1Request,
    context: Option<&NativeRequestHeaderTemplateContext>,
) -> Option<String> {
    if let Some(value) = context.and_then(|context| context.variable(variable)) {
        return Some(value.to_owned());
    }
    match variable {
        "host" => request_header_value(request, "host").map(str::to_owned),
        "scheme" => Some(
            if request.downstream_tls {
                "https"
            } else {
                "http"
            }
            .to_owned(),
        ),
        "uri" => Some(request.target.clone()),
        "path" => Some(
            request
                .target
                .split_once('?')
                .map(|(path, _)| path)
                .unwrap_or(request.target.as_str())
                .to_owned(),
        ),
        "query" => request
            .target
            .split_once('?')
            .map(|(_, query)| query.to_owned()),
        "request_id" => request_header_value(request, "x-request-id").map(str::to_owned),
        "tls.client_cert_sha256" => request
            .tls_identity
            .as_ref()
            .and_then(|identity| identity.cert_sha256.clone()),
        "tls.client_cert_serial" => request
            .tls_identity
            .as_ref()
            .and_then(|identity| identity.serial_number.clone()),
        "tls.version" => request
            .tls_identity
            .as_ref()
            .and_then(|identity| identity.version.clone()),
        "http.upgrade" => request_header_value(request, "upgrade").map(str::to_owned),
        #[cfg(not(feature = "privacy-mode"))]
        "remote_addr" => request
            .effective_client_addr
            .as_ref()
            .or(request.peer_addr.as_ref())
            .map(std::net::SocketAddr::ip)
            .map(|ip| ip.to_string()),
        #[cfg(feature = "privacy-mode")]
        "remote_addr" => None,
        _ => None,
    }
}

impl NativeRouteRequestHeaderPolicy {
    pub(crate) fn from_policy(policy: &RequestHeaderPolicyConfig) -> Self {
        Self {
            enabled: policy.enabled,
            strip_inbound_client_ip_headers: policy.strip_inbound_client_ip_headers,
            #[cfg(not(feature = "privacy-mode"))]
            x_forwarded_for: policy.x_forwarded_for,
            #[cfg(not(feature = "privacy-mode"))]
            x_real_ip: policy.x_real_ip,
            #[cfg(not(feature = "privacy-mode"))]
            x_forwarded_host: policy.x_forwarded_host,
            #[cfg(not(feature = "privacy-mode"))]
            x_forwarded_proto: policy.x_forwarded_proto,
            #[cfg(not(feature = "privacy-mode"))]
            forwarded: policy.forwarded,
            #[cfg(not(feature = "privacy-mode"))]
            trusted_sources: Vec::new(),
            unset: policy.effective_unset(),
            set: policy.effective_set().into_iter().collect(),
            append: flatten_append_headers(&policy.append),
        }
    }

    fn from_overlay(overlay: &fluxheim_config::RequestHeaderPolicyOverlayConfig) -> Self {
        let mut policy = Self::from_policy(&RequestHeaderPolicyConfig::default());
        if let Some(enabled) = overlay.enabled {
            policy.enabled = enabled;
        }
        if let Some(strip) = overlay.strip_inbound_client_ip_headers {
            policy.strip_inbound_client_ip_headers = strip;
        }
        #[cfg(not(feature = "privacy-mode"))]
        {
            if let Some(mode) = overlay.x_forwarded_for {
                policy.x_forwarded_for = mode;
            }
            if let Some(x_real_ip) = overlay.x_real_ip {
                policy.x_real_ip = x_real_ip;
            }
            if let Some(x_forwarded_host) = overlay.x_forwarded_host {
                policy.x_forwarded_host = x_forwarded_host;
            }
            if let Some(x_forwarded_proto) = overlay.x_forwarded_proto {
                policy.x_forwarded_proto = x_forwarded_proto;
            }
            if let Some(forwarded) = overlay.forwarded {
                policy.forwarded = forwarded;
            }
        }
        policy.unset = overlay.effective_unset();
        policy.set = overlay.effective_set().into_iter().collect();
        policy.append = flatten_append_headers(&overlay.append);
        policy
    }

    pub(crate) fn apply(
        &self,
        request: &mut NativeHttp1Request,
        context: Option<&NativeRequestHeaderTemplateContext>,
    ) {
        if !self.enabled {
            #[cfg(feature = "privacy-mode")]
            strip_spoofable_client_ip_headers(request);
            return;
        }
        #[cfg(not(feature = "privacy-mode"))]
        self.apply_forwarded_headers(request);
        for name in &self.unset {
            request
                .headers
                .retain(|(header_name, _)| !header_name.eq_ignore_ascii_case(name));
        }
        for (name, value) in &self.set {
            request
                .headers
                .retain(|(header_name, _)| !header_name.eq_ignore_ascii_case(name));
            let value = render_native_request_header_template(value, request, context);
            if !value.is_empty() {
                request.headers.push((name.clone(), value));
            }
        }
        for (name, value) in &self.append {
            let value = render_native_request_header_template(value, request, context);
            if !value.is_empty() {
                request.headers.push((name.clone(), value));
            }
        }
        #[cfg(feature = "privacy-mode")]
        strip_spoofable_client_ip_headers(request);
    }

    #[cfg(not(feature = "privacy-mode"))]
    fn apply_forwarded_headers(&self, request: &mut NativeHttp1Request) {
        let original_host = header_value(request, "host").map(str::to_owned);
        let proto = if request.downstream_tls {
            "https"
        } else {
            "http"
        };

        if self.strip_inbound_client_ip_headers {
            strip_spoofable_client_ip_headers(request);
        }

        let original_x_forwarded_for = joined_header_value(request, "x-forwarded-for");
        let listener_effective_addr = request.effective_client_addr;
        let direct_ip = request.peer_addr.map(|addr| addr.ip());
        let trusted_direct_peer = direct_ip.is_some_and(|ip| self.trusted_source_contains(ip));
        let trusted_proxy_matcher = |ip| self.trusted_source_contains(ip);
        let client_ip = listener_effective_addr.map(|addr| addr.ip()).or_else(|| {
            direct_ip.map(|ip| {
                effective_client_ip(
                    ip,
                    trusted_direct_peer,
                    original_x_forwarded_for.as_deref(),
                    Some(&trusted_proxy_matcher),
                )
            })
        });
        if let Some(client_ip) = client_ip {
            let port = listener_effective_addr
                .filter(|addr| addr.ip() == client_ip)
                .map(|addr| addr.port())
                .or_else(|| {
                    request
                        .peer_addr
                        .filter(|addr| addr.ip() == client_ip)
                        .map(|addr| addr.port())
                })
                .unwrap_or(0);
            request.effective_client_addr = Some(std::net::SocketAddr::new(client_ip, port));
        }
        match (self.x_forwarded_for, client_ip) {
            (ForwardedClientIpHeaderMode::Off, _) => {
                remove_request_header(request, "x-forwarded-for")
            }
            (ForwardedClientIpHeaderMode::Replace, Some(ip)) => {
                replace_request_header(request, "x-forwarded-for", ip.to_string());
            }
            (ForwardedClientIpHeaderMode::Append, Some(ip)) => {
                let value = trusted_direct_peer
                    .then_some(original_x_forwarded_for.as_deref())
                    .flatten()
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| format!("{value}, {ip}"))
                    .unwrap_or_else(|| ip.to_string());
                replace_request_header(request, "x-forwarded-for", value);
            }
            (ForwardedClientIpHeaderMode::Replace | ForwardedClientIpHeaderMode::Append, None) => {
                remove_request_header(request, "x-forwarded-for");
            }
        }

        if self.x_real_ip {
            if let Some(ip) = client_ip {
                replace_request_header(request, "x-real-ip", ip.to_string());
            } else {
                remove_request_header(request, "x-real-ip");
            }
        }

        if self.x_forwarded_host {
            if let Some(host) = &original_host {
                replace_request_header(request, "x-forwarded-host", host.clone());
            } else {
                remove_request_header(request, "x-forwarded-host");
            }
        }

        if self.x_forwarded_proto {
            replace_request_header(request, "x-forwarded-proto", proto);
        }

        if self.forwarded {
            if let Some(ip) = client_ip {
                replace_request_header(
                    request,
                    "forwarded",
                    build_forwarded_header(ip, original_host.as_deref(), proto),
                );
            } else {
                remove_request_header(request, "forwarded");
            }
        }
    }

    #[cfg(not(feature = "privacy-mode"))]
    pub(crate) fn set_trusted_sources(&mut self, trusted_sources: Vec<ProxyProtocolTrustedSource>) {
        self.trusted_sources = trusted_sources;
    }

    #[cfg(not(feature = "privacy-mode"))]
    fn trusted_source_contains(&self, address: std::net::IpAddr) -> bool {
        self.trusted_sources
            .iter()
            .any(|source| source.contains(address))
    }
}

impl NativeRequestHeaderTemplateContext {
    fn from_route(route: &NativeHttp1RouteProxyRoute, path: &str) -> Self {
        Self {
            route_regex_captures: route_regex_header_captures(path, &route.matcher),
        }
    }

    fn variable(&self, variable: &str) -> Option<&str> {
        self.route_regex_captures
            .iter()
            .find_map(|(name, value)| (name == variable).then_some(value.as_str()))
    }
}

pub(crate) fn default_native_request_header_policy() -> NativeRouteRequestHeaderPolicy {
    NativeRouteRequestHeaderPolicy::from_policy(&RequestHeaderPolicyConfig::default())
}

impl NativeRouteResponseHeaderPolicy {
    pub(crate) fn from_policy(policy: &ResponseHeaderPolicyConfig) -> Self {
        let mut native = Self {
            enabled: policy.enabled,
            unset: policy.effective_unset(),
            set: policy.effective_set().into_iter().collect(),
            append: flatten_append_headers(&policy.append),
            rewrite: policy.rewrite.clone(),
        };
        native.apply_standard_headers_from_policy(policy);
        native
    }

    fn from_overlay(overlay: &ResponseHeaderPolicyOverlayConfig) -> Self {
        let mut policy = Self {
            enabled: overlay.enabled.unwrap_or(true),
            unset: overlay.effective_unset(),
            set: overlay.effective_set().into_iter().collect(),
            append: flatten_append_headers(&overlay.append),
            rewrite: overlay.rewrite.clone(),
        };
        policy.apply_standard_headers(overlay);
        policy
    }

    fn apply_standard_headers_from_policy(&mut self, policy: &ResponseHeaderPolicyConfig) {
        if let Some(value) = &policy.strict_transport_security {
            self.set_optional_header("strict-transport-security", Some(value.clone()));
        } else if let Some(hsts) = &policy.hsts
            && let Some(value) = hsts.header_value()
        {
            self.set_optional_header("strict-transport-security", Some(value));
        }
        if let Some(value) = &policy.content_security_policy {
            self.set_optional_header("content-security-policy", Some(value.clone()));
        }
        if let Some(value) = &policy.x_content_type_options {
            self.set_optional_header("x-content-type-options", Some(value.clone()));
        }
        if let Some(value) = &policy.x_frame_options {
            self.set_optional_header("x-frame-options", Some(value.clone()));
        }
        if let Some(value) = &policy.referrer_policy {
            self.set_optional_header("referrer-policy", Some(value.clone()));
        }
    }

    fn apply_standard_headers(&mut self, overlay: &ResponseHeaderPolicyOverlayConfig) {
        if let Some(value) = &overlay.hsts {
            self.set_optional_header(
                "strict-transport-security",
                value.as_ref().and_then(|hsts| hsts.header_value()),
            );
        }
        if let Some(value) = &overlay.strict_transport_security {
            self.set_optional_header("strict-transport-security", value.clone());
        }
        if let Some(value) = &overlay.content_security_policy {
            self.set_optional_header("content-security-policy", value.clone());
        }
        if let Some(value) = &overlay.x_content_type_options {
            self.set_optional_header("x-content-type-options", value.clone());
        }
        if let Some(value) = &overlay.x_frame_options {
            self.set_optional_header("x-frame-options", value.clone());
        }
        if let Some(value) = &overlay.referrer_policy {
            self.set_optional_header("referrer-policy", value.clone());
        }
    }

    fn set_optional_header(&mut self, name: &str, value: Option<String>) {
        if let Some(value) = value {
            self.set.push((name.to_owned(), value));
        } else {
            self.unset.push(name.to_owned());
        }
    }

    pub(crate) fn apply(&self, response: &mut NativeHttp1Response) {
        if !self.enabled {
            return;
        }
        apply_response_rewrites(response, &self.rewrite);
        for name in &self.unset {
            response.remove_header(name);
        }
        for (name, value) in &self.set {
            response.remove_header(name);
            response.push_header(name.clone(), value.clone());
        }
        for (name, value) in &self.append {
            response.push_header(name.clone(), value.clone());
        }
    }
}

fn apply_response_rewrites(
    response: &mut NativeHttp1Response,
    rewrite: &ResponseHeaderRewriteConfig,
) {
    rewrite_response_header_values(
        response,
        "location",
        &rewrite.location,
        rewrite_header_prefix,
    );
    rewrite_response_header_values(response, "refresh", &rewrite.refresh, rewrite_refresh_url);
    rewrite_set_cookie_header_values(response, rewrite);
}

fn rewrite_response_header_values(
    response: &mut NativeHttp1Response,
    name: &'static str,
    rules: &[fluxheim_config::ResponseHeaderRewriteRuleConfig],
    rewrite_value: fn(&str, &[fluxheim_config::ResponseHeaderRewriteRuleConfig]) -> Option<String>,
) {
    if rules.is_empty() {
        return;
    }
    let mut changed = false;
    let mut rewritten = Vec::with_capacity(response.headers().len());
    for (header_name, header_value) in response.headers() {
        if header_name.eq_ignore_ascii_case(name)
            && let Some(value) = rewrite_value(header_value, rules)
        {
            rewritten.push((header_name.clone(), value));
            changed = true;
        } else {
            rewritten.push((header_name.clone(), header_value.clone()));
        }
    }
    if changed {
        replace_response_headers(response, rewritten);
    }
}

fn rewrite_set_cookie_header_values(
    response: &mut NativeHttp1Response,
    rewrite: &ResponseHeaderRewriteConfig,
) {
    if rewrite.cookie_domain.is_empty() && rewrite.cookie_path.is_empty() {
        return;
    }
    let mut changed = false;
    let mut rewritten = Vec::with_capacity(response.headers().len());
    for (header_name, header_value) in response.headers() {
        if header_name.eq_ignore_ascii_case("set-cookie")
            && let Some(value) = rewrite_set_cookie_value(header_value, rewrite)
        {
            rewritten.push((header_name.clone(), value));
            changed = true;
        } else {
            rewritten.push((header_name.clone(), header_value.clone()));
        }
    }
    if changed {
        replace_response_headers(response, rewritten);
    }
}

fn replace_response_headers(response: &mut NativeHttp1Response, headers: Vec<(String, String)>) {
    let names = response
        .headers()
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    for name in names {
        response.remove_header(&name);
    }
    for (name, value) in headers {
        response.push_header(name, value);
    }
}

fn flatten_append_headers(
    append: &std::collections::BTreeMap<String, HeaderValues>,
) -> Vec<(String, String)> {
    let mut flattened = Vec::new();
    for (name, values) in append {
        for value in values.iter() {
            flattened.push((name.clone(), value.to_owned()));
        }
    }
    flattened
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn native_rate_limit_prune_is_bounded_and_incremental() {
        let now = Instant::now();
        let expired_at = now - Duration::from_secs(10);
        let fresh_at = now - Duration::from_secs(1);
        let first = NativeRateLimitKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let second = NativeRateLimitKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)));
        let third = NativeRateLimitKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)));
        let mut buckets = NativeRateLimitBuckets {
            entries: HashMap::from([
                (
                    first,
                    NativeRateLimitBucket {
                        tokens: 1.0,
                        updated_at: expired_at,
                        last_seen: expired_at,
                    },
                ),
                (
                    second,
                    NativeRateLimitBucket {
                        tokens: 1.0,
                        updated_at: expired_at,
                        last_seen: expired_at,
                    },
                ),
                (
                    third,
                    NativeRateLimitBucket {
                        tokens: 1.0,
                        updated_at: fresh_at,
                        last_seen: fresh_at,
                    },
                ),
            ]),
            prune_queue: VecDeque::from([first, second, third]),
            last_pruned_at: None,
        };

        prune_native_rate_limit_entries(&mut buckets, now, Duration::from_secs(5), 1);
        assert!(!buckets.entries.contains_key(&first));
        assert!(buckets.entries.contains_key(&second));
        assert!(buckets.entries.contains_key(&third));

        prune_native_rate_limit_entries(&mut buckets, now, Duration::from_secs(5), 2);
        assert!(!buckets.entries.contains_key(&second));
        assert!(buckets.entries.contains_key(&third));
        assert_eq!(buckets.prune_queue, VecDeque::from([third]));
    }

    #[test]
    fn native_rate_limit_prune_tolerates_future_bucket_times() {
        let now = Instant::now();
        let future = now + Duration::from_secs(5);
        let key = NativeRateLimitKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
        let mut buckets = NativeRateLimitBuckets {
            entries: HashMap::from([(
                key,
                NativeRateLimitBucket {
                    tokens: 1.0,
                    updated_at: future,
                    last_seen: future,
                },
            )]),
            prune_queue: VecDeque::from([key]),
            last_pruned_at: None,
        };

        prune_native_rate_limit_entries(&mut buckets, now, Duration::from_secs(1), 1);

        assert!(buckets.entries.contains_key(&key));
        assert_eq!(buckets.prune_queue, VecDeque::from([key]));
    }

    #[test]
    fn native_rate_limit_check_tolerates_future_bucket_update_time() {
        let limiter = NativeRateLimit {
            enabled: true,
            requests_per_second: 1.0,
            burst: 1.0,
            status: 429,
            table_max_entries: 16,
            entry_ttl: Duration::from_secs(60),
            mode: RateLimitMode::Nodelay,
            max_delay: Duration::from_millis(100),
            reject_indeterminate: false,
            state: Arc::new(NativeRateLimitState {
                shards: native_rate_limit_shards(),
            }),
        };
        let key = NativeRateLimitKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)));
        let shard = native_rate_limit_shard(key);
        let future = Instant::now() + Duration::from_secs(5);
        {
            let mut buckets = limiter.state.shards[shard].lock().unwrap();
            buckets.prune_queue.push_back(key);
            buckets.entries.insert(
                key,
                NativeRateLimitBucket {
                    tokens: 0.0,
                    updated_at: future,
                    last_seen: future,
                },
            );
        }

        assert_eq!(
            limiter.check(Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)))),
            NativeRateLimitDecision::Reject(429)
        );
    }

    #[test]
    fn native_rate_limit_shard_uses_full_ipv4_address() {
        let first = NativeRateLimitKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42)));
        let first_shard = native_rate_limit_shard(first);
        let differs = (1..=254).any(|octet| {
            let candidate = NativeRateLimitKey::Ip(IpAddr::V4(Ipv4Addr::new(octet, 51, 100, 42)));
            native_rate_limit_shard(candidate) != first_shard
        });

        assert!(differs);
    }

    #[test]
    fn native_rate_limit_shard_uses_full_ipv6_address() {
        let first = NativeRateLimitKey::Ip(IpAddr::V6(Ipv6Addr::from([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
        ])));
        let first_shard = native_rate_limit_shard(first);
        let differs = (0..=255).any(|byte| {
            let candidate = NativeRateLimitKey::Ip(IpAddr::V6(Ipv6Addr::from([
                0x20, 0x01, 0x0d, byte, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
            ])));
            native_rate_limit_shard(candidate) != first_shard
        });

        assert!(differs);
    }

    #[test]
    fn native_rate_limit_indeterminate_key_is_seeded() {
        assert!(
            native_rate_limit_shard(NativeRateLimitKey::Indeterminate) < NATIVE_RATE_LIMIT_SHARDS
        );
    }
}
