use std::cmp::Reverse;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::Arc;
#[cfg(feature = "cache")]
use std::sync::Mutex;
#[cfg(feature = "cache")]
use std::sync::OnceLock;
#[cfg(feature = "cache")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(any(feature = "cache", feature = "php-fpm"))]
use std::time::Duration;
#[cfg(any(not(feature = "privacy-mode"), feature = "cache", feature = "php-fpm"))]
use std::time::Instant;

use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use bytes::Bytes;
#[cfg(feature = "cache")]
use pingora::ErrorSource;
#[cfg(feature = "cache")]
use pingora::cache::CacheKey as PingoraCacheKey;
#[cfg(feature = "cache")]
use pingora::cache::key::{CacheHashKey, HashBinary};
#[cfg(feature = "cache")]
use pingora::cache::lock::CacheKeyLockImpl;
#[cfg(feature = "cache")]
use pingora::cache::predictor::{CacheablePredictor, Predictor};
#[cfg(any(feature = "cache", feature = "php-fpm"))]
use pingora::http::StatusCode;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::prelude::{HttpPeer, Result};
#[cfg(feature = "cache")]
use pingora::proxy::RangeType;
use pingora::proxy::{FailToProxy, ProxyHttp, Session};
use pingora::{Error, ErrorType};
#[cfg(feature = "cache")]
use pingora::{
    cache::CacheMeta, cache::CacheOptionOverrides, cache::CachePhase, cache::ForcedFreshness,
    cache::HitHandler, cache::NoCacheReason, cache::RespCacheable,
};

#[cfg(not(feature = "privacy-mode"))]
use crate::config::AccessLoggingConfig;
use crate::config::{
    Config, HostRoutingConfig, HttpsRedirectConfig, ProxyConfig, RouteRedirectConfig,
    ServerLimitsConfig, normalize_host,
};
#[cfg(feature = "load-balancer")]
use crate::load_balancer::{UpstreamLoadBalancer, UpstreamLoadBalancerService};
#[cfg(feature = "web")]
use crate::web::{ResolveResult, StaticFileServer};

#[cfg(feature = "cache")]
const MAX_VARY_HEADER_BYTES: usize = 2048;
#[cfg(feature = "cache")]
const MAX_VARY_FIELDS: usize = 16;
#[cfg(feature = "cache")]
const CACHE_MIN_USES_REASON: &str = "cache-min-uses";
#[cfg(feature = "cache")]
const CACHE_MIN_USES_COUNTER_CAPACITY: u64 = 65_536;
#[cfg(feature = "cache")]
const CACHE_MIN_USES_COUNTER_TTL_SECS: u64 = 600;
#[cfg(feature = "cache")]
const CACHE_PASS_COUNTER_CAPACITY: u64 = 65_536;
#[cfg(feature = "cache")]
const CACHE_PASS_COUNTER_TTL_SECS: u64 = 600;
#[cfg(feature = "cache")]
const CACHE_PREDICTOR_SHARDS: usize = 16;
#[cfg(feature = "cache")]
const REVALIDATION_VARY_CHANGED_REASON: &str = "revalidation-vary-changed";
#[cfg(feature = "cache")]
const CACHE_ONLY_RESPONSE_MAX_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(feature = "cache")]
type FluxCachePredictor = Predictor<CACHE_PREDICTOR_SHARDS>;
#[cfg(feature = "cache")]
const PEER_FILL_CONCURRENCY_MAX_KEYS: usize = 4096;
#[cfg(feature = "cache")]
static PEER_FILL_CONCURRENCY: OnceLock<Mutex<HashMap<String, Arc<AtomicUsize>>>> = OnceLock::new();

#[derive(Clone)]
pub struct FluxProxy {
    state: Arc<ArcSwap<ProxyRuntimeState>>,
    health_reporter: Arc<ArcSwapOption<Box<dyn ProxyHealthReporter>>>,
}

impl std::fmt::Debug for FluxProxy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FluxProxy")
            .field("state", &self.snapshot().state)
            .field("health_reporter", &self.has_health_reporter())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProxyHealthSignal {
    Success,
    Failure,
}

impl ProxyHealthSignal {
    pub fn healthy(self) -> bool {
        matches!(self, Self::Success)
    }
}

pub trait ProxyHealthReporter: Send + Sync + 'static {
    fn record_proxy_health_signal(&self, signal: ProxyHealthSignal);
}

impl<T> ProxyHealthReporter for Arc<T>
where
    T: ProxyHealthReporter + ?Sized,
{
    fn record_proxy_health_signal(&self, signal: ProxyHealthSignal) {
        (**self).record_proxy_health_signal(signal);
    }
}

#[derive(Debug, Clone)]
struct ProxyRuntimeState {
    vhosts: Vec<RuntimeVhost>,
    host_index: HashMap<String, usize>,
    wildcard_hosts: Vec<WildcardHost>,
    default_vhost: usize,
    trusted_proxies: Vec<TrustedProxy>,
    limits: ServerLimitsConfig,
    https_redirect: HttpsRedirectConfig,
    host_routing: HostRoutingConfig,
    #[cfg(feature = "otel-tracing")]
    tracing: crate::config::TracingConfig,
    #[cfg(feature = "otel-otlp")]
    trace_exporter: Option<crate::otel_otlp::TraceExporter>,
    #[cfg(not(feature = "privacy-mode"))]
    access_log: AccessLoggingConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TrustedProxy {
    Exact(IpAddr),
    Cidr { network: IpAddr, prefix: u8 },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum HostRoutingRejectReason {
    Missing,
    Invalid,
    Unknown,
}

impl HostRoutingRejectReason {
    fn status(self) -> u16 {
        match self {
            Self::Missing | Self::Invalid => 400,
            Self::Unknown => 421,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Invalid => "invalid",
            Self::Unknown => "unknown",
        }
    }

    fn response_body(self) -> &'static [u8] {
        match self {
            Self::Missing => b"missing host header",
            Self::Invalid => b"invalid host header",
            Self::Unknown => b"unknown host",
        }
    }
}

impl TrustedProxy {
    fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::Exact(trusted), address) => trusted == address,
            (
                Self::Cidr {
                    network: IpAddr::V4(network),
                    prefix,
                },
                IpAddr::V4(address),
            ) => ipv4_prefix_match(network, address, prefix),
            (
                Self::Cidr {
                    network: IpAddr::V6(network),
                    prefix,
                },
                IpAddr::V6(address),
            ) => ipv6_prefix_match(network, address, prefix),
            _ => false,
        }
    }
}

impl FluxProxy {
    pub fn from_config(config: &Config) -> io::Result<Self> {
        Ok(Self {
            state: Arc::new(ArcSwap::from_pointee(ProxyRuntimeState::from_config(
                config,
            )?)),
            health_reporter: Arc::new(ArcSwapOption::empty()),
        })
    }

    pub fn reload_from_config(&self, config: &Config) -> io::Result<()> {
        self.state
            .store(Arc::new(ProxyRuntimeState::from_config(config)?));
        Ok(())
    }

    pub fn snapshot(&self) -> ProxySnapshot {
        ProxySnapshot {
            state: self.state.load_full(),
        }
    }

    pub fn route_host(&self, host: Option<&str>) -> String {
        self.snapshot().route_host(host).to_owned()
    }

    pub fn set_health_reporter(&self, reporter: Arc<dyn ProxyHealthReporter>) {
        self.health_reporter
            .store(Some(Arc::new(Box::new(reporter))));
    }

    pub(crate) fn has_health_reporter(&self) -> bool {
        self.health_reporter.load_full().is_some()
    }

    fn report_proxy_health_signal(&self, signal: ProxyHealthSignal, ctx: &mut RequestContext) {
        if ctx.health_signal_recorded {
            return;
        }
        ctx.health_signal_recorded = true;

        let reporter = self.health_reporter.load_full();
        if let Some(reporter) = reporter {
            reporter.record_proxy_health_signal(signal);
        }
    }

    #[cfg(not(feature = "privacy-mode"))]
    fn emit_access_log(&self, session: &Session, error: Option<&Error>, ctx: &RequestContext) {
        let state = ctx.state.clone().unwrap_or_else(|| self.state.load_full());
        if !state.access_log.enabled {
            return;
        }

        let vhost = ctx
            .vhost_index
            .and_then(|index| state.vhosts.get(index))
            .map(|vhost| vhost.name.as_str())
            .unwrap_or("unknown");
        let status = session
            .response_written()
            .map(|response| response.status.as_u16());
        let latency_ms = ctx
            .started_at
            .map(|started_at| started_at.elapsed().as_millis())
            .unwrap_or(0);

        log::info!(
            target: "fluxheim::access",
            "{}",
            access_log_json(AccessLogEvent {
                method: session.req_header().method.as_str(),
                host: state
                    .access_log
                    .include_host
                    .then(|| request_host(session))
                    .flatten(),
                vhost,
                path: state
                    .access_log
                    .include_path
                    .then(|| session.req_header().uri.path()),
                status,
                status_class: status.map(status_class),
                error: error.is_some(),
                request_id: ctx.request_id.as_deref(),
                #[cfg(feature = "otel-tracing")]
                trace_id: (state.tracing.enabled && state.tracing.log_trace_id)
                    .then(|| ctx.trace_context.map(|context| context.trace_id_hex()))
                    .flatten(),
                request_body_bytes: ctx.request_body_bytes_seen,
                response_body_bytes: ctx.response_body_bytes_seen,
                latency_ms,
            })
        );
    }

    #[cfg(feature = "otel-otlp")]
    fn export_otlp_trace_span(
        &self,
        session: &Session,
        error: Option<&Error>,
        ctx: &RequestContext,
    ) {
        let state = ctx.state.clone().unwrap_or_else(|| self.state.load_full());
        let Some(exporter) = state.trace_exporter.as_ref() else {
            return;
        };
        if !state.tracing.enabled || !state.tracing.otlp.enabled {
            return;
        }
        let Some(trace_context) = ctx.trace_context else {
            return;
        };
        let vhost = ctx
            .vhost_index
            .and_then(|index| state.vhosts.get(index))
            .map(|vhost| vhost.name.as_str())
            .unwrap_or("unknown");
        let route = ctx
            .route_index
            .map(|route_index| format!("route-{route_index}"));
        let status = session
            .response_written()
            .map(|response| response.status.as_u16());
        let method = session.req_header().method.as_str().to_owned();
        #[cfg(feature = "cache")]
        let cache_phase = Some(effective_cache_phase(session, ctx).as_str().to_owned());
        #[cfg(not(feature = "cache"))]
        let cache_phase = None;
        #[cfg(feature = "cache")]
        let cache_lookup_duration_ms = session
            .cache
            .lookup_duration()
            .map(|duration| duration.as_secs_f64() * 1000.0);
        #[cfg(not(feature = "cache"))]
        let cache_lookup_duration_ms = None;
        #[cfg(feature = "cache")]
        let cache_lock_wait_duration_ms = session
            .cache
            .lock_duration()
            .map(|duration| duration.as_secs_f64() * 1000.0);
        #[cfg(not(feature = "cache"))]
        let cache_lock_wait_duration_ms = None;
        exporter.try_export(crate::otel_otlp::TraceSpan {
            trace_id: trace_context.trace_id_hex(),
            span_id: trace_context.span_id_hex(),
            parent_span_id: trace_context.parent_span_id_hex(),
            name: format!("HTTP {method}"),
            method,
            vhost: vhost.to_owned(),
            route,
            status_code: status,
            error: error.is_some() || status.is_some_and(|status| status >= 500),
            start_time_unix_nanos: ctx.started_at_unix_nanos.unwrap_or_else(unix_time_nanos),
            end_time_unix_nanos: unix_time_nanos(),
            request_body_bytes: ctx.request_body_bytes_seen,
            response_body_bytes: ctx.response_body_bytes_seen,
            cache_phase,
            cache_lookup_duration_ms,
            cache_lock_wait_duration_ms,
        });
    }

    #[cfg(all(feature = "cache", feature = "metrics"))]
    fn record_cache_operation_duration_metrics(&self, session: &Session, ctx: &RequestContext) {
        let lookup_duration = session.cache.lookup_duration();
        let lock_duration = session.cache.lock_duration();
        if lookup_duration.is_none() && lock_duration.is_none() {
            return;
        }

        let state = ctx.state.clone().unwrap_or_else(|| self.state.load_full());
        let vhost = ctx
            .vhost_index
            .and_then(|index| state.vhosts.get(index))
            .or_else(|| state.vhosts.get(state.vhost_index(request_host(session))));
        let Some(vhost) = vhost else {
            return;
        };
        let route = ctx
            .route_index
            .and_then(|index| vhost.route(index).cache.as_ref())
            .map(|cache| cache.name.as_str());
        let phase = effective_cache_phase(session, ctx).as_str();

        if let Some(duration) = lookup_duration {
            crate::metrics::record_cache_operation_duration(
                vhost.name.as_str(),
                route,
                phase,
                "lookup",
                duration,
            );
        }
        if let Some(duration) = lock_duration {
            crate::metrics::record_cache_operation_duration(
                vhost.name.as_str(),
                route,
                phase,
                "lock_wait",
                duration,
            );
        }
    }

    #[cfg(feature = "cache")]
    pub fn image_cache_key_for_request_header(
        &self,
        request: &RequestHeader,
        vhost_index: usize,
    ) -> Option<crate::cache::CacheKey> {
        self.snapshot()
            .image_cache_key_for_request_header(request, vhost_index)
    }

    #[cfg(feature = "cache")]
    pub fn image_memory_cache_for_request_header(
        &self,
        request: &RequestHeader,
        vhost_index: usize,
    ) -> Option<(crate::cache::CacheKey, crate::cache::MemoryImageCache)> {
        self.snapshot()
            .image_memory_cache_for_request_header(request, vhost_index)
    }

    #[cfg(feature = "cache")]
    pub fn pingora_memory_storage_stats_for_request_header(
        &self,
        request: &RequestHeader,
        vhost_index: usize,
    ) -> Option<crate::cache::MemoryCacheStats> {
        self.snapshot()
            .pingora_memory_storage_stats_for_request_header(request, vhost_index)
    }

    #[cfg(feature = "cache")]
    pub fn cache_runtime_stats(&self) -> io::Result<CacheRuntimeStats> {
        self.snapshot().cache_runtime_stats()
    }

    #[cfg(feature = "cache")]
    pub fn reset_cache_activity(&self) -> CacheActivityResetResult {
        self.snapshot().reset_cache_activity()
    }

    #[cfg(feature = "cache")]
    pub fn purge_image_cache(
        &self,
        request: CachePurgeRequest<'_>,
    ) -> io::Result<CachePurgeResult> {
        self.snapshot().purge_image_cache(request)
    }

    #[cfg(feature = "cache")]
    pub fn purge_image_cache_bulk(
        &self,
        request: CacheBulkPurgeRequest<'_>,
    ) -> io::Result<CacheBulkPurgeResult> {
        self.snapshot().purge_image_cache_bulk(request)
    }

    #[cfg(feature = "cache")]
    pub fn purge_indexed_image_cache(
        &self,
        request: CacheIndexedPurgeRequest<'_>,
    ) -> io::Result<CacheIndexedPurgeResult> {
        self.snapshot().purge_indexed_image_cache(request)
    }

    #[cfg(feature = "cache")]
    pub fn purge_indexed_image_cache_path_prefix(
        &self,
        request: CacheIndexedPathPrefixPurgeRequest<'_>,
    ) -> io::Result<CacheIndexedPurgeResult> {
        self.snapshot()
            .purge_indexed_image_cache_path_prefix(request)
    }

    #[cfg(feature = "cache")]
    pub fn purge_indexed_image_cache_tag(
        &self,
        request: CacheIndexedTagPurgeRequest<'_>,
    ) -> io::Result<CacheIndexedPurgeResult> {
        self.snapshot().purge_indexed_image_cache_tag(request)
    }

    #[cfg(feature = "cache")]
    pub fn purge_stale_image_cache(
        &self,
        request: CacheStalePurgeRequest<'_>,
    ) -> io::Result<CacheStalePurgeResult> {
        self.snapshot().purge_stale_image_cache(request)
    }

    #[cfg(feature = "cache")]
    pub fn purge_stale_disk_cache_once(
        &self,
        limit: usize,
        batches: usize,
    ) -> io::Result<CacheBackgroundPurgeResult> {
        self.snapshot().purge_stale_disk_cache_once(limit, batches)
    }

    #[cfg(feature = "cache")]
    pub fn purge_indexed_image_cache_path_pattern(
        &self,
        request: CacheIndexedPathPatternPurgeRequest<'_>,
    ) -> io::Result<CacheIndexedPurgeResult> {
        self.snapshot()
            .purge_indexed_image_cache_path_pattern(request)
    }
}

#[derive(Debug, Clone)]
pub struct ProxySnapshot {
    state: Arc<ProxyRuntimeState>,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CachePurgeRequest<'a> {
    pub vhost: Option<&'a str>,
    pub route: Option<&'a str>,
    pub host: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheBulkPurgeRequest<'a> {
    pub vhost: Option<&'a str>,
    pub route: Option<&'a str>,
    pub host: &'a str,
    pub method: &'a str,
    pub paths: Vec<&'a str>,
    pub query: Option<&'a str>,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheIndexedPurgeRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub limit: usize,
    pub soft: bool,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheIndexedPathPrefixPurgeRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub path_prefix: &'a str,
    pub limit: usize,
    pub soft: bool,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheIndexedTagPurgeRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub cache_tag: &'a str,
    pub limit: usize,
    pub soft: bool,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheStalePurgeRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub limit: usize,
    pub dry_run: bool,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheIndexedPathPatternPurgeRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub path_pattern: &'a str,
    pub limit: usize,
    pub soft: bool,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheKeyPreview {
    pub vhost: String,
    pub route: Option<String>,
    pub scope: CacheKeyPreviewScope,
    pub eligible: bool,
    pub cache_lock_enabled: bool,
    pub cache_lock_wait_timeout_secs: u64,
    pub cache_predictor_enabled: bool,
    pub peer_fill_enabled: bool,
    pub peer_fill_peer_count: usize,
    pub peer_fill_max_concurrent_requests: usize,
    pub peer_fill_fail_open: bool,
    pub memory_tier_enabled: bool,
    pub disk_tier_enabled: bool,
    pub storage_tiers: u8,
    pub reason: Option<String>,
    pub namespace: Option<String>,
    pub key_namespace: Option<String>,
    pub primary_key: Option<String>,
    pub primary_hash: Option<String>,
    pub variance_hash: Option<String>,
    pub combined_hash: Option<String>,
    pub user_tag: Option<String>,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheObjectLookup {
    pub preview: CacheKeyPreview,
    pub objects: Vec<crate::cache::CacheObjectMetadata>,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CacheKeyPreviewScope {
    Vhost,
    Route,
}

#[cfg(feature = "cache")]
impl CacheKeyPreviewScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vhost => "vhost",
            Self::Route => "route",
        }
    }
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CachePurgeResult {
    pub vhost: String,
    pub route: Option<String>,
    pub host: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub cache_key: String,
    pub memory_purged: bool,
    pub disk_purged: bool,
}

#[cfg(feature = "cache")]
impl CachePurgeResult {
    pub fn purged(&self) -> bool {
        self.memory_purged || self.disk_purged
    }

    pub fn not_purged(&self) -> bool {
        !self.purged()
    }

    pub fn memory_not_purged(&self) -> bool {
        !self.memory_purged
    }

    pub fn disk_not_purged(&self) -> bool {
        !self.disk_purged
    }
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheBulkPurgeResult {
    pub vhost: String,
    pub results: Vec<CachePurgeResult>,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheIndexedPurgeResult {
    pub vhost: String,
    pub route: Option<String>,
    pub memory_matched: usize,
    pub memory_purged: usize,
    pub memory_truncated: bool,
    pub disk_matched: usize,
    pub disk_purged: usize,
    pub disk_truncated: bool,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheStalePurgeResult {
    pub vhost: String,
    pub route: Option<String>,
    pub memory_scanned: usize,
    pub memory_stale: usize,
    pub memory_purged: usize,
    pub memory_truncated: bool,
    pub disk_scanned: usize,
    pub disk_stale: usize,
    pub disk_purged: usize,
    pub disk_truncated: bool,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct CacheBackgroundPurgeResult {
    pub targets: usize,
    pub scanned: usize,
    pub stale: usize,
    pub purged: usize,
    pub truncated: bool,
}

#[cfg(feature = "cache")]
impl CacheStalePurgeResult {
    pub fn scanned(&self) -> usize {
        self.memory_scanned.saturating_add(self.disk_scanned)
    }

    pub fn stale(&self) -> usize {
        self.memory_stale.saturating_add(self.disk_stale)
    }

    pub fn purged(&self) -> usize {
        self.memory_purged.saturating_add(self.disk_purged)
    }

    pub fn not_purged(&self) -> usize {
        self.stale().saturating_sub(self.purged())
    }

    pub fn truncated(&self) -> bool {
        self.memory_truncated || self.disk_truncated
    }

    pub fn route(&self) -> Option<&str> {
        self.route.as_deref()
    }
}

#[cfg(feature = "cache")]
impl CacheIndexedPurgeResult {
    pub fn matched(&self) -> usize {
        self.memory_matched.saturating_add(self.disk_matched)
    }

    pub fn purged(&self) -> usize {
        self.memory_purged.saturating_add(self.disk_purged)
    }

    pub fn not_purged(&self) -> usize {
        self.matched().saturating_sub(self.purged())
    }

    pub fn memory_not_purged(&self) -> usize {
        self.memory_matched.saturating_sub(self.memory_purged)
    }

    pub fn disk_not_purged(&self) -> usize {
        self.disk_matched.saturating_sub(self.disk_purged)
    }

    pub fn truncated(&self) -> bool {
        self.memory_truncated || self.disk_truncated
    }
}

#[cfg(feature = "cache")]
impl CacheBulkPurgeResult {
    pub fn route(&self) -> Option<&str> {
        self.results
            .first()
            .and_then(|result| result.route.as_deref())
    }

    pub fn requested(&self) -> usize {
        self.results.len()
    }

    pub fn purged(&self) -> usize {
        self.results.iter().filter(|result| result.purged()).count()
    }

    pub fn not_purged(&self) -> usize {
        self.requested().saturating_sub(self.purged())
    }

    pub fn memory_purged(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.memory_purged)
            .count()
    }

    pub fn memory_not_purged(&self) -> usize {
        self.requested().saturating_sub(self.memory_purged())
    }

    pub fn disk_purged(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.disk_purged)
            .count()
    }

    pub fn disk_not_purged(&self) -> usize {
        self.requested().saturating_sub(self.disk_purged())
    }
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheRuntimeStats {
    pub totals: CacheRuntimeTotals,
    pub vhosts: Vec<CacheVhostStats>,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct CacheRuntimeTotals {
    pub vhosts: u64,
    pub enabled_vhosts: u64,
    pub tiered_vhosts: u64,
    pub configured_routes: u64,
    pub routes_total: u64,
    pub enabled_routes: u64,
    pub tiered_routes: u64,
    pub lock_enabled_policies: u64,
    pub peer_fill_enabled_policies: u64,
    pub peer_fill_peers: u64,
    pub peer_fill_max_concurrent_requests: u64,
    pub memory_tiers: u64,
    pub memory_entries: u64,
    pub memory_weighted_size_bytes: u64,
    pub memory_max_size_bytes: u64,
    pub memory_purge_index_entries: u64,
    pub memory_purge_index_max_entries: u64,
    pub disk_tiers: u64,
    pub disk_entries: u64,
    pub disk_size_bytes: u64,
    pub disk_allocated_size_bytes: u64,
    pub disk_free_size_bytes: u64,
    pub disk_free_range_count: u64,
    pub disk_largest_free_range_bytes: u64,
    pub disk_bin_files: u64,
    pub disk_max_size_bytes: u64,
    pub disk_purge_index_entries: u64,
    pub disk_purge_index_max_entries: u64,
    pub hits: u64,
    pub misses: u64,
    pub stores: u64,
    pub store_refusals: u64,
    pub evictions: u64,
    pub purges: u64,
}

#[cfg(feature = "cache")]
impl CacheRuntimeTotals {
    pub fn enabled_cache_policies(&self) -> u64 {
        self.enabled_vhosts.saturating_add(self.enabled_routes)
    }
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheVhostStats {
    pub name: String,
    pub enabled: bool,
    pub tiered: bool,
    pub lock_enabled: bool,
    pub lock_wait_timeout_secs: u64,
    pub peer_fill_enabled: bool,
    pub peer_fill_peers: usize,
    pub peer_fill_max_concurrent_requests: usize,
    pub peer_fill_fail_open: bool,
    pub configured_routes: u64,
    pub routes_total: u64,
    pub enabled_routes: u64,
    pub tiered_routes: u64,
    pub memory: Option<crate::cache::MemoryCacheStats>,
    pub disk: Option<crate::cache::DiskCacheStats>,
    pub routes: Vec<CacheRouteStats>,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheRouteStats {
    pub name: String,
    pub enabled: bool,
    pub tiered: bool,
    pub lock_enabled: bool,
    pub lock_wait_timeout_secs: u64,
    pub peer_fill_enabled: bool,
    pub peer_fill_peers: usize,
    pub peer_fill_max_concurrent_requests: usize,
    pub peer_fill_fail_open: bool,
    pub memory: Option<crate::cache::MemoryCacheStats>,
    pub disk: Option<crate::cache::DiskCacheStats>,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CacheActivityResetResult {
    pub vhosts: u64,
    pub enabled_vhosts: u64,
    pub configured_routes: u64,
    pub routes_total: u64,
    pub enabled_routes: u64,
    pub memory_tiers: u64,
    pub disk_tiers: u64,
    pub tiered_vhosts: u64,
    pub tiered_routes: u64,
}

impl ProxySnapshot {
    pub fn route_host(&self, host: Option<&str>) -> &str {
        &self.state.vhosts[self.state.vhost_index(host)].name
    }

    #[cfg(feature = "cache")]
    pub fn image_cache_key_for_request_header(
        &self,
        request: &RequestHeader,
        vhost_index: usize,
    ) -> Option<crate::cache::CacheKey> {
        let cache = &self.state.vhost(vhost_index).cache;
        let cache_request = cache_request_from_header(request);
        crate::cache::image_cache_key(cache, &cache_request)
    }

    #[cfg(feature = "cache")]
    pub fn pingora_image_cache_key_preview_for_request_header(
        &self,
        request: &RequestHeader,
    ) -> CacheKeyPreview {
        let host = request_host_header(request);
        let vhost_index = self.state.vhost_index(host);
        let vhost = self.state.vhost(vhost_index);
        let route_index = vhost.route_index(request.uri.path());
        let route_cache = route_index.and_then(|index| vhost.route(index).cache.as_ref());
        let cache_config = route_cache
            .map(|cache| &cache.config)
            .unwrap_or(&vhost.cache);
        let scope = if route_cache.is_some() {
            CacheKeyPreviewScope::Route
        } else {
            CacheKeyPreviewScope::Vhost
        };
        let (cache_lock_enabled, cache_lock_wait_timeout_secs) = route_cache
            .map(|cache| {
                (
                    cache.pingora_cache_lock.is_some(),
                    cache.cache_lock_wait_timeout.as_secs(),
                )
            })
            .unwrap_or((
                vhost.pingora_cache_lock.is_some(),
                vhost.cache_lock_wait_timeout.as_secs(),
            ));
        let memory_tier_enabled = route_cache
            .map(|cache| cache.pingora_memory_storage.is_some())
            .unwrap_or(vhost.pingora_memory_storage.is_some());
        let disk_tier_enabled = route_cache
            .map(|cache| cache.pingora_disk_storage.is_some())
            .unwrap_or(vhost.pingora_disk_storage.is_some());
        let cache_predictor_enabled = route_cache
            .map(|cache| cache.pingora_cache_predictor.is_some())
            .unwrap_or(vhost.pingora_cache_predictor.is_some());
        let peer_fill_enabled = cache_config.peer_fill.enabled;
        let peer_fill_peer_count = cache_config.peer_fill.peers.len();
        let peer_fill_max_concurrent_requests = cache_config.peer_fill.max_concurrent_requests;
        let peer_fill_fail_open = cache_config.peer_fill.fail_open;
        let storage_tiers = u8::from(memory_tier_enabled) + u8::from(disk_tier_enabled);
        let key = self.state.pingora_effective_cache_key_for_request_header(
            request,
            vhost_index,
            route_index,
        );

        match key {
            Some(key) => CacheKeyPreview {
                vhost: vhost.name.clone(),
                route: route_cache.map(|cache| cache.name.clone()),
                scope,
                eligible: true,
                cache_lock_enabled,
                cache_lock_wait_timeout_secs,
                cache_predictor_enabled,
                peer_fill_enabled,
                peer_fill_peer_count,
                peer_fill_max_concurrent_requests,
                peer_fill_fail_open,
                memory_tier_enabled,
                disk_tier_enabled,
                storage_tiers,
                reason: None,
                namespace: key.namespace_str().map(ToOwned::to_owned),
                key_namespace: cache_config.key_namespace.clone(),
                primary_key: key.primary_key_str().map(ToOwned::to_owned),
                primary_hash: Some(key.primary()),
                variance_hash: key.variance(),
                combined_hash: Some(key.combined()),
                user_tag: Some(key.user_tag().to_owned()),
            },
            None => CacheKeyPreview {
                vhost: vhost.name.clone(),
                route: route_cache.map(|cache| cache.name.clone()),
                scope,
                eligible: false,
                cache_lock_enabled,
                cache_lock_wait_timeout_secs,
                cache_predictor_enabled,
                peer_fill_enabled,
                peer_fill_peer_count,
                peer_fill_max_concurrent_requests,
                peer_fill_fail_open,
                memory_tier_enabled,
                disk_tier_enabled,
                storage_tiers,
                reason: Some(cache_key_preview_ineligible_reason(cache_config, request)),
                namespace: None,
                key_namespace: cache_config.key_namespace.clone(),
                primary_key: None,
                primary_hash: None,
                variance_hash: None,
                combined_hash: None,
                user_tag: None,
            },
        }
    }

    #[cfg(feature = "cache")]
    pub fn pingora_image_cache_object_lookup_for_request_header(
        &self,
        request: &RequestHeader,
    ) -> pingora::Result<CacheObjectLookup> {
        let preview = self.pingora_image_cache_key_preview_for_request_header(request);
        if !preview.eligible {
            return Ok(CacheObjectLookup {
                preview,
                objects: Vec::new(),
            });
        }

        let host = request_host_header(request);
        let vhost_index = self.state.vhost_index(host);
        let vhost = self.state.vhost(vhost_index);
        let route_index = vhost.route_index(request.uri.path());
        let route_cache = route_index.and_then(|index| vhost.route(index).cache.as_ref());
        let Some(key) = self.state.pingora_effective_cache_key_for_request_header(
            request,
            vhost_index,
            route_index,
        ) else {
            return Ok(CacheObjectLookup {
                preview,
                objects: Vec::new(),
            });
        };

        let memory_storage = route_cache
            .and_then(|cache| cache.pingora_memory_storage)
            .or(vhost
                .pingora_memory_storage
                .filter(|_| route_cache.is_none()));
        let disk_storage = route_cache
            .and_then(|cache| cache.pingora_disk_storage)
            .or(vhost.pingora_disk_storage.filter(|_| route_cache.is_none()));

        let mut objects = Vec::new();
        if let Some(storage) = memory_storage
            && let Some(metadata) = storage.inspect_cache_key(&key)?
        {
            objects.push(metadata);
        }
        if let Some(storage) = disk_storage
            && let Some(metadata) = storage.inspect_cache_key(&key)?
        {
            objects.push(metadata);
        }

        Ok(CacheObjectLookup { preview, objects })
    }

    #[cfg(feature = "cache")]
    pub fn image_memory_cache_for_request_header(
        &self,
        request: &RequestHeader,
        vhost_index: usize,
    ) -> Option<(crate::cache::CacheKey, crate::cache::MemoryImageCache)> {
        let vhost = self.state.vhost(vhost_index);
        let memory_cache = vhost.memory_cache.as_ref()?.clone();
        let cache_request = cache_request_from_header(request);
        let key = crate::cache::image_cache_key(&vhost.cache, &cache_request)?;
        Some((key, memory_cache))
    }

    #[cfg(feature = "cache")]
    pub fn pingora_memory_storage_stats_for_request_header(
        &self,
        request: &RequestHeader,
        vhost_index: usize,
    ) -> Option<crate::cache::MemoryCacheStats> {
        let vhost = self.state.vhost(vhost_index);
        let storage = vhost.pingora_memory_storage?;
        let cache_request = cache_request_from_header(request);
        crate::cache::image_cache_key(&vhost.cache, &cache_request)?;
        Some(storage.stats())
    }

    #[cfg(feature = "cache")]
    pub fn cache_runtime_stats(&self) -> io::Result<CacheRuntimeStats> {
        let mut vhosts = Vec::with_capacity(self.state.vhosts.len());
        let mut totals = CacheRuntimeTotals {
            vhosts: self.state.vhosts.len() as u64,
            ..CacheRuntimeTotals::default()
        };
        for vhost in &self.state.vhosts {
            if vhost.cache.enabled {
                totals.enabled_vhosts = totals.enabled_vhosts.saturating_add(1);
            }
            if vhost.pingora_tiered_storage.is_some() {
                totals.tiered_vhosts = totals.tiered_vhosts.saturating_add(1);
            }
            if vhost.pingora_cache_lock.is_some() {
                totals.lock_enabled_policies = totals.lock_enabled_policies.saturating_add(1);
            }
            accumulate_peer_fill_stats(&mut totals, &vhost.cache);
            let configured_routes = vhost.routes.len() as u64;
            totals.configured_routes = totals.configured_routes.saturating_add(configured_routes);

            let memory = vhost.pingora_memory_storage.map(|storage| storage.stats());
            let disk = vhost
                .pingora_disk_storage
                .map(|storage| storage.stats())
                .transpose()?;
            accumulate_cache_stats(&mut totals, memory.as_ref(), disk.as_ref());

            let mut routes = Vec::new();
            let mut enabled_routes = 0_u64;
            let mut tiered_routes = 0_u64;
            for route in &vhost.routes {
                let Some(cache) = &route.cache else {
                    continue;
                };
                totals.routes_total = totals.routes_total.saturating_add(1);
                if cache.config.enabled {
                    totals.enabled_routes = totals.enabled_routes.saturating_add(1);
                    enabled_routes = enabled_routes.saturating_add(1);
                }
                if cache.pingora_tiered_storage.is_some() {
                    totals.tiered_routes = totals.tiered_routes.saturating_add(1);
                    tiered_routes = tiered_routes.saturating_add(1);
                }
                if cache.pingora_cache_lock.is_some() {
                    totals.lock_enabled_policies = totals.lock_enabled_policies.saturating_add(1);
                }
                accumulate_peer_fill_stats(&mut totals, &cache.config);
                let route_memory = cache.pingora_memory_storage.map(|storage| storage.stats());
                let route_disk = cache
                    .pingora_disk_storage
                    .map(|storage| storage.stats())
                    .transpose()?;
                accumulate_cache_stats(&mut totals, route_memory.as_ref(), route_disk.as_ref());
                routes.push(CacheRouteStats {
                    name: cache.name.clone(),
                    enabled: cache.config.enabled,
                    tiered: cache.pingora_tiered_storage.is_some(),
                    lock_enabled: cache.pingora_cache_lock.is_some(),
                    lock_wait_timeout_secs: cache.cache_lock_wait_timeout.as_secs(),
                    peer_fill_enabled: cache.config.peer_fill.enabled,
                    peer_fill_peers: cache.config.peer_fill.peers.len(),
                    peer_fill_max_concurrent_requests: cache
                        .config
                        .peer_fill
                        .max_concurrent_requests,
                    peer_fill_fail_open: cache.config.peer_fill.fail_open,
                    memory: route_memory,
                    disk: route_disk,
                });
            }

            vhosts.push(CacheVhostStats {
                name: vhost.name.clone(),
                enabled: vhost.cache.enabled,
                tiered: vhost.pingora_tiered_storage.is_some(),
                lock_enabled: vhost.pingora_cache_lock.is_some(),
                lock_wait_timeout_secs: vhost.cache_lock_wait_timeout.as_secs(),
                peer_fill_enabled: vhost.cache.peer_fill.enabled,
                peer_fill_peers: vhost.cache.peer_fill.peers.len(),
                peer_fill_max_concurrent_requests: vhost.cache.peer_fill.max_concurrent_requests,
                peer_fill_fail_open: vhost.cache.peer_fill.fail_open,
                configured_routes,
                routes_total: routes.len() as u64,
                enabled_routes,
                tiered_routes,
                memory,
                disk,
                routes,
            });
        }
        Ok(CacheRuntimeStats { totals, vhosts })
    }

    #[cfg(feature = "cache")]
    pub fn reset_cache_activity(&self) -> CacheActivityResetResult {
        let mut result = CacheActivityResetResult {
            vhosts: 0,
            enabled_vhosts: 0,
            configured_routes: 0,
            routes_total: 0,
            enabled_routes: 0,
            memory_tiers: 0,
            disk_tiers: 0,
            tiered_vhosts: 0,
            tiered_routes: 0,
        };
        for vhost in &self.state.vhosts {
            result.vhosts = result.vhosts.saturating_add(1);
            if vhost.cache.enabled {
                result.enabled_vhosts = result.enabled_vhosts.saturating_add(1);
            }
            result.configured_routes = result
                .configured_routes
                .saturating_add(vhost.routes.len() as u64);
            if let Some(storage) = vhost.pingora_memory_storage {
                storage.reset_activity();
                result.memory_tiers = result.memory_tiers.saturating_add(1);
            }
            if let Some(storage) = vhost.pingora_disk_storage {
                storage.reset_activity();
                result.disk_tiers = result.disk_tiers.saturating_add(1);
            }
            if vhost.pingora_tiered_storage.is_some() {
                result.tiered_vhosts = result.tiered_vhosts.saturating_add(1);
            }
            for route in &vhost.routes {
                let Some(cache) = &route.cache else {
                    continue;
                };
                result.routes_total = result.routes_total.saturating_add(1);
                if cache.config.enabled {
                    result.enabled_routes = result.enabled_routes.saturating_add(1);
                }
                if let Some(storage) = cache.pingora_memory_storage {
                    storage.reset_activity();
                    result.memory_tiers = result.memory_tiers.saturating_add(1);
                }
                if let Some(storage) = cache.pingora_disk_storage {
                    storage.reset_activity();
                    result.disk_tiers = result.disk_tiers.saturating_add(1);
                }
                if cache.pingora_tiered_storage.is_some() {
                    result.tiered_routes = result.tiered_routes.saturating_add(1);
                }
            }
        }
        result
    }

    #[cfg(feature = "cache")]
    pub fn purge_image_cache(
        &self,
        request: CachePurgeRequest<'_>,
    ) -> io::Result<CachePurgeResult> {
        let vhost_index = if let Some(vhost_name) = request.vhost {
            self.state
                .vhosts
                .iter()
                .position(|vhost| vhost.name == vhost_name)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("vhost not found: {vhost_name}"),
                    )
                })?
        } else {
            self.state.vhost_index(Some(request.host))
        };
        let vhost = self.state.vhost(vhost_index);
        let route_cache = if let Some(route_name) = request.route {
            Some(
                vhost
                    .routes
                    .iter()
                    .filter_map(|route| route.cache.as_ref())
                    .find(|cache| cache.name == route_name)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("route cache not found: {}/{}", vhost.name, route_name),
                        )
                    })?,
            )
        } else {
            None
        };
        let cache_config = route_cache
            .map(|cache| &cache.config)
            .unwrap_or(&vhost.cache);
        let route_user_tag;
        let user_tag = if let Some(route_cache) = route_cache {
            route_user_tag = format!("{}:route:{}", vhost.name, route_cache.name);
            route_user_tag.as_str()
        } else {
            vhost.name.as_str()
        };
        let cache_request = crate::cache::CacheRequest {
            method: request.method,
            host: Some(request.host),
            path: request.path,
            query: request.query,
        };
        #[cfg(feature = "web")]
        let static_key =
            self.state
                .static_cache_key_for_purge_request(vhost, route_cache, &request);
        #[cfg(not(feature = "web"))]
        let static_key = None;
        let key = static_key
            .or_else(|| {
                crate::cache::pingora_image_cache_key(
                    "fluxheim-image-v1",
                    cache_config,
                    &cache_request,
                    user_tag,
                )
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    if route_cache.is_some() {
                        "request is not eligible for this route cache policy"
                    } else {
                        "request is not eligible for this vhost cache policy"
                    },
                )
            })?;
        let cache_key = key.combined();
        let mut memory_purged = route_cache
            .and_then(|cache| cache.pingora_memory_storage)
            .or(vhost
                .pingora_memory_storage
                .filter(|_| route_cache.is_none()))
            .is_some_and(|storage| storage.purge_cache_key(&key));
        let mut disk_purged = route_cache
            .and_then(|cache| cache.pingora_disk_storage)
            .or(vhost.pingora_disk_storage.filter(|_| route_cache.is_none()))
            .map(|storage| storage.purge_cache_key(&key))
            .transpose()?
            .unwrap_or(false);
        if cache_config.range.enabled && cache_config.range.slice.enabled {
            let slice_limit = usize::try_from(cache_config.range.slice.max_slices)
                .unwrap_or(usize::MAX.saturating_sub(4))
                .saturating_add(4);
            if let Some(storage) = route_cache
                .and_then(|cache| cache.pingora_memory_storage)
                .or(vhost
                    .pingora_memory_storage
                    .filter(|_| route_cache.is_none()))
            {
                memory_purged |= storage
                    .purge_indexed_path_exact(user_tag, request.path, slice_limit)
                    .purged
                    > 0;
            }
            if let Some(storage) = route_cache
                .and_then(|cache| cache.pingora_disk_storage)
                .or(vhost.pingora_disk_storage.filter(|_| route_cache.is_none()))
            {
                disk_purged |= storage
                    .purge_indexed_path_exact(user_tag, request.path, slice_limit)?
                    .purged
                    > 0;
            }
        }
        Ok(CachePurgeResult {
            vhost: vhost.name.clone(),
            route: route_cache.map(|cache| cache.name.clone()),
            host: request.host.to_owned(),
            method: request.method.to_owned(),
            path: request.path.to_owned(),
            query: request.query.map(str::to_owned),
            cache_key,
            memory_purged,
            disk_purged,
        })
    }

    #[cfg(feature = "cache")]
    pub fn purge_image_cache_bulk(
        &self,
        request: CacheBulkPurgeRequest<'_>,
    ) -> io::Result<CacheBulkPurgeResult> {
        if request.paths.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one cache purge path is required",
            ));
        }

        let mut results = Vec::with_capacity(request.paths.len());
        for path in request.paths {
            results.push(self.purge_image_cache(CachePurgeRequest {
                vhost: request.vhost,
                route: request.route,
                host: request.host,
                method: request.method,
                path,
                query: request.query,
            })?);
        }
        let vhost = results
            .first()
            .map(|result| result.vhost.clone())
            .unwrap_or_default();
        Ok(CacheBulkPurgeResult { vhost, results })
    }

    #[cfg(feature = "cache")]
    pub fn purge_indexed_image_cache(
        &self,
        request: CacheIndexedPurgeRequest<'_>,
    ) -> io::Result<CacheIndexedPurgeResult> {
        if request.limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache indexed purge limit must be greater than zero",
            ));
        }

        let vhost = self
            .state
            .vhosts
            .iter()
            .find(|vhost| vhost.name == request.vhost)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("vhost not found: {}", request.vhost),
                )
            })?;

        let route_cache = if let Some(route_name) = request.route {
            Some(
                vhost
                    .routes
                    .iter()
                    .filter_map(|route| route.cache.as_ref())
                    .find(|cache| cache.name == route_name)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("route cache not found: {}/{}", vhost.name, route_name),
                        )
                    })?,
            )
        } else {
            None
        };

        let user_tag = route_cache
            .map(|cache| format!("{}:route:{}", vhost.name, cache.name))
            .unwrap_or_else(|| vhost.name.clone());

        let memory = route_cache
            .and_then(|cache| cache.pingora_memory_storage)
            .or(vhost
                .pingora_memory_storage
                .filter(|_| route_cache.is_none()))
            .map(|storage| {
                if request.soft {
                    storage.soft_purge_indexed_user_tag(&user_tag, request.limit)
                } else {
                    Ok(storage.purge_indexed_user_tag(&user_tag, request.limit))
                }
            })
            .transpose()
            .map_err(|error| io::Error::other(error.to_string()))?
            .unwrap_or_default();
        let disk = route_cache
            .and_then(|cache| cache.pingora_disk_storage)
            .or(vhost.pingora_disk_storage.filter(|_| route_cache.is_none()))
            .map(|storage| {
                if request.soft {
                    storage
                        .soft_purge_indexed_user_tag(&user_tag, request.limit)
                        .map_err(|error| io::Error::other(error.to_string()))
                } else {
                    storage.purge_indexed_user_tag(&user_tag, request.limit)
                }
            })
            .transpose()?
            .unwrap_or_default();

        Ok(CacheIndexedPurgeResult {
            vhost: vhost.name.clone(),
            route: route_cache.map(|cache| cache.name.clone()),
            memory_matched: memory.matched,
            memory_purged: memory.purged,
            memory_truncated: memory.truncated,
            disk_matched: disk.matched,
            disk_purged: disk.purged,
            disk_truncated: disk.truncated,
        })
    }

    #[cfg(feature = "cache")]
    pub fn purge_indexed_image_cache_path_prefix(
        &self,
        request: CacheIndexedPathPrefixPurgeRequest<'_>,
    ) -> io::Result<CacheIndexedPurgeResult> {
        if request.limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache indexed purge limit must be greater than zero",
            ));
        }
        if !request.path_prefix.starts_with('/') || request.path_prefix == "/" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache indexed path-prefix purge requires a non-root path prefix",
            ));
        }

        let vhost = self
            .state
            .vhosts
            .iter()
            .find(|vhost| vhost.name == request.vhost)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("vhost not found: {}", request.vhost),
                )
            })?;

        let route_cache = if let Some(route_name) = request.route {
            Some(
                vhost
                    .routes
                    .iter()
                    .filter_map(|route| route.cache.as_ref())
                    .find(|cache| cache.name == route_name)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("route cache not found: {}/{}", vhost.name, route_name),
                        )
                    })?,
            )
        } else {
            None
        };

        let user_tag = route_cache
            .map(|cache| format!("{}:route:{}", vhost.name, cache.name))
            .unwrap_or_else(|| vhost.name.clone());

        let memory = route_cache
            .and_then(|cache| cache.pingora_memory_storage)
            .or(vhost
                .pingora_memory_storage
                .filter(|_| route_cache.is_none()))
            .map(|storage| {
                if request.soft {
                    storage.soft_purge_indexed_path_prefix(
                        &user_tag,
                        request.path_prefix,
                        request.limit,
                    )
                } else {
                    Ok(storage.purge_indexed_path_prefix(
                        &user_tag,
                        request.path_prefix,
                        request.limit,
                    ))
                }
            })
            .transpose()
            .map_err(|error| io::Error::other(error.to_string()))?
            .unwrap_or_default();
        let disk = route_cache
            .and_then(|cache| cache.pingora_disk_storage)
            .or(vhost.pingora_disk_storage.filter(|_| route_cache.is_none()))
            .map(|storage| {
                if request.soft {
                    storage
                        .soft_purge_indexed_path_prefix(
                            &user_tag,
                            request.path_prefix,
                            request.limit,
                        )
                        .map_err(|error| io::Error::other(error.to_string()))
                } else {
                    storage.purge_indexed_path_prefix(&user_tag, request.path_prefix, request.limit)
                }
            })
            .transpose()?
            .unwrap_or_default();

        Ok(CacheIndexedPurgeResult {
            vhost: vhost.name.clone(),
            route: route_cache.map(|cache| cache.name.clone()),
            memory_matched: memory.matched,
            memory_purged: memory.purged,
            memory_truncated: memory.truncated,
            disk_matched: disk.matched,
            disk_purged: disk.purged,
            disk_truncated: disk.truncated,
        })
    }

    #[cfg(feature = "cache")]
    pub fn purge_indexed_image_cache_tag(
        &self,
        request: CacheIndexedTagPurgeRequest<'_>,
    ) -> io::Result<CacheIndexedPurgeResult> {
        if request.limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache indexed purge limit must be greater than zero",
            ));
        }
        if request.cache_tag.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache tag purge requires a non-empty cache tag",
            ));
        }

        let vhost = self
            .state
            .vhosts
            .iter()
            .find(|vhost| vhost.name == request.vhost)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("vhost not found: {}", request.vhost),
                )
            })?;

        let route_cache = if let Some(route_name) = request.route {
            Some(
                vhost
                    .routes
                    .iter()
                    .filter_map(|route| route.cache.as_ref())
                    .find(|cache| cache.name == route_name)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("route cache not found: {}/{}", vhost.name, route_name),
                        )
                    })?,
            )
        } else {
            None
        };

        let user_tag = route_cache
            .map(|cache| format!("{}:route:{}", vhost.name, cache.name))
            .unwrap_or_else(|| vhost.name.clone());

        let memory =
            route_cache
                .and_then(|cache| cache.pingora_memory_storage)
                .or(vhost
                    .pingora_memory_storage
                    .filter(|_| route_cache.is_none()))
                .map(|storage| {
                    if request.soft {
                        storage.soft_purge_indexed_cache_tag(
                            &user_tag,
                            request.cache_tag,
                            request.limit,
                        )
                    } else {
                        Ok(storage.purge_indexed_cache_tag(
                            &user_tag,
                            request.cache_tag,
                            request.limit,
                        ))
                    }
                })
                .transpose()
                .map_err(|error| io::Error::other(error.to_string()))?
                .unwrap_or_default();
        let disk = route_cache
            .and_then(|cache| cache.pingora_disk_storage)
            .or(vhost.pingora_disk_storage.filter(|_| route_cache.is_none()))
            .map(|storage| {
                if request.soft {
                    storage
                        .soft_purge_indexed_cache_tag(&user_tag, request.cache_tag, request.limit)
                        .map_err(|error| io::Error::other(error.to_string()))
                } else {
                    storage.purge_indexed_cache_tag(&user_tag, request.cache_tag, request.limit)
                }
            })
            .transpose()?
            .unwrap_or_default();

        Ok(CacheIndexedPurgeResult {
            vhost: vhost.name.clone(),
            route: route_cache.map(|cache| cache.name.clone()),
            memory_matched: memory.matched,
            memory_purged: memory.purged,
            memory_truncated: memory.truncated,
            disk_matched: disk.matched,
            disk_purged: disk.purged,
            disk_truncated: disk.truncated,
        })
    }

    #[cfg(feature = "cache")]
    pub fn purge_stale_image_cache(
        &self,
        request: CacheStalePurgeRequest<'_>,
    ) -> io::Result<CacheStalePurgeResult> {
        if request.limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache stale purge limit must be greater than zero",
            ));
        }

        let vhost = self
            .state
            .vhosts
            .iter()
            .find(|vhost| vhost.name == request.vhost)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("vhost not found: {}", request.vhost),
                )
            })?;

        let route_cache = if let Some(route_name) = request.route {
            Some(
                vhost
                    .routes
                    .iter()
                    .filter_map(|route| route.cache.as_ref())
                    .find(|cache| cache.name == route_name)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("route cache not found: {}/{}", vhost.name, route_name),
                        )
                    })?,
            )
        } else {
            None
        };

        let user_tag = route_cache
            .map(|cache| format!("{}:route:{}", vhost.name, cache.name))
            .unwrap_or_else(|| vhost.name.clone());

        let memory = route_cache
            .and_then(|cache| cache.pingora_memory_storage)
            .or(vhost
                .pingora_memory_storage
                .filter(|_| route_cache.is_none()))
            .map(|storage| {
                storage.purge_indexed_stale_user_tag(&user_tag, request.limit, request.dry_run)
            })
            .transpose()
            .map_err(|error| io::Error::other(error.to_string()))?
            .unwrap_or_default();
        let disk = route_cache
            .and_then(|cache| cache.pingora_disk_storage)
            .or(vhost.pingora_disk_storage.filter(|_| route_cache.is_none()))
            .map(|storage| {
                storage.purge_indexed_stale_user_tag(&user_tag, request.limit, request.dry_run)
            })
            .transpose()
            .map_err(|error| io::Error::other(error.to_string()))?
            .unwrap_or_default();

        Ok(CacheStalePurgeResult {
            vhost: vhost.name.clone(),
            route: route_cache.map(|cache| cache.name.clone()),
            memory_scanned: memory.scanned,
            memory_stale: memory.stale,
            memory_purged: memory.purged,
            memory_truncated: memory.truncated,
            disk_scanned: disk.scanned,
            disk_stale: disk.stale,
            disk_purged: disk.purged,
            disk_truncated: disk.truncated,
        })
    }

    #[cfg(feature = "cache")]
    pub fn purge_stale_disk_cache_once(
        &self,
        limit: usize,
        batches: usize,
    ) -> io::Result<CacheBackgroundPurgeResult> {
        if limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache stale disk purge limit must be greater than zero",
            ));
        }
        if batches == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache stale disk purge batches must be greater than zero",
            ));
        }

        let mut result = CacheBackgroundPurgeResult::default();
        for vhost in &self.state.vhosts {
            if let Some(storage) = vhost.pingora_disk_storage {
                purge_stale_disk_storage_batches(
                    storage,
                    &vhost.name,
                    limit,
                    batches,
                    &mut result,
                )?;
            }

            for route in &vhost.routes {
                let Some(cache) = &route.cache else {
                    continue;
                };
                let Some(storage) = cache.pingora_disk_storage else {
                    continue;
                };
                let user_tag = format!("{}:route:{}", vhost.name, cache.name);
                purge_stale_disk_storage_batches(storage, &user_tag, limit, batches, &mut result)?;
            }
        }

        Ok(result)
    }

    #[cfg(feature = "cache")]
    pub fn purge_indexed_image_cache_path_pattern(
        &self,
        request: CacheIndexedPathPatternPurgeRequest<'_>,
    ) -> io::Result<CacheIndexedPurgeResult> {
        if request.limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache indexed purge limit must be greater than zero",
            ));
        }
        if !request.path_pattern.starts_with('/')
            || !request.path_pattern.contains('*')
            || request
                .path_pattern
                .chars()
                .filter(|character| *character != '*')
                .collect::<String>()
                == "/"
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache indexed wildcard purge requires a non-root absolute path pattern",
            ));
        }

        let vhost = self
            .state
            .vhosts
            .iter()
            .find(|vhost| vhost.name == request.vhost)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("vhost not found: {}", request.vhost),
                )
            })?;

        let route_cache = if let Some(route_name) = request.route {
            Some(
                vhost
                    .routes
                    .iter()
                    .filter_map(|route| route.cache.as_ref())
                    .find(|cache| cache.name == route_name)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("route cache not found: {}/{}", vhost.name, route_name),
                        )
                    })?,
            )
        } else {
            None
        };

        let user_tag = route_cache
            .map(|cache| format!("{}:route:{}", vhost.name, cache.name))
            .unwrap_or_else(|| vhost.name.clone());

        let memory = route_cache
            .and_then(|cache| cache.pingora_memory_storage)
            .or(vhost
                .pingora_memory_storage
                .filter(|_| route_cache.is_none()))
            .map(|storage| {
                if request.soft {
                    storage.soft_purge_indexed_path_pattern(
                        &user_tag,
                        request.path_pattern,
                        request.limit,
                    )
                } else {
                    Ok(storage.purge_indexed_path_pattern(
                        &user_tag,
                        request.path_pattern,
                        request.limit,
                    ))
                }
            })
            .transpose()
            .map_err(|error| io::Error::other(error.to_string()))?
            .unwrap_or_default();
        let disk = route_cache
            .and_then(|cache| cache.pingora_disk_storage)
            .or(vhost.pingora_disk_storage.filter(|_| route_cache.is_none()))
            .map(|storage| {
                if request.soft {
                    storage
                        .soft_purge_indexed_path_pattern(
                            &user_tag,
                            request.path_pattern,
                            request.limit,
                        )
                        .map_err(|error| io::Error::other(error.to_string()))
                } else {
                    storage.purge_indexed_path_pattern(
                        &user_tag,
                        request.path_pattern,
                        request.limit,
                    )
                }
            })
            .transpose()?
            .unwrap_or_default();

        Ok(CacheIndexedPurgeResult {
            vhost: vhost.name.clone(),
            route: route_cache.map(|cache| cache.name.clone()),
            memory_matched: memory.matched,
            memory_purged: memory.purged,
            memory_truncated: memory.truncated,
            disk_matched: disk.matched,
            disk_purged: disk.purged,
            disk_truncated: disk.truncated,
        })
    }
}

#[cfg(feature = "cache")]
fn cache_key_preview_ineligible_reason(
    cache_config: &crate::config::CacheConfig,
    request: &RequestHeader,
) -> String {
    if !cache_config.enabled {
        return "selected cache policy is disabled".to_owned();
    }
    if !cache_config.has_enabled_tier() {
        return "selected cache policy has no enabled storage tier".to_owned();
    }
    if proxy_cache_method_temporarily_bypassed(request.method.as_str()) {
        return format!(
            "method {} currently bypasses proxy cache storage",
            request.method
        );
    }
    if !cache_config
        .methods
        .iter()
        .any(|method| method == request.method.as_str())
    {
        return format!(
            "method {} is not allowed by selected cache policy",
            request.method
        );
    }
    if crate::cache::eligible_image_request(cache_config, &cache_request_from_header(request)) {
        "request is eligible but no cache key was generated".to_owned()
    } else {
        "path or query is not admitted by selected image cache policy".to_owned()
    }
}

#[cfg(feature = "cache")]
fn purge_stale_disk_storage_batches(
    storage: &'static crate::cache::PingoraDiskStorageBackend,
    user_tag: &str,
    limit: usize,
    batches: usize,
    result: &mut CacheBackgroundPurgeResult,
) -> io::Result<()> {
    result.targets = result.targets.saturating_add(1);

    for _ in 0..batches {
        let batch = storage
            .purge_indexed_stale_user_tag(user_tag, limit, false)
            .map_err(|error| io::Error::other(error.to_string()))?;
        result.scanned = result.scanned.saturating_add(batch.scanned);
        result.stale = result.stale.saturating_add(batch.stale);
        result.purged = result.purged.saturating_add(batch.purged);
        result.truncated |= batch.truncated;

        if !batch.truncated {
            break;
        }
    }

    Ok(())
}

#[cfg(feature = "cache")]
fn accumulate_cache_stats(
    totals: &mut CacheRuntimeTotals,
    memory: Option<&crate::cache::MemoryCacheStats>,
    disk: Option<&crate::cache::DiskCacheStats>,
) {
    if let Some(memory) = memory {
        totals.memory_tiers = totals.memory_tiers.saturating_add(1);
        totals.memory_entries = totals.memory_entries.saturating_add(memory.entries);
        totals.memory_weighted_size_bytes = totals
            .memory_weighted_size_bytes
            .saturating_add(memory.weighted_size_bytes);
        totals.memory_max_size_bytes = totals
            .memory_max_size_bytes
            .saturating_add(memory.max_size_bytes.as_u64());
        totals.memory_purge_index_entries = totals
            .memory_purge_index_entries
            .saturating_add(memory.purge_index_entries);
        totals.memory_purge_index_max_entries = totals
            .memory_purge_index_max_entries
            .saturating_add(memory.purge_index_max_entries);
        totals.hits = totals.hits.saturating_add(memory.activity.hits);
        totals.misses = totals.misses.saturating_add(memory.activity.misses);
        totals.stores = totals.stores.saturating_add(memory.activity.stores);
        totals.store_refusals = totals
            .store_refusals
            .saturating_add(memory.activity.store_refusals);
        totals.evictions = totals.evictions.saturating_add(memory.activity.evictions);
        totals.purges = totals.purges.saturating_add(memory.activity.purges);
    }

    if let Some(disk) = disk {
        totals.disk_tiers = totals.disk_tiers.saturating_add(1);
        totals.disk_entries = totals.disk_entries.saturating_add(disk.entries);
        totals.disk_size_bytes = totals.disk_size_bytes.saturating_add(disk.size_bytes);
        totals.disk_allocated_size_bytes = totals
            .disk_allocated_size_bytes
            .saturating_add(disk.allocated_size_bytes);
        totals.disk_free_size_bytes = totals
            .disk_free_size_bytes
            .saturating_add(disk.free_size_bytes);
        totals.disk_free_range_count = totals
            .disk_free_range_count
            .saturating_add(disk.free_range_count);
        totals.disk_largest_free_range_bytes = totals
            .disk_largest_free_range_bytes
            .max(disk.largest_free_range_bytes);
        totals.disk_bin_files = totals.disk_bin_files.saturating_add(disk.bin_files);
        totals.disk_max_size_bytes = totals
            .disk_max_size_bytes
            .saturating_add(disk.max_size_bytes.as_u64());
        totals.disk_purge_index_entries = totals
            .disk_purge_index_entries
            .saturating_add(disk.purge_index_entries);
        totals.disk_purge_index_max_entries = totals
            .disk_purge_index_max_entries
            .saturating_add(disk.purge_index_max_entries);
        totals.hits = totals.hits.saturating_add(disk.activity.hits);
        totals.misses = totals.misses.saturating_add(disk.activity.misses);
        totals.stores = totals.stores.saturating_add(disk.activity.stores);
        totals.store_refusals = totals
            .store_refusals
            .saturating_add(disk.activity.store_refusals);
        totals.evictions = totals.evictions.saturating_add(disk.activity.evictions);
        totals.purges = totals.purges.saturating_add(disk.activity.purges);
    }
}

#[cfg(feature = "cache")]
fn accumulate_peer_fill_stats(totals: &mut CacheRuntimeTotals, cache: &crate::config::CacheConfig) {
    if !cache.peer_fill.enabled {
        return;
    }
    totals.peer_fill_enabled_policies = totals.peer_fill_enabled_policies.saturating_add(1);
    totals.peer_fill_peers = totals
        .peer_fill_peers
        .saturating_add(cache.peer_fill.peers.len() as u64);
    totals.peer_fill_max_concurrent_requests = totals
        .peer_fill_max_concurrent_requests
        .max(cache.peer_fill.max_concurrent_requests as u64);
}

impl ProxyRuntimeState {
    fn from_config(config: &Config) -> io::Result<Self> {
        #[cfg(feature = "load-balancer")]
        {
            Self::from_config_with_load_balancers(config, |_name, proxy| {
                UpstreamLoadBalancer::from_proxy_config(proxy)
            })
        }

        #[cfg(not(feature = "load-balancer"))]
        {
            Self::from_config_without_load_balancers(config)
        }
    }
}

impl FluxProxy {
    #[cfg(feature = "load-balancer")]
    pub fn from_config_with_background_services(
        config: &Config,
    ) -> io::Result<(Self, Vec<UpstreamLoadBalancerService>)> {
        let mut services = Vec::new();
        let state = ProxyRuntimeState::from_config_with_load_balancers(config, |name, proxy| {
            let Some((load_balancer, service)) =
                UpstreamLoadBalancer::background_service_from_proxy_config(name, proxy)?
            else {
                return Ok(None);
            };

            services.push(service);
            Ok(Some(load_balancer))
        })?;
        let proxy = Self {
            state: Arc::new(ArcSwap::from_pointee(state)),
            health_reporter: Arc::new(ArcSwapOption::empty()),
        };

        Ok((proxy, services))
    }
}

impl ProxyRuntimeState {
    #[cfg(feature = "load-balancer")]
    fn from_config_with_load_balancers<F>(config: &Config, mut load_balancer: F) -> io::Result<Self>
    where
        F: FnMut(&str, &ProxyConfig) -> io::Result<Option<UpstreamLoadBalancer>>,
    {
        let mut vhosts = Vec::new();
        let mut host_index = HashMap::new();
        let mut wildcard_hosts = Vec::new();

        if config.vhosts.is_empty() {
            let runtime = RuntimeVhost::from_legacy(
                config.proxy.clone(),
                config.cache.clone(),
                config.headers.clone(),
                config.web.clone(),
                load_balancer("default", &config.proxy)?,
            )
            .map_err(|error| {
                io::Error::new(error.kind(), format!("default vhost runtime: {error}"))
            })?;
            vhosts.push(runtime);
        } else {
            for configured in &config.vhosts {
                let index = vhosts.len();
                let runtime = RuntimeVhost::from_config(
                    config,
                    configured,
                    &config.headers,
                    load_balancer(&configured.name, &configured.proxy)?,
                )
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("vhost {:?} runtime: {error}", configured.name),
                    )
                })?;
                for host in &runtime.hosts {
                    if let Some(suffix) = host.strip_prefix("*.") {
                        wildcard_hosts.push(WildcardHost {
                            suffix: suffix.to_owned(),
                            vhost_index: index,
                        });
                    } else {
                        host_index.insert(host.clone(), index);
                    }
                }
                vhosts.push(runtime);
            }
        }

        wildcard_hosts.sort_by_key(|wildcard| Reverse(wildcard.suffix.len()));
        let default_vhost = config
            .server
            .default_vhost
            .as_ref()
            .and_then(|name| vhosts.iter().position(|vhost| &vhost.name == name))
            .unwrap_or(0);

        Ok(Self {
            vhosts,
            host_index,
            wildcard_hosts,
            default_vhost,
            trusted_proxies: parse_trusted_proxies(&config.server.trusted_proxies)?,
            limits: config.server.limits,
            https_redirect: config.server.https_redirect,
            host_routing: config.server.host_routing,
            #[cfg(feature = "otel-tracing")]
            tracing: config.tracing.clone(),
            #[cfg(feature = "otel-otlp")]
            trace_exporter: crate::otel_otlp::TraceExporter::from_config(&config.tracing.otlp)
                .map_err(|error| io::Error::new(error.kind(), format!("tracing.otlp: {error}")))?,
            #[cfg(not(feature = "privacy-mode"))]
            access_log: config.logging.access.clone(),
        })
    }

    #[cfg(not(feature = "load-balancer"))]
    fn from_config_without_load_balancers(config: &Config) -> io::Result<Self> {
        let mut vhosts = Vec::new();
        let mut host_index = HashMap::new();
        let mut wildcard_hosts = Vec::new();

        if config.vhosts.is_empty() {
            let runtime = RuntimeVhost::from_legacy(
                config.proxy.clone(),
                config.cache.clone(),
                config.headers.clone(),
                config.web.clone(),
            )
            .map_err(|error| {
                io::Error::new(error.kind(), format!("default vhost runtime: {error}"))
            })?;
            vhosts.push(runtime);
        } else {
            for configured in &config.vhosts {
                let index = vhosts.len();
                let runtime = RuntimeVhost::from_config(config, configured, &config.headers)
                    .map_err(|error| {
                        io::Error::new(
                            error.kind(),
                            format!("vhost {:?} runtime: {error}", configured.name),
                        )
                    })?;
                for host in &runtime.hosts {
                    if let Some(suffix) = host.strip_prefix("*.") {
                        wildcard_hosts.push(WildcardHost {
                            suffix: suffix.to_owned(),
                            vhost_index: index,
                        });
                    } else {
                        host_index.insert(host.clone(), index);
                    }
                }
                vhosts.push(runtime);
            }
        }

        wildcard_hosts.sort_by_key(|wildcard| Reverse(wildcard.suffix.len()));
        let default_vhost = config
            .server
            .default_vhost
            .as_ref()
            .and_then(|name| vhosts.iter().position(|vhost| &vhost.name == name))
            .unwrap_or(0);

        Ok(Self {
            vhosts,
            host_index,
            wildcard_hosts,
            default_vhost,
            trusted_proxies: parse_trusted_proxies(&config.server.trusted_proxies)?,
            limits: config.server.limits,
            https_redirect: config.server.https_redirect,
            host_routing: config.server.host_routing,
            #[cfg(feature = "otel-tracing")]
            tracing: config.tracing.clone(),
            #[cfg(feature = "otel-otlp")]
            trace_exporter: crate::otel_otlp::TraceExporter::from_config(&config.tracing.otlp)
                .map_err(|error| io::Error::new(error.kind(), format!("tracing.otlp: {error}")))?,
            #[cfg(not(feature = "privacy-mode"))]
            access_log: config.logging.access.clone(),
        })
    }

    fn vhost_index(&self, host: Option<&str>) -> usize {
        self.resolve_vhost_index(host).unwrap_or(self.default_vhost)
    }

    fn request_vhost_index(
        &self,
        host: Option<&str>,
    ) -> std::result::Result<usize, HostRoutingRejectReason> {
        match self.resolve_vhost_index(host) {
            Ok(index) => Ok(index),
            Err(reason) if self.host_routing.strict => Err(reason),
            Err(_) => Ok(self.default_vhost),
        }
    }

    fn resolve_vhost_index(
        &self,
        host: Option<&str>,
    ) -> std::result::Result<usize, HostRoutingRejectReason> {
        let Some(host) = host else {
            return Err(HostRoutingRejectReason::Missing);
        };
        let Some(host) = normalize_host(host) else {
            return Err(HostRoutingRejectReason::Invalid);
        };

        if let Some(index) = self.host_index.get(&host) {
            return Ok(*index);
        }

        self.wildcard_hosts
            .iter()
            .find(|wildcard| wildcard.matches(&host))
            .map(|wildcard| wildcard.vhost_index)
            .ok_or(HostRoutingRejectReason::Unknown)
    }

    fn vhost(&self, index: usize) -> &RuntimeVhost {
        &self.vhosts[index]
    }

    fn trusted_proxy(&self, address: IpAddr) -> bool {
        self.trusted_proxies
            .iter()
            .any(|trusted_proxy| trusted_proxy.contains(address))
    }

    #[cfg(feature = "cache")]
    fn pingora_effective_cache_key_for_request_header(
        &self,
        request: &RequestHeader,
        vhost_index: usize,
        route_index: Option<usize>,
    ) -> Option<PingoraCacheKey> {
        #[cfg(feature = "web")]
        if let Some(key) =
            self.static_cache_key_for_request_header(request, vhost_index, route_index)
        {
            return Some(key);
        }
        let key =
            self.pingora_image_cache_key_for_request_header(request, vhost_index, route_index)?;
        let vhost = self.vhost(vhost_index);
        let cache_config = route_index
            .and_then(|index| vhost.route(index).cache.as_ref())
            .map(|cache| &cache.config)
            .unwrap_or(&vhost.cache);
        if let Some(range) = selected_cache_range_request(request, cache_config) {
            range_cache_key(key, range).ok()
        } else {
            Some(key)
        }
    }

    #[cfg(all(feature = "cache", feature = "web"))]
    fn static_cache_key_for_request_header(
        &self,
        request: &RequestHeader,
        vhost_index: usize,
        route_index: Option<usize>,
    ) -> Option<PingoraCacheKey> {
        if proxy_cache_method_temporarily_bypassed(request.method.as_str()) {
            return None;
        }
        let vhost = self.vhost(vhost_index);
        let route_cache = route_index.and_then(|index| vhost.route(index).cache.as_ref());
        let cache_config = route_cache
            .map(|cache| &cache.config)
            .unwrap_or(&vhost.cache);
        if !cache_config.local_static {
            return None;
        }

        let file = local_static_file_for_request(vhost, route_index, request.uri.path()).ok()??;
        let route_user_tag;
        let user_tag = if let Some(route_cache) = route_cache {
            route_user_tag = format!("{}:route:{}", vhost.name, route_cache.name);
            route_user_tag.as_str()
        } else {
            vhost.name.as_str()
        };
        static_cache_key_for_file_parts(
            request.method.as_str(),
            request_host_header(request),
            request.uri.path(),
            request.uri.query(),
            cache_config,
            user_tag,
            &file,
        )
    }

    #[cfg(all(feature = "cache", feature = "web"))]
    fn static_cache_key_for_purge_request(
        &self,
        vhost: &RuntimeVhost,
        route_cache: Option<&RuntimeRouteCache>,
        request: &CachePurgeRequest<'_>,
    ) -> Option<PingoraCacheKey> {
        let route_index = route_cache.and_then(|cache| {
            vhost.routes.iter().position(|route| {
                route
                    .cache
                    .as_ref()
                    .is_some_and(|candidate| candidate.name == cache.name)
            })
        });
        let cache_config = route_cache
            .map(|cache| &cache.config)
            .unwrap_or(&vhost.cache);
        if !cache_config.local_static {
            return None;
        }

        let file = local_static_file_for_request(vhost, route_index, request.path).ok()??;
        let route_user_tag;
        let user_tag = if let Some(route_cache) = route_cache {
            route_user_tag = format!("{}:route:{}", vhost.name, route_cache.name);
            route_user_tag.as_str()
        } else {
            vhost.name.as_str()
        };
        static_cache_key_for_file_parts(
            request.method,
            Some(request.host),
            request.path,
            request.query,
            cache_config,
            user_tag,
            &file,
        )
    }

    #[cfg(feature = "cache")]
    fn pingora_image_cache_key_for_request_header(
        &self,
        request: &RequestHeader,
        vhost_index: usize,
        route_index: Option<usize>,
    ) -> Option<PingoraCacheKey> {
        let vhost = self.vhost(vhost_index);
        let route_cache = route_index.and_then(|index| vhost.route(index).cache.as_ref());
        let cache_config = route_cache
            .map(|cache| &cache.config)
            .unwrap_or(&vhost.cache);
        if proxy_cache_method_temporarily_bypassed(request.method.as_str()) {
            return None;
        }
        let cache_request = cache_request_from_header(request);
        let route_user_tag;
        let user_tag = if let Some(route_cache) = route_cache {
            route_user_tag = format!("{}:route:{}", vhost.name, route_cache.name);
            route_user_tag.as_str()
        } else {
            vhost.name.as_str()
        };
        crate::cache::pingora_image_cache_key(
            "fluxheim-image-v1",
            cache_config,
            &cache_request,
            user_tag,
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct WildcardHost {
    suffix: String,
    vhost_index: usize,
}

impl WildcardHost {
    fn matches(&self, host: &str) -> bool {
        let Some(prefix) = host.strip_suffix(self.suffix.as_str()) else {
            return false;
        };

        prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.')
    }
}

#[derive(Clone)]
struct RuntimeVhost {
    name: String,
    hosts: Vec<String>,
    max_request_body_bytes: Option<crate::config::ByteSize>,
    proxy: RuntimeProxy,
    request_headers: crate::config::RequestHeaderPolicyConfig,
    response_headers: crate::config::ResponseHeaderPolicyConfig,
    #[cfg(feature = "cache")]
    cache: crate::config::CacheConfig,
    #[cfg(feature = "cache")]
    memory_cache: Option<crate::cache::MemoryImageCache>,
    #[cfg(feature = "cache")]
    pingora_memory_storage: Option<&'static crate::cache::PingoraMemoryStorage>,
    #[cfg(feature = "cache")]
    pingora_disk_storage: Option<&'static crate::cache::PingoraDiskStorageBackend>,
    #[cfg(feature = "cache")]
    pingora_tiered_storage: Option<&'static crate::cache::PingoraTieredStorage>,
    #[cfg(feature = "cache")]
    pingora_cache_lock: Option<&'static CacheKeyLockImpl>,
    #[cfg(feature = "cache")]
    pingora_cache_predictor: Option<&'static (dyn CacheablePredictor + Sync)>,
    #[cfg(feature = "cache")]
    cache_lock_wait_timeout: std::time::Duration,
    #[cfg(feature = "load-balancer")]
    load_balancer: Option<UpstreamLoadBalancer>,
    #[cfg(feature = "web")]
    web: Option<StaticFileServer>,
    #[cfg(feature = "php-fpm")]
    php: Option<RuntimePhp>,
    routes: Vec<RuntimeRoute>,
}

impl std::fmt::Debug for RuntimeVhost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("RuntimeVhost");
        debug
            .field("name", &self.name)
            .field("hosts", &self.hosts)
            .field("max_request_body_bytes", &self.max_request_body_bytes)
            .field("proxy", &self.proxy)
            .field("request_headers", &self.request_headers)
            .field("response_headers", &self.response_headers);

        #[cfg(feature = "cache")]
        debug
            .field("cache", &self.cache)
            .field("memory_cache", &self.memory_cache)
            .field(
                "pingora_memory_storage",
                &self.pingora_memory_storage.is_some(),
            )
            .field("pingora_disk_storage", &self.pingora_disk_storage.is_some())
            .field(
                "pingora_tiered_storage",
                &self.pingora_tiered_storage.is_some(),
            )
            .field("pingora_cache_lock", &self.pingora_cache_lock.is_some())
            .field(
                "pingora_cache_predictor",
                &self.pingora_cache_predictor.is_some(),
            )
            .field("cache_lock_wait_timeout", &self.cache_lock_wait_timeout);

        #[cfg(feature = "load-balancer")]
        debug.field("load_balancer", &self.load_balancer);

        #[cfg(feature = "web")]
        debug.field("web", &self.web);
        #[cfg(feature = "php-fpm")]
        debug.field("php", &self.php);
        debug.field("routes", &self.routes);

        debug.finish()
    }
}

#[derive(Debug, Clone)]
struct RuntimeRoute {
    matcher: RuntimeRouteMatcher,
    https_redirect_exempt: bool,
    strip_prefix: Option<String>,
    max_request_body_bytes: Option<crate::config::ByteSize>,
    action: RuntimeRouteAction,
    #[cfg(feature = "cache")]
    cache: Option<RuntimeRouteCache>,
    request_headers: crate::config::RequestHeaderPolicyConfig,
    response_headers: crate::config::ResponseHeaderPolicyConfig,
}

#[cfg(feature = "cache")]
#[derive(Clone)]
struct RuntimeRouteCache {
    name: String,
    config: crate::config::CacheConfig,
    memory_cache: Option<crate::cache::MemoryImageCache>,
    pingora_memory_storage: Option<&'static crate::cache::PingoraMemoryStorage>,
    pingora_disk_storage: Option<&'static crate::cache::PingoraDiskStorageBackend>,
    pingora_tiered_storage: Option<&'static crate::cache::PingoraTieredStorage>,
    pingora_cache_lock: Option<&'static CacheKeyLockImpl>,
    pingora_cache_predictor: Option<&'static (dyn CacheablePredictor + Sync)>,
    cache_lock_wait_timeout: std::time::Duration,
}

#[cfg(feature = "cache")]
impl std::fmt::Debug for RuntimeRouteCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeRouteCache")
            .field("name", &self.name)
            .field("config", &self.config)
            .field("memory_cache", &self.memory_cache)
            .field(
                "pingora_memory_storage",
                &self.pingora_memory_storage.is_some(),
            )
            .field("pingora_disk_storage", &self.pingora_disk_storage.is_some())
            .field(
                "pingora_tiered_storage",
                &self.pingora_tiered_storage.is_some(),
            )
            .field("pingora_cache_lock", &self.pingora_cache_lock.is_some())
            .field(
                "pingora_cache_predictor",
                &self.pingora_cache_predictor.is_some(),
            )
            .field("cache_lock_wait_timeout", &self.cache_lock_wait_timeout)
            .finish()
    }
}

#[cfg(feature = "cache")]
impl RuntimeRouteCache {
    fn from_config(
        vhost_name: &str,
        name: &str,
        config: &crate::config::CacheConfig,
    ) -> io::Result<Self> {
        let pingora_memory_storage =
            crate::cache::pingora_memory_storage_from_config_with_metric_scope(
                config,
                vhost_name,
                Some(name),
            );
        let pingora_disk_storage =
            crate::cache::pingora_disk_storage_backend_from_config_with_metric_scope(
                config,
                vhost_name,
                Some(name),
            )
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("vhost {vhost_name:?} route {name:?} cache.disk: {error}"),
                )
            })?;
        let pingora_tiered_storage = pingora_memory_storage
            .zip(pingora_disk_storage)
            .map(|(memory, disk)| crate::cache::pingora_tiered_storage_from_parts(memory, disk));
        let pingora_cache_lock = cache_lock_from_config(
            config,
            pingora_memory_storage.is_some() || pingora_disk_storage.is_some(),
        );
        let pingora_cache_predictor = cache_predictor_from_config(
            config,
            pingora_memory_storage.is_some() || pingora_disk_storage.is_some(),
        );

        Ok(Self {
            name: name.to_owned(),
            config: config.clone(),
            memory_cache: crate::cache::memory_image_cache_from_config(config),
            pingora_memory_storage,
            pingora_disk_storage,
            pingora_tiered_storage,
            pingora_cache_lock,
            pingora_cache_predictor,
            cache_lock_wait_timeout: cache_lock_wait_timeout(config),
        })
    }

    fn storage(&self) -> Option<&'static (dyn pingora::cache::Storage + Sync)> {
        if let Some(storage) = self.pingora_tiered_storage {
            Some(storage)
        } else if let Some(storage) = self.pingora_memory_storage {
            Some(storage)
        } else {
            self.pingora_disk_storage
                .map(|storage| storage as &'static (dyn pingora::cache::Storage + Sync))
        }
    }
}

#[cfg(feature = "cache")]
fn cache_lock_from_config(
    config: &crate::config::CacheConfig,
    has_storage: bool,
) -> Option<&'static CacheKeyLockImpl> {
    (has_storage && config.lock.enabled).then(|| {
        crate::cache::pingora_cache_lock(std::time::Duration::from_secs(
            config.lock.age_timeout_secs,
        ))
    })
}

#[cfg(feature = "cache")]
fn cache_lock_wait_timeout(config: &crate::config::CacheConfig) -> std::time::Duration {
    std::time::Duration::from_secs(config.lock.wait_timeout_secs)
}

#[cfg(feature = "cache")]
fn cache_predictor_from_config(
    config: &crate::config::CacheConfig,
    has_storage: bool,
) -> Option<&'static (dyn CacheablePredictor + Sync)> {
    if !has_storage || !config.predictor.enabled {
        return None;
    }
    let shard_capacity = config
        .predictor
        .capacity
        .div_ceil(CACHE_PREDICTOR_SHARDS)
        .max(1);
    Some(Box::leak(Box::new(FluxCachePredictor::new(
        shard_capacity,
        Some(skip_fluxheim_predictor_custom_reason),
    ))) as &'static (dyn CacheablePredictor + Sync))
}

#[cfg(feature = "cache")]
fn skip_fluxheim_predictor_custom_reason(_reason: &'static str) -> bool {
    true
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum RuntimeRouteMatcher {
    Exact(String),
    Prefix(String),
    Fallback,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum RuntimeRouteAction {
    Redirect(RouteRedirectConfig),
    Proxy(RuntimeProxy),
    #[cfg(feature = "acme")]
    AcmeHttp01(crate::acme::AcmeHttp01ChallengeStore),
    #[cfg(feature = "web")]
    Web(StaticFileServer),
    #[cfg(feature = "php-fpm")]
    Php(RuntimePhp),
}

#[derive(Debug, Clone)]
struct RuntimeProxy {
    enabled: bool,
    config: ProxyConfig,
    error_pages: Vec<RuntimeErrorPage>,
}

#[cfg(feature = "php-fpm")]
#[derive(Debug, Clone)]
struct RuntimePhp {
    config: crate::config::PhpConfig,
    root: std::path::PathBuf,
    fpm_root: std::path::PathBuf,
    files: StaticFileServer,
    error_pages: Vec<RuntimeErrorPage>,
    pool: Option<Arc<PhpFpmPool>>,
}

#[cfg(feature = "php-fpm")]
struct PhpFpmPool {
    endpoint: PhpFpmEndpoint,
    metric_vhost: String,
    metric_pool: String,
    max_idle: usize,
    idle_timeout: Duration,
    idle: tokio::sync::Mutex<Vec<PhpFpmPoolEntry>>,
}

#[cfg(feature = "php-fpm")]
impl std::fmt::Debug for PhpFpmPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PhpFpmPool")
            .field("endpoint", &self.endpoint)
            .field("metric_vhost", &self.metric_vhost)
            .field("metric_pool", &self.metric_pool)
            .field("max_idle", &self.max_idle)
            .field("idle_timeout", &self.idle_timeout)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "php-fpm")]
#[derive(Debug, Clone)]
enum PhpFpmEndpoint {
    Tcp(String),
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

#[cfg(feature = "php-fpm")]
struct PhpFpmPoolEntry {
    client: PhpFpmPooledClient,
    last_used: Instant,
}

#[cfg(feature = "php-fpm")]
enum PhpFpmPooledClient {
    Tcp(
        fastcgi_client::Client<
            fastcgi_client::io::TokioCompat<tokio::net::TcpStream>,
            fastcgi_client::conn::KeepAlive,
        >,
    ),
    #[cfg(unix)]
    Unix(
        fastcgi_client::Client<
            fastcgi_client::io::TokioCompat<tokio::net::UnixStream>,
            fastcgi_client::conn::KeepAlive,
        >,
    ),
}

#[cfg(feature = "web")]
#[derive(Debug, Clone)]
struct RuntimeErrorPage {
    status: u16,
    path: String,
    web: StaticFileServer,
}

#[cfg(not(feature = "web"))]
#[derive(Debug, Clone)]
struct RuntimeErrorPage {
    status: u16,
}

impl RuntimeProxy {
    fn from_config(config: &ProxyConfig, scope: &str) -> io::Result<Self> {
        let error_pages = config
            .error_pages
            .iter()
            .map(|error_page| RuntimeErrorPage::from_config(scope, error_page))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            enabled: config.has_configured_upstream(),
            config: config.clone(),
            error_pages,
        })
    }

    fn error_page(&self, status: u16) -> Option<&RuntimeErrorPage> {
        self.error_pages.iter().find(|page| page.status == status)
    }
}

#[cfg(feature = "php-fpm")]
impl RuntimePhp {
    fn from_config(
        scope: impl std::fmt::Display,
        metric_vhost: &str,
        metric_pool: &str,
        config: &crate::config::PhpConfig,
    ) -> io::Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }
        let scope = scope.to_string();
        let root = config.root.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{scope}: enabled PHP requires php.root"),
            )
        })?;
        let root_metadata = std::fs::symlink_metadata(root).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("{scope}: php root {}: {error}", root.display()),
            )
        })?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{scope}: php root is not a real directory: {}",
                    root.display()
                ),
            ));
        }
        let root = root.canonicalize().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("{scope}: php root {}: {error}", root.display()),
            )
        })?;
        let fpm_root = config.fpm_root.clone().unwrap_or_else(|| root.clone());
        let files = StaticFileServer::from_config(&crate::config::WebConfig {
            root: Some(root.clone()),
            index_files: vec![config.index.clone()],
            deny_dotfiles: true,
            directory_listing: crate::config::DirectoryListingConfig::default(),
            cache_control: "private, no-store".to_owned(),
            expires: None,
        })
        .map_err(|error| io::Error::new(error.kind(), format!("{scope}: {error}")))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{scope}: enabled PHP requires php.root"),
            )
        })?;
        let error_pages = config
            .error_pages
            .iter()
            .map(|error_page| RuntimeErrorPage::from_config(&scope, error_page))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Some(Self {
            pool: PhpFpmPool::from_config(&config.fpm, metric_vhost, metric_pool).map(Arc::new),
            config: config.clone(),
            root,
            fpm_root,
            files,
            error_pages,
        }))
    }

    fn error_page(&self, status: u16) -> Option<&RuntimeErrorPage> {
        self.error_pages.iter().find(|page| page.status == status)
    }
}

#[cfg(feature = "php-fpm")]
impl PhpFpmPool {
    fn from_config(
        config: &crate::config::PhpFpmConfig,
        metric_vhost: &str,
        metric_pool: &str,
    ) -> Option<Self> {
        if !config.keepalive {
            return None;
        }
        let endpoint = if let Some(address) = config.tcp.as_deref() {
            PhpFpmEndpoint::Tcp(address.to_owned())
        } else if let Some(socket) = config.socket.as_deref() {
            #[cfg(unix)]
            {
                PhpFpmEndpoint::Unix(socket.to_path_buf())
            }
            #[cfg(not(unix))]
            {
                let _ = socket;
                return None;
            }
        } else {
            return None;
        };
        Some(Self {
            endpoint,
            metric_vhost: metric_vhost.to_owned(),
            metric_pool: metric_pool.to_owned(),
            max_idle: config.pool_max_idle,
            idle_timeout: Duration::from_secs(config.idle_timeout_secs),
            idle: tokio::sync::Mutex::new(Vec::new()),
        })
    }

    fn record_pool_event(&self, event: &str) {
        #[cfg(feature = "metrics")]
        crate::metrics::record_php_fpm_pool_event(&self.metric_vhost, &self.metric_pool, event);
        let _ = event;
    }

    fn record_pool_idle(&self, idle_connections: usize) {
        #[cfg(feature = "metrics")]
        crate::metrics::record_php_fpm_pool_idle(
            &self.metric_vhost,
            &self.metric_pool,
            idle_connections,
        );
        let _ = idle_connections;
    }

    async fn execute(
        &self,
        params: fastcgi_client::Params<'_>,
        body: Vec<u8>,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> io::Result<fastcgi_client::Response> {
        let mut entry = self.checkout(connect_timeout).await?;
        let result = entry.execute(params, body, request_timeout).await;
        if result.is_ok() {
            self.checkin(entry).await;
        }
        result
    }

    async fn checkout(&self, connect_timeout: Duration) -> io::Result<PhpFpmPoolEntry> {
        let now = Instant::now();
        {
            let mut idle = self.idle.lock().await;
            let before_retain = idle.len();
            idle.retain(|entry| now.duration_since(entry.last_used) <= self.idle_timeout);
            if before_retain > idle.len() {
                self.record_pool_event("drop_stale");
            }
            if let Some(entry) = idle.pop() {
                self.record_pool_event("reuse");
                self.record_pool_idle(idle.len());
                return Ok(entry);
            }
            self.record_pool_idle(idle.len());
        }
        let client = self.connect_client(connect_timeout).await?;
        self.record_pool_event("connect");
        Ok(PhpFpmPoolEntry {
            client,
            last_used: now,
        })
    }

    async fn checkin(&self, mut entry: PhpFpmPoolEntry) {
        entry.last_used = Instant::now();
        let mut idle = self.idle.lock().await;
        let before_retain = idle.len();
        idle.retain(|entry| entry.last_used.elapsed() <= self.idle_timeout);
        if before_retain > idle.len() {
            self.record_pool_event("drop_stale");
        }
        if idle.len() < self.max_idle {
            idle.push(entry);
            self.record_pool_event("return");
        } else {
            self.record_pool_event("discard_full");
        }
        self.record_pool_idle(idle.len());
    }

    async fn connect_client(&self, timeout: Duration) -> io::Result<PhpFpmPooledClient> {
        match &self.endpoint {
            PhpFpmEndpoint::Tcp(address) => {
                let stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "php-fpm connect timed out")
                    })??;
                Ok(PhpFpmPooledClient::Tcp(
                    fastcgi_client::Client::new_keep_alive_tokio(stream),
                ))
            }
            #[cfg(unix)]
            PhpFpmEndpoint::Unix(socket) => {
                let stream = tokio::time::timeout(timeout, tokio::net::UnixStream::connect(socket))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "php-fpm socket connect timed out")
                    })??;
                Ok(PhpFpmPooledClient::Unix(
                    fastcgi_client::Client::new_keep_alive_tokio(stream),
                ))
            }
        }
    }
}

#[cfg(feature = "php-fpm")]
impl PhpFpmPoolEntry {
    async fn execute(
        &mut self,
        params: fastcgi_client::Params<'_>,
        body: Vec<u8>,
        timeout: Duration,
    ) -> io::Result<fastcgi_client::Response> {
        self.client.execute(params, body, timeout).await
    }
}

#[cfg(feature = "php-fpm")]
impl PhpFpmPooledClient {
    async fn execute(
        &mut self,
        params: fastcgi_client::Params<'_>,
        body: Vec<u8>,
        timeout: Duration,
    ) -> io::Result<fastcgi_client::Response> {
        let request = fastcgi_client::Request::new(params, fastcgi_client::io::Cursor::new(body));
        match self {
            Self::Tcp(client) => tokio::time::timeout(timeout, client.execute(request))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "php-fpm request timed out"))?
                .map_err(|error| io::Error::other(error.to_string())),
            #[cfg(unix)]
            Self::Unix(client) => tokio::time::timeout(timeout, client.execute(request))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "php-fpm request timed out"))?
                .map_err(|error| io::Error::other(error.to_string())),
        }
    }
}

impl RuntimeErrorPage {
    fn from_config(scope: &str, config: &crate::config::ProxyErrorPageConfig) -> io::Result<Self> {
        #[cfg(feature = "web")]
        {
            let web = static_file_server_from_config(
                format!("{scope} error page status {} web", config.status),
                &config.web,
            )?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "proxy error page for status {} requires web.root",
                        config.status
                    ),
                )
            })?;
            Ok(Self {
                status: config.status,
                path: config.path.clone(),
                web,
            })
        }

        #[cfg(not(feature = "web"))]
        {
            let _ = scope;
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "proxy error page for status {} requires the web feature",
                    config.status
                ),
            ))
        }
    }
}

impl RuntimeRoute {
    fn from_config(
        vhost_name: &str,
        route: &crate::config::RouteConfig,
        base_headers: &crate::config::HeaderPolicyConfig,
    ) -> io::Result<Self> {
        #[cfg(not(feature = "cache"))]
        let _ = vhost_name;

        let headers = base_headers.with_vhost_overlay(&route.headers);
        let matcher = if let Some(path) = &route.path_exact {
            RuntimeRouteMatcher::Exact(path.clone())
        } else if let Some(path) = &route.path_prefix {
            RuntimeRouteMatcher::Prefix(path.clone())
        } else {
            RuntimeRouteMatcher::Fallback
        };
        let action = if let Some(redirect) = &route.redirect {
            RuntimeRouteAction::Redirect(redirect.clone())
        } else if let Some(proxy) = &route.proxy {
            if !proxy.has_configured_upstream() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "vhost {vhost_name:?} route {:?} proxy requires upstream or upstreams",
                        route.name
                    ),
                ));
            }
            let proxy_scope = format!("vhost {vhost_name:?} route {:?} proxy", route.name);
            RuntimeRouteAction::Proxy(RuntimeProxy::from_config(proxy, &proxy_scope)?)
        } else if let Some(web) = &route.web {
            #[cfg(feature = "web")]
            {
                let web = static_file_server_from_config(
                    format!("vhost {vhost_name:?} route {:?} web", route.name),
                    web,
                )?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "vhost {vhost_name:?} route {:?} static web action requires web.root",
                            route.name
                        ),
                    )
                })?;
                RuntimeRouteAction::Web(web)
            }
            #[cfg(not(feature = "web"))]
            {
                let _ = web;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("route {:?} requires the web feature", route.name),
                ));
            }
        } else if let Some(php) = &route.php {
            #[cfg(feature = "php-fpm")]
            {
                let php = RuntimePhp::from_config(
                    format!("vhost {vhost_name:?} route {:?} php", route.name),
                    vhost_name,
                    &route.name,
                    php,
                )?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "vhost {vhost_name:?} route {:?} PHP action requires php.enabled = true",
                            route.name
                        ),
                    )
                })?;
                RuntimeRouteAction::Php(php)
            }
            #[cfg(not(feature = "php-fpm"))]
            {
                let _ = php;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("route {:?} requires the php-fpm feature", route.name),
                ));
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("route {:?} has no runtime action", route.name),
            ));
        };

        Ok(Self {
            matcher,
            https_redirect_exempt: route.https_redirect_exempt,
            strip_prefix: route.strip_prefix.clone(),
            max_request_body_bytes: route.max_request_body_bytes,
            action,
            #[cfg(feature = "cache")]
            cache: route
                .cache
                .as_ref()
                .map(|cache| RuntimeRouteCache::from_config(vhost_name, &route.name, cache))
                .transpose()?,
            request_headers: headers.request,
            response_headers: headers.response,
        })
    }

    #[cfg(feature = "acme")]
    fn acme_http_01(
        vhost_name: &str,
        storage: &std::path::Path,
        base_headers: &crate::config::HeaderPolicyConfig,
    ) -> Self {
        Self {
            matcher: RuntimeRouteMatcher::Prefix("/.well-known/acme-challenge/".to_owned()),
            https_redirect_exempt: true,
            strip_prefix: None,
            max_request_body_bytes: None,
            action: RuntimeRouteAction::AcmeHttp01(crate::acme::AcmeHttp01ChallengeStore::new(
                storage, vhost_name,
            )),
            #[cfg(feature = "cache")]
            cache: None,
            request_headers: base_headers.request.clone(),
            response_headers: base_headers.response.clone(),
        }
    }
}

#[cfg(feature = "acme")]
fn managed_http_01_owner_vhost<'a>(
    config: &'a Config,
    request_vhost: &'a crate::config::VhostConfig,
) -> Option<&'a str> {
    if request_vhost.tls.enabled && request_vhost.tls.acme.enabled {
        return Some(&request_vhost.name);
    }

    let request_hosts: std::collections::HashSet<String> = request_vhost
        .hosts
        .iter()
        .filter_map(|host| normalize_host(host))
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
            let Some(domain) = normalize_host(domain) else {
                continue;
            };
            if request_hosts.contains(&domain) {
                return Some(candidate.name.as_str());
            }
        }

        None
    })
}

impl RuntimeVhost {
    fn route_index(&self, path: &str) -> Option<usize> {
        let mut fallback = None;
        let mut best_prefix: Option<(usize, usize)> = None;

        for (index, route) in self.routes.iter().enumerate() {
            match &route.matcher {
                RuntimeRouteMatcher::Exact(exact) if path == exact => return Some(index),
                RuntimeRouteMatcher::Prefix(prefix)
                    if path.starts_with(prefix)
                        && best_prefix.is_none_or(|(_, len)| prefix.len() > len) =>
                {
                    best_prefix = Some((index, prefix.len()));
                }
                RuntimeRouteMatcher::Fallback => fallback = Some(index),
                _ => {}
            }
        }

        best_prefix.map(|(index, _)| index).or(fallback)
    }

    fn route(&self, index: usize) -> &RuntimeRoute {
        &self.routes[index]
    }

    fn from_legacy(
        proxy: ProxyConfig,
        #[cfg_attr(not(feature = "cache"), allow(unused_variables))]
        cache: crate::config::CacheConfig,
        headers: crate::config::HeaderPolicyConfig,
        #[cfg_attr(not(feature = "web"), allow(unused_variables))] web: crate::config::WebConfig,
        #[cfg(feature = "load-balancer")] load_balancer: Option<UpstreamLoadBalancer>,
    ) -> io::Result<Self> {
        #[cfg(feature = "cache")]
        let pingora_memory_storage =
            crate::cache::pingora_memory_storage_from_config_with_metric_scope(
                &cache, "default", None,
            );
        #[cfg(feature = "cache")]
        let pingora_disk_storage =
            crate::cache::pingora_disk_storage_backend_from_config_with_metric_scope(
                &cache, "default", None,
            )
            .map_err(|error| {
                io::Error::new(error.kind(), format!("default vhost cache.disk: {error}"))
            })?;
        #[cfg(feature = "cache")]
        let pingora_tiered_storage = pingora_memory_storage
            .zip(pingora_disk_storage)
            .map(|(memory, disk)| crate::cache::pingora_tiered_storage_from_parts(memory, disk));
        #[cfg(feature = "cache")]
        let pingora_cache_lock = cache_lock_from_config(
            &cache,
            pingora_memory_storage.is_some() || pingora_disk_storage.is_some(),
        );
        #[cfg(feature = "cache")]
        let pingora_cache_predictor = cache_predictor_from_config(
            &cache,
            pingora_memory_storage.is_some() || pingora_disk_storage.is_some(),
        );

        Ok(Self {
            name: "default".to_owned(),
            hosts: vec![],
            max_request_body_bytes: None,
            #[cfg(feature = "load-balancer")]
            load_balancer,
            proxy: RuntimeProxy::from_config(&proxy, "default proxy")?,
            request_headers: headers.request,
            response_headers: headers.response,
            #[cfg(feature = "cache")]
            memory_cache: crate::cache::memory_image_cache_from_config(&cache),
            #[cfg(feature = "cache")]
            pingora_memory_storage,
            #[cfg(feature = "cache")]
            pingora_disk_storage,
            #[cfg(feature = "cache")]
            pingora_tiered_storage,
            #[cfg(feature = "cache")]
            pingora_cache_lock,
            #[cfg(feature = "cache")]
            pingora_cache_predictor,
            #[cfg(feature = "cache")]
            cache_lock_wait_timeout: cache_lock_wait_timeout(&cache),
            #[cfg(feature = "cache")]
            cache,
            #[cfg(feature = "web")]
            web: static_file_server_from_config("default web", &web)?,
            #[cfg(feature = "php-fpm")]
            php: None,
            routes: Vec::new(),
        })
    }

    fn from_config(
        #[cfg_attr(not(feature = "acme"), allow(unused_variables))] config: &Config,
        vhost: &crate::config::VhostConfig,
        global_headers: &crate::config::HeaderPolicyConfig,
        #[cfg(feature = "load-balancer")] load_balancer: Option<UpstreamLoadBalancer>,
    ) -> io::Result<Self> {
        let headers = global_headers.with_vhost_overlay(&vhost.headers);
        let route_base_headers = crate::config::HeaderPolicyConfig {
            request: headers.request.clone(),
            response: headers.response.clone(),
        };
        let mut routes = Vec::new();
        #[cfg(feature = "acme")]
        if !vhost.acme_challenge.enabled
            && config.tls.acme.enabled
            && config.tls.acme.challenge == crate::config::AcmeChallenge::Http01
            && let Some(storage) = config.tls.acme.storage.as_deref()
            && let Some(acme_vhost_name) = managed_http_01_owner_vhost(config, vhost)
        {
            routes.push(RuntimeRoute::acme_http_01(
                acme_vhost_name,
                storage,
                &route_base_headers,
            ));
        }
        routes.extend(
            vhost
                .acme_challenge
                .route_config()
                .into_iter()
                .chain(vhost.routes.iter().cloned())
                .chain(vhost.redirect.route_config())
                .map(|route| RuntimeRoute::from_config(&vhost.name, &route, &route_base_headers))
                .collect::<io::Result<Vec<_>>>()
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("vhost {:?} routes: {error}", vhost.name),
                    )
                })?,
        );
        #[cfg(feature = "cache")]
        let pingora_memory_storage =
            crate::cache::pingora_memory_storage_from_config_with_metric_scope(
                &vhost.cache,
                &vhost.name,
                None,
            );
        #[cfg(feature = "cache")]
        let pingora_disk_storage =
            crate::cache::pingora_disk_storage_backend_from_config_with_metric_scope(
                &vhost.cache,
                &vhost.name,
                None,
            )
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("vhost {:?} cache.disk: {error}", vhost.name),
                )
            })?;
        #[cfg(feature = "cache")]
        let pingora_tiered_storage = pingora_memory_storage
            .zip(pingora_disk_storage)
            .map(|(memory, disk)| crate::cache::pingora_tiered_storage_from_parts(memory, disk));
        #[cfg(feature = "cache")]
        let pingora_cache_lock = cache_lock_from_config(
            &vhost.cache,
            pingora_memory_storage.is_some() || pingora_disk_storage.is_some(),
        );
        #[cfg(feature = "cache")]
        let pingora_cache_predictor = cache_predictor_from_config(
            &vhost.cache,
            pingora_memory_storage.is_some() || pingora_disk_storage.is_some(),
        );
        let proxy_scope = format!("vhost {:?} proxy", vhost.name);
        #[cfg(feature = "web")]
        let web_scope = format!("vhost {:?} web", vhost.name);
        #[cfg(feature = "php-fpm")]
        let php_scope = format!("vhost {:?} php", vhost.name);

        Ok(Self {
            name: vhost.name.clone(),
            hosts: vhost.normalized_hosts(),
            max_request_body_bytes: vhost.max_request_body_bytes,
            #[cfg(feature = "load-balancer")]
            load_balancer,
            proxy: RuntimeProxy::from_config(&vhost.proxy, &proxy_scope)?,
            request_headers: headers.request,
            response_headers: headers.response,
            #[cfg(feature = "cache")]
            memory_cache: crate::cache::memory_image_cache_from_config(&vhost.cache),
            #[cfg(feature = "cache")]
            pingora_memory_storage,
            #[cfg(feature = "cache")]
            pingora_disk_storage,
            #[cfg(feature = "cache")]
            pingora_tiered_storage,
            #[cfg(feature = "cache")]
            pingora_cache_lock,
            #[cfg(feature = "cache")]
            pingora_cache_predictor,
            #[cfg(feature = "cache")]
            cache_lock_wait_timeout: cache_lock_wait_timeout(&vhost.cache),
            #[cfg(feature = "cache")]
            cache: vhost.cache.clone(),
            #[cfg(feature = "web")]
            web: static_file_server_from_config(web_scope, &vhost.web)?,
            #[cfg(feature = "php-fpm")]
            php: RuntimePhp::from_config(php_scope, &vhost.name, "default", &vhost.php)?,
            routes,
        })
    }
}

#[cfg(feature = "web")]
fn static_file_server_from_config(
    scope: impl std::fmt::Display,
    web: &crate::config::WebConfig,
) -> io::Result<Option<StaticFileServer>> {
    let scope = scope.to_string();
    StaticFileServer::from_config(web)
        .map_err(|error| io::Error::new(error.kind(), format!("{scope}: {error}")))
}

#[derive(Debug, Default)]
pub struct RequestContext {
    state: Option<Arc<ProxyRuntimeState>>,
    vhost_index: Option<usize>,
    route_index: Option<usize>,
    request_body_limit_bytes: Option<u64>,
    request_body_bytes_seen: u64,
    response_body_bytes_seen: u64,
    health_signal_recorded: bool,
    #[cfg(not(feature = "privacy-mode"))]
    started_at: Option<Instant>,
    #[cfg(not(feature = "privacy-mode"))]
    request_id: Option<String>,
    #[cfg(feature = "otel-tracing")]
    trace_context: Option<crate::trace_context::TraceContext>,
    #[cfg(feature = "otel-otlp")]
    started_at_unix_nanos: Option<u128>,
    #[cfg(feature = "cache")]
    cache_status_override: Option<CacheStatusOverride>,
    #[cfg(feature = "cache")]
    cache_observed_phase: Option<CachePhase>,
    #[cfg(feature = "cache")]
    cache_range: Option<CacheRangeRequest>,
    #[cfg(feature = "cache")]
    revalidation_304_headers: Option<Revalidation304Headers>,
}

#[cfg(feature = "cache")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CacheStatusOverride {
    status: &'static str,
    reason: Option<&'static str>,
}

#[cfg(feature = "cache")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CacheRangeRequest {
    start: u64,
    end: u64,
}

#[cfg(feature = "cache")]
impl CacheRangeRequest {
    fn len(self) -> u64 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }

    fn component(self) -> String {
        format!("bytes={}-{}", self.start, self.end)
    }
}

#[cfg(feature = "cache")]
#[derive(Clone, Debug, Eq, PartialEq)]
enum CacheClientRange {
    Bounded { start: u64, end: u64 },
    OpenEnded { start: u64 },
    Suffix { len: u64 },
}

#[cfg(feature = "cache")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct CacheSliceRangeRequest {
    ranges: Vec<CacheClientRange>,
    if_range: Option<String>,
}

#[cfg(feature = "cache")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CacheSliceBounds {
    start: u64,
    end: u64,
}

#[cfg(feature = "cache")]
impl CacheSliceBounds {
    fn len(self) -> u64 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }

    fn range_request(self) -> CacheRangeRequest {
        CacheRangeRequest {
            start: self.start,
            end: self.end,
        }
    }
}

#[cfg(feature = "cache")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CacheContentRange {
    start: u64,
    end: u64,
    total: Option<u64>,
}

#[cfg(feature = "cache")]
#[derive(Debug)]
struct CacheSliceObject {
    bounds: CacheSliceBounds,
    total: u64,
    body: Bytes,
    meta: CacheMeta,
}

#[cfg(feature = "cache")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct CacheSliceIdentity {
    total: u64,
    etag: Option<String>,
    last_modified: Option<String>,
}

#[cfg(feature = "cache")]
struct SliceFillPermit {
    counter: Arc<AtomicUsize>,
}

#[cfg(feature = "cache")]
impl Drop for SliceFillPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(feature = "cache")]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Revalidation304Headers {
    last_modified: Vec<::http::HeaderValue>,
    vary: Vec<::http::HeaderValue>,
}

#[async_trait]
impl ProxyHttp for FluxProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        #[cfg(not(feature = "privacy-mode"))]
        let ctx = RequestContext {
            started_at: Some(Instant::now()),
            #[cfg(feature = "otel-otlp")]
            started_at_unix_nanos: Some(unix_time_nanos()),
            ..RequestContext::default()
        };

        #[cfg(feature = "privacy-mode")]
        let ctx = RequestContext {
            #[cfg(feature = "otel-otlp")]
            started_at_unix_nanos: Some(unix_time_nanos()),
            ..RequestContext::default()
        };

        ctx
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let state = self.state.load_full();
        ctx.state = Some(Arc::clone(&state));

        let vhost_index = match state.request_vhost_index(request_host(session)) {
            Ok(index) => index,
            Err(reason) => {
                respond_host_routing_rejection(session, reason).await?;
                return Ok(true);
            }
        };
        ctx.vhost_index = Some(vhost_index);
        let vhost = state.vhost(vhost_index);
        ctx.route_index = vhost.route_index(session.req_header().uri.path());
        ctx.request_body_limit_bytes = ctx
            .route_index
            .and_then(|route_index| vhost.route(route_index).max_request_body_bytes)
            .or(vhost.max_request_body_bytes)
            .map(|bytes| bytes.as_u64())
            .or(Some(state.limits.max_request_body_bytes.as_u64()));
        #[cfg(feature = "otel-tracing")]
        if state.tracing.enabled && state.tracing.traceparent {
            let client_addr = session.client_addr().and_then(|addr| addr.as_inet());
            let trusted_peer = client_addr
                .map(|addr| state.trusted_proxy(addr.ip()))
                .unwrap_or(false);
            ctx.trace_context = crate::trace_context::context_from_traceparent(
                request_header_value(session.req_header(), "traceparent"),
                trusted_peer,
            );
        }
        if let Some(status) = request_limit_status(
            &state.limits,
            ctx.request_body_limit_bytes,
            session.req_header(),
        ) {
            session.respond_error(status).await?;
            return Ok(true);
        }
        #[cfg(not(feature = "privacy-mode"))]
        {
            ctx.request_id = access_log_request_id(&state.access_log, session.req_header());
        }

        if state.https_redirect.enabled && !downstream_tls(session) {
            match ctx.route_index.map(|route_index| vhost.route(route_index)) {
                Some(route)
                    if route.https_redirect_exempt
                        || matches!(&route.action, RuntimeRouteAction::Redirect(_)) => {}
                _ => {
                    respond_https_redirect(session, &state.https_redirect, &vhost.response_headers)
                        .await?;
                    return Ok(true);
                }
            }
        }

        if let Some(route_index) = ctx.route_index {
            let route = vhost.route(route_index);
            match &route.action {
                RuntimeRouteAction::Redirect(redirect) => {
                    respond_route_redirect(session, redirect, &route.response_headers).await?;
                    return Ok(true);
                }
                RuntimeRouteAction::Proxy(_) => {
                    if !selected_runtime_proxy(vhost, ctx).enabled {
                        session
                            .respond_error_with_body(
                                502,
                                Bytes::from_static(b"proxy upstream not configured"),
                            )
                            .await?;
                        return Ok(true);
                    }
                    #[cfg(feature = "cache")]
                    if respond_proxy_slice_cache_request(session, ctx, &state, vhost_index).await? {
                        return Ok(true);
                    }
                    #[cfg(feature = "cache")]
                    if respond_proxy_cache_only_request(session, ctx, &state, vhost_index).await? {
                        return Ok(true);
                    }
                    return Ok(false);
                }
                #[cfg(feature = "acme")]
                RuntimeRouteAction::AcmeHttp01(store) => {
                    respond_acme_http_01_challenge(session, ctx, store, route).await?;
                    return Ok(true);
                }
                #[cfg(feature = "web")]
                RuntimeRouteAction::Web(web) => {
                    if serve_static_route(session, ctx, vhost, route_index, web, route).await? {
                        return Ok(true);
                    }
                    return continue_to_proxy_or_not_found(session, vhost, ctx).await;
                }
                #[cfg(feature = "php-fpm")]
                RuntimeRouteAction::Php(php) => {
                    let request_path = route
                        .strip_prefix
                        .as_deref()
                        .and_then(|_| route_rewritten_path_and_query(session.req_header(), route))
                        .and_then(|path_and_query| {
                            path_and_query
                                .split_once('?')
                                .map(|(path, _)| path.to_owned())
                                .or(Some(path_and_query))
                        });
                    respond_php_request(
                        session,
                        ctx,
                        vhost,
                        &route.response_headers,
                        php,
                        false,
                        request_path,
                    )
                    .await?;
                    return Ok(true);
                }
            }
        }

        #[cfg(feature = "php-fpm")]
        if let Some(php) = &vhost.php
            && respond_php_request(
                session,
                ctx,
                vhost,
                &vhost.response_headers,
                php,
                true,
                None,
            )
            .await?
        {
            return Ok(true);
        }

        #[cfg(feature = "web")]
        {
            let Some(web) = &vhost.web else {
                #[cfg(feature = "cache")]
                if respond_proxy_slice_cache_request(session, ctx, &state, vhost_index).await? {
                    return Ok(true);
                }
                #[cfg(feature = "cache")]
                if respond_proxy_cache_only_request(session, ctx, &state, vhost_index).await? {
                    return Ok(true);
                }
                return continue_to_proxy_or_not_found(session, vhost, ctx).await;
            };

            let method = session.req_header().method.as_str().to_owned();
            if method != "GET" && method != "HEAD" {
                return continue_to_proxy_or_not_found(session, vhost, ctx).await;
            }

            match web.resolve(session.req_header().uri.path()) {
                Ok(ResolveResult::Found(file)) => {
                    let if_match = request_header_values_joined(session.req_header(), "if-match");
                    let if_unmodified_since =
                        request_header_values_joined(session.req_header(), "if-unmodified-since");
                    let if_none_match =
                        request_header_values_joined(session.req_header(), "if-none-match");
                    let if_modified_since =
                        request_header_values_joined(session.req_header(), "if-modified-since");
                    let cache_control =
                        request_header_values_joined(session.req_header(), "cache-control");
                    let pragma = request_header_values_joined(session.req_header(), "pragma");
                    let range = request_header_values_joined(session.req_header(), "range");
                    let if_range = request_header_values_joined(session.req_header(), "if-range");
                    let plan = crate::web::plan_static_response(
                        &file,
                        &method,
                        crate::web::StaticRequestConditions {
                            if_match: if_match.as_deref(),
                            if_unmodified_since: if_unmodified_since.as_deref(),
                            if_none_match: if_none_match.as_deref(),
                            if_modified_since: if_modified_since.as_deref(),
                            cache_control: cache_control.as_deref(),
                            pragma: pragma.as_deref(),
                            range: range.as_deref(),
                            if_range: if_range.as_deref(),
                        },
                    );
                    if plan.response_body_bytes > crate::web::MAX_STATIC_BUFFERED_BODY_BYTES {
                        session
                            .respond_error_with_body(
                                413,
                                Bytes::from_static(b"static response too large"),
                            )
                            .await?;
                        return Ok(true);
                    }
                    let static_request = StaticServeRequest {
                        #[cfg(feature = "cache")]
                        vhost,
                        #[cfg(feature = "cache")]
                        route_index: None,
                        web,
                        file: &file,
                        plan: &plan,
                        response_headers: &vhost.response_headers,
                    };
                    serve_static_file_maybe_cached(session, ctx, static_request).await?;
                    Ok(true)
                }
                Ok(ResolveResult::DirectoryListing(listing)) => {
                    ctx.response_body_bytes_seen = crate::web::serve_directory_listing(
                        session,
                        &listing,
                        &method,
                        &vhost.response_headers,
                    )
                    .await?;
                    Ok(true)
                }
                Ok(ResolveResult::Forbidden) => {
                    session
                        .respond_error_with_body(403, Bytes::from_static(b"forbidden"))
                        .await?;
                    Ok(true)
                }
                Ok(ResolveResult::NotFound) => {
                    #[cfg(feature = "cache")]
                    if respond_proxy_slice_cache_request(session, ctx, &state, vhost_index).await? {
                        return Ok(true);
                    }
                    #[cfg(feature = "cache")]
                    if respond_proxy_cache_only_request(session, ctx, &state, vhost_index).await? {
                        return Ok(true);
                    }
                    continue_to_proxy_or_not_found(session, vhost, ctx).await
                }
                Err(error) => {
                    log::error!("static file resolver failed: {error}");
                    session
                        .respond_error_with_body(500, Bytes::from_static(b"internal server error"))
                        .await?;
                    Ok(true)
                }
            }
        }

        #[cfg(not(feature = "web"))]
        {
            #[cfg(feature = "cache")]
            if respond_proxy_slice_cache_request(session, ctx, &state, vhost_index).await? {
                return Ok(true);
            }
            #[cfg(feature = "cache")]
            if respond_proxy_cache_only_request(session, ctx, &state, vhost_index).await? {
                return Ok(true);
            }
            continue_to_proxy_or_not_found(session, vhost, ctx).await
        }
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let state = ctx.state.clone().unwrap_or_else(|| self.state.load_full());
        let vhost_index = ctx
            .vhost_index
            .unwrap_or_else(|| state.vhost_index(request_host(session)));
        let vhost = state.vhost(vhost_index);
        let proxy = selected_runtime_proxy(vhost, ctx);

        #[cfg(feature = "load-balancer")]
        if let Some(load_balancer) = &vhost.load_balancer
            && let Some(upstream) = load_balancer.select()
        {
            let peer = http_peer_for_proxy(upstream, &proxy.config)?;
            return Ok(Box::new(peer));
        }

        let upstream = proxy.config.configured_primary_upstream().ok_or_else(|| {
            Error::explain(
                ErrorType::ConnectError,
                "proxy upstream is not configured for selected vhost or route",
            )
        })?;
        let peer = http_peer_for_proxy(upstream, &proxy.config)?;

        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let state = ctx.state.clone().unwrap_or_else(|| self.state.load_full());
        let vhost_index = ctx
            .vhost_index
            .unwrap_or_else(|| state.vhost_index(request_host(session)));
        ctx.vhost_index = Some(vhost_index);
        let vhost = state.vhost(vhost_index);
        let request_headers = ctx
            .route_index
            .map(|route_index| &vhost.route(route_index).request_headers)
            .unwrap_or(&vhost.request_headers);
        if let Some(route_index) = ctx.route_index {
            let route = vhost.route(route_index);
            if let Some(rewritten) = route_rewritten_path_and_query(session.req_header(), route) {
                upstream_request.uri = match rewritten.parse() {
                    Ok(uri) => uri,
                    Err(_) => {
                        return Error::e_explain(
                            ErrorType::HTTPStatus(400),
                            "route rewrite produced an invalid URI",
                        );
                    }
                };
            }
        }
        let downstream_tls = downstream_tls(session);
        let client_addr = session.client_addr().and_then(|addr| addr.as_inet());
        let trusted_proxy = client_addr
            .map(|addr| state.trusted_proxy(addr.ip()))
            .unwrap_or(false);
        let trusted_proxy_matcher = |address| state.trusted_proxy(address);
        #[cfg(not(feature = "privacy-mode"))]
        if let Some(request_id) = ctx.request_id.as_deref() {
            upstream_request
                .insert_header(state.access_log.request_id_header.clone(), request_id)?;
        }
        #[cfg(feature = "otel-tracing")]
        if state.tracing.enabled
            && state.tracing.traceparent
            && let Some(trace_context) = ctx.trace_context
        {
            upstream_request.insert_header("traceparent", trace_context.to_traceparent())?;
        }
        #[cfg(not(feature = "privacy-mode"))]
        let request_id = ctx.request_id.as_deref();
        #[cfg(feature = "privacy-mode")]
        let request_id = None;
        crate::headers::apply_upstream_request_policy(
            upstream_request,
            request_headers,
            client_addr,
            trusted_proxy,
            Some(&trusted_proxy_matcher),
            downstream_tls,
            request_id,
        )?;
        normalize_cookie_headers(upstream_request)?;

        #[cfg(feature = "cache")]
        if let Some(range) = ctx.cache_range {
            upstream_request.insert_header("range", range.component())?;
        }

        Ok(())
    }

    #[cfg(feature = "cache")]
    async fn proxy_upstream_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        let state = ctx.state.clone().unwrap_or_else(|| self.state.load_full());
        let vhost_index = ctx
            .vhost_index
            .unwrap_or_else(|| state.vhost_index(request_host(session)));
        let vhost = state.vhost(vhost_index);
        let cache = selected_cache_config(vhost, ctx);
        if !cache.peer_fill.enabled || session.req_header().method.as_str() != "GET" {
            return Ok(true);
        }
        let Some(storage) = selected_cache_storage(vhost, ctx) else {
            return Ok(true);
        };
        if !session.cache.enabled() {
            return Ok(true);
        }

        let cache_key = session.cache.cache_key().clone();
        let peer_fill = cache.peer_fill.clone();
        let Some(_peer_fill_permit) = acquire_peer_fill_concurrency_permit(
            peer_fill_concurrency_key(&vhost.name, ctx.route_index),
            peer_fill.max_concurrent_requests,
        ) else {
            log::warn!(
                "peer fill concurrency limit reached for vhost {} route {:?}",
                vhost.name,
                ctx.route_index
            );
            #[cfg(feature = "metrics")]
            record_cache_policy_activity(vhost, ctx.route_index, "peer_fill_error");
            if peer_fill.fail_open {
                #[cfg(feature = "metrics")]
                record_cache_policy_activity(vhost, ctx.route_index, "peer_fill_fallback");
                return Ok(true);
            }
            #[cfg(feature = "metrics")]
            record_cache_policy_activity(vhost, ctx.route_index, "peer_fill_fail_closed");
            respond_proxy_cache_only_miss(
                session,
                ctx,
                cache,
                selected_response_headers(vhost, ctx),
                "peer-fill-concurrency-limit",
                Some("MISS"),
            )
            .await?;
            return Ok(false);
        };
        let request = peer_fill_request_from_header(session.req_header());
        let response_headers = selected_response_headers(vhost, ctx);
        let max_body_bytes = peer_fill
            .max_object_bytes
            .unwrap_or(cache.max_object_bytes)
            .as_u64()
            .min(cache.max_object_bytes.as_u64());

        for peer in &peer_fill.peers {
            let peer = peer.clone();
            let peer_name = peer.name.clone();
            let request = request.clone();
            let peer_fill_for_request = peer_fill.clone();
            let result = tokio::task::spawn_blocking(move || {
                fetch_peer_fill_response(&peer, &peer_fill_for_request, &request, max_body_bytes)
            })
            .await
            .map_err(|error| {
                Error::because(
                    ErrorType::InternalError,
                    "peer fill worker task failed",
                    error,
                )
            })?;

            let response = match result {
                Ok(Some(response)) => response,
                Ok(None) => {
                    #[cfg(feature = "metrics")]
                    record_cache_policy_activity(vhost, ctx.route_index, "peer_fill_miss");
                    continue;
                }
                Err(error) => {
                    log::warn!("peer fill from {peer_name} failed: {error}");
                    #[cfg(feature = "metrics")]
                    record_cache_policy_activity(vhost, ctx.route_index, "peer_fill_error");
                    continue;
                }
            };

            if response.status != 200 {
                continue;
            }

            let mut response_header = response.to_response_header()?;
            if let Some(header) = cache.status_header.as_deref() {
                response_header.remove_header(header);
            }
            if let Some(header) = cache.status_reason_header.as_deref() {
                response_header.remove_header(header);
            }
            if response_cache_admission_rejection(&response_header, cache).is_some() {
                continue;
            }
            let peer_age_secs = response_age_secs(&response_header);
            let Some(ttl_secs) = cache_response_fresh_ttl_secs(cache, &response_header)
                .and_then(|ttl_secs| remaining_fresh_ttl_secs(ttl_secs, peer_age_secs))
            else {
                continue;
            };
            let now = std::time::SystemTime::now();
            let created_at = now
                .checked_sub(std::time::Duration::from_secs(peer_age_secs))
                .unwrap_or(now);
            let fresh_until = now
                .checked_add(std::time::Duration::from_secs(u64::from(ttl_secs)))
                .unwrap_or(now);
            let mut meta = CacheMeta::new(
                fresh_until,
                created_at,
                cache.stale_while_revalidate_secs.unwrap_or(0),
                cache.stale_if_error_secs.unwrap_or(0),
                response_header.clone(),
            );
            let trace = pingora::cache::trace::Span::inactive().handle();
            let mut store_key = cache_key.clone();
            if let Some(variance) = response_vary_variance(&meta, session.req_header(), cache) {
                meta.set_variance(variance);
                if let Some((_base_meta, base_hit)) = storage.lookup(&cache_key, &trace).await? {
                    base_hit.finish(storage, &cache_key, &trace).await?;
                    store_key.set_variance_key(variance);
                }
            }
            let mut miss = storage.get_miss_handler(&store_key, &meta, &trace).await?;
            miss.write_body(response.body.clone(), true).await?;
            let _ = miss.finish().await?;

            response_header.remove_header("age");
            response_header.insert_header("age", peer_age_secs.to_string())?;
            response_header.remove_header("content-length");
            response_header.insert_header("content-length", response.body.len().to_string())?;
            insert_cache_status_headers(
                &mut response_header,
                cache,
                Some(CacheStatusOverride {
                    status: "PEER-HIT",
                    reason: None,
                }),
                CachePhase::Hit,
            )?;
            crate::headers::apply_response_policy(&mut response_header, response_headers)?;
            #[cfg(feature = "metrics")]
            record_cache_policy_activity(vhost, ctx.route_index, "peer_fill_hit");
            ctx.cache_observed_phase = Some(CachePhase::Hit);
            ctx.response_body_bytes_seen = response.body.len() as u64;
            session
                .write_response_header(Box::new(response_header), response.body.is_empty())
                .await?;
            if !response.body.is_empty() {
                session
                    .write_response_body(Some(response.body.clone()), true)
                    .await?;
            }
            return Ok(false);
        }

        if peer_fill.fail_open {
            #[cfg(feature = "metrics")]
            record_cache_policy_activity(vhost, ctx.route_index, "peer_fill_fallback");
            Ok(true)
        } else {
            #[cfg(feature = "metrics")]
            record_cache_policy_activity(vhost, ctx.route_index, "peer_fill_fail_closed");
            respond_proxy_cache_only_miss(
                session,
                ctx,
                cache,
                response_headers,
                "peer-fill-miss",
                Some("MISS"),
            )
            .await?;
            Ok(false)
        }
    }

    #[cfg(feature = "cache")]
    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let state = ctx.state.clone().unwrap_or_else(|| self.state.load_full());
        let vhost_index = ctx
            .vhost_index
            .unwrap_or_else(|| state.vhost_index(request_host(session)));
        ctx.vhost_index = Some(vhost_index);
        let vhost = state.vhost(vhost_index);
        ignore_origin_cache_headers(
            upstream_response,
            selected_cache_config(vhost, ctx),
            session.cache.phase(),
        );
        apply_cache_status_ttl(
            upstream_response,
            selected_cache_config(vhost, ctx),
            session.cache.phase(),
        )?;
        strip_cache_response_headers(
            upstream_response,
            selected_cache_config(vhost, ctx),
            session.cache.phase(),
        );
        ctx.revalidation_304_headers = capture_revalidation_304_headers(upstream_response);
        Ok(())
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let Some(body) = body.as_ref() else {
            return Ok(());
        };

        let state = ctx.state.clone().unwrap_or_else(|| self.state.load_full());
        if let Some(status) = request_body_chunk_limit_status(
            ctx.request_body_limit_bytes
                .unwrap_or(state.limits.max_request_body_bytes.as_u64()),
            &mut ctx.request_body_bytes_seen,
            body.len(),
        ) {
            return Error::e_explain(
                ErrorType::HTTPStatus(status),
                "request body exceeds configured limit",
            );
        }

        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let state = ctx.state.clone().unwrap_or_else(|| self.state.load_full());
        let vhost_index = ctx
            .vhost_index
            .unwrap_or_else(|| state.vhost_index(request_host(session)));
        ctx.vhost_index = Some(vhost_index);
        let vhost = state.vhost(vhost_index);
        apply_downstream_flow_control(session, &selected_runtime_proxy(vhost, ctx).config);
        #[cfg(feature = "cache")]
        insert_cache_status_headers(
            response,
            selected_cache_config(vhost, ctx),
            ctx.cache_status_override,
            effective_cache_phase(session, ctx),
        )?;
        let response_headers = selected_response_headers(vhost, ctx);
        crate::headers::apply_response_policy(response, response_headers)
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>>
    where
        Self::CTX: Send + Sync,
    {
        count_response_body_chunk(&mut ctx.response_body_bytes_seen, body.as_ref());
        Ok(None)
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        error: &Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        let code = proxy_error_status(error);
        if code > 0 {
            let state = ctx.state.clone().unwrap_or_else(|| self.state.load_full());
            let vhost_index = ctx
                .vhost_index
                .unwrap_or_else(|| state.vhost_index(request_host(session)));
            let vhost = state.vhost(vhost_index);
            let proxy = selected_runtime_proxy(vhost, ctx);
            let response_headers = selected_response_headers(vhost, ctx);
            let custom_sent = match proxy.error_page(code) {
                Some(page) => {
                    match respond_custom_proxy_error_page(session, code, page, response_headers)
                        .await
                    {
                        Ok(sent) => sent,
                        Err(error) => {
                            log::error!("failed to serve custom proxy error page: {error}");
                            false
                        }
                    }
                }
                None => false,
            };

            if !custom_sent && let Err(error) = session.respond_error(code).await {
                log::error!("failed to send error response to downstream: {error}");
            }
        }

        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    async fn logging(&self, session: &mut Session, error: Option<&Error>, ctx: &mut Self::CTX)
    where
        Self::CTX: Send + Sync,
    {
        #[cfg(feature = "metrics")]
        crate::metrics::record_proxy_outcome(
            proxy_metrics_vhost(ctx),
            session.req_header().method.as_str(),
            session
                .response_written()
                .map(|response| response.status.as_u16()),
            error.is_some(),
        );
        #[cfg(all(feature = "cache", feature = "metrics"))]
        self.record_cache_operation_duration_metrics(session, ctx);

        #[cfg(not(feature = "privacy-mode"))]
        self.emit_access_log(session, error, ctx);

        #[cfg(feature = "otel-otlp")]
        self.export_otlp_trace_span(session, error, ctx);

        let Some(signal) = proxy_health_signal(session, error) else {
            return;
        };
        self.report_proxy_health_signal(signal, ctx);
    }

    #[cfg(feature = "cache")]
    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let state = ctx.state.clone().unwrap_or_else(|| self.state.load_full());
        let vhost_index = ctx
            .vhost_index
            .unwrap_or_else(|| state.vhost_index(request_host(session)));
        let vhost = state.vhost(vhost_index);
        let route_cache = ctx
            .route_index
            .and_then(|route_index| vhost.route(route_index).cache.as_ref());
        let cache_config = route_cache
            .map(|cache| &cache.config)
            .unwrap_or(&vhost.cache);

        if let Some(reason) = request_cache_bypass_reason(session.req_header(), cache_config) {
            #[cfg(feature = "metrics")]
            record_cache_policy_activity(vhost, ctx.route_index, "bypass");
            ctx.cache_status_override = Some(CacheStatusOverride {
                status: "BYPASS",
                reason: Some(reason),
            });
            return Ok(());
        }

        if proxy_cache_method_temporarily_bypassed(session.req_header().method.as_str()) {
            #[cfg(feature = "metrics")]
            record_cache_policy_activity(vhost, ctx.route_index, "bypass");
            ctx.cache_status_override = Some(CacheStatusOverride {
                status: "BYPASS",
                reason: Some(CACHE_HEAD_BYPASS_REASON),
            });
            return Ok(());
        }

        ctx.cache_range = selected_cache_range_request(session.req_header(), cache_config);

        let storage = route_cache
            .and_then(RuntimeRouteCache::storage)
            .or_else(|| {
                route_cache
                    .is_none()
                    .then(|| vhost_cache_storage(vhost))
                    .flatten()
            });
        let Some(storage) = storage else {
            return Ok(());
        };

        let Some(cache_key) = state.pingora_image_cache_key_for_request_header(
            session.req_header(),
            vhost_index,
            ctx.route_index,
        ) else {
            return Ok(());
        };
        if cache_pass_should_bypass(cache_pass_counter(), cache_config, &cache_key.combined()) {
            #[cfg(feature = "metrics")]
            record_cache_policy_activity(vhost, ctx.route_index, "pass");
            ctx.cache_status_override = Some(CacheStatusOverride {
                status: "BYPASS",
                reason: Some(CACHE_PASS_REASON),
            });
            return Ok(());
        }

        let mut cache_option_overrides = CacheOptionOverrides::default();
        let cache_lock = route_cache
            .map(|cache| cache.pingora_cache_lock)
            .unwrap_or(vhost.pingora_cache_lock);
        let cache_predictor = route_cache
            .map(|cache| cache.pingora_cache_predictor)
            .unwrap_or(vhost.pingora_cache_predictor);
        if cache_lock.is_some() {
            cache_option_overrides.wait_timeout = Some(
                route_cache
                    .map(|cache| cache.cache_lock_wait_timeout)
                    .unwrap_or(vhost.cache_lock_wait_timeout),
            );
        }
        session.cache.enable(
            storage,
            None,
            cache_predictor,
            cache_lock,
            Some(cache_option_overrides),
        );
        let max_file_size_bytes = ctx
            .cache_range
            .map(|_| cache_config.range.max_bytes)
            .unwrap_or(cache_config.max_object_bytes);
        session
            .cache
            .set_max_file_size_bytes(max_file_size_bytes.as_usize());
        Ok(())
    }

    #[cfg(feature = "cache")]
    fn cache_miss(&self, session: &mut Session, ctx: &mut Self::CTX) {
        ctx.cache_observed_phase = Some(CachePhase::Miss);
        session.cache.cache_miss();
    }

    #[cfg(feature = "cache")]
    fn cache_key_callback(
        &self,
        session: &Session,
        ctx: &mut Self::CTX,
    ) -> Result<PingoraCacheKey> {
        let state = ctx.state.clone().unwrap_or_else(|| self.state.load_full());
        let vhost_index = ctx
            .vhost_index
            .unwrap_or_else(|| state.vhost_index(request_host(session)));
        let mut cache_key = state
            .pingora_image_cache_key_for_request_header(
                session.req_header(),
                vhost_index,
                ctx.route_index,
            )
            .ok_or_else(|| {
                Error::explain(
                    ErrorType::InternalError,
                    "cache key callback called for a non-cacheable request",
                )
            })?;
        if let Some(range) = ctx.cache_range {
            cache_key = range_cache_key(cache_key, range)?;
        }
        Ok(cache_key)
    }

    #[cfg(feature = "cache")]
    fn response_cache_filter(
        &self,
        session: &Session,
        response: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        let state = ctx.state.clone().unwrap_or_else(|| self.state.load_full());
        let vhost_index = ctx
            .vhost_index
            .unwrap_or_else(|| state.vhost_index(request_host(session)));
        let vhost = state.vhost(vhost_index);
        let cache = selected_cache_config(vhost, ctx);
        let cache_key = session.cache.cache_key().combined();
        let adjusted_response;
        let response = if let Some(revalidation_headers) = ctx.revalidation_304_headers.as_ref() {
            if revalidation_304_vary_changed(response, revalidation_headers) {
                log::warn!(
                    "origin changed Vary during cache revalidation for vhost {}; keeping existing cached metadata",
                    vhost.name
                );
                return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                    REVALIDATION_VARY_CHANGED_REASON,
                )));
            }
            adjusted_response =
                response_with_revalidation_304_headers(response, revalidation_headers)?;
            &adjusted_response
        } else {
            response
        };

        if let Some(reason) = range_response_cache_admission_rejection(response, ctx.cache_range) {
            cache_pass_record_uncacheable(cache_pass_counter(), cache, &cache_key);
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(reason)));
        }

        let admission_rejection = if ctx.cache_range.is_some() {
            response_range_cache_admission_rejection(response, cache)
        } else {
            response_cache_admission_rejection(response, cache)
        };
        if let Some(reason) = admission_rejection {
            cache_pass_record_uncacheable(cache_pass_counter(), cache, &cache_key);
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(reason)));
        }

        let cache_control =
            pingora::cache::cache_control::CacheControl::from_resp_headers(response);
        let authorization_present = session.req_header().headers.contains_key("authorization");
        let decision = pingora::cache::filters::resp_cacheable(
            cache_control.as_ref(),
            response.clone(),
            authorization_present,
            &FLUXHEIM_CACHE_DEFAULTS,
        );
        if !decision.is_cacheable() {
            cache_pass_record_uncacheable(cache_pass_counter(), cache, &cache_key);
            return Ok(decision);
        }
        if session.cache.maybe_cache_meta().is_none() && ctx.cache_status_override.is_none() {
            ctx.cache_observed_phase = Some(CachePhase::Miss);
            ctx.cache_status_override = Some(CacheStatusOverride {
                status: "MISS",
                reason: None,
            });
        }
        cache_pass_record_cacheable(cache_pass_counter(), &cache_key);
        if !cache_min_uses_allows_store(cache_min_uses_counter(), cache, &cache_key) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                CACHE_MIN_USES_REASON,
            )));
        }
        Ok(decision)
    }

    #[cfg(feature = "cache")]
    fn range_header_filter(
        &self,
        session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> RangeType {
        let Some(cached_range) = ctx.cache_range else {
            return pingora::proxy::range_header_filter(session.req_header(), response, None);
        };

        if response.status != StatusCode::PARTIAL_CONTENT {
            return pingora::proxy::range_header_filter(session.req_header(), response, None);
        }
        let Ok(end) = usize::try_from(cached_range.len()) else {
            return RangeType::Invalid;
        };
        RangeType::Single(0..end)
    }

    #[cfg(feature = "cache")]
    async fn cache_hit_filter(
        &self,
        session: &mut Session,
        _meta: &CacheMeta,
        _hit_handler: &mut HitHandler,
        _is_fresh: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<ForcedFreshness>>
    where
        Self::CTX: Send + Sync,
    {
        let state = ctx.state.clone().unwrap_or_else(|| self.state.load_full());
        let vhost_index = ctx
            .vhost_index
            .unwrap_or_else(|| state.vhost_index(request_host(session)));
        let vhost = state.vhost(vhost_index);
        let route_cache = ctx
            .route_index
            .and_then(|route_index| vhost.route(route_index).cache.as_ref());
        let cache_config = route_cache
            .map(|cache| &cache.config)
            .unwrap_or(&vhost.cache);
        if !request_cache_revalidation_requested(session.req_header(), cache_config) {
            return Ok(None);
        }

        #[cfg(feature = "metrics")]
        {
            record_cache_policy_activity(vhost, ctx.route_index, "revalidate");
        }
        ctx.cache_status_override = Some(CacheStatusOverride {
            status: "REVALIDATE",
            reason: Some("request-refresh"),
        });
        Ok(Some(ForcedFreshness::ForceExpired))
    }

    #[cfg(feature = "cache")]
    fn should_serve_stale(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
        error: Option<&Error>,
    ) -> bool {
        let state = ctx.state.clone().unwrap_or_else(|| self.state.load_full());
        let vhost_index = ctx
            .vhost_index
            .unwrap_or_else(|| state.vhost_index(request_host(session)));
        let vhost = state.vhost(vhost_index);
        let event = match error {
            Some(error) if error.esource() == &ErrorSource::Upstream => {
                if let ErrorType::HTTPStatus(status) = error.etype() {
                    CacheStaleEvent::UpstreamHttpStatus(*status)
                } else {
                    CacheStaleEvent::UpstreamError(cache_stale_error_kind(error))
                }
            }
            Some(_) => CacheStaleEvent::OtherError,
            None => CacheStaleEvent::Updating,
        };
        let allowed = cache_should_serve_stale(selected_cache_config(vhost, ctx), event);
        if allowed {
            #[cfg(feature = "metrics")]
            record_cache_policy_activity(vhost, ctx.route_index, "stale");
        }
        allowed
    }

    #[cfg(feature = "cache")]
    fn cache_vary_filter(
        &self,
        meta: &pingora::cache::CacheMeta,
        ctx: &mut Self::CTX,
        request: &RequestHeader,
    ) -> Option<HashBinary> {
        let state = ctx.state.clone().unwrap_or_else(|| self.state.load_full());
        let vhost_index = ctx
            .vhost_index
            .unwrap_or_else(|| state.vhost_index(request_host_header(request)));
        let vhost = state.vhost(vhost_index);
        let cache = selected_cache_config(vhost, ctx);

        match cache_vary_policy(meta.headers(), cache) {
            VaryCachePolicy::Fields(fields) => Some(vary_request_hash(&fields, request)),
            VaryCachePolicy::None | VaryCachePolicy::Uncacheable(_) => None,
        }
    }
}

#[cfg(feature = "cache")]
static FLUXHEIM_CACHE_DEFAULTS: pingora::cache::CacheMetaDefaults =
    pingora::cache::CacheMetaDefaults::new(no_default_cache_ttl, 0, 0);

#[cfg(feature = "cache")]
fn no_default_cache_ttl(_status: StatusCode) -> Option<std::time::Duration> {
    None
}

fn request_host(session: &Session) -> Option<&str> {
    request_host_header(session.req_header())
}

#[cfg(feature = "cache")]
async fn respond_proxy_cache_only_request(
    session: &mut Session,
    ctx: &mut RequestContext,
    state: &ProxyRuntimeState,
    vhost_index: usize,
) -> Result<bool> {
    if !request_cache_only_if_cached(session.req_header()) {
        return Ok(false);
    }

    let vhost = state.vhost(vhost_index);
    let cache = selected_cache_config(vhost, ctx);
    let response_headers = selected_response_headers(vhost, ctx);

    if session.req_header().method.as_str() != "GET" {
        respond_proxy_cache_only_miss(
            session,
            ctx,
            cache,
            response_headers,
            "method-ineligible",
            Some("BYPASS"),
        )
        .await?;
        return Ok(true);
    }

    let Some(storage) = selected_cache_storage(vhost, ctx) else {
        respond_proxy_cache_only_miss(
            session,
            ctx,
            cache,
            response_headers,
            "storage-unavailable",
            Some("BYPASS"),
        )
        .await?;
        return Ok(true);
    };

    if let Some(reason) = request_cache_bypass_reason(session.req_header(), cache) {
        #[cfg(feature = "metrics")]
        record_cache_policy_activity(vhost, ctx.route_index, "bypass");
        respond_proxy_cache_only_miss(
            session,
            ctx,
            cache,
            response_headers,
            reason,
            Some("BYPASS"),
        )
        .await?;
        return Ok(true);
    }

    let Some(cache_key) = state.pingora_image_cache_key_for_request_header(
        session.req_header(),
        vhost_index,
        ctx.route_index,
    ) else {
        respond_proxy_cache_only_miss(
            session,
            ctx,
            cache,
            response_headers,
            "cache-key-unavailable",
            Some("MISS"),
        )
        .await?;
        return Ok(true);
    };

    if cache_pass_should_bypass(cache_pass_counter(), cache, &cache_key.combined()) {
        #[cfg(feature = "metrics")]
        record_cache_policy_activity(vhost, ctx.route_index, "pass");
        respond_proxy_cache_only_miss(
            session,
            ctx,
            cache,
            response_headers,
            CACHE_PASS_REASON,
            Some("BYPASS"),
        )
        .await?;
        return Ok(true);
    }

    let trace = pingora::cache::trace::Span::inactive().handle();
    let Some((meta, hit, cache_key)) =
        lookup_proxy_cache_only_object(storage, cache_key, session.req_header(), cache, &trace)
            .await?
    else {
        #[cfg(feature = "metrics")]
        record_cache_policy_activity(vhost, ctx.route_index, "miss");
        respond_proxy_cache_only_miss(
            session,
            ctx,
            cache,
            response_headers,
            "only-if-cached-miss",
            Some("MISS"),
        )
        .await?;
        return Ok(true);
    };

    if !meta.is_fresh(std::time::SystemTime::now()) {
        #[cfg(feature = "metrics")]
        record_cache_policy_activity(vhost, ctx.route_index, "stale");
        hit.finish(storage, &cache_key, &trace).await?;
        respond_proxy_cache_only_miss(
            session,
            ctx,
            cache,
            response_headers,
            "only-if-cached-stale",
            Some("STALE"),
        )
        .await?;
        return Ok(true);
    }

    let max_body_bytes = cache
        .max_object_bytes
        .as_u64()
        .min(CACHE_ONLY_RESPONSE_MAX_BYTES);
    let body = read_cache_hit_body(hit, storage, &cache_key, &trace, max_body_bytes).await?;
    let body_len = body.len();
    let mut response = meta.response_header_copy();
    response.remove_header("age");
    response.insert_header("age", meta.age().as_secs().to_string())?;
    response.remove_header("content-length");
    response.insert_header("content-length", body_len.to_string())?;
    insert_cache_status_headers(
        &mut response,
        cache,
        Some(CacheStatusOverride {
            status: "HIT",
            reason: None,
        }),
        CachePhase::Hit,
    )?;
    crate::headers::apply_response_policy(&mut response, response_headers)?;
    #[cfg(feature = "metrics")]
    record_cache_policy_activity(vhost, ctx.route_index, "hit");
    ctx.cache_observed_phase = Some(CachePhase::Hit);
    ctx.response_body_bytes_seen = body_len as u64;
    session
        .write_response_header(Box::new(response), body.is_empty())
        .await?;
    if !body.is_empty() {
        session.write_response_body(Some(body), true).await?;
    }
    Ok(true)
}

#[cfg(feature = "cache")]
async fn lookup_proxy_cache_only_object(
    storage: &'static (dyn pingora::cache::Storage + Sync),
    mut cache_key: PingoraCacheKey,
    request: &RequestHeader,
    cache: &crate::config::CacheConfig,
    trace: &pingora::cache::trace::SpanHandle,
) -> Result<Option<(CacheMeta, HitHandler, PingoraCacheKey)>> {
    let Some((meta, hit)) = storage.lookup(&cache_key, trace).await? else {
        return Ok(None);
    };

    match cache_vary_policy(meta.headers(), cache) {
        VaryCachePolicy::None => Ok(Some((meta, hit, cache_key))),
        VaryCachePolicy::Uncacheable(_) => {
            hit.finish(storage, &cache_key, trace).await?;
            Ok(None)
        }
        VaryCachePolicy::Fields(fields) => {
            let variance = vary_request_hash(&fields, request);
            if meta.variance() == Some(variance) {
                return Ok(Some((meta, hit, cache_key)));
            }

            hit.finish(storage, &cache_key, trace).await?;
            cache_key.set_variance_key(variance);
            let Some((meta, hit)) = storage.lookup(&cache_key, trace).await? else {
                return Ok(None);
            };
            if meta.variance() == Some(variance) {
                Ok(Some((meta, hit, cache_key)))
            } else {
                hit.finish(storage, &cache_key, trace).await?;
                Ok(None)
            }
        }
    }
}

#[cfg(feature = "cache")]
async fn respond_proxy_slice_cache_request(
    session: &mut Session,
    ctx: &mut RequestContext,
    state: &ProxyRuntimeState,
    vhost_index: usize,
) -> Result<bool> {
    let vhost = state.vhost(vhost_index);
    let cache = selected_cache_config(vhost, ctx);
    if !cache.range.enabled || !cache.range.slice.enabled {
        return Ok(false);
    }
    let Some(slice_request) = selected_cache_slice_range_request(session.req_header(), cache)
    else {
        return Ok(false);
    };
    if let Some(reason) = request_cache_bypass_reason(session.req_header(), cache) {
        #[cfg(feature = "metrics")]
        record_cache_policy_activity(vhost, ctx.route_index, "bypass");
        ctx.cache_status_override = Some(CacheStatusOverride {
            status: "BYPASS",
            reason: Some(reason),
        });
        return Ok(false);
    }
    let Some(storage) = selected_cache_storage(vhost, ctx) else {
        return Ok(false);
    };
    let Some(base_key) = state.pingora_image_cache_key_for_request_header(
        session.req_header(),
        vhost_index,
        ctx.route_index,
    ) else {
        return Ok(false);
    };
    if cache_pass_should_bypass(cache_pass_counter(), cache, &base_key.combined()) {
        #[cfg(feature = "metrics")]
        record_cache_policy_activity(vhost, ctx.route_index, "pass");
        ctx.cache_status_override = Some(CacheStatusOverride {
            status: "BYPASS",
            reason: Some(CACHE_PASS_REASON),
        });
        return Ok(false);
    }

    let proxy = selected_runtime_proxy(vhost, ctx);
    let response_headers = selected_response_headers(vhost, ctx);
    let Some(response) = proxy_slice_cache_response(
        session.req_header(),
        storage,
        base_key,
        cache,
        proxy,
        ctx.route_index.map(|index| vhost.route(index)),
        slice_request,
    )
    .await?
    else {
        return Ok(false);
    };

    let mut response_header = response.header;
    insert_cache_status_headers(
        &mut response_header,
        cache,
        Some(CacheStatusOverride {
            status: if response.filled { "MISS" } else { "HIT" },
            reason: Some(if response.filled {
                "slice-fill"
            } else {
                "slice"
            }),
        }),
        CachePhase::Hit,
    )?;
    crate::headers::apply_response_policy(&mut response_header, response_headers)?;
    #[cfg(feature = "metrics")]
    record_cache_policy_activity(
        vhost,
        ctx.route_index,
        if response.filled {
            "slice_fill"
        } else {
            "slice_hit"
        },
    );
    ctx.cache_observed_phase = Some(CachePhase::Hit);
    ctx.response_body_bytes_seen = response.body.len() as u64;
    session
        .write_response_header(Box::new(response_header), response.body.is_empty())
        .await?;
    if !response.body.is_empty() {
        session
            .write_response_body(Some(response.body), true)
            .await?;
    }
    Ok(true)
}

#[cfg(feature = "cache")]
struct CacheSliceComposedResponse {
    header: ResponseHeader,
    body: Bytes,
    filled: bool,
}

#[cfg(feature = "cache")]
async fn proxy_slice_cache_response(
    request: &RequestHeader,
    storage: &'static (dyn pingora::cache::Storage + Sync),
    base_key: PingoraCacheKey,
    cache: &crate::config::CacheConfig,
    proxy: &RuntimeProxy,
    route: Option<&RuntimeRoute>,
    slice_request: CacheSliceRangeRequest,
) -> Result<Option<CacheSliceComposedResponse>> {
    let trace = pingora::cache::trace::Span::inactive().handle();
    let fill_context = CacheSliceFillContext {
        request,
        storage,
        cache,
        proxy,
        route,
        trace: &trace,
    };
    let slice_size = cache.range.slice.size_bytes.as_u64();
    let Some((total, first_slice, first_filled)) =
        discover_slice_total(&fill_context, base_key.clone(), slice_size).await?
    else {
        return Ok(None);
    };

    let Some(ranges) = resolve_client_slice_ranges(&slice_request.ranges, total) else {
        return Ok(Some(slice_416_response(total)?));
    };
    if ranges.is_empty() {
        return Ok(Some(slice_416_response(total)?));
    }
    if !slice_request_within_policy(&ranges, cache, slice_size) {
        return Ok(None);
    }

    let first_identity = slice_identity(&first_slice);
    if let Some(if_range) = slice_request.if_range.as_deref()
        && !if_range_matches_slice_identity(if_range, &first_identity)
    {
        return Ok(None);
    }

    let mut filled = first_filled;
    let mut slices = HashMap::<(u64, u64), CacheSliceObject>::new();
    slices.insert(
        (first_slice.bounds.start, first_slice.bounds.end),
        first_slice,
    );
    for bounds in required_slice_bounds(&ranges, slice_size, total) {
        if slices.contains_key(&(bounds.start, bounds.end)) {
            continue;
        }
        let Some(slice) = lookup_or_fill_slice(&fill_context, base_key.clone(), bounds).await?
        else {
            return Ok(None);
        };
        filled |= slice.filled;
        if slice_identity(&slice.object) != first_identity {
            return Ok(None);
        }
        slices.insert((bounds.start, bounds.end), slice.object);
    }

    compose_slice_response(&ranges, &slices, &first_identity, filled)
}

#[cfg(feature = "cache")]
struct CacheSliceLookupResult {
    object: CacheSliceObject,
    filled: bool,
}

#[cfg(feature = "cache")]
struct CacheSliceFillContext<'a> {
    request: &'a RequestHeader,
    storage: &'static (dyn pingora::cache::Storage + Sync),
    cache: &'a crate::config::CacheConfig,
    proxy: &'a RuntimeProxy,
    route: Option<&'a RuntimeRoute>,
    trace: &'a pingora::cache::trace::SpanHandle,
}

#[cfg(feature = "cache")]
async fn discover_slice_total(
    context: &CacheSliceFillContext<'_>,
    base_key: PingoraCacheKey,
    slice_size: u64,
) -> Result<Option<(u64, CacheSliceObject, bool)>> {
    let bounds = CacheSliceBounds {
        start: 0,
        end: slice_size.saturating_sub(1),
    };
    let Some(result) = lookup_or_fill_slice(context, base_key, bounds).await? else {
        return Ok(None);
    };
    Ok(Some((result.object.total, result.object, result.filled)))
}

#[cfg(feature = "cache")]
async fn lookup_or_fill_slice(
    context: &CacheSliceFillContext<'_>,
    base_key: PingoraCacheKey,
    bounds: CacheSliceBounds,
) -> Result<Option<CacheSliceLookupResult>> {
    let slice_key = slice_cache_key(base_key.clone(), bounds.range_request())?;
    if let Some(object) = lookup_cached_slice(
        context.storage,
        slice_key.clone(),
        context.request,
        context.cache,
        context.trace,
    )
    .await?
    {
        return Ok(Some(CacheSliceLookupResult {
            object,
            filled: false,
        }));
    }
    if !context.cache.range.slice.fill_missing {
        return Ok(None);
    }

    let Some(_permit) = acquire_slice_fill_permit(slice_key.combined()) else {
        return wait_for_cached_slice(
            context.storage,
            slice_key,
            context.request,
            context.cache,
            context.trace,
        )
        .await;
    };
    if let Some(object) = lookup_cached_slice(
        context.storage,
        slice_key.clone(),
        context.request,
        context.cache,
        context.trace,
    )
    .await?
    {
        return Ok(Some(CacheSliceLookupResult {
            object,
            filled: false,
        }));
    }

    let Some(object) = fetch_and_store_slice(context, slice_key, bounds).await? else {
        return Ok(None);
    };
    Ok(Some(CacheSliceLookupResult {
        object,
        filled: true,
    }))
}

#[cfg(feature = "cache")]
async fn wait_for_cached_slice(
    storage: &'static (dyn pingora::cache::Storage + Sync),
    slice_key: PingoraCacheKey,
    request: &RequestHeader,
    cache: &crate::config::CacheConfig,
    trace: &pingora::cache::trace::SpanHandle,
) -> Result<Option<CacheSliceLookupResult>> {
    let timeout = std::time::Duration::from_secs(cache.lock.wait_timeout_secs.max(1));
    let deadline = Instant::now() + timeout;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        if let Some(object) =
            lookup_cached_slice(storage, slice_key.clone(), request, cache, trace).await?
        {
            return Ok(Some(CacheSliceLookupResult {
                object,
                filled: false,
            }));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
    }
}

#[cfg(feature = "cache")]
async fn lookup_cached_slice(
    storage: &'static (dyn pingora::cache::Storage + Sync),
    slice_key: PingoraCacheKey,
    request: &RequestHeader,
    cache: &crate::config::CacheConfig,
    trace: &pingora::cache::trace::SpanHandle,
) -> Result<Option<CacheSliceObject>> {
    let Some((meta, hit, resolved_key)) =
        lookup_proxy_cache_only_object(storage, slice_key, request, cache, trace).await?
    else {
        return Ok(None);
    };
    if !meta.is_fresh(std::time::SystemTime::now()) {
        hit.finish(storage, &resolved_key, trace).await?;
        return Ok(None);
    }
    let max_body_bytes = cache.range.slice.size_bytes.as_u64();
    let body = read_cache_hit_body(hit, storage, &resolved_key, trace, max_body_bytes).await?;
    slice_object_from_meta_body(meta, body).map(Some)
}

#[cfg(feature = "cache")]
async fn fetch_and_store_slice(
    context: &CacheSliceFillContext<'_>,
    slice_key: PingoraCacheKey,
    bounds: CacheSliceBounds,
) -> Result<Option<CacheSliceObject>> {
    let max_body_bytes = context.cache.range.slice.size_bytes.as_u64();
    let response = match fetch_origin_slice(
        context.request,
        context.proxy,
        context.route,
        bounds,
        max_body_bytes,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            log::warn!("slice cache origin fetch failed: {error}");
            return Ok(None);
        }
    };
    if response.status == StatusCode::RANGE_NOT_SATISFIABLE {
        return Ok(None);
    }
    let mut header = response.to_response_header()?;
    ignore_origin_cache_headers(&mut header, context.cache, CachePhase::Miss);
    apply_cache_status_ttl(&mut header, context.cache, CachePhase::Miss)?;
    if range_response_cache_admission_rejection(&header, Some(bounds.range_request())).is_some()
        || response_range_cache_admission_rejection(&header, context.cache).is_some()
        || response_has_non_identity_encoding(&header)
    {
        return Ok(None);
    }
    let Some(ttl_secs) = cache_response_fresh_ttl_secs(context.cache, &header) else {
        return Ok(None);
    };
    let now = std::time::SystemTime::now();
    let fresh_until = now
        .checked_add(std::time::Duration::from_secs(u64::from(ttl_secs)))
        .unwrap_or(now);
    let meta = CacheMeta::new(
        fresh_until,
        now,
        context.cache.stale_while_revalidate_secs.unwrap_or(0),
        context.cache.stale_if_error_secs.unwrap_or(0),
        header,
    );
    let body = response.body;
    let mut miss = context
        .storage
        .get_miss_handler(&slice_key, &meta, context.trace)
        .await?;
    miss.write_body(body.clone(), true).await?;
    let _ = miss.finish().await?;
    let object = slice_object_from_meta_body(meta, body)?;
    Ok(Some(object))
}

#[cfg(feature = "cache")]
#[derive(Clone, Debug)]
struct CacheSliceOriginResponse {
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: Bytes,
}

#[cfg(feature = "cache")]
impl CacheSliceOriginResponse {
    fn to_response_header(&self) -> Result<ResponseHeader> {
        let mut response = ResponseHeader::build(self.status, Some(self.headers.len()))?;
        for (name, value) in &self.headers {
            if peer_fill_hop_by_hop_header(name) {
                continue;
            }
            response.append_header(name.clone(), value.clone())?;
        }
        response.remove_header("content-length");
        response.insert_header("content-length", self.body.len().to_string())?;
        Ok(response)
    }
}

#[cfg(feature = "cache")]
async fn fetch_origin_slice(
    request: &RequestHeader,
    proxy: &RuntimeProxy,
    route: Option<&RuntimeRoute>,
    bounds: CacheSliceBounds,
    max_body_bytes: u64,
) -> std::io::Result<CacheSliceOriginResponse> {
    let proxy = proxy.clone();
    let request = origin_slice_request_from_header(request, route, bounds)?;
    tokio::task::spawn_blocking(move || {
        let url = origin_slice_url(&proxy.config, &request.path_and_query)?;
        let timeout = std::time::Duration::from_secs(
            proxy
                .config
                .connect_timeout_secs
                .unwrap_or(10)
                .saturating_add(proxy.config.read_timeout_secs.unwrap_or(30)),
        );
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .into();
        let mut builder = agent
            .get(&url)
            .header("range", bounds.range_request().component())
            .header("accept-encoding", "identity");
        if let Some(host) = request.host.as_deref() {
            builder = builder.header("host", host);
        }
        let mut response = builder.call().map_err(peer_fill_io_error)?;
        let status = StatusCode::from_u16(response.status().as_u16()).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
        })?;
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect::<Vec<_>>();
        let body = response
            .body_mut()
            .with_config()
            .limit(max_body_bytes.saturating_add(1))
            .read_to_vec()
            .map_err(peer_fill_io_error)?;
        if body.len() as u64 > max_body_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "origin slice exceeds configured slice size",
            ));
        }
        Ok(CacheSliceOriginResponse {
            status,
            headers,
            body: Bytes::from(body),
        })
    })
    .await
    .map_err(|error| std::io::Error::other(error.to_string()))?
}

#[cfg(feature = "cache")]
#[derive(Clone, Debug)]
struct OriginSliceRequest {
    path_and_query: String,
    host: Option<String>,
}

#[cfg(feature = "cache")]
fn origin_slice_request_from_header(
    request: &RequestHeader,
    route: Option<&RuntimeRoute>,
    _bounds: CacheSliceBounds,
) -> std::io::Result<OriginSliceRequest> {
    let path_and_query = route
        .and_then(|route| route_rewritten_path_and_query(request, route))
        .or_else(|| {
            request
                .uri
                .path_and_query()
                .map(|value| value.as_str().to_owned())
        })
        .unwrap_or_else(|| request.uri.path().to_owned());
    if !path_and_query.starts_with('/') || path_and_query.chars().any(char::is_control) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "origin slice path must be absolute and printable",
        ));
    }
    Ok(OriginSliceRequest {
        path_and_query,
        host: request_host_header(request).map(ToOwned::to_owned),
    })
}

#[cfg(feature = "cache")]
fn origin_slice_url(proxy: &ProxyConfig, path_and_query: &str) -> std::io::Result<String> {
    let scheme = if proxy.upstream_tls { "https" } else { "http" };
    if !path_and_query.starts_with('/') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "origin slice request path must be absolute",
        ));
    }
    Ok(format!(
        "{scheme}://{}{}",
        proxy.primary_upstream(),
        path_and_query
    ))
}

#[cfg(feature = "cache")]
fn selected_cache_slice_range_request(
    request: &RequestHeader,
    cache: &crate::config::CacheConfig,
) -> Option<CacheSliceRangeRequest> {
    if !cache.range.enabled || !cache.range.slice.enabled || request.method.as_str() != "GET" {
        return None;
    }
    let mut values = request_header_values(request, "range");
    let range = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let if_range = request_header_values_joined(request, "if-range");
    parse_cache_client_ranges(range).map(|ranges| CacheSliceRangeRequest { ranges, if_range })
}

#[cfg(feature = "cache")]
fn parse_cache_client_ranges(value: &str) -> Option<Vec<CacheClientRange>> {
    let value = value.trim();
    let value = value.strip_prefix("bytes=")?;
    let mut ranges = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        let (start, end) = part.split_once('-')?;
        if start.is_empty() {
            let len = end.parse::<u64>().ok()?;
            if len == 0 {
                return None;
            }
            ranges.push(CacheClientRange::Suffix { len });
        } else if end.is_empty() {
            ranges.push(CacheClientRange::OpenEnded {
                start: start.parse::<u64>().ok()?,
            });
        } else {
            let start = start.parse::<u64>().ok()?;
            let end = end.parse::<u64>().ok()?;
            if end < start {
                return None;
            }
            ranges.push(CacheClientRange::Bounded { start, end });
        }
    }
    (!ranges.is_empty()).then_some(ranges)
}

#[cfg(feature = "cache")]
fn resolve_client_slice_ranges(
    ranges: &[CacheClientRange],
    total: u64,
) -> Option<Vec<CacheSliceBounds>> {
    if total == 0 {
        return Some(Vec::new());
    }
    let last = total.saturating_sub(1);
    let mut resolved = Vec::new();
    for range in ranges {
        match *range {
            CacheClientRange::Bounded { start, end } => {
                if start > last {
                    continue;
                }
                resolved.push(CacheSliceBounds {
                    start,
                    end: end.min(last),
                });
            }
            CacheClientRange::OpenEnded { start } => {
                if start > last {
                    continue;
                }
                resolved.push(CacheSliceBounds { start, end: last });
            }
            CacheClientRange::Suffix { len } => {
                if len == 0 {
                    continue;
                }
                resolved.push(CacheSliceBounds {
                    start: total.saturating_sub(len),
                    end: last,
                });
            }
        }
    }
    Some(resolved)
}

#[cfg(feature = "cache")]
fn slice_request_within_policy(
    ranges: &[CacheSliceBounds],
    cache: &crate::config::CacheConfig,
    slice_size: u64,
) -> bool {
    let requested_bytes = ranges
        .iter()
        .try_fold(0_u64, |sum, range| sum.checked_add(range.len()));
    let Some(requested_bytes) = requested_bytes else {
        return false;
    };
    if requested_bytes > cache.range.max_bytes.as_u64() {
        return false;
    }
    let slices = required_slice_bounds(ranges, slice_size, u64::MAX);
    !slices.is_empty() && slices.len() <= cache.range.slice.max_slices as usize
}

#[cfg(feature = "cache")]
fn required_slice_bounds(
    ranges: &[CacheSliceBounds],
    slice_size: u64,
    total: u64,
) -> Vec<CacheSliceBounds> {
    let mut slices = Vec::new();
    let last = total.saturating_sub(1);
    for range in ranges {
        let mut start = (range.start / slice_size).saturating_mul(slice_size);
        while start <= range.end && start <= last {
            let end = start.saturating_add(slice_size.saturating_sub(1)).min(last);
            let slice = CacheSliceBounds { start, end };
            if !slices.contains(&slice) {
                slices.push(slice);
            }
            let Some(next) = start.checked_add(slice_size) else {
                break;
            };
            start = next;
        }
    }
    slices.sort_by_key(|slice| slice.start);
    slices
}

#[cfg(feature = "cache")]
fn slice_cache_key(mut base: PingoraCacheKey, range: CacheRangeRequest) -> Result<PingoraCacheKey> {
    let namespace = base.namespace().to_vec();
    let user_tag = base.user_tag.clone();
    let Some(primary) = base.primary_key_str() else {
        return Error::e_explain(
            ErrorType::InternalError,
            "cache slice key requires utf-8 primary key material",
        );
    };
    let mut primary = primary.to_owned();
    append_cache_key_component(&mut primary, "slice", &range.component());
    base = PingoraCacheKey::new(namespace, primary, user_tag);
    Ok(base)
}

#[cfg(feature = "cache")]
fn slice_object_from_meta_body(meta: CacheMeta, body: Bytes) -> Result<CacheSliceObject> {
    let Some(content_range) = response_content_range(meta.headers()) else {
        return Error::e_explain(
            ErrorType::InternalError,
            "cached slice is missing Content-Range metadata",
        );
    };
    let Some(total) = content_range.total else {
        return Error::e_explain(
            ErrorType::InternalError,
            "cached slice is missing complete object length",
        );
    };
    let bounds = CacheSliceBounds {
        start: content_range.start,
        end: content_range.end,
    };
    if body.len() as u64 != bounds.len() {
        return Error::e_explain(
            ErrorType::InternalError,
            "cached slice body length does not match Content-Range",
        );
    }
    Ok(CacheSliceObject {
        bounds,
        total,
        body,
        meta,
    })
}

#[cfg(feature = "cache")]
fn response_content_range(headers: &::http::HeaderMap) -> Option<CacheContentRange> {
    headers
        .get_all("content-range")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(parse_content_range)
}

#[cfg(feature = "cache")]
fn parse_content_range(value: &str) -> Option<CacheContentRange> {
    let value = value.trim();
    let rest = value.strip_prefix("bytes ")?;
    if let Some(total) = rest.strip_prefix("*/") {
        return Some(CacheContentRange {
            start: 0,
            end: 0,
            total: total.parse::<u64>().ok(),
        });
    }
    let (range, complete_len) = rest.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start = start.parse::<u64>().ok()?;
    let end = end.parse::<u64>().ok()?;
    if end < start {
        return None;
    }
    let total = if complete_len == "*" {
        None
    } else {
        Some(complete_len.parse::<u64>().ok()?)
    };
    Some(CacheContentRange { start, end, total })
}

#[cfg(feature = "cache")]
fn slice_identity(slice: &CacheSliceObject) -> CacheSliceIdentity {
    CacheSliceIdentity {
        total: slice.total,
        etag: first_header_value(slice.meta.headers(), "etag"),
        last_modified: first_header_value(slice.meta.headers(), "last-modified"),
    }
}

#[cfg(feature = "cache")]
fn first_header_value(headers: &::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .next()
        .map(ToOwned::to_owned)
}

#[cfg(feature = "cache")]
fn if_range_matches_slice_identity(if_range: &str, identity: &CacheSliceIdentity) -> bool {
    let if_range = if_range.trim();
    identity.etag.as_deref() == Some(if_range)
        || identity.last_modified.as_deref() == Some(if_range)
}

#[cfg(feature = "cache")]
fn response_has_non_identity_encoding(response: &ResponseHeader) -> bool {
    response
        .headers
        .get_all("content-encoding")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| !value.trim().eq_ignore_ascii_case("identity"))
}

#[cfg(feature = "cache")]
fn compose_slice_response(
    ranges: &[CacheSliceBounds],
    slices: &HashMap<(u64, u64), CacheSliceObject>,
    identity: &CacheSliceIdentity,
    filled: bool,
) -> Result<Option<CacheSliceComposedResponse>> {
    let Some(first_slice) = slices.values().min_by_key(|slice| slice.bounds.start) else {
        return Ok(None);
    };
    if ranges.len() == 1 {
        let range = ranges[0];
        let body = compose_single_slice_body(range, slices)?;
        let mut response = first_slice.meta.response_header_copy();
        response.status = StatusCode::PARTIAL_CONTENT;
        response.remove_header("content-range");
        response.insert_header(
            "content-range",
            format!("bytes {}-{}/{}", range.start, range.end, identity.total),
        )?;
        response.remove_header("content-length");
        response.insert_header("content-length", body.len().to_string())?;
        response.remove_header("age");
        response.insert_header("age", max_slice_age_secs(slices).to_string())?;
        return Ok(Some(CacheSliceComposedResponse {
            header: response,
            body,
            filled,
        }));
    }

    let boundary = format!("fluxheim-slice-{}", identity.total);
    let body = compose_multipart_slice_body(ranges, slices, identity.total, &boundary)?;
    let mut response = first_slice.meta.response_header_copy();
    response.status = StatusCode::PARTIAL_CONTENT;
    response.remove_header("content-range");
    response.remove_header("content-type");
    response.insert_header(
        "content-type",
        format!("multipart/byteranges; boundary={boundary}"),
    )?;
    response.remove_header("content-length");
    response.insert_header("content-length", body.len().to_string())?;
    response.remove_header("age");
    response.insert_header("age", max_slice_age_secs(slices).to_string())?;
    Ok(Some(CacheSliceComposedResponse {
        header: response,
        body,
        filled,
    }))
}

#[cfg(feature = "cache")]
fn compose_single_slice_body(
    range: CacheSliceBounds,
    slices: &HashMap<(u64, u64), CacheSliceObject>,
) -> Result<Bytes> {
    let mut body = Vec::with_capacity(usize::try_from(range.len()).unwrap_or(usize::MAX));
    for slice in slices_for_range(range, slices) {
        append_slice_overlap(&mut body, range, slice)?;
    }
    Ok(Bytes::from(body))
}

#[cfg(feature = "cache")]
fn compose_multipart_slice_body(
    ranges: &[CacheSliceBounds],
    slices: &HashMap<(u64, u64), CacheSliceObject>,
    total: u64,
    boundary: &str,
) -> Result<Bytes> {
    let content_type = slices
        .values()
        .find_map(|slice| first_header_value(slice.meta.headers(), "content-type"))
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    let mut body = Vec::new();
    for range in ranges {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Range: bytes {}-{}/{}\r\n\r\n",
                range.start, range.end, total
            )
            .as_bytes(),
        );
        for slice in slices_for_range(*range, slices) {
            append_slice_overlap(&mut body, *range, slice)?;
        }
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(Bytes::from(body))
}

#[cfg(feature = "cache")]
fn slices_for_range(
    range: CacheSliceBounds,
    slices: &HashMap<(u64, u64), CacheSliceObject>,
) -> Vec<&CacheSliceObject> {
    let mut selected = slices
        .values()
        .filter(|slice| slice.bounds.start <= range.end && slice.bounds.end >= range.start)
        .collect::<Vec<_>>();
    selected.sort_by_key(|slice| slice.bounds.start);
    selected
}

#[cfg(feature = "cache")]
fn append_slice_overlap(
    body: &mut Vec<u8>,
    range: CacheSliceBounds,
    slice: &CacheSliceObject,
) -> Result<()> {
    let start = range.start.max(slice.bounds.start);
    let end = range.end.min(slice.bounds.end);
    if end < start {
        return Ok(());
    }
    let offset = usize::try_from(start.saturating_sub(slice.bounds.start))
        .map_err(|_| Error::new_str("slice offset exceeds platform size"))?;
    let len = usize::try_from(end.saturating_sub(start).saturating_add(1))
        .map_err(|_| Error::new_str("slice length exceeds platform size"))?;
    let end_offset = offset.saturating_add(len);
    if end_offset > slice.body.len() {
        return Error::e_explain(
            ErrorType::InternalError,
            "slice overlap exceeds body length",
        );
    }
    body.extend_from_slice(&slice.body[offset..end_offset]);
    Ok(())
}

#[cfg(feature = "cache")]
fn max_slice_age_secs(slices: &HashMap<(u64, u64), CacheSliceObject>) -> u64 {
    slices
        .values()
        .map(|slice| slice.meta.age().as_secs())
        .max()
        .unwrap_or(0)
}

#[cfg(feature = "cache")]
fn slice_416_response(total: u64) -> Result<CacheSliceComposedResponse> {
    let mut response = ResponseHeader::build(StatusCode::RANGE_NOT_SATISFIABLE, Some(2))?;
    response.insert_header("content-range", format!("bytes */{total}"))?;
    response.insert_header("content-length", "0")?;
    Ok(CacheSliceComposedResponse {
        header: response,
        body: Bytes::new(),
        filled: false,
    })
}

#[cfg(feature = "cache")]
fn acquire_slice_fill_permit(key: String) -> Option<SliceFillPermit> {
    static SLICE_FILL_CONCURRENCY: OnceLock<Mutex<HashMap<String, Arc<AtomicUsize>>>> =
        OnceLock::new();
    let counter = {
        let mut counters = SLICE_FILL_CONCURRENCY
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        counters
            .entry(key)
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone()
    };
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= 1 {
            return None;
        }
        match counter.compare_exchange_weak(current, 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(SliceFillPermit { counter }),
            Err(observed) => current = observed,
        }
    }
}

#[cfg(feature = "cache")]
struct PeerFillConcurrencyPermit {
    counter: Arc<AtomicUsize>,
}

#[cfg(feature = "cache")]
impl Drop for PeerFillConcurrencyPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(feature = "cache")]
fn peer_fill_concurrency_key(vhost_name: &str, route_index: Option<usize>) -> String {
    match route_index {
        Some(route_index) => format!("vhost:{vhost_name}:route:{route_index}"),
        None => format!("vhost:{vhost_name}:route:_"),
    }
}

#[cfg(feature = "cache")]
fn acquire_peer_fill_concurrency_permit(
    key: String,
    max_concurrent_requests: usize,
) -> Option<PeerFillConcurrencyPermit> {
    let counter = {
        let mut counters = PEER_FILL_CONCURRENCY
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        prune_inactive_peer_fill_concurrency_counters(
            &mut counters,
            PEER_FILL_CONCURRENCY_MAX_KEYS,
        );
        if counters.len() >= PEER_FILL_CONCURRENCY_MAX_KEYS && !counters.contains_key(&key) {
            return None;
        }
        counters
            .entry(key)
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone()
    };

    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= max_concurrent_requests {
            return None;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(PeerFillConcurrencyPermit { counter }),
            Err(observed) => current = observed,
        }
    }
}

#[cfg(feature = "cache")]
fn prune_inactive_peer_fill_concurrency_counters(
    counters: &mut HashMap<String, Arc<AtomicUsize>>,
    max_keys: usize,
) {
    if counters.len() < max_keys {
        return;
    }
    counters.retain(|_, counter| counter.load(Ordering::Acquire) > 0);
}

#[cfg(feature = "cache")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PeerFillRequest {
    uri_path_and_query: String,
    host: Option<String>,
    headers: Vec<(&'static str, String)>,
}

#[cfg(feature = "cache")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PeerFillResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Bytes,
}

#[cfg(feature = "cache")]
impl PeerFillResponse {
    fn to_response_header(&self) -> Result<ResponseHeader> {
        let mut response = ResponseHeader::build(self.status, Some(self.headers.len()))?;
        for (name, value) in &self.headers {
            if peer_fill_hop_by_hop_header(name) {
                continue;
            }
            response.append_header(name.clone(), value.clone())?;
        }
        response.remove_header("content-length");
        response.insert_header("content-length", self.body.len().to_string())?;
        Ok(response)
    }
}

#[cfg(feature = "cache")]
fn peer_fill_request_from_header(request: &RequestHeader) -> PeerFillRequest {
    let mut headers = Vec::new();
    for name in ["accept", "accept-encoding", "accept-language"] {
        for value in request_header_values(request, name) {
            headers.push((name, value.to_owned()));
        }
    }
    PeerFillRequest {
        uri_path_and_query: request
            .uri
            .path_and_query()
            .map(|value| value.as_str().to_owned())
            .unwrap_or_else(|| request.uri.path().to_owned()),
        host: request_host_header(request).map(ToOwned::to_owned),
        headers,
    }
}

#[cfg(feature = "cache")]
fn fetch_peer_fill_response(
    peer: &crate::config::CachePeerConfig,
    peer_fill: &crate::config::CachePeerFillConfig,
    request: &PeerFillRequest,
    max_body_bytes: u64,
) -> std::io::Result<Option<PeerFillResponse>> {
    let url = peer_fill_url(&peer.base_url, &request.uri_path_and_query)?;
    let timeout = std::time::Duration::from_secs(
        peer_fill
            .connect_timeout_secs
            .saturating_add(peer_fill.read_timeout_secs),
    );
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into();
    let mut builder = agent
        .get(&url)
        .header("cache-control", "only-if-cached")
        .header("x-fluxheim-peer-fill", "1");
    if let Some(host) = request.host.as_deref() {
        builder = builder.header("host", host);
    }
    for (name, value) in &request.headers {
        builder = builder.header(*name, value.as_str());
    }

    let mut response = builder.call().map_err(peer_fill_io_error)?;
    if response.status().as_u16() == 504 {
        return Ok(None);
    }
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect::<Vec<_>>();
    let body = response
        .body_mut()
        .with_config()
        .limit(max_body_bytes.saturating_add(1))
        .read_to_vec()
        .map_err(peer_fill_io_error)?;
    if body.len() as u64 > max_body_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "peer fill response exceeds configured object limit",
        ));
    }

    Ok(Some(PeerFillResponse {
        status,
        headers,
        body: Bytes::from(body),
    }))
}

#[cfg(feature = "cache")]
fn peer_fill_url(base_url: &str, path_and_query: &str) -> std::io::Result<String> {
    let base_url = base_url.trim_end_matches('/');
    if safe_forward_path_and_query(path_and_query) {
        Ok(format!("{base_url}{path_and_query}"))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "peer fill request path must be absolute and traversal-free",
        ))
    }
}

#[cfg(feature = "cache")]
fn peer_fill_io_error(error: ureq::Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

#[cfg(feature = "cache")]
fn peer_fill_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(feature = "cache")]
async fn respond_proxy_cache_only_miss(
    session: &mut Session,
    ctx: &mut RequestContext,
    cache: &crate::config::CacheConfig,
    response_headers: &crate::config::ResponseHeaderPolicyConfig,
    reason: &'static str,
    status: Option<&'static str>,
) -> Result<()> {
    let body = Bytes::from_static(b"cache miss");
    let mut response = ResponseHeader::build(504, Some(6))?;
    response.insert_header("content-type", "text/plain; charset=utf-8")?;
    response.insert_header("cache-control", "no-store")?;
    response.insert_header("content-length", body.len().to_string())?;
    insert_cache_status_headers(
        &mut response,
        cache,
        Some(CacheStatusOverride {
            status: status.unwrap_or("MISS"),
            reason: Some(reason),
        }),
        CachePhase::Miss,
    )?;
    crate::headers::apply_response_policy(&mut response, response_headers)?;
    ctx.cache_observed_phase = Some(CachePhase::Miss);
    ctx.response_body_bytes_seen = body.len() as u64;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session.write_response_body(Some(body), true).await
}

#[cfg(feature = "cache")]
fn request_cache_only_if_cached(request: &RequestHeader) -> bool {
    request_header_values(request, "cache-control").any(|value| {
        value.split(',').any(|directive| {
            directive
                .trim()
                .split_once('=')
                .map_or(directive.trim(), |(name, _)| name.trim())
                .eq_ignore_ascii_case("only-if-cached")
        })
    })
}

fn downstream_tls(session: &Session) -> bool {
    session
        .digest()
        .is_some_and(|digest| digest.ssl_digest.is_some())
}

async fn respond_host_routing_rejection(
    session: &mut Session,
    reason: HostRoutingRejectReason,
) -> Result<()> {
    log::warn!(
        target: "fluxheim::security",
        "rejecting request with {} host routing failure",
        reason.as_str()
    );
    #[cfg(feature = "metrics")]
    crate::metrics::record_host_routing_rejection(reason.as_str());
    session
        .respond_error_with_body(reason.status(), Bytes::from_static(reason.response_body()))
        .await
}

#[cfg(feature = "php-fpm")]
const MAX_PHP_PARAM_VALUE_BYTES: usize = 16 * 1024;

#[cfg(feature = "php-fpm")]
#[derive(Debug, Clone, Eq, PartialEq)]
struct PhpScriptResolution {
    file: crate::web::StaticFile,
    script_name: String,
    path_info: String,
}

#[cfg(feature = "php-fpm")]
enum PhpResolveOutcome {
    Execute(PhpScriptResolution),
    RedirectDirectorySlash,
    Decline,
    Forbidden,
    NotFound,
}

#[cfg(feature = "php-fpm")]
fn record_php_request_metrics(
    vhost: &RuntimeVhost,
    method: &str,
    status: Option<u16>,
    outcome: &str,
    started_at: Instant,
) {
    #[cfg(feature = "metrics")]
    crate::metrics::record_php_request(
        vhost.name.as_str(),
        method,
        status,
        outcome,
        started_at.elapsed(),
    );

    #[cfg(not(feature = "metrics"))]
    {
        let _ = (vhost, method, status, outcome, started_at);
    }
}

async fn respond_php_request(
    session: &mut Session,
    ctx: &mut RequestContext,
    vhost: &RuntimeVhost,
    response_headers: &crate::config::ResponseHeaderPolicyConfig,
    php: &RuntimePhp,
    decline_existing_static: bool,
    request_path_override: Option<String>,
) -> Result<bool> {
    let request_path =
        request_path_override.unwrap_or_else(|| session.req_header().uri.path().to_owned());
    let query = session.req_header().uri.query().unwrap_or("").to_owned();
    let request_uri = session
        .req_header()
        .uri
        .path_and_query()
        .map(|path_and_query| path_and_query.as_str().to_owned())
        .unwrap_or_else(|| request_path.clone());
    let method = session.req_header().method.as_str().to_owned();
    let started_at = Instant::now();
    let version = session.req_header().version;
    let resolution = match resolve_php_script(php, &request_path, decline_existing_static) {
        PhpResolveOutcome::Execute(resolution) => resolution,
        PhpResolveOutcome::RedirectDirectorySlash => {
            respond_directory_slash_redirect(session, response_headers).await?;
            record_php_request_metrics(vhost, &method, Some(308), "redirect", started_at);
            return Ok(true);
        }
        PhpResolveOutcome::Decline => {
            record_php_request_metrics(vhost, &method, None, "declined", started_at);
            return Ok(false);
        }
        PhpResolveOutcome::Forbidden => {
            session
                .respond_error_with_body(403, Bytes::from_static(b"forbidden"))
                .await?;
            record_php_request_metrics(vhost, &method, Some(403), "forbidden", started_at);
            return Ok(true);
        }
        PhpResolveOutcome::NotFound => {
            session
                .respond_error_with_body(404, Bytes::from_static(b"not found"))
                .await?;
            record_php_request_metrics(vhost, &method, Some(404), "not_found", started_at);
            return Ok(true);
        }
    };

    let body_limit = php
        .config
        .max_request_body_bytes
        .map(|bytes| bytes.as_u64())
        .or(ctx.request_body_limit_bytes)
        .unwrap_or(u64::MAX);
    let request_body = if php.config.pass_request_body {
        read_php_request_body(session, ctx, body_limit).await?
    } else {
        drain_php_request_body(session, ctx, body_limit).await?;
        Vec::new()
    };
    let content_type = if php.config.pass_request_body {
        request_header_values_joined(session.req_header(), "content-type").unwrap_or_default()
    } else {
        String::new()
    };
    let is_tls = downstream_tls(session);
    let request_scheme = if is_tls { "https" } else { "http" };
    let server_port = if is_tls { 443 } else { 80 };
    let remote = session.client_addr().and_then(|address| address.as_inet());
    let remote_addr = remote
        .map(|address| address.ip().to_string())
        .unwrap_or_default();
    let remote_port = remote.map(|address| address.port()).unwrap_or_default();
    let document_root = php.fpm_root.to_string_lossy().to_string();
    let script_filename = php_fpm_script_filename(php, &resolution.file.path)
        .unwrap_or_else(|| resolution.file.path.to_string_lossy().to_string());
    let host = request_host(session).unwrap_or(vhost.name.as_str());

    let mut params = fastcgi_client::Params::default()
        .gateway_interface("CGI/1.1")
        .server_software("fluxheim")
        .server_protocol(http_version_cgi(version))
        .request_method(method.clone())
        .script_name(resolution.script_name.clone())
        .script_filename(script_filename)
        .query_string(query)
        .request_uri(request_uri)
        .document_root(document_root)
        .document_uri(resolution.script_name.clone())
        .remote_addr(remote_addr)
        .remote_port(remote_port)
        .server_addr("")
        .server_port(server_port)
        .server_name(host.to_owned())
        .content_type(content_type)
        .content_length(request_body.len())
        .custom("REQUEST_SCHEME", request_scheme)
        .custom("HTTPS", if is_tls { "on" } else { "off" })
        .custom("REDIRECT_STATUS", "200");
    if php.config.pass_request_headers {
        add_php_request_header_params(&mut params, session.req_header());
        add_php_host_param(&mut params, host);
    }
    add_php_custom_params(&mut params, &php.config.params);
    if !resolution.path_info.is_empty() {
        params = params.custom("PATH_INFO", resolution.path_info.clone());
        let path_translated = php_fpm_path_translated(php, &resolution.path_info);
        params = params.custom("PATH_TRANSLATED", path_translated);
    }

    let timeout = std::time::Duration::from_secs(php.config.request_timeout_secs);
    let output = match execute_php_fpm(
        php.pool.as_deref(),
        &php.config.fpm,
        params,
        request_body,
        timeout,
        &method,
        vhost.name.as_str(),
    )
    .await
    {
        Ok(output) => output,
        Err(error) => {
            record_php_request_metrics(
                vhost,
                &method,
                Some(502),
                php_fpm_error_outcome(&error),
                started_at,
            );
            return Err(Error::because(
                ErrorType::HTTPStatus(502),
                "php-fpm request failed",
                error,
            ));
        }
    };
    if let Some(stderr) = output.stderr.as_deref()
        && !stderr.is_empty()
    {
        let stderr_max_bytes = php.config.stderr_max_bytes.as_u64() as usize;
        #[cfg(feature = "metrics")]
        crate::metrics::record_php_stderr(
            vhost.name.as_str(),
            php_stderr_metric_state(stderr, stderr_max_bytes),
        );
        if php.config.stderr_log {
            log::warn!(
                "php-fpm stderr: {}",
                sanitized_php_stderr(stderr, stderr_max_bytes)
            );
        }
    }
    let stdout = output.stdout.unwrap_or_default();
    let (mut response, body) = match parse_php_response(
        &stdout,
        php.config.max_response_bytes.as_u64(),
        php.config.max_response_header_bytes.as_u64(),
    ) {
        Ok(parsed) => parsed,
        Err(error) => {
            record_php_request_metrics(vhost, &method, Some(502), "invalid_response", started_at);
            return Err(Error::because(
                ErrorType::HTTPStatus(502),
                "php-fpm response was invalid",
                error,
            ));
        }
    };
    apply_php_x_accel_expires(&mut response).map_err(|error| {
        Error::because(
            ErrorType::HTTPStatus(502),
            "php-fpm response cache controls were invalid",
            error,
        )
    })?;
    if response.status == StatusCode::OK {
        match php_static_offload_file(&mut response, php) {
            Ok(Some(file)) => {
                let status =
                    respond_php_static_offload(session, ctx, php, &file, &method, response_headers)
                        .await?;
                record_php_request_metrics(
                    vhost,
                    &method,
                    Some(status),
                    if status == 413 {
                        "offload_error"
                    } else {
                        "offload"
                    },
                    started_at,
                );
                return Ok(true);
            }
            Ok(None) => {}
            Err(error) => {
                let status = match error.kind() {
                    io::ErrorKind::PermissionDenied => 403,
                    io::ErrorKind::NotFound => 404,
                    _ => 502,
                };
                record_php_request_metrics(
                    vhost,
                    &method,
                    Some(status),
                    "offload_error",
                    started_at,
                );
                session.respond_error(status).await?;
                ctx.response_body_bytes_seen = 0;
                return Ok(true);
            }
        }
    } else {
        strip_php_static_offload_headers(&mut response);
    }
    strip_php_response_headers(&mut response, &php.config);
    if php_should_intercept_error_status(response.status, php) {
        let status = response.status.as_u16();
        let sent_custom_page = if let Some(error_page) = php.error_page(status) {
            respond_custom_proxy_error_page(session, status, error_page, response_headers).await?
        } else {
            false
        };
        if !sent_custom_page {
            session.respond_error(status).await?;
        }
        record_php_request_metrics(vhost, &method, Some(status), "intercepted", started_at);
        ctx.response_body_bytes_seen = 0;
        return Ok(true);
    }
    response.remove_header("content-length");
    response.insert_header("content-length", body.len().to_string())?;
    crate::headers::apply_response_policy(&mut response, response_headers)?;

    let is_head = method == "HEAD";
    let response_status = response.status.as_u16();
    ctx.response_body_bytes_seen = if is_head { 0 } else { body.len() as u64 };
    session
        .write_response_header(Box::new(response), is_head || body.is_empty())
        .await?;
    if !is_head && !body.is_empty() {
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
    }
    record_php_request_metrics(
        vhost,
        &method,
        Some(response_status),
        "response",
        started_at,
    );
    Ok(true)
}

#[cfg(feature = "php-fpm")]
async fn respond_php_static_offload(
    session: &mut Session,
    ctx: &mut RequestContext,
    php: &RuntimePhp,
    file: &crate::web::StaticFile,
    method: &str,
    response_headers: &crate::config::ResponseHeaderPolicyConfig,
) -> Result<u16> {
    let request = session.req_header();
    let if_match = request_header_values_joined(request, "if-match");
    let if_unmodified_since = request_header_values_joined(request, "if-unmodified-since");
    let if_none_match = request_header_values_joined(request, "if-none-match");
    let if_modified_since = request_header_values_joined(request, "if-modified-since");
    let cache_control = request_header_values_joined(request, "cache-control");
    let pragma = request_header_values_joined(request, "pragma");
    let range = request_header_values_joined(request, "range");
    let if_range = request_header_values_joined(request, "if-range");
    let plan = crate::web::plan_static_response(
        file,
        method,
        crate::web::StaticRequestConditions {
            if_match: if_match.as_deref(),
            if_unmodified_since: if_unmodified_since.as_deref(),
            if_none_match: if_none_match.as_deref(),
            if_modified_since: if_modified_since.as_deref(),
            cache_control: cache_control.as_deref(),
            pragma: pragma.as_deref(),
            range: range.as_deref(),
            if_range: if_range.as_deref(),
        },
    );
    if plan.response_body_bytes > crate::web::MAX_STATIC_BUFFERED_BODY_BYTES {
        session
            .respond_error_with_body(
                413,
                Bytes::from_static(b"static offload response too large"),
            )
            .await?;
        ctx.response_body_bytes_seen = 0;
        return Ok(413);
    }

    let status = plan.status;
    ctx.response_body_bytes_seen = plan.response_body_bytes;
    crate::web::serve_static_file(session, &php.files, file, &plan, response_headers).await?;
    Ok(status)
}

#[cfg(feature = "php-fpm")]
fn resolve_php_script(
    php: &RuntimePhp,
    request_path: &str,
    decline_existing_static: bool,
) -> PhpResolveOutcome {
    let Some((script_name, path_info, explicit_php)) =
        php_script_name_for_request(php, request_path)
    else {
        return PhpResolveOutcome::Forbidden;
    };
    if php_script_name_denied(php, &script_name) {
        return PhpResolveOutcome::Forbidden;
    }

    if !explicit_php && let Ok(ResolveResult::Found(file)) = php.files.resolve(request_path) {
        if let Some(script_name) = php_static_file_script_name(php, &file) {
            if php_should_redirect_directory_index(request_path, &script_name, php) {
                return PhpResolveOutcome::RedirectDirectorySlash;
            }
            return PhpResolveOutcome::Execute(PhpScriptResolution {
                file,
                script_name,
                path_info,
            });
        }
        if decline_existing_static {
            return PhpResolveOutcome::Decline;
        }
    }
    if !explicit_php && php.config.try_files == crate::config::PhpTryFilesMode::Strict {
        return PhpResolveOutcome::NotFound;
    }

    match php.files.resolve(&script_name) {
        Ok(ResolveResult::Found(file)) => PhpResolveOutcome::Execute(PhpScriptResolution {
            file,
            script_name,
            path_info,
        }),
        Ok(ResolveResult::Forbidden) => PhpResolveOutcome::Forbidden,
        Ok(ResolveResult::NotFound | ResolveResult::DirectoryListing(_)) => {
            PhpResolveOutcome::NotFound
        }
        Err(error) => {
            log::warn!("php script resolver failed: {error}");
            PhpResolveOutcome::NotFound
        }
    }
}

#[cfg(feature = "php-fpm")]
async fn respond_directory_slash_redirect(
    session: &mut Session,
    response_headers: &crate::config::ResponseHeaderPolicyConfig,
) -> Result<()> {
    let Some(location) = directory_slash_redirect_location(session.req_header()) else {
        session
            .respond_error_with_body(400, Bytes::from_static(b"invalid redirect target"))
            .await?;
        return Ok(());
    };
    let mut response = ResponseHeader::build(308, Some(4))?;
    response.insert_header("location", location)?;
    response.insert_header("content-length", "0")?;
    crate::headers::apply_response_policy(&mut response, response_headers)?;
    session
        .write_response_header(Box::new(response), true)
        .await
}

#[cfg(feature = "php-fpm")]
fn directory_slash_redirect_location(request: &RequestHeader) -> Option<String> {
    let path = request.uri.path();
    if path.is_empty() || path.ends_with('/') || path.contains('\\') {
        return None;
    }
    let mut location = String::with_capacity(
        path.len()
            + 1
            + request
                .uri
                .query()
                .map(|query| query.len() + 1)
                .unwrap_or(0),
    );
    location.push_str(path);
    location.push('/');
    if let Some(query) = request.uri.query() {
        location.push('?');
        location.push_str(query);
    }
    Some(location)
}

#[cfg(feature = "php-fpm")]
fn php_should_redirect_directory_index(
    request_path: &str,
    script_name: &str,
    php: &RuntimePhp,
) -> bool {
    if request_path.ends_with('/') || request_path.contains('\\') {
        return false;
    }
    let Some(parent) = script_name.strip_suffix(&format!("/{}", php.config.index)) else {
        return false;
    };
    !parent.is_empty() && parent == request_path
}

#[cfg(feature = "php-fpm")]
fn php_static_file_script_name(php: &RuntimePhp, file: &crate::web::StaticFile) -> Option<String> {
    let relative = file.path.strip_prefix(&php.root).ok()?;
    let mut script_name = String::new();
    for component in relative.components() {
        let std::path::Component::Normal(segment) = component else {
            return None;
        };
        let segment = segment.to_str()?;
        if segment.is_empty() || segment == "." || segment == ".." || segment.starts_with('.') {
            return None;
        }
        script_name.push('/');
        script_name.push_str(segment);
    }
    if script_name.is_empty() || !php_segment_has_allowed_extension(&script_name, php) {
        return None;
    }
    Some(script_name)
}

#[cfg(feature = "php-fpm")]
fn php_fpm_script_filename(php: &RuntimePhp, local_path: &std::path::Path) -> Option<String> {
    let relative = local_path.strip_prefix(&php.root).ok()?;
    Some(php.fpm_root.join(relative).to_string_lossy().to_string())
}

#[cfg(feature = "php-fpm")]
fn php_fpm_path_translated(php: &RuntimePhp, path_info: &str) -> String {
    php.fpm_root
        .join(path_info.trim_start_matches('/'))
        .to_string_lossy()
        .to_string()
}

#[cfg(feature = "php-fpm")]
fn php_script_name_for_request(
    php: &RuntimePhp,
    request_path: &str,
) -> Option<(String, String, bool)> {
    let decoded = percent_encoding::percent_decode_str(request_path)
        .decode_utf8()
        .ok()?;
    if !decoded.starts_with('/') || decoded.contains('\0') {
        return None;
    }

    let mut segments = Vec::new();
    for segment in decoded.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." || segment.contains('\\') || segment.starts_with('.') {
            return None;
        }
        segments.push(segment.to_owned());
    }

    if let Some((index, _)) = segments
        .iter()
        .enumerate()
        .find(|(_, segment)| php_segment_has_allowed_extension(segment, php))
    {
        let script_name = format!("/{}", segments[..=index].join("/"));
        let trailing = &segments[index + 1..];
        if !trailing.is_empty() && php.config.path_info == crate::config::PhpPathInfoMode::Disabled
        {
            return None;
        }
        let path_info = if trailing.is_empty() {
            String::new()
        } else {
            format!("/{}", trailing.join("/"))
        };
        return Some((script_name, path_info, true));
    }

    Some((format!("/{}", php.config.index), String::new(), false))
}

#[cfg(feature = "php-fpm")]
fn php_script_name_denied(php: &RuntimePhp, script_name: &str) -> bool {
    php.config.deny_path_prefixes.iter().any(|prefix| {
        script_name == prefix
            || script_name
                .strip_prefix(prefix)
                .is_some_and(|rest| prefix.ends_with('/') || rest.starts_with('/'))
    })
}

#[cfg(feature = "php-fpm")]
fn php_segment_has_allowed_extension(segment: &str, php: &RuntimePhp) -> bool {
    segment.rsplit_once('.').is_some_and(|(_, extension)| {
        php.config
            .allowed_extensions
            .iter()
            .any(|allowed| extension.eq_ignore_ascii_case(allowed))
    })
}

#[cfg(feature = "php-fpm")]
fn add_php_request_header_params(params: &mut fastcgi_client::Params<'_>, request: &RequestHeader) {
    let mut translated = std::collections::BTreeMap::<String, String>::new();
    for (name, value) in &request.headers {
        let Some(param_name) = php_header_param_name(name.as_str()) else {
            continue;
        };
        let Ok(value) = value.to_str() else {
            continue;
        };
        if !safe_php_param_value(value) {
            continue;
        }
        translated
            .entry(param_name)
            .and_modify(|existing| {
                if name.as_str().eq_ignore_ascii_case("cookie") {
                    existing.push_str("; ");
                } else {
                    existing.push_str(", ");
                }
                existing.push_str(value);
            })
            .or_insert_with(|| value.to_owned());
    }

    for (name, value) in translated {
        params.insert(name.into(), value.into());
    }
}

#[cfg(feature = "php-fpm")]
fn add_php_host_param(params: &mut fastcgi_client::Params<'_>, host: &str) {
    if safe_php_param_value(host) {
        params.insert("HTTP_HOST".into(), host.to_owned().into());
    }
}

#[cfg(feature = "php-fpm")]
fn add_php_custom_params(
    params: &mut fastcgi_client::Params<'_>,
    custom: &std::collections::BTreeMap<String, String>,
) {
    for (name, value) in custom {
        params.insert(name.clone().into(), value.clone().into());
    }
}

#[cfg(feature = "php-fpm")]
fn php_header_param_name(name: &str) -> Option<String> {
    if name.eq_ignore_ascii_case("proxy")
        || name.eq_ignore_ascii_case("content-type")
        || name.eq_ignore_ascii_case("content-length")
    {
        return None;
    }
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return None;
    }

    let mut param = String::with_capacity("HTTP_".len() + name.len());
    param.push_str("HTTP_");
    for byte in name.bytes() {
        if byte == b'-' {
            param.push('_');
        } else {
            param.push((byte as char).to_ascii_uppercase());
        }
    }
    Some(param)
}

#[cfg(feature = "php-fpm")]
fn safe_php_param_value(value: &str) -> bool {
    value.len() <= MAX_PHP_PARAM_VALUE_BYTES
        && value.bytes().all(|byte| !matches!(byte, 0..=31 | 127))
}

#[cfg(feature = "php-fpm")]
async fn read_php_request_body(
    session: &mut Session,
    ctx: &mut RequestContext,
    limit_bytes: u64,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = session.as_downstream_mut().read_request_body().await? {
        if request_body_chunk_limit_status(
            limit_bytes,
            &mut ctx.request_body_bytes_seen,
            chunk.len(),
        )
        .is_some()
        {
            return Error::e_explain(
                ErrorType::HTTPStatus(413),
                "PHP request body exceeds configured limit",
            );
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(feature = "php-fpm")]
async fn drain_php_request_body(
    session: &mut Session,
    ctx: &mut RequestContext,
    limit_bytes: u64,
) -> Result<()> {
    while let Some(chunk) = session.as_downstream_mut().read_request_body().await? {
        if request_body_chunk_limit_status(
            limit_bytes,
            &mut ctx.request_body_bytes_seen,
            chunk.len(),
        )
        .is_some()
        {
            return Error::e_explain(
                ErrorType::HTTPStatus(413),
                "PHP request body exceeds configured limit",
            );
        }
    }
    Ok(())
}

#[cfg(feature = "php-fpm")]
fn php_fpm_error_outcome(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::TimedOut => {
            if error.to_string().contains("connect") {
                "connect_timeout"
            } else {
                "request_timeout"
            }
        }
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::NotConnected
        | io::ErrorKind::AddrInUse
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::NotFound
        | io::ErrorKind::UnexpectedEof => "connection_error",
        io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported => "configuration_error",
        _ => "fpm_error",
    }
}

#[cfg(feature = "php-fpm")]
async fn execute_php_fpm(
    pool: Option<&PhpFpmPool>,
    fpm: &crate::config::PhpFpmConfig,
    params: fastcgi_client::Params<'_>,
    body: Vec<u8>,
    timeout: std::time::Duration,
    method: &str,
    vhost_name: &str,
) -> io::Result<fastcgi_client::Response> {
    let connect_timeout = fpm
        .connect_timeout_secs
        .map(Duration::from_secs)
        .unwrap_or(timeout);
    let max_retries = php_fpm_retry_attempts(fpm, method);
    let mut attempts = 0;
    loop {
        let result = execute_php_fpm_once(
            pool,
            fpm,
            params.clone(),
            body.clone(),
            connect_timeout,
            timeout,
        )
        .await;
        match result {
            Ok(response) => return Ok(response),
            Err(error) if attempts < max_retries && php_fpm_retryable_error(&error) => {
                attempts += 1;
                #[cfg(feature = "metrics")]
                crate::metrics::record_php_fpm_retry(vhost_name, php_fpm_error_outcome(&error));
                log::debug!("retrying php-fpm request after {}", error);
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(feature = "php-fpm")]
async fn execute_php_fpm_once(
    pool: Option<&PhpFpmPool>,
    fpm: &crate::config::PhpFpmConfig,
    params: fastcgi_client::Params<'_>,
    body: Vec<u8>,
    connect_timeout: Duration,
    timeout: std::time::Duration,
) -> io::Result<fastcgi_client::Response> {
    if let Some(pool) = pool {
        return pool.execute(params, body, connect_timeout, timeout).await;
    }
    if let Some(address) = fpm.tcp.as_deref() {
        let stream = tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(address))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "php-fpm connect timed out"))??;
        execute_php_fpm_stream(stream, params, body, timeout).await
    } else if let Some(socket) = fpm.socket.as_deref() {
        #[cfg(unix)]
        {
            let stream =
                tokio::time::timeout(connect_timeout, tokio::net::UnixStream::connect(socket))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "php-fpm socket connect timed out")
                    })??;
            execute_php_fpm_stream(stream, params, body, timeout).await
        }
        #[cfg(not(unix))]
        {
            let _ = socket;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "php-fpm Unix sockets are only supported on Unix",
            ))
        }
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "php-fpm socket or tcp is required",
        ))
    }
}

#[cfg(feature = "php-fpm")]
fn php_fpm_retry_attempts(fpm: &crate::config::PhpFpmConfig, method: &str) -> u8 {
    if fpm.max_retries == 0
        || !fpm
            .retry_methods
            .iter()
            .any(|retry_method| retry_method.eq_ignore_ascii_case(method))
    {
        return 0;
    }
    fpm.max_retries
}

#[cfg(feature = "php-fpm")]
fn php_fpm_retryable_error(error: &io::Error) -> bool {
    match error.kind() {
        io::ErrorKind::TimedOut => error.to_string().contains("connect"),
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::NotConnected
        | io::ErrorKind::AddrInUse
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::NotFound
        | io::ErrorKind::UnexpectedEof => true,
        _ => false,
    }
}

#[cfg(feature = "php-fpm")]
async fn execute_php_fpm_stream<S>(
    stream: S,
    params: fastcgi_client::Params<'_>,
    body: Vec<u8>,
    timeout: std::time::Duration,
) -> io::Result<fastcgi_client::Response>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let client = fastcgi_client::Client::new_tokio(stream);
    let request = fastcgi_client::Request::new(params, fastcgi_client::io::Cursor::new(body));
    tokio::time::timeout(timeout, client.execute_once(request))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "php-fpm request timed out"))?
        .map_err(|error| io::Error::other(error.to_string()))
}

#[cfg(feature = "php-fpm")]
fn parse_php_response(
    stdout: &[u8],
    max_response_bytes: u64,
    max_response_header_bytes: u64,
) -> io::Result<(ResponseHeader, Vec<u8>)> {
    if stdout.len() as u64 > max_response_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "php-fpm response exceeds maximum buffered size",
        ));
    }
    let (header_bytes, body) = split_php_response(stdout)?;
    if header_bytes.len() as u64 > max_response_header_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "php-fpm response headers exceed maximum size",
        ));
    }

    let mut status = 200;
    let mut response = php_response_header(status)?;
    for line in header_bytes.split(|byte| *byte == b'\n') {
        let line = trim_ascii_cr(line);
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_first_colon() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "php-fpm response header is malformed",
            ));
        };
        let name = trim_ascii(name);
        let value = trim_ascii(value);
        if !safe_php_header_name(name) || !safe_php_header_value(value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "php-fpm response header contains unsafe bytes",
            ));
        }
        if name.eq_ignore_ascii_case(b"status") {
            status = parse_php_status(value)?;
            response.status = StatusCode::from_u16(status)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            continue;
        }
        let name = std::str::from_utf8(name)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let value = std::str::from_utf8(value)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        response
            .append_header(name.to_owned(), value.to_owned())
            .map_err(|error| io::Error::other(error.to_string()))?;
    }

    Ok((response, body.to_vec()))
}

#[cfg(feature = "php-fpm")]
fn http_version_cgi(version: http::Version) -> &'static str {
    match version {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2.0",
        http::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

#[cfg(feature = "php-fpm")]
fn php_response_header(status: u16) -> io::Result<ResponseHeader> {
    ResponseHeader::build(status, Some(8)).map_err(|error| io::Error::other(error.to_string()))
}

#[cfg(feature = "php-fpm")]
fn split_php_response(stdout: &[u8]) -> io::Result<(&[u8], &[u8])> {
    if let Some(index) = stdout.windows(4).position(|window| window == b"\r\n\r\n") {
        return Ok((&stdout[..index], &stdout[index + 4..]));
    }
    if let Some(index) = stdout.windows(2).position(|window| window == b"\n\n") {
        return Ok((&stdout[..index], &stdout[index + 2..]));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "php-fpm response is missing header terminator",
    ))
}

#[cfg(feature = "php-fpm")]
fn parse_php_status(value: &[u8]) -> io::Result<u16> {
    let text = std::str::from_utf8(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let status = text
        .split_whitespace()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty PHP Status header"))?
        .parse::<u16>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if !(100..=599).contains(&status) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PHP Status header is outside HTTP status range",
        ));
    }
    Ok(status)
}

#[cfg(feature = "php-fpm")]
fn trim_ascii_cr(value: &[u8]) -> &[u8] {
    value.strip_suffix(b"\r").unwrap_or(value)
}

#[cfg(feature = "php-fpm")]
fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(feature = "php-fpm")]
fn safe_php_header_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
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
                )
        })
}

#[cfg(feature = "php-fpm")]
fn safe_php_header_value(value: &[u8]) -> bool {
    value.iter().all(|byte| !matches!(byte, b'\r' | b'\n' | 0))
}

#[cfg(feature = "php-fpm")]
trait SplitFirstColon {
    fn split_first_colon(&self) -> Option<(&[u8], &[u8])>;
}

#[cfg(feature = "php-fpm")]
impl SplitFirstColon for [u8] {
    fn split_first_colon(&self) -> Option<(&[u8], &[u8])> {
        let index = self.iter().position(|byte| *byte == b':')?;
        Some((&self[..index], &self[index + 1..]))
    }
}

#[cfg(all(feature = "php-fpm", any(feature = "metrics", test)))]
fn php_stderr_metric_state(stderr: &[u8], max_bytes: usize) -> &'static str {
    if stderr.len() > max_bytes {
        "truncated"
    } else {
        "emitted"
    }
}

fn sanitized_php_stderr(stderr: &[u8], max_bytes: usize) -> String {
    let max_bytes = max_bytes.max(1);
    let truncated = stderr.len() > max_bytes;
    let mut output: String = String::from_utf8_lossy(&stderr[..stderr.len().min(max_bytes)])
        .chars()
        .map(|char| if char.is_control() { ' ' } else { char })
        .collect();
    if truncated {
        output.push_str(" ... <truncated>");
    }
    output
}

#[cfg(feature = "web")]
async fn serve_static_route(
    session: &mut Session,
    ctx: &mut RequestContext,
    vhost: &RuntimeVhost,
    route_index: usize,
    web: &StaticFileServer,
    route: &RuntimeRoute,
) -> Result<bool> {
    #[cfg(not(feature = "cache"))]
    {
        let _ = vhost;
        let _ = route_index;
    }

    let method = session.req_header().method.as_str().to_owned();
    if method != "GET" && method != "HEAD" {
        return Ok(false);
    }

    let request_path = route
        .strip_prefix
        .as_deref()
        .and_then(|_| route_rewritten_path_and_query(session.req_header(), route))
        .and_then(|path_and_query| {
            path_and_query
                .split_once('?')
                .map(|(path, _)| path.to_owned())
                .or(Some(path_and_query))
        })
        .unwrap_or_else(|| session.req_header().uri.path().to_owned());

    match web.resolve(&request_path) {
        Ok(ResolveResult::Found(file)) => {
            let if_match = request_header_values_joined(session.req_header(), "if-match");
            let if_unmodified_since =
                request_header_values_joined(session.req_header(), "if-unmodified-since");
            let if_none_match = request_header_values_joined(session.req_header(), "if-none-match");
            let if_modified_since =
                request_header_values_joined(session.req_header(), "if-modified-since");
            let cache_control = request_header_values_joined(session.req_header(), "cache-control");
            let pragma = request_header_values_joined(session.req_header(), "pragma");
            let range = request_header_values_joined(session.req_header(), "range");
            let if_range = request_header_values_joined(session.req_header(), "if-range");
            let plan = crate::web::plan_static_response(
                &file,
                &method,
                crate::web::StaticRequestConditions {
                    if_match: if_match.as_deref(),
                    if_unmodified_since: if_unmodified_since.as_deref(),
                    if_none_match: if_none_match.as_deref(),
                    if_modified_since: if_modified_since.as_deref(),
                    cache_control: cache_control.as_deref(),
                    pragma: pragma.as_deref(),
                    range: range.as_deref(),
                    if_range: if_range.as_deref(),
                },
            );
            if plan.response_body_bytes > crate::web::MAX_STATIC_BUFFERED_BODY_BYTES {
                session
                    .respond_error_with_body(413, Bytes::from_static(b"static response too large"))
                    .await?;
                return Ok(true);
            }
            let static_request = StaticServeRequest {
                #[cfg(feature = "cache")]
                vhost,
                #[cfg(feature = "cache")]
                route_index: Some(route_index),
                web,
                file: &file,
                plan: &plan,
                response_headers: &route.response_headers,
            };
            serve_static_file_maybe_cached(session, ctx, static_request).await?;
            Ok(true)
        }
        Ok(ResolveResult::DirectoryListing(listing)) => {
            ctx.response_body_bytes_seen = crate::web::serve_directory_listing(
                session,
                &listing,
                &method,
                &route.response_headers,
            )
            .await?;
            Ok(true)
        }
        Ok(ResolveResult::Forbidden) => {
            session
                .respond_error_with_body(403, Bytes::from_static(b"forbidden"))
                .await?;
            Ok(true)
        }
        Ok(ResolveResult::NotFound) => Ok(false),
        Err(error) => {
            log::error!("static route resolver failed: {error}");
            session
                .respond_error_with_body(500, Bytes::from_static(b"internal server error"))
                .await?;
            Ok(true)
        }
    }
}

#[cfg(feature = "web")]
struct StaticServeRequest<'a> {
    #[cfg(feature = "cache")]
    vhost: &'a RuntimeVhost,
    #[cfg(feature = "cache")]
    route_index: Option<usize>,
    web: &'a StaticFileServer,
    file: &'a crate::web::StaticFile,
    plan: &'a crate::web::StaticResponsePlan,
    response_headers: &'a crate::config::ResponseHeaderPolicyConfig,
}

#[cfg(all(feature = "web", feature = "cache"))]
async fn serve_static_file_maybe_cached(
    session: &mut Session,
    ctx: &mut RequestContext,
    request: StaticServeRequest<'_>,
) -> Result<()> {
    let StaticServeRequest {
        vhost,
        route_index,
        web,
        file,
        plan,
        response_headers,
    } = request;
    let cache = static_cache_config(vhost, route_index);
    let cache_headers = |status, reason| crate::web::StaticCacheHeaders {
        status_header: cache.status_header.as_deref(),
        status,
        reason_header: cache.status_reason_header.as_deref(),
        reason,
        age_secs: None,
    };

    let Some(storage) = static_cache_storage(vhost, route_index) else {
        ctx.response_body_bytes_seen = plan.response_body_bytes;
        return crate::web::serve_static_file(session, web, file, plan, response_headers).await;
    };

    let Some(cache_key) =
        static_cache_key_for_file(session.req_header(), cache, vhost, route_index, file)
    else {
        ctx.response_body_bytes_seen = plan.response_body_bytes;
        let headers = if cache.local_static {
            cache_headers(Some("BYPASS"), Some("static-ineligible"))
        } else {
            crate::web::StaticCacheHeaders::default()
        };
        return crate::web::serve_static_file_with_cache_headers(
            session,
            web,
            file,
            plan,
            response_headers,
            plan.status,
            headers,
        )
        .await;
    };

    if let Some(reason) = request_cache_bypass_reason(session.req_header(), cache) {
        #[cfg(feature = "metrics")]
        record_cache_policy_activity(vhost, route_index, "bypass");
        ctx.response_body_bytes_seen = plan.response_body_bytes;
        return crate::web::serve_static_file_with_cache_headers(
            session,
            web,
            file,
            plan,
            response_headers,
            plan.status,
            cache_headers(Some("BYPASS"), Some(reason)),
        )
        .await;
    }

    let request_refresh = request_cache_revalidation_requested(session.req_header(), cache);
    let trace = pingora::cache::trace::Span::inactive().handle();
    if !request_refresh
        && let Some((meta, hit)) = storage.lookup(&cache_key, &trace).await?
        && meta.is_fresh(std::time::SystemTime::now())
    {
        #[cfg(feature = "metrics")]
        record_cache_policy_activity(vhost, route_index, "hit");
        let age_secs = meta.age().as_secs();
        let body = read_cache_hit_body(
            hit,
            storage,
            &cache_key,
            &trace,
            crate::web::MAX_STATIC_BUFFERED_BODY_BYTES,
        )
        .await?;
        if body.len() as u64 == file.len {
            let body = static_cached_body_for_plan(&body, plan)?;
            let mut headers = cache_headers(Some("HIT"), None);
            headers.age_secs = Some(age_secs);
            ctx.response_body_bytes_seen = plan.response_body_bytes;
            return crate::web::serve_static_file_with_body_and_cache_headers(
                session,
                web,
                file,
                plan,
                response_headers,
                headers,
                body,
            )
            .await;
        }
    }

    let storeable = plan.status == 200
        && matches!(plan.body, crate::web::StaticResponseBody::Full)
        && plan.response_body_bytes <= cache.max_object_bytes.as_u64();
    if !storeable {
        ctx.response_body_bytes_seen = plan.response_body_bytes;
        return crate::web::serve_static_file_with_cache_headers(
            session,
            web,
            file,
            plan,
            response_headers,
            plan.status,
            cache_headers(Some("BYPASS"), Some("static-not-storeable")),
        )
        .await;
    }

    let body = crate::web::read_static_response_body(file, plan.body).map_err(|error| {
        Error::because(
            ErrorType::InternalError,
            "failed to read static file",
            error,
        )
    })?;
    let store_response = crate::web::build_static_response_header(
        web,
        file,
        plan,
        response_headers,
        crate::web::StaticCacheHeaders::default(),
    )?;
    if let Some(reason) = response_cache_admission_rejection(&store_response, cache) {
        ctx.response_body_bytes_seen = plan.response_body_bytes;
        return crate::web::serve_static_file_with_body_and_cache_headers(
            session,
            web,
            file,
            plan,
            response_headers,
            cache_headers(Some("BYPASS"), Some(reason)),
            body,
        )
        .await;
    }
    let Some(ttl_secs) = cache_response_fresh_ttl_secs(cache, &store_response) else {
        ctx.response_body_bytes_seen = plan.response_body_bytes;
        return crate::web::serve_static_file_with_body_and_cache_headers(
            session,
            web,
            file,
            plan,
            response_headers,
            cache_headers(Some("BYPASS"), Some("zero-freshness")),
            body,
        )
        .await;
    };

    let now = std::time::SystemTime::now();
    let fresh_until = now
        .checked_add(std::time::Duration::from_secs(u64::from(ttl_secs)))
        .unwrap_or(now);
    let meta = CacheMeta::new(
        fresh_until,
        now,
        cache.stale_while_revalidate_secs.unwrap_or(0),
        cache.stale_if_error_secs.unwrap_or(0),
        store_response,
    );
    let mut miss = storage.get_miss_handler(&cache_key, &meta, &trace).await?;
    miss.write_body(body.clone(), true).await?;
    let _ = miss.finish().await?;
    #[cfg(feature = "metrics")]
    record_cache_policy_activity(vhost, route_index, "store");
    ctx.response_body_bytes_seen = plan.response_body_bytes;
    crate::web::serve_static_file_with_body_and_cache_headers(
        session,
        web,
        file,
        plan,
        response_headers,
        cache_headers(
            Some(if request_refresh {
                "REVALIDATED"
            } else {
                "MISS"
            }),
            None,
        ),
        body,
    )
    .await
}

#[cfg(all(feature = "web", not(feature = "cache")))]
async fn serve_static_file_maybe_cached(
    session: &mut Session,
    ctx: &mut RequestContext,
    request: StaticServeRequest<'_>,
) -> Result<()> {
    let StaticServeRequest {
        web,
        file,
        plan,
        response_headers,
        ..
    } = request;
    ctx.response_body_bytes_seen = plan.response_body_bytes;
    crate::web::serve_static_file(session, web, file, plan, response_headers).await
}

#[cfg(all(feature = "web", feature = "cache"))]
fn static_cache_config(
    vhost: &RuntimeVhost,
    route_index: Option<usize>,
) -> &crate::config::CacheConfig {
    route_index
        .and_then(|index| vhost.route(index).cache.as_ref())
        .map(|cache| &cache.config)
        .unwrap_or(&vhost.cache)
}

#[cfg(all(feature = "web", feature = "cache"))]
fn static_cache_storage(
    vhost: &RuntimeVhost,
    route_index: Option<usize>,
) -> Option<&'static (dyn pingora::cache::Storage + Sync)> {
    if let Some(route_cache) = route_index.and_then(|index| vhost.route(index).cache.as_ref()) {
        return route_cache
            .pingora_memory_storage
            .map(|storage| storage as &'static (dyn pingora::cache::Storage + Sync))
            .or_else(|| {
                route_cache
                    .pingora_disk_storage
                    .map(|storage| storage as &'static (dyn pingora::cache::Storage + Sync))
            });
    }
    vhost
        .pingora_memory_storage
        .map(|storage| storage as &'static (dyn pingora::cache::Storage + Sync))
        .or_else(|| {
            vhost
                .pingora_disk_storage
                .map(|storage| storage as &'static (dyn pingora::cache::Storage + Sync))
        })
}

#[cfg(all(feature = "web", feature = "cache"))]
fn static_cache_key_for_file(
    request: &RequestHeader,
    cache: &crate::config::CacheConfig,
    vhost: &RuntimeVhost,
    route_index: Option<usize>,
    file: &crate::web::StaticFile,
) -> Option<PingoraCacheKey> {
    let route_user_tag;
    let user_tag = if let Some(route_index) = route_index
        && let Some(route_cache) = vhost.route(route_index).cache.as_ref()
    {
        route_user_tag = format!("{}:route:{}", vhost.name, route_cache.name);
        route_user_tag.as_str()
    } else {
        vhost.name.as_str()
    };
    static_cache_key_for_file_parts(
        request.method.as_str(),
        request_host_header(request),
        request.uri.path(),
        request.uri.query(),
        cache,
        user_tag,
        file,
    )
}

#[cfg(all(feature = "web", feature = "cache"))]
fn static_cache_key_for_file_parts(
    method: &str,
    host: Option<&str>,
    path: &str,
    query: Option<&str>,
    cache: &crate::config::CacheConfig,
    user_tag: &str,
    file: &crate::web::StaticFile,
) -> Option<PingoraCacheKey> {
    crate::cache::pingora_static_cache_key(
        "fluxheim-static-v1",
        cache,
        &crate::cache::StaticCacheRequest {
            method,
            host,
            path,
            query,
            file_identity: &file.cache_identity(),
        },
        user_tag,
    )
}

#[cfg(all(feature = "web", feature = "cache"))]
fn local_static_file_for_request(
    vhost: &RuntimeVhost,
    route_index: Option<usize>,
    request_path: &str,
) -> io::Result<Option<crate::web::StaticFile>> {
    if let Some(route_index) = route_index {
        let route = vhost.route(route_index);
        let RuntimeRouteAction::Web(web) = &route.action else {
            return Ok(None);
        };
        let path = static_route_request_path_from_parts(request_path, route);
        return match web.resolve(&path)? {
            ResolveResult::Found(file) => Ok(Some(file)),
            _ => Ok(None),
        };
    }

    let Some(web) = vhost.web.as_ref() else {
        return Ok(None);
    };
    match web.resolve(request_path)? {
        ResolveResult::Found(file) => Ok(Some(file)),
        _ => Ok(None),
    }
}

#[cfg(all(feature = "web", feature = "cache"))]
fn static_route_request_path_from_parts(request_path: &str, route: &RuntimeRoute) -> String {
    let Some(strip_prefix) = route.strip_prefix.as_deref() else {
        return request_path.to_owned();
    };
    let Some(suffix) = request_path.strip_prefix(strip_prefix) else {
        return request_path.to_owned();
    };
    if suffix.is_empty() {
        "/".to_owned()
    } else if suffix.starts_with('/') {
        suffix.to_owned()
    } else {
        format!("/{suffix}")
    }
}

#[cfg(feature = "cache")]
async fn read_cache_hit_body(
    mut hit: HitHandler,
    storage: &'static (dyn pingora::cache::Storage + Sync),
    key: &PingoraCacheKey,
    trace: &pingora::cache::trace::SpanHandle,
    max_body_bytes: u64,
) -> Result<Bytes> {
    let mut body = bytes::BytesMut::new();
    while let Some(chunk) = hit.read_body().await? {
        body.extend_from_slice(&chunk);
        if body.len() as u64 > max_body_bytes {
            return Error::e_explain(
                ErrorType::InternalError,
                "cached body exceeds buffered response limit",
            );
        }
    }
    hit.finish(storage, key, trace).await?;
    Ok(body.freeze())
}

#[cfg(all(feature = "web", feature = "cache"))]
fn static_cached_body_for_plan(
    cached: &Bytes,
    plan: &crate::web::StaticResponsePlan,
) -> Result<Bytes> {
    match plan.body {
        crate::web::StaticResponseBody::None => Ok(Bytes::new()),
        crate::web::StaticResponseBody::Full => Ok(cached.clone()),
        crate::web::StaticResponseBody::Range { start, len } => {
            let start = usize::try_from(start)
                .map_err(|_| Error::new_str("cached static range start exceeds platform size"))?;
            let len = usize::try_from(len)
                .map_err(|_| Error::new_str("cached static range length exceeds platform size"))?;
            let end = start.saturating_add(len);
            if end > cached.len() {
                return Error::e_explain(
                    ErrorType::InternalError,
                    "cached static range exceeds cached body",
                );
            }
            Ok(cached.slice(start..end))
        }
    }
}

#[cfg(feature = "cache")]
fn selected_cache_range_request(
    request: &RequestHeader,
    cache: &crate::config::CacheConfig,
) -> Option<CacheRangeRequest> {
    if !cache.range.enabled || request.method.as_str() != "GET" {
        return None;
    }
    let mut values = request_header_values(request, "range");
    let range = values.next()?;
    if values.next().is_some() {
        return None;
    }
    if request_header_values(request, "if-range").next().is_some() {
        return None;
    }
    let parsed = parse_bounded_single_range(range)?;
    (parsed.len() <= cache.range.max_bytes.as_u64()).then_some(parsed)
}

#[cfg(feature = "cache")]
fn parse_bounded_single_range(range: &str) -> Option<CacheRangeRequest> {
    let range = range.trim();
    let range = range.strip_prefix("bytes=")?;
    if range.contains(',') {
        return None;
    }
    let (start, end) = range.split_once('-')?;
    if start.is_empty() || end.is_empty() {
        return None;
    }
    let start = start.parse::<u64>().ok()?;
    let end = end.parse::<u64>().ok()?;
    if end < start {
        return None;
    }
    Some(CacheRangeRequest { start, end })
}

#[cfg(feature = "cache")]
fn range_cache_key(mut base: PingoraCacheKey, range: CacheRangeRequest) -> Result<PingoraCacheKey> {
    let namespace = base.namespace().to_vec();
    let user_tag = base.user_tag.clone();
    let Some(primary) = base.primary_key_str() else {
        return Error::e_explain(
            ErrorType::InternalError,
            "cache range key requires utf-8 primary key material",
        );
    };
    let mut primary = primary.to_owned();
    append_cache_key_component(&mut primary, "range", &range.component());
    base = PingoraCacheKey::new(namespace, primary, user_tag);
    Ok(base)
}

#[cfg(feature = "cache")]
fn append_cache_key_component(key: &mut String, label: &str, value: &str) {
    use std::fmt::Write as _;
    let _ = write!(key, "{label}:{}:{value};", value.len());
}

#[cfg(feature = "cache")]
fn range_response_cache_admission_rejection(
    response: &ResponseHeader,
    range: Option<CacheRangeRequest>,
) -> Option<&'static str> {
    match range {
        Some(range) => {
            if response.status != StatusCode::PARTIAL_CONTENT {
                return Some("range-cache-non-partial");
            }
            if !content_range_matches(response, range) {
                return Some("range-cache-content-range");
            }
            if !content_length_matches_range(response, range) {
                return Some("range-cache-content-length");
            }
            None
        }
        None if response.status == StatusCode::PARTIAL_CONTENT => Some("range-response"),
        None => None,
    }
}

#[cfg(feature = "cache")]
fn content_range_matches(response: &ResponseHeader, expected: CacheRangeRequest) -> bool {
    response
        .headers
        .get_all("content-range")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            parse_content_range_bounds(value)
                .is_some_and(|range| range.start == expected.start && range.end == expected.end)
        })
}

#[cfg(feature = "cache")]
fn parse_content_range_bounds(value: &str) -> Option<CacheRangeRequest> {
    let value = value.trim();
    let rest = value.strip_prefix("bytes ")?;
    let (range, _complete_len) = rest.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start = start.parse::<u64>().ok()?;
    let end = end.parse::<u64>().ok()?;
    if end < start {
        return None;
    }
    Some(CacheRangeRequest { start, end })
}

#[cfg(feature = "cache")]
fn content_length_matches_range(response: &ResponseHeader, expected: CacheRangeRequest) -> bool {
    response
        .headers
        .get_all("content-length")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.trim().parse::<u64>().ok() == Some(expected.len()))
}

#[cfg(feature = "cache")]
fn cache_response_fresh_ttl_secs(
    cache: &crate::config::CacheConfig,
    response: &ResponseHeader,
) -> Option<u32> {
    cache
        .status_ttls
        .get(&response.status.as_u16())
        .copied()
        .or(cache.default_status_ttl_secs)
        .or_else(|| response_cache_control_max_age(response))
        .filter(|ttl| *ttl > 0)
}

#[cfg(feature = "cache")]
fn remaining_fresh_ttl_secs(ttl_secs: u32, age_secs: u64) -> Option<u32> {
    let remaining = u64::from(ttl_secs).checked_sub(age_secs)?;
    u32::try_from(remaining).ok().filter(|ttl| *ttl > 0)
}

#[cfg(feature = "cache")]
fn response_age_secs(response: &ResponseHeader) -> u64 {
    response
        .headers
        .get_all("age")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

#[cfg(feature = "cache")]
fn response_vary_variance(
    meta: &CacheMeta,
    request: &RequestHeader,
    cache: &crate::config::CacheConfig,
) -> Option<HashBinary> {
    if let VaryCachePolicy::Fields(fields) = cache_vary_policy(meta.headers(), cache) {
        Some(vary_request_hash(&fields, request))
    } else {
        None
    }
}

#[cfg(feature = "cache")]
fn response_cache_control_max_age(response: &ResponseHeader) -> Option<u32> {
    response
        .headers
        .get_all("cache-control")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .find_map(|directive| {
            let (name, value) = directive.trim().split_once('=')?;
            if name.trim().eq_ignore_ascii_case("s-maxage")
                || name.trim().eq_ignore_ascii_case("max-age")
            {
                value.trim().trim_matches('"').parse::<u32>().ok()
            } else {
                None
            }
        })
}

fn selected_runtime_proxy<'a>(vhost: &'a RuntimeVhost, ctx: &RequestContext) -> &'a RuntimeProxy {
    ctx.route_index
        .and_then(|route_index| match &vhost.route(route_index).action {
            RuntimeRouteAction::Proxy(proxy) => Some(proxy),
            _ => None,
        })
        .unwrap_or(&vhost.proxy)
}

fn normalize_cookie_headers(request: &mut RequestHeader) -> Result<()> {
    let cookies = request
        .headers
        .get_all("cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();

    if cookies.len() <= 1 {
        return Ok(());
    }

    request.remove_header("cookie");
    request.insert_header("cookie", cookies.join("; "))?;
    Ok(())
}

async fn continue_to_proxy_or_not_found(
    session: &mut Session,
    vhost: &RuntimeVhost,
    ctx: &RequestContext,
) -> Result<bool> {
    if selected_runtime_proxy(vhost, ctx).enabled {
        Ok(false)
    } else {
        session.respond_error(404).await?;
        Ok(true)
    }
}

fn selected_response_headers<'a>(
    vhost: &'a RuntimeVhost,
    ctx: &RequestContext,
) -> &'a crate::config::ResponseHeaderPolicyConfig {
    ctx.route_index
        .map(|route_index| &vhost.route(route_index).response_headers)
        .unwrap_or(&vhost.response_headers)
}

#[cfg(feature = "cache")]
fn selected_cache_config<'a>(
    vhost: &'a RuntimeVhost,
    ctx: &RequestContext,
) -> &'a crate::config::CacheConfig {
    ctx.route_index
        .and_then(|route_index| vhost.route(route_index).cache.as_ref())
        .map(|cache| &cache.config)
        .unwrap_or(&vhost.cache)
}

#[cfg(feature = "cache")]
fn selected_cache_storage(
    vhost: &RuntimeVhost,
    ctx: &RequestContext,
) -> Option<&'static (dyn pingora::cache::Storage + Sync)> {
    ctx.route_index
        .and_then(|route_index| vhost.route(route_index).cache.as_ref())
        .and_then(RuntimeRouteCache::storage)
        .or_else(|| vhost_cache_storage(vhost))
}

#[cfg(all(feature = "cache", feature = "metrics"))]
fn record_cache_policy_activity(
    vhost: &RuntimeVhost,
    route_index: Option<usize>,
    event: &'static str,
) {
    crate::metrics::record_cache_activity("policy", event);
    let route = route_index
        .and_then(|index| vhost.route(index).cache.as_ref())
        .map(|cache| cache.name.as_str());
    crate::metrics::record_cache_activity_scope(vhost.name.as_str(), route, "policy", event);
}

#[cfg(feature = "cache")]
fn capture_revalidation_304_headers(response: &ResponseHeader) -> Option<Revalidation304Headers> {
    if response.status != StatusCode::NOT_MODIFIED {
        return None;
    }

    let headers = Revalidation304Headers {
        last_modified: response
            .headers
            .get_all("last-modified")
            .iter()
            .cloned()
            .collect(),
        vary: response.headers.get_all("vary").iter().cloned().collect(),
    };

    (!headers.last_modified.is_empty() || !headers.vary.is_empty()).then_some(headers)
}

#[cfg(feature = "cache")]
fn response_with_revalidation_304_headers(
    response: &ResponseHeader,
    revalidation_headers: &Revalidation304Headers,
) -> Result<ResponseHeader> {
    let mut response = response.clone();
    replace_response_header_values(
        &mut response,
        "last-modified",
        &revalidation_headers.last_modified,
    )?;
    Ok(response)
}

#[cfg(feature = "cache")]
fn replace_response_header_values(
    response: &mut ResponseHeader,
    header_name: &'static str,
    values: &[::http::HeaderValue],
) -> Result<()> {
    if values.is_empty() {
        return Ok(());
    }
    response.remove_header(header_name);
    for (index, value) in values.iter().enumerate() {
        if index == 0 {
            response.insert_header(header_name, value.clone())?;
        } else {
            response.append_header(header_name, value.clone())?;
        }
    }
    Ok(())
}

#[cfg(feature = "cache")]
fn revalidation_304_vary_changed(
    response: &ResponseHeader,
    revalidation_headers: &Revalidation304Headers,
) -> bool {
    if revalidation_headers.vary.is_empty() {
        return false;
    }
    let current = response
        .headers
        .get_all("vary")
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    current != revalidation_headers.vary
}

#[cfg(feature = "cache")]
fn insert_cache_status_headers(
    response: &mut ResponseHeader,
    cache: &crate::config::CacheConfig,
    override_status: Option<CacheStatusOverride>,
    phase: CachePhase,
) -> Result<()> {
    if let Some(header_name) = cache.status_header.as_deref()
        && let Some(status) = cache_status_header_value(phase, override_status)
    {
        response.insert_header(header_name.to_owned(), status)?;
    }

    if let Some(header_name) = cache.status_reason_header.as_deref()
        && let Some(reason) = cache_status_reason_header_value(phase, override_status)
    {
        response.insert_header(header_name.to_owned(), reason)?;
    }

    Ok(())
}

#[cfg(feature = "cache")]
fn effective_cache_phase(session: &Session, ctx: &RequestContext) -> CachePhase {
    ctx.cache_observed_phase
        .unwrap_or_else(|| session.cache.phase())
}

#[cfg(feature = "cache")]
fn ignore_origin_cache_headers(
    response: &mut ResponseHeader,
    cache: &crate::config::CacheConfig,
    phase: CachePhase,
) {
    if !cache_request_participated(phase) || !cache.ignore_origin_cache_headers {
        return;
    }
    response.remove_header("cache-control");
    response.remove_header("expires");
}

#[cfg(feature = "cache")]
fn apply_cache_status_ttl(
    response: &mut ResponseHeader,
    cache: &crate::config::CacheConfig,
    phase: CachePhase,
) -> Result<()> {
    if !cache_request_participated(phase) {
        return Ok(());
    }
    let status = response.status.as_u16();
    if let Some(ttl_secs) = cache
        .status_ttls
        .get(&status)
        .copied()
        .or(cache.default_status_ttl_secs)
    {
        response.remove_header("expires");
        return response.insert_header(
            "cache-control",
            cache_control_freshness_value(
                ttl_secs,
                cache.stale_while_revalidate_secs,
                cache.stale_if_error_secs,
            ),
        );
    }

    if !response.headers.contains_key("cache-control")
        || response_cache_admission_rejection(response, cache).is_some()
    {
        return Ok(());
    }

    if let Some(stale_while_revalidate_secs) = cache.stale_while_revalidate_secs {
        append_cache_control_directive(
            response,
            &format!("stale-while-revalidate={stale_while_revalidate_secs}"),
            "stale-while-revalidate",
        )?;
    }
    if let Some(stale_if_error_secs) = cache.stale_if_error_secs {
        append_cache_control_directive(
            response,
            &format!("stale-if-error={stale_if_error_secs}"),
            "stale-if-error",
        )?;
    }

    Ok(())
}

#[cfg(feature = "cache")]
fn strip_cache_response_headers(
    response: &mut ResponseHeader,
    cache: &crate::config::CacheConfig,
    phase: CachePhase,
) {
    if !cache_request_participated(phase) {
        return;
    }
    for header in &cache.hide_response_headers {
        response.remove_header(header.as_str());
    }
}

#[cfg(feature = "php-fpm")]
fn strip_php_response_headers(response: &mut ResponseHeader, php: &crate::config::PhpConfig) {
    let connection_header_tokens = response
        .headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();

    for header in PHP_HOP_BY_HOP_RESPONSE_HEADERS {
        response.remove_header(*header);
    }
    for header in connection_header_tokens {
        response.remove_header(header.as_str());
    }
    for header in &php.hide_response_headers {
        response.remove_header(header.as_str());
    }
}

#[cfg(feature = "php-fpm")]
fn php_static_offload_file(
    response: &mut ResponseHeader,
    php: &RuntimePhp,
) -> io::Result<Option<crate::web::StaticFile>> {
    let x_accel_redirect = php_internal_response_header(response, "x-accel-redirect");
    let x_sendfile = php_internal_response_header(response, "x-sendfile");
    strip_php_static_offload_headers(response);

    if let Some(target) = x_accel_redirect {
        return php_static_offload_uri(php, &target);
    }
    if let Some(target) = x_sendfile {
        return php_static_offload_rooted_path(php, &target);
    }
    Ok(None)
}

#[cfg(feature = "php-fpm")]
fn php_internal_response_header(response: &ResponseHeader, name: &str) -> Option<String> {
    response
        .headers
        .get_all(name)
        .iter()
        .next()
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(feature = "php-fpm")]
fn strip_php_static_offload_headers(response: &mut ResponseHeader) {
    response.remove_header("x-accel-redirect");
    response.remove_header("x-sendfile");
}

#[cfg(feature = "php-fpm")]
fn php_static_offload_uri(
    php: &RuntimePhp,
    target: &str,
) -> io::Result<Option<crate::web::StaticFile>> {
    if target.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "php X-Accel-Redirect target contains control characters",
        ));
    }
    match php.files.resolve(target)? {
        ResolveResult::Found(file) if php_static_offload_file_allowed(php, &file) => Ok(Some(file)),
        ResolveResult::Found(_) | ResolveResult::Forbidden => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "php static offload target is forbidden",
        )),
        ResolveResult::NotFound => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "php static offload target was not found",
        )),
        ResolveResult::DirectoryListing(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "php static offload target must be a file",
        )),
    }
}

#[cfg(feature = "php-fpm")]
fn php_static_offload_rooted_path(
    php: &RuntimePhp,
    target: &str,
) -> io::Result<Option<crate::web::StaticFile>> {
    if target.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "php X-Sendfile target contains control characters",
        ));
    }
    let target_path = std::path::Path::new(target);
    let local_path = target_path
        .strip_prefix(&php.fpm_root)
        .ok()
        .map(|relative| php.root.join(relative))
        .unwrap_or_else(|| target_path.to_path_buf());
    match php.files.resolve_rooted_file(&local_path)? {
        ResolveResult::Found(file) if php_static_offload_file_allowed(php, &file) => Ok(Some(file)),
        ResolveResult::Found(_) | ResolveResult::Forbidden => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "php static offload target is forbidden",
        )),
        ResolveResult::NotFound => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "php static offload target was not found",
        )),
        ResolveResult::DirectoryListing(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "php static offload target must be a file",
        )),
    }
}

#[cfg(feature = "php-fpm")]
fn php_static_offload_file_allowed(php: &RuntimePhp, file: &crate::web::StaticFile) -> bool {
    !file
        .path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            php.config
                .allowed_extensions
                .iter()
                .any(|allowed| extension.eq_ignore_ascii_case(allowed))
        })
}

#[cfg(feature = "php-fpm")]
fn apply_php_x_accel_expires(response: &mut ResponseHeader) -> io::Result<()> {
    let Some(raw_value) = response
        .headers
        .get_all("x-accel-expires")
        .iter()
        .next()
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .map(str::to_owned)
    else {
        return Ok(());
    };
    response.remove_header("x-accel-expires");
    if raw_value.is_empty() || raw_value.eq_ignore_ascii_case("off") {
        return Ok(());
    }

    let Some(ttl_secs) = php_x_accel_expires_ttl_secs(&raw_value) else {
        return Ok(());
    };

    response.remove_header("cache-control");
    response.remove_header("expires");
    response.remove_header("pragma");
    if ttl_secs == 0 {
        response
            .insert_header("cache-control", "no-store, private")
            .map_err(|error| io::Error::other(error.to_string()))?;
        response
            .insert_header(
                "expires",
                httpdate::fmt_http_date(std::time::SystemTime::UNIX_EPOCH),
            )
            .map_err(|error| io::Error::other(error.to_string()))?;
        return Ok(());
    }

    let directive = if response.headers.contains_key("set-cookie") {
        format!("private, max-age={ttl_secs}")
    } else {
        format!("public, max-age={ttl_secs}")
    };
    response
        .insert_header("cache-control", directive)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let expires = std::time::SystemTime::now()
        .checked_add(std::time::Duration::from_secs(ttl_secs))
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    response
        .insert_header("expires", httpdate::fmt_http_date(expires))
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(())
}

#[cfg(feature = "php-fpm")]
fn php_x_accel_expires_ttl_secs(value: &str) -> Option<u64> {
    if let Some(epoch) = value.strip_prefix('@') {
        let epoch = epoch.parse::<u64>().ok()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .ok()?
            .as_secs();
        return Some(epoch.saturating_sub(now));
    }
    let ttl = value.parse::<i64>().ok()?;
    Some(u64::try_from(ttl).unwrap_or(0))
}

#[cfg(feature = "php-fpm")]
fn php_should_intercept_error_status(status: StatusCode, php: &RuntimePhp) -> bool {
    php.error_page(status.as_u16()).is_some()
        || php
            .config
            .intercept_error_statuses
            .iter()
            .any(|intercept_status| *intercept_status == status.as_u16())
}

#[cfg(feature = "php-fpm")]
const PHP_HOP_BY_HOP_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

#[cfg(feature = "cache")]
fn cache_control_freshness_value(
    ttl_secs: u32,
    stale_while_revalidate_secs: Option<u32>,
    stale_if_error_secs: Option<u32>,
) -> String {
    let mut value = format!("public, max-age={ttl_secs}");
    if let Some(stale_while_revalidate_secs) = stale_while_revalidate_secs {
        value.push_str(", stale-while-revalidate=");
        value.push_str(&stale_while_revalidate_secs.to_string());
    }
    if let Some(stale_if_error_secs) = stale_if_error_secs {
        value.push_str(", stale-if-error=");
        value.push_str(&stale_if_error_secs.to_string());
    }
    value
}

#[cfg(feature = "cache")]
fn append_cache_control_directive(
    response: &mut ResponseHeader,
    directive: &str,
    directive_name: &str,
) -> Result<()> {
    let mut directives = Vec::new();
    for value in response.headers.get_all("cache-control") {
        let Ok(value) = value.to_str() else {
            return Ok(());
        };
        directives.extend(
            value
                .split(',')
                .map(str::trim)
                .filter(|part| {
                    !part.is_empty()
                        && !part
                            .split_once('=')
                            .map(|(name, _)| name.trim())
                            .unwrap_or(part)
                            .eq_ignore_ascii_case(directive_name)
                })
                .map(str::to_owned),
        );
    }

    directives.push(directive.to_owned());
    response.remove_header("cache-control");
    response.insert_header("cache-control", directives.join(", "))
}

#[cfg(feature = "cache")]
fn cache_request_participated(phase: CachePhase) -> bool {
    !matches!(
        phase,
        CachePhase::Disabled(NoCacheReason::NeverEnabled) | CachePhase::Uninit | CachePhase::Bypass
    )
}

#[cfg(feature = "cache")]
fn cache_min_uses_counter() -> &'static moka::sync::Cache<String, u32> {
    static COUNTER: OnceLock<moka::sync::Cache<String, u32>> = OnceLock::new();
    COUNTER.get_or_init(|| {
        moka::sync::Cache::builder()
            .max_capacity(CACHE_MIN_USES_COUNTER_CAPACITY)
            .time_to_live(Duration::from_secs(CACHE_MIN_USES_COUNTER_TTL_SECS))
            .build()
    })
}

#[cfg(feature = "cache")]
fn cache_min_uses_allows_store(
    counter: &moka::sync::Cache<String, u32>,
    cache: &crate::config::CacheConfig,
    cache_key: &str,
) -> bool {
    if cache.min_uses <= 1 {
        return true;
    }

    let uses = counter.get(cache_key).unwrap_or(0).saturating_add(1);
    if uses >= cache.min_uses {
        counter.invalidate(cache_key);
        true
    } else {
        counter.insert(cache_key.to_owned(), uses);
        false
    }
}

#[cfg(feature = "cache")]
fn cache_pass_counter() -> &'static moka::sync::Cache<String, u32> {
    static COUNTER: OnceLock<moka::sync::Cache<String, u32>> = OnceLock::new();
    COUNTER.get_or_init(|| {
        moka::sync::Cache::builder()
            .max_capacity(CACHE_PASS_COUNTER_CAPACITY)
            .time_to_live(Duration::from_secs(CACHE_PASS_COUNTER_TTL_SECS))
            .build()
    })
}

#[cfg(feature = "cache")]
fn cache_pass_should_bypass(
    counter: &moka::sync::Cache<String, u32>,
    cache: &crate::config::CacheConfig,
    cache_key: &str,
) -> bool {
    cache.pass_uncacheable_after > 0
        && counter
            .get(cache_key)
            .is_some_and(|uses| uses >= cache.pass_uncacheable_after)
}

#[cfg(feature = "cache")]
fn cache_pass_record_uncacheable(
    counter: &moka::sync::Cache<String, u32>,
    cache: &crate::config::CacheConfig,
    cache_key: &str,
) {
    if cache.pass_uncacheable_after == 0 {
        return;
    }

    let uses = counter
        .get(cache_key)
        .unwrap_or(0)
        .saturating_add(1)
        .min(cache.pass_uncacheable_after);
    counter.insert(cache_key.to_owned(), uses);
}

#[cfg(feature = "cache")]
fn cache_pass_record_cacheable(counter: &moka::sync::Cache<String, u32>, cache_key: &str) {
    counter.invalidate(cache_key);
}

#[cfg(feature = "cache")]
const CACHE_PASS_REASON: &str = "cache-pass";

#[cfg(feature = "cache")]
const CACHE_HEAD_BYPASS_REASON: &str = "method-head";

#[cfg(feature = "cache")]
fn proxy_cache_method_temporarily_bypassed(method: &str) -> bool {
    method == "HEAD"
}

#[cfg(feature = "cache")]
fn cache_should_serve_stale(cache: &crate::config::CacheConfig, event: CacheStaleEvent) -> bool {
    match event {
        CacheStaleEvent::UpstreamError(kind) => {
            cache.stale_if_error_secs.is_some() && cache.stale_if_error_on.contains(&kind)
        }
        CacheStaleEvent::UpstreamHttpStatus(status) => {
            cache.stale_if_error_secs.is_some()
                && cache
                    .stale_if_error_on
                    .contains(&crate::config::CacheStaleErrorKind::HttpStatus)
                && cache_stale_status_allows(cache, status)
        }
        CacheStaleEvent::OtherError => false,
        CacheStaleEvent::Updating => cache.stale_while_revalidate_secs.is_some(),
    }
}

#[cfg(feature = "cache")]
fn cache_stale_status_allows(cache: &crate::config::CacheConfig, status: u16) -> bool {
    (500..=599).contains(&status)
        && (cache.stale_if_error_statuses.is_empty()
            || cache.stale_if_error_statuses.contains(&status))
}

#[cfg(feature = "cache")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CacheStaleEvent {
    Updating,
    UpstreamError(crate::config::CacheStaleErrorKind),
    UpstreamHttpStatus(u16),
    OtherError,
}

#[cfg(feature = "cache")]
fn cache_stale_error_kind(error: &Error) -> crate::config::CacheStaleErrorKind {
    match error.etype() {
        ErrorType::ConnectTimedout
        | ErrorType::TLSHandshakeTimedout
        | ErrorType::ReadTimedout
        | ErrorType::WriteTimedout => crate::config::CacheStaleErrorKind::Timeout,
        ErrorType::ConnectRefused
        | ErrorType::ConnectNoRoute
        | ErrorType::ConnectError
        | ErrorType::SocketError
        | ErrorType::ConnectProxyFailure => crate::config::CacheStaleErrorKind::Connect,
        ErrorType::ReadError => crate::config::CacheStaleErrorKind::Read,
        ErrorType::WriteError => crate::config::CacheStaleErrorKind::Write,
        ErrorType::ConnectionClosed => crate::config::CacheStaleErrorKind::ConnectionClosed,
        ErrorType::InvalidHTTPHeader
        | ErrorType::H1Error
        | ErrorType::H2Error
        | ErrorType::H2Downgrade
        | ErrorType::InvalidH2 => crate::config::CacheStaleErrorKind::Protocol,
        ErrorType::TLSWantX509Lookup
        | ErrorType::TLSHandshakeFailure
        | ErrorType::InvalidCert
        | ErrorType::HandshakeError => crate::config::CacheStaleErrorKind::Tls,
        ErrorType::HTTPStatus(_) => crate::config::CacheStaleErrorKind::HttpStatus,
        _ => crate::config::CacheStaleErrorKind::Other,
    }
}

#[cfg(feature = "cache")]
fn cache_status_header_value(
    phase: CachePhase,
    override_status: Option<CacheStatusOverride>,
) -> Option<&'static str> {
    if let Some(override_status) = override_status {
        return Some(override_status.status);
    }

    match phase {
        CachePhase::Disabled(NoCacheReason::NeverEnabled)
        | CachePhase::Uninit
        | CachePhase::CacheKey => None,
        CachePhase::Disabled(_) | CachePhase::Bypass => Some("BYPASS"),
        CachePhase::Hit => Some("HIT"),
        CachePhase::Miss => Some("MISS"),
        CachePhase::Stale => Some("STALE"),
        CachePhase::StaleUpdating => Some("STALE-UPDATING"),
        CachePhase::Expired => Some("EXPIRED"),
        CachePhase::Revalidated => Some("REVALIDATED"),
        CachePhase::RevalidatedNoCache(_) => Some("REVALIDATED-NOCACHE"),
    }
}

#[cfg(feature = "cache")]
fn cache_status_reason_header_value(
    phase: CachePhase,
    override_status: Option<CacheStatusOverride>,
) -> Option<&'static str> {
    if let Some(override_status) = override_status {
        return override_status.reason;
    }

    match phase {
        CachePhase::Disabled(NoCacheReason::NeverEnabled)
        | CachePhase::Uninit
        | CachePhase::Bypass
        | CachePhase::CacheKey
        | CachePhase::Hit
        | CachePhase::Miss
        | CachePhase::Stale
        | CachePhase::StaleUpdating
        | CachePhase::Expired
        | CachePhase::Revalidated => None,
        CachePhase::Disabled(reason) | CachePhase::RevalidatedNoCache(reason) => {
            Some(reason.as_str())
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct DownstreamFlowControl {
    write_timeout: Option<std::time::Duration>,
    min_send_rate: Option<usize>,
}

fn downstream_flow_control(proxy: &ProxyConfig) -> DownstreamFlowControl {
    DownstreamFlowControl {
        write_timeout: proxy
            .downstream_write_timeout_secs
            .map(std::time::Duration::from_secs),
        min_send_rate: proxy.downstream_min_send_rate_bytes_per_sec,
    }
}

fn apply_downstream_flow_control(session: &mut Session, proxy: &ProxyConfig) {
    let flow_control = downstream_flow_control(proxy);
    let downstream = session.as_downstream_mut();
    downstream.set_write_timeout(flow_control.write_timeout);
    downstream.set_min_send_rate(flow_control.min_send_rate);
}

#[cfg(feature = "cache")]
fn vhost_cache_storage(
    vhost: &RuntimeVhost,
) -> Option<&'static (dyn pingora::cache::Storage + Sync)> {
    if let Some(storage) = vhost.pingora_tiered_storage {
        Some(storage)
    } else if let Some(storage) = vhost.pingora_memory_storage {
        Some(storage)
    } else {
        vhost
            .pingora_disk_storage
            .map(|storage| storage as &'static (dyn pingora::cache::Storage + Sync))
    }
}

#[cfg(feature = "acme")]
async fn respond_acme_http_01_challenge(
    session: &mut Session,
    ctx: &mut RequestContext,
    store: &crate::acme::AcmeHttp01ChallengeStore,
    route: &RuntimeRoute,
) -> Result<()> {
    let method = session.req_header().method.as_str();
    if method != "GET" && method != "HEAD" {
        session.respond_error(405).await?;
        return Ok(());
    }

    let Some(token) = crate::acme::http_01_token_from_path(session.req_header().uri.path()) else {
        session.respond_error(404).await?;
        return Ok(());
    };

    let key_authorization = match store.load_key_authorization(token) {
        Ok(Some(value)) => value,
        Ok(None) => {
            session.respond_error(404).await?;
            return Ok(());
        }
        Err(error) => {
            log::error!("failed to load ACME HTTP-01 challenge token: {error}");
            session
                .respond_error_with_body(500, Bytes::from_static(b"internal server error"))
                .await?;
            return Ok(());
        }
    };

    let body = Bytes::from(key_authorization);
    let body_len = body.len();
    let mut response = ResponseHeader::build(200, Some(5))?;
    response.insert_header("content-type", "text/plain")?;
    response.insert_header("cache-control", "no-store")?;
    response.insert_header("content-length", body_len.to_string())?;
    crate::headers::apply_response_policy(&mut response, &route.response_headers)?;

    if method == "HEAD" {
        ctx.response_body_bytes_seen = 0;
        session
            .write_response_header(Box::new(response), true)
            .await?;
    } else {
        ctx.response_body_bytes_seen = body_len as u64;
        session
            .write_response_header(Box::new(response), false)
            .await?;
        session.write_response_body(Some(body), true).await?;
    }

    Ok(())
}

fn proxy_error_status(error: &Error) -> u16 {
    match error.etype() {
        ErrorType::HTTPStatus(code) => *code,
        _ => match error.esource().as_str() {
            "Upstream" => 502,
            "Downstream" => match error.etype() {
                ErrorType::WriteError | ErrorType::ReadError | ErrorType::ConnectionClosed => 0,
                _ => 400,
            },
            "Internal" | "" => 500,
            _ => 500,
        },
    }
}

#[cfg(feature = "web")]
async fn respond_custom_proxy_error_page(
    session: &mut Session,
    status: u16,
    error_page: &RuntimeErrorPage,
    response_headers: &crate::config::ResponseHeaderPolicyConfig,
) -> Result<bool> {
    use pingora::prelude::{InternalError, OrErr};

    let file = match error_page
        .web
        .resolve(&error_page.path)
        .or_err(InternalError, "failed to resolve custom proxy error page")?
    {
        ResolveResult::Found(file) => file,
        ResolveResult::DirectoryListing(_) | ResolveResult::NotFound | ResolveResult::Forbidden => {
            return Ok(false);
        }
    };

    let method = session.req_header().method.as_str();
    let plan = crate::web::plan_static_response(
        &file,
        method,
        crate::web::StaticRequestConditions::default(),
    );
    if plan.response_body_bytes > crate::web::MAX_STATIC_BUFFERED_BODY_BYTES {
        return Ok(false);
    }

    crate::web::serve_static_file_with_status(
        session,
        &error_page.web,
        &file,
        &plan,
        response_headers,
        status,
    )
    .await?;
    Ok(true)
}

#[cfg(not(feature = "web"))]
async fn respond_custom_proxy_error_page(
    _session: &mut Session,
    _status: u16,
    _error_page: &RuntimeErrorPage,
    _response_headers: &crate::config::ResponseHeaderPolicyConfig,
) -> Result<bool> {
    Ok(false)
}

async fn respond_route_redirect(
    session: &mut Session,
    redirect: &RouteRedirectConfig,
    response_policy: &crate::config::ResponseHeaderPolicyConfig,
) -> Result<()> {
    let Some(location) = route_redirect_location(session.req_header(), redirect) else {
        session
            .respond_error_with_body(400, Bytes::from_static(b"invalid redirect target"))
            .await?;
        return Ok(());
    };

    let mut response = ResponseHeader::build(redirect.status, Some(4))?;
    response.insert_header("location", location)?;
    response.insert_header("content-length", 0)?;
    crate::headers::apply_response_policy(&mut response, response_policy)?;
    session
        .write_response_header(Box::new(response), true)
        .await
}

async fn respond_https_redirect(
    session: &mut Session,
    config: &HttpsRedirectConfig,
    response_policy: &crate::config::ResponseHeaderPolicyConfig,
) -> Result<()> {
    let Some(location) = https_redirect_location(session.req_header(), config) else {
        session
            .respond_error_with_body(400, Bytes::from_static(b"missing or invalid host"))
            .await?;
        return Ok(());
    };

    let mut response = ResponseHeader::build(config.status, Some(4))?;
    response.insert_header("location", location)?;
    response.insert_header("content-length", 0)?;
    crate::headers::apply_response_policy(&mut response, response_policy)?;
    session
        .write_response_header(Box::new(response), true)
        .await
}

fn https_redirect_location(
    request: &RequestHeader,
    config: &HttpsRedirectConfig,
) -> Option<String> {
    let host = request
        .headers
        .get("host")
        .and_then(|value| value.to_str().ok())?;
    let normalized_host = normalize_host(host)?;
    let authority = redirect_authority(&normalized_host, config.target_port)?;
    let path_and_query = request
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    if !path_and_query.starts_with('/') || path_and_query.chars().any(char::is_control) {
        return None;
    }

    Some(format!("https://{authority}{path_and_query}"))
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
    request: &RequestHeader,
    redirect: &RouteRedirectConfig,
) -> Option<String> {
    let uri = request
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let path = request.uri.path();
    let query = request.uri.query().unwrap_or("");
    if !uri.starts_with('/') || uri.chars().any(char::is_control) {
        return None;
    }

    let location = redirect
        .to
        .replace("{uri}", uri)
        .replace("{path}", path)
        .replace("{query}", query);
    if location.contains('{')
        || location.contains('}')
        || location.contains('\\')
        || location
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || !(location.starts_with("https://") || location.starts_with("http://"))
    {
        return None;
    }
    Some(location)
}

fn route_rewritten_path_and_query(request: &RequestHeader, route: &RuntimeRoute) -> Option<String> {
    let strip_prefix = route.strip_prefix.as_deref()?;
    let path = request.uri.path();
    let suffix = path.strip_prefix(strip_prefix)?;
    let rewritten_path = if suffix.is_empty() {
        "/".to_owned()
    } else if suffix.starts_with('/') {
        suffix.to_owned()
    } else {
        format!("/{suffix}")
    };
    if !safe_forward_path(&rewritten_path) {
        return None;
    }
    match request.uri.query() {
        Some(query) => Some(format!("{rewritten_path}?{query}")),
        None => Some(rewritten_path),
    }
}

#[cfg(feature = "cache")]
fn safe_forward_path_and_query(path_and_query: &str) -> bool {
    let path = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _)| path);
    safe_forward_path(path)
}

fn safe_forward_path(path: &str) -> bool {
    if !path.starts_with('/')
        || path.chars().any(char::is_control)
        || path.as_bytes().contains(&b'\\')
    {
        return false;
    }

    path.split('/').all(safe_forward_path_segment)
}

fn safe_forward_path_segment(segment: &str) -> bool {
    if segment == ".." {
        return false;
    }

    let Some(decoded) = percent_decode_path_segment(segment) else {
        return false;
    };
    decoded != b".." && !decoded.iter().any(|byte| matches!(byte, b'/' | b'\\'))
}

fn percent_decode_path_segment(segment: &str) -> Option<Vec<u8>> {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            decoded.push((hex_value(high)? << 4) | hex_value(low)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Some(decoded)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(not(feature = "privacy-mode"))]
struct AccessLogEvent<'a> {
    method: &'a str,
    host: Option<&'a str>,
    vhost: &'a str,
    path: Option<&'a str>,
    status: Option<u16>,
    status_class: Option<&'static str>,
    error: bool,
    request_id: Option<&'a str>,
    #[cfg(feature = "otel-tracing")]
    trace_id: Option<String>,
    request_body_bytes: u64,
    response_body_bytes: u64,
    latency_ms: u128,
}

#[cfg(not(feature = "privacy-mode"))]
fn access_log_json(event: AccessLogEvent<'_>) -> String {
    let status = event
        .status
        .map(|status| status.to_string())
        .unwrap_or_else(|| "null".to_owned());
    let status_class = event.status_class.unwrap_or("unknown");
    let host = event.host.unwrap_or("");
    let path = event.path.unwrap_or("");
    let request_id = event.request_id.unwrap_or("");
    let body = format!(
        "{{\"event\":\"access\",\"method\":\"{}\",\"host\":\"{}\",\"vhost\":\"{}\",\"path\":\"{}\",\"status\":{},\"status_class\":\"{}\",\"error\":{},\"request_id\":\"{}\",\"request_body_bytes\":{},\"response_body_bytes\":{},\"latency_ms\":{}}}",
        json_escape(event.method),
        json_escape(host),
        json_escape(event.vhost),
        json_escape(path),
        status,
        status_class,
        event.error,
        json_escape(request_id),
        event.request_body_bytes,
        event.response_body_bytes,
        event.latency_ms,
    );
    #[cfg(feature = "otel-tracing")]
    {
        let mut body = body;
        if let Some(trace_id) = event.trace_id.as_deref() {
            let insert_at = body.len().saturating_sub(1);
            body.insert_str(
                insert_at,
                &format!(r#","trace_id":"{}""#, json_escape(trace_id)),
            );
        }
        body
    }
    #[cfg(not(feature = "otel-tracing"))]
    {
        body
    }
}

#[cfg(feature = "otel-otlp")]
fn unix_time_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

#[cfg(not(feature = "privacy-mode"))]
fn status_class(status: u16) -> &'static str {
    match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

#[cfg(not(feature = "privacy-mode"))]
fn access_log_request_id(config: &AccessLoggingConfig, request: &RequestHeader) -> Option<String> {
    if !config.enabled || !config.request_id {
        return None;
    }

    request
        .headers
        .get(config.request_id_header.as_str())
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| valid_request_id(value))
        .map(str::to_owned)
        .or_else(generate_request_id)
}

fn count_response_body_chunk(bytes_seen: &mut u64, body: Option<&Bytes>) {
    if let Some(body) = body {
        *bytes_seen = bytes_seen.saturating_add(body.len() as u64);
    }
}

#[cfg(not(feature = "privacy-mode"))]
fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/' | b'@')
        })
}

#[cfg(not(feature = "privacy-mode"))]
fn generate_request_id() -> Option<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).ok()?;

    let mut id = String::with_capacity(35);
    id.push_str("fh-");
    for byte in random {
        let _ = std::fmt::Write::write_fmt(&mut id, format_args!("{byte:02x}"));
    }
    Some(id)
}

#[cfg(not(feature = "privacy-mode"))]
fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write;
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn parse_trusted_proxies(values: &[String]) -> io::Result<Vec<TrustedProxy>> {
    values
        .iter()
        .map(|value| parse_trusted_proxy(value))
        .collect()
}

fn parse_trusted_proxy(value: &str) -> io::Result<TrustedProxy> {
    let value = value.trim();
    if let Some((address, prefix)) = value.split_once('/') {
        let network = address.parse::<IpAddr>().map_err(invalid_trusted_proxy)?;
        let prefix = prefix.parse::<u8>().map_err(invalid_trusted_proxy)?;
        let valid_prefix = match network {
            IpAddr::V4(_) => prefix <= 32,
            IpAddr::V6(_) => prefix <= 128,
        };
        if !valid_prefix {
            return Err(invalid_trusted_proxy("invalid prefix length"));
        }
        return Ok(TrustedProxy::Cidr { network, prefix });
    }

    value
        .parse::<IpAddr>()
        .map(TrustedProxy::Exact)
        .map_err(invalid_trusted_proxy)
}

fn invalid_trusted_proxy(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid trusted proxy: {error}"),
    )
}

fn ipv4_prefix_match(network: Ipv4Addr, address: Ipv4Addr, prefix: u8) -> bool {
    let mask = prefix_mask_u32(prefix);
    u32::from(network) & mask == u32::from(address) & mask
}

fn ipv6_prefix_match(network: Ipv6Addr, address: Ipv6Addr, prefix: u8) -> bool {
    let mask = prefix_mask_u128(prefix);
    u128::from(network) & mask == u128::from(address) & mask
}

fn prefix_mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn prefix_mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn proxy_health_signal(session: &Session, error: Option<&Error>) -> Option<ProxyHealthSignal> {
    if error.is_some() {
        return Some(ProxyHealthSignal::Failure);
    }

    let status = session.response_written()?.status.as_u16();
    if (200..400).contains(&status) {
        Some(ProxyHealthSignal::Success)
    } else if status >= 500 {
        Some(ProxyHealthSignal::Failure)
    } else {
        None
    }
}

#[cfg(feature = "metrics")]
fn proxy_metrics_vhost(ctx: &RequestContext) -> &str {
    let Some(state) = ctx.state.as_deref() else {
        return "unknown";
    };
    let Some(vhost_index) = ctx.vhost_index else {
        return "unknown";
    };
    state
        .vhosts
        .get(vhost_index)
        .map(|vhost| vhost.name.as_str())
        .unwrap_or("unknown")
}

#[cfg(feature = "cache")]
#[cfg_attr(not(test), allow(dead_code))]
fn request_cache_bypass(request: &RequestHeader, cache: &crate::config::CacheConfig) -> bool {
    request_cache_bypass_reason(request, cache).is_some()
}

#[cfg(feature = "cache")]
fn request_cache_bypass_reason(
    request: &RequestHeader,
    cache: &crate::config::CacheConfig,
) -> Option<&'static str> {
    if cache
        .bypass_request_headers
        .iter()
        .any(|header| request.headers.contains_key(header.as_str()))
    {
        return Some("request-header");
    }
    if request_headers_match_cache_bypass_value(request, &cache.bypass_request_header_values) {
        return Some("request-header-value");
    }
    if request_cookies_match_cache_bypass(
        request_header_values(request, "cookie"),
        &cache.bypass_cookie_names,
        &cache.bypass_cookie_values,
    ) {
        return Some("request-cookie");
    }
    if request.uri.query().is_some_and(|query| {
        query_matches_cache_bypass(
            query,
            &cache.bypass_query_params,
            &cache.bypass_query_values,
        )
    }) {
        return Some("request-query");
    }

    crate::cache_headers::request_values_forbid_cache_store(request_header_values(
        request,
        "cache-control",
    ))
    .then_some("request-no-store")
}

#[cfg(feature = "cache")]
fn request_cache_revalidation_requested(
    request: &RequestHeader,
    cache: &crate::config::CacheConfig,
) -> bool {
    if !cache.allow_client_cache_refresh {
        return false;
    }
    crate::cache_headers::request_values_force_cache_revalidation(
        request_header_values(request, "cache-control"),
        request_header_values(request, "pragma"),
    )
}

#[cfg(feature = "cache")]
fn request_headers_match_cache_bypass_value(
    request: &RequestHeader,
    configured_values: &std::collections::BTreeMap<String, String>,
) -> bool {
    !configured_values.is_empty()
        && configured_values.iter().any(|(header, configured)| {
            request_header_values(request, header).any(|value| value == configured)
        })
}

#[cfg(feature = "cache")]
fn request_cookies_match_cache_bypass<'a>(
    cookie_headers: impl Iterator<Item = &'a str>,
    configured_names: &[String],
    configured_values: &std::collections::BTreeMap<String, String>,
) -> bool {
    if configured_names.is_empty() && configured_values.is_empty() {
        return false;
    }
    cookie_headers
        .flat_map(cookie_header_pairs)
        .any(|(name, value)| {
            configured_names.iter().any(|configured| configured == name)
                || configured_values
                    .get(name)
                    .is_some_and(|configured| configured == value)
        })
}

#[cfg(feature = "cache")]
fn cookie_header_pairs(header: &str) -> impl Iterator<Item = (&str, &str)> {
    header.split(';').filter_map(|part| {
        let (name, value) = part.trim_start().split_once('=')?;
        (!name.is_empty()).then_some((name, value))
    })
}

#[cfg(feature = "cache")]
fn query_matches_cache_bypass(
    query: &str,
    configured_params: &[String],
    configured_values: &std::collections::BTreeMap<String, String>,
) -> bool {
    if configured_params.is_empty() && configured_values.is_empty() {
        return false;
    }
    query.split('&').any(|part| {
        let (name, value) = part.split_once('=').unwrap_or((part, ""));
        !name.is_empty()
            && (configured_params
                .iter()
                .any(|configured| configured == name)
                || configured_values
                    .get(name)
                    .is_some_and(|configured| configured == value))
    })
}

#[cfg(feature = "cache")]
fn response_cache_admission_rejection(
    response: &ResponseHeader,
    cache: &crate::config::CacheConfig,
) -> Option<&'static str> {
    let headers = &response.headers;
    let status = response.status.as_u16();
    let status_has_ttl =
        cache.status_ttls.contains_key(&status) || cache.default_status_ttl_secs.is_some();
    if response.status != StatusCode::OK && !status_has_ttl {
        return Some("status-not-cacheable");
    }

    if response.status == StatusCode::OK && !response_content_type_is_cacheable(headers, cache) {
        return if headers.contains_key("content-type") {
            Some("content-type-not-cacheable")
        } else {
            Some("content-type-missing")
        };
    }

    response_cache_header_policy_rejection(response, cache)
}

#[cfg(feature = "cache")]
fn response_range_cache_admission_rejection(
    response: &ResponseHeader,
    cache: &crate::config::CacheConfig,
) -> Option<&'static str> {
    let headers = &response.headers;
    if !response_content_type_is_cacheable(headers, cache) {
        return if headers.contains_key("content-type") {
            Some("content-type-not-cacheable")
        } else {
            Some("content-type-missing")
        };
    }

    response_cache_header_policy_rejection(response, cache)
}

#[cfg(feature = "cache")]
fn response_cache_header_policy_rejection(
    response: &ResponseHeader,
    cache: &crate::config::CacheConfig,
) -> Option<&'static str> {
    let headers = &response.headers;
    if headers.contains_key("set-cookie") {
        return Some("set-cookie");
    }
    if cache
        .no_store_response_headers
        .iter()
        .any(|header| headers.contains_key(header.as_str()))
    {
        return Some("configured-no-store-response-header");
    }
    if response_headers_match_cache_no_store_value(response, &cache.no_store_response_header_values)
    {
        return Some("configured-no-store-response-header-value");
    }
    if let Some(reason) = crate::cache_headers::response_values_forbid_shared_cache(
        response_header_values(response, "cache-control"),
    ) {
        return Some(reason);
    }
    match vary_cache_policy(headers) {
        VaryCachePolicy::Uncacheable(reason) => Some(reason),
        VaryCachePolicy::None | VaryCachePolicy::Fields(_) => None,
    }
}

#[cfg(feature = "cache")]
fn response_headers_match_cache_no_store_value(
    response: &ResponseHeader,
    configured_values: &std::collections::BTreeMap<String, String>,
) -> bool {
    !configured_values.is_empty()
        && configured_values.iter().any(|(header, configured)| {
            response_header_values(response, header).any(|value| value == configured)
        })
}

#[cfg(feature = "cache")]
fn cache_vary_policy(
    headers: &http::HeaderMap,
    cache: &crate::config::CacheConfig,
) -> VaryCachePolicy {
    let mut fields = match vary_cache_policy(headers) {
        VaryCachePolicy::None => Vec::new(),
        VaryCachePolicy::Fields(fields) => fields,
        VaryCachePolicy::Uncacheable(reason) => return VaryCachePolicy::Uncacheable(reason),
    };

    for configured in &cache.vary_request_headers {
        let field = configured.to_ascii_lowercase();
        if !fields.contains(&field) {
            fields.push(field);
        }
        if fields.len() > MAX_VARY_FIELDS {
            return VaryCachePolicy::Uncacheable("vary-too-many-fields");
        }
    }

    if fields.is_empty() {
        VaryCachePolicy::None
    } else {
        fields.sort();
        VaryCachePolicy::Fields(fields)
    }
}

#[cfg(feature = "cache")]
fn response_content_type_is_cacheable(
    headers: &http::HeaderMap,
    cache: &crate::config::CacheConfig,
) -> bool {
    let Some(media_type) = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
    else {
        return false;
    };
    cache
        .content_types
        .iter()
        .any(|candidate| content_type_pattern_matches(candidate, media_type))
}

#[cfg(feature = "cache")]
fn content_type_pattern_matches(pattern: &str, media_type: &str) -> bool {
    let pattern = pattern.trim();
    let media_type = media_type.trim();
    if let Some(prefix) = pattern.strip_suffix("/*") {
        let Some((kind, _subtype)) = media_type.split_once('/') else {
            return false;
        };
        return kind.eq_ignore_ascii_case(prefix);
    }
    pattern.eq_ignore_ascii_case(media_type)
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
enum VaryCachePolicy {
    None,
    Fields(Vec<String>),
    Uncacheable(&'static str),
}

#[cfg(feature = "cache")]
fn vary_cache_policy(headers: &http::HeaderMap) -> VaryCachePolicy {
    let mut fields = Vec::new();
    let mut total_bytes = 0usize;

    for value in headers.get_all("vary").iter() {
        total_bytes = total_bytes.saturating_add(value.as_bytes().len());
        if total_bytes > MAX_VARY_HEADER_BYTES {
            return VaryCachePolicy::Uncacheable("vary-too-large");
        }

        let Ok(line) = value.to_str() else {
            return VaryCachePolicy::Uncacheable("vary-invalid");
        };

        for raw_field in line.split(',') {
            let field = raw_field.trim();
            if field.is_empty() {
                return VaryCachePolicy::Uncacheable("vary-invalid");
            }
            if field == "*" {
                return VaryCachePolicy::Uncacheable("vary-star");
            }
            if http::header::HeaderName::from_bytes(field.as_bytes()).is_err() {
                return VaryCachePolicy::Uncacheable("vary-invalid");
            }

            let field = field.to_ascii_lowercase();
            if is_sensitive_vary_field(&field) {
                return VaryCachePolicy::Uncacheable("vary-sensitive-field");
            }
            if !fields.contains(&field) {
                fields.push(field);
            }
            if fields.len() > MAX_VARY_FIELDS {
                return VaryCachePolicy::Uncacheable("vary-too-many-fields");
            }
        }
    }

    if fields.is_empty() {
        VaryCachePolicy::None
    } else {
        fields.sort();
        VaryCachePolicy::Fields(fields)
    }
}

#[cfg(feature = "cache")]
fn is_sensitive_vary_field(field: &str) -> bool {
    matches!(field, "authorization" | "cookie" | "proxy-authorization")
}

#[cfg(feature = "cache")]
fn vary_request_hash(fields: &[String], request: &RequestHeader) -> HashBinary {
    let mut material = Vec::new();
    material.extend_from_slice(b"fluxheim-vary-v2");

    for field in fields {
        append_vary_hash_component(&mut material, field.as_bytes());
        let values = request.headers.get_all(field.as_str());
        material.extend_from_slice(&(values.iter().count() as u32).to_le_bytes());
        for value in request.headers.get_all(field.as_str()).iter() {
            append_vary_hash_component(&mut material, value.as_bytes());
        }
    }

    pingora::cache::key::hash_key(material)
}

#[cfg(feature = "cache")]
fn append_vary_hash_component(material: &mut Vec<u8>, bytes: &[u8]) {
    material.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    material.extend_from_slice(bytes);
}

#[cfg(feature = "cache")]
fn cache_request_from_header(request: &RequestHeader) -> crate::cache::CacheRequest<'_> {
    crate::cache::CacheRequest {
        method: request.method.as_str(),
        host: request_host_header(request),
        path: request.uri.path(),
        query: request.uri.query(),
    }
}

#[cfg(any(feature = "web", feature = "cache"))]
fn request_header_values<'a>(
    request: &'a RequestHeader,
    name: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    request
        .headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
}

#[cfg(feature = "otel-tracing")]
fn request_header_value<'a>(request: &'a RequestHeader, name: &str) -> Option<&'a str> {
    request
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
}

#[cfg(feature = "cache")]
fn response_header_values<'a>(
    response: &'a ResponseHeader,
    name: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    response
        .headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
}

#[cfg(any(feature = "web", feature = "cache"))]
fn request_header_values_joined(request: &RequestHeader, name: &str) -> Option<String> {
    let mut values = request_header_values(request, name);
    let first = values.next()?.to_owned();
    Some(values.fold(first, |mut joined, value| {
        joined.push_str(", ");
        joined.push_str(value);
        joined
    }))
}

fn http_peer_for_proxy<A>(address: A, proxy: &ProxyConfig) -> Result<HttpPeer>
where
    A: ToSocketAddrs + std::fmt::Debug,
{
    let mut addrs = address.to_socket_addrs().map_err(|error| {
        Error::because(
            ErrorType::ConnectError,
            format!("failed to resolve upstream {address:?}"),
            error,
        )
    })?;
    let address = addrs.next().ok_or_else(|| {
        Error::explain(
            ErrorType::ConnectError,
            "upstream resolution returned no addresses",
        )
    })?;
    let mut peer = HttpPeer::new(address, proxy.upstream_tls, proxy.upstream_sni());
    apply_proxy_timeouts(&mut peer, proxy);
    Ok(peer)
}

fn apply_proxy_timeouts(peer: &mut HttpPeer, proxy: &ProxyConfig) {
    peer.options.connection_timeout = proxy
        .connect_timeout_secs
        .map(std::time::Duration::from_secs);
    peer.options.read_timeout = proxy.read_timeout_secs.map(std::time::Duration::from_secs);
    peer.options.write_timeout = proxy.send_timeout_secs.map(std::time::Duration::from_secs);
}

fn request_host_header(request: &RequestHeader) -> Option<&str> {
    request
        .headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .or_else(|| request.uri.authority().map(|authority| authority.as_str()))
}

fn request_limit_status(
    limits: &ServerLimitsConfig,
    request_body_limit_bytes: Option<u64>,
    request: &RequestHeader,
) -> Option<u16> {
    if request.uri.to_string().len() > limits.max_uri_bytes.as_usize() {
        return Some(414);
    }

    if request.headers.len() > limits.max_request_headers {
        return Some(431);
    }

    if approximate_request_header_bytes(request) > limits.max_request_header_bytes.as_usize() {
        return Some(431);
    }

    if let Some(status) = request_body_limit_status(
        request_body_limit_bytes.unwrap_or(limits.max_request_body_bytes.as_u64()),
        request,
    ) {
        return Some(status);
    }

    None
}

fn request_body_limit_status(limit_bytes: u64, request: &RequestHeader) -> Option<u16> {
    let content_length = match content_length(request) {
        Ok(content_length) => content_length,
        Err(status) => return Some(status),
    };

    if has_non_identity_transfer_encoding(request) {
        return if content_length.is_some() {
            Some(400)
        } else {
            Some(411)
        };
    }

    if content_length.is_some_and(|bytes| bytes > limit_bytes) {
        return Some(413);
    }

    None
}

fn request_body_chunk_limit_status(
    limit_bytes: u64,
    bytes_seen: &mut u64,
    chunk_len: usize,
) -> Option<u16> {
    *bytes_seen = bytes_seen.saturating_add(chunk_len as u64);
    if *bytes_seen > limit_bytes {
        Some(413)
    } else {
        None
    }
}

fn content_length(request: &RequestHeader) -> std::result::Result<Option<u64>, u16> {
    let mut values = request.headers.get_all("content-length").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };

    if values.next().is_some() {
        return Err(400);
    }

    let value = value.to_str().map_err(|_| 400_u16)?;
    let value = value.trim().parse::<u64>().map_err(|_| 400_u16)?;
    Ok(Some(value))
}

fn has_non_identity_transfer_encoding(request: &RequestHeader) -> bool {
    request
        .headers
        .get_all("transfer-encoding")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|coding| coding.trim())
        .any(|coding| !coding.is_empty() && !coding.eq_ignore_ascii_case("identity"))
}

fn approximate_request_header_bytes(request: &RequestHeader) -> usize {
    let request_line_bytes = request
        .method
        .as_str()
        .len()
        .saturating_add(1)
        .saturating_add(request.uri.to_string().len())
        .saturating_add(1)
        .saturating_add("HTTP/1.1".len())
        .saturating_add(2);

    request.headers.iter().fold(
        request_line_bytes.saturating_add(2),
        |total, (name, value)| {
            total
                .saturating_add(name.as_str().len())
                .saturating_add(2)
                .saturating_add(value.as_bytes().len())
                .saturating_add(2)
        },
    )
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "php-fpm")]
    use std::fs;
    #[cfg(feature = "php-fpm")]
    use std::io;
    use std::time::Duration;

    use bytes::Bytes;
    #[cfg(feature = "php-fpm")]
    use pingora::http::{ResponseHeader, StatusCode};

    use crate::config::{
        ByteSize, CacheConfig, Config, HostRoutingConfig, HttpsRedirectConfig, ProxyConfig,
        RouteConfig, RouteRedirectConfig, ServerConfig, ServerLimitsConfig, VhostConfig, WebConfig,
    };
    #[cfg(any(feature = "cache", feature = "web"))]
    use crate::test_support::unique_temp_path;

    #[cfg(feature = "cache")]
    use super::CacheRangeRequest;
    #[cfg(feature = "cache")]
    use super::{
        CACHE_PASS_REASON, CacheClientRange, CacheSliceBounds, CacheStaleEvent,
        CacheStatusOverride, MAX_VARY_FIELDS, VaryCachePolicy, apply_cache_status_ttl,
        cache_min_uses_allows_store, cache_pass_record_cacheable, cache_pass_record_uncacheable,
        cache_pass_should_bypass, cache_request_participated, cache_should_serve_stale,
        cache_stale_status_allows, cache_status_header_value, cache_status_reason_header_value,
        cache_vary_policy, ignore_origin_cache_headers, lookup_proxy_cache_only_object,
        parse_bounded_single_range, parse_cache_client_ranges, range_cache_key,
        range_response_cache_admission_rejection, read_cache_hit_body, remaining_fresh_ttl_secs,
        required_slice_bounds, resolve_client_slice_ranges, response_age_secs,
        response_cache_admission_rejection, response_vary_variance, selected_cache_range_request,
        slice_cache_key, slice_request_within_policy, strip_cache_response_headers,
        vary_cache_policy, vary_request_hash,
    };
    #[cfg(feature = "cache")]
    use super::{CacheBulkPurgeRequest, CachePurgeRequest};
    use super::{
        FluxProxy, HostRoutingRejectReason, approximate_request_header_bytes,
        count_response_body_chunk, http_peer_for_proxy, https_redirect_location,
        normalize_cookie_headers, redirect_authority, request_body_chunk_limit_status,
        request_limit_status, route_redirect_location, route_rewritten_path_and_query,
    };
    #[cfg(feature = "cache")]
    use super::{
        PeerFillResponse, acquire_peer_fill_concurrency_permit, peer_fill_concurrency_key,
        peer_fill_request_from_header, peer_fill_url,
        prune_inactive_peer_fill_concurrency_counters,
    };
    #[cfg(feature = "php-fpm")]
    use super::{
        PhpResolveOutcome, RuntimePhp, add_php_host_param, add_php_request_header_params,
        apply_php_x_accel_expires, directory_slash_redirect_location, parse_php_response,
        php_fpm_error_outcome, php_fpm_path_translated, php_fpm_retry_attempts,
        php_fpm_retryable_error, php_fpm_script_filename, php_header_param_name,
        php_script_name_denied, php_script_name_for_request, php_should_intercept_error_status,
        php_static_offload_file, php_stderr_metric_state, php_x_accel_expires_ttl_secs,
        resolve_php_script, sanitized_php_stderr, strip_php_response_headers,
    };
    #[cfg(feature = "cache")]
    use super::{
        capture_revalidation_304_headers, request_cache_bypass, request_cache_bypass_reason,
        request_cache_only_if_cached, request_cache_revalidation_requested,
        response_with_revalidation_304_headers, revalidation_304_vary_changed,
    };

    #[test]
    fn normalizes_split_cookie_headers_for_upstream_http1() {
        let mut request = pingora::http::RequestHeader::build("GET", b"/wp-admin/", None).unwrap();
        request
            .append_header("cookie", "wordpress_logged_in=abc")
            .unwrap();
        request
            .append_header("cookie", "wordpress_sec=def")
            .unwrap();
        request
            .append_header("cookie", "wordpress_test_cookie=WP%20Cookie%20check")
            .unwrap();

        normalize_cookie_headers(&mut request).unwrap();

        let cookies = request
            .headers
            .get_all("cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>();
        assert_eq!(
            cookies,
            [
                "wordpress_logged_in=abc; wordpress_sec=def; wordpress_test_cookie=WP%20Cookie%20check"
            ]
        );
    }

    #[test]
    fn leaves_single_cookie_header_unchanged() {
        let mut request = pingora::http::RequestHeader::build("GET", b"/wp-admin/", None).unwrap();
        request
            .insert_header(
                "cookie",
                "wordpress_logged_in=abc; wordpress_sec=def; wordpress_test_cookie=1",
            )
            .unwrap();

        normalize_cookie_headers(&mut request).unwrap();

        let cookies = request
            .headers
            .get_all("cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>();
        assert_eq!(
            cookies,
            ["wordpress_logged_in=abc; wordpress_sec=def; wordpress_test_cookie=1"]
        );
    }

    #[cfg(feature = "php-fpm")]
    fn php_test_runtime(name: &str) -> RuntimePhp {
        let root = unique_temp_path(name);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("index.php"), "<?php echo 'index';").unwrap();
        fs::write(root.join("app.php"), "<?php echo 'app';").unwrap();
        fs::write(root.join("style.css"), "body{}").unwrap();
        fs::create_dir_all(root.join("blog")).unwrap();
        fs::write(root.join("blog").join("index.php"), "<?php echo 'blog';").unwrap();
        let config = crate::config::PhpConfig {
            enabled: true,
            root: Some(root.clone()),
            fpm: crate::config::PhpFpmConfig {
                tcp: Some("127.0.0.1:9000".to_owned()),
                ..crate::config::PhpFpmConfig::default()
            },
            ..crate::config::PhpConfig::default()
        };
        let files = crate::web::StaticFileServer::from_config(&crate::config::WebConfig {
            root: Some(root.clone()),
            index_files: vec![config.index.clone()],
            deny_dotfiles: true,
            directory_listing: crate::config::DirectoryListingConfig::default(),
            cache_control: "private, no-store".to_owned(),
            expires: None,
        })
        .unwrap()
        .unwrap();
        RuntimePhp {
            config,
            root: root.canonicalize().unwrap(),
            fpm_root: root.canonicalize().unwrap(),
            files,
            error_pages: Vec::new(),
            pool: None,
        }
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_fpm_root_maps_script_and_path_info_for_split_containers() {
        let mut php = php_test_runtime("php-fpm-root-mapping");
        php.fpm_root = std::path::PathBuf::from("/app/public");
        let local_script = php.root.join("blog").join("index.php");

        assert_eq!(
            php_fpm_script_filename(&php, &local_script).as_deref(),
            Some("/app/public/blog/index.php")
        );
        assert_eq!(
            php_fpm_path_translated(&php, "/uploads/file.txt"),
            "/app/public/uploads/file.txt"
        );
    }

    #[cfg(all(feature = "php-fpm", unix))]
    #[test]
    fn php_runtime_reports_scope_and_path_for_unreadable_root() {
        use std::os::unix::fs::PermissionsExt;

        let parent = unique_temp_path("proxy-php-unreadable-root");
        let root = parent.join("public");
        fs::create_dir_all(&root).unwrap();
        let original_permissions = fs::metadata(&parent).unwrap().permissions();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o000)).unwrap();

        let config = crate::config::PhpConfig {
            enabled: true,
            root: Some(root.clone()),
            fpm: crate::config::PhpFpmConfig {
                tcp: Some("127.0.0.1:9000".to_owned()),
                ..crate::config::PhpFpmConfig::default()
            },
            ..crate::config::PhpConfig::default()
        };

        let result = RuntimePhp::from_config(
            "vhost \"fluxheim.test\" php",
            "fluxheim.test",
            "default",
            &config,
        );
        fs::set_permissions(&parent, original_permissions).unwrap();
        let error = result.unwrap_err().to_string();
        assert!(error.contains("vhost \"fluxheim.test\" php"), "{error}");
        assert!(error.contains(&root.display().to_string()), "{error}");
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_script_resolution_accepts_direct_script_and_front_controller() {
        let php = php_test_runtime("proxy-php-script-resolution");

        let (script, path_info, explicit) = php_script_name_for_request(&php, "/app.php").unwrap();
        assert_eq!(script, "/app.php");
        assert_eq!(path_info, "");
        assert!(explicit);

        let (script, path_info, explicit) =
            php_script_name_for_request(&php, "/missing/page").unwrap();
        assert_eq!(script, "/index.php");
        assert_eq!(path_info, "");
        assert!(!explicit);
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_script_resolution_rejects_traversal_and_disabled_path_info() {
        let php = php_test_runtime("proxy-php-script-resolution-reject");

        assert!(php_script_name_for_request(&php, "/../app.php").is_none());
        assert!(php_script_name_for_request(&php, "/app.php/admin").is_none());
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_denies_configured_script_prefixes() {
        let mut php = php_test_runtime("proxy-php-deny-prefixes");
        fs::create_dir_all(php.root.join("wp-content").join("uploads")).unwrap();
        fs::write(
            php.root
                .join("wp-content")
                .join("uploads")
                .join("shell.php"),
            "<?php echo 'blocked';",
        )
        .unwrap();
        php.config.deny_path_prefixes = vec!["/wp-content/uploads/".to_owned()];

        assert!(php_script_name_denied(
            &php,
            "/wp-content/uploads/shell.php"
        ));
        assert!(!php_script_name_denied(
            &php,
            "/wp-content/uploads2/app.php"
        ));
        assert!(matches!(
            resolve_php_script(&php, "/wp-content/uploads/shell.php", true),
            PhpResolveOutcome::Forbidden
        ));
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_path_info_split_mode_extracts_safe_trailing_segments() {
        let mut php = php_test_runtime("proxy-php-path-info-split");
        php.config.path_info = crate::config::PhpPathInfoMode::Split;

        let (script, path_info, explicit) =
            php_script_name_for_request(&php, "/app.php/user/1").unwrap();
        assert_eq!(script, "/app.php");
        assert_eq!(path_info, "/user/1");
        assert!(explicit);

        assert!(php_script_name_for_request(&php, "/app.php/../admin").is_none());
        assert!(php_script_name_for_request(&php, "/app.php/.hidden").is_none());
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_resolution_declines_static_assets_but_executes_directory_php_index() {
        let php = php_test_runtime("proxy-php-existing-static");

        assert!(matches!(
            resolve_php_script(&php, "/style.css", true),
            PhpResolveOutcome::Decline
        ));
        let PhpResolveOutcome::Execute(resolution) = resolve_php_script(&php, "/blog/", true)
        else {
            panic!("expected directory PHP index to execute");
        };
        assert_eq!(resolution.script_name, "/blog/index.php");
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_resolution_redirects_slashless_directory_php_index() {
        let php = php_test_runtime("proxy-php-directory-slash");

        assert!(matches!(
            resolve_php_script(&php, "/blog", true),
            PhpResolveOutcome::RedirectDirectorySlash
        ));

        let PhpResolveOutcome::Execute(resolution) = resolve_php_script(&php, "/blog/", true)
        else {
            panic!("expected canonical directory PHP index to execute");
        };
        assert_eq!(resolution.script_name, "/blog/index.php");
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_directory_slash_redirect_location_preserves_query() {
        let request = pingora::http::RequestHeader::build("GET", b"/blog?preview=1", None).unwrap();

        assert_eq!(
            directory_slash_redirect_location(&request).as_deref(),
            Some("/blog/?preview=1")
        );
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_strict_try_files_rejects_missing_front_controller_fallback() {
        let mut php = php_test_runtime("proxy-php-strict-try-files");
        php.config.try_files = crate::config::PhpTryFilesMode::Strict;

        assert!(matches!(
            resolve_php_script(&php, "/missing/page", true),
            PhpResolveOutcome::NotFound
        ));

        let PhpResolveOutcome::Execute(resolution) = resolve_php_script(&php, "/app.php", true)
        else {
            panic!("expected direct PHP script to execute");
        };
        assert_eq!(resolution.script_name, "/app.php");

        let PhpResolveOutcome::Execute(resolution) = resolve_php_script(&php, "/blog/", true)
        else {
            panic!("expected directory PHP index to execute");
        };
        assert_eq!(resolution.script_name, "/blog/index.php");
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_header_param_translation_adds_common_headers_and_drops_httpoxy_proxy() {
        let mut request = pingora::http::RequestHeader::build("GET", b"/index.php", None).unwrap();
        request.insert_header("host", "example.test").unwrap();
        request.insert_header("x-forwarded-proto", "https").unwrap();
        request
            .insert_header("proxy", "http://attacker.invalid")
            .unwrap();
        request
            .insert_header("content-type", "application/json")
            .unwrap();

        let mut params = fastcgi_client::Params::default();
        add_php_request_header_params(&mut params, &request);

        assert_eq!(
            params.get("HTTP_HOST").map(|value| value.as_ref()),
            Some("example.test")
        );
        assert_eq!(
            params
                .get("HTTP_X_FORWARDED_PROTO")
                .map(|value| value.as_ref()),
            Some("https")
        );
        assert!(!params.contains_key("HTTP_PROXY"));
        assert!(!params.contains_key("HTTP_CONTENT_TYPE"));
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_header_param_translation_joins_split_cookie_headers_with_semicolon() {
        let mut request = pingora::http::RequestHeader::build("GET", b"/index.php", None).unwrap();
        request
            .append_header("cookie", "wordpress_logged_in=abc")
            .unwrap();
        request
            .append_header("cookie", "wordpress_sec=def")
            .unwrap();
        request
            .append_header("cookie", "wordpress_test_cookie=WP%20Cookie%20check")
            .unwrap();

        let mut params = fastcgi_client::Params::default();
        add_php_request_header_params(&mut params, &request);

        assert_eq!(
            params.get("HTTP_COOKIE").map(|value| value.as_ref()),
            Some(
                "wordpress_logged_in=abc; wordpress_sec=def; wordpress_test_cookie=WP%20Cookie%20check",
            )
        );
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_host_param_uses_resolved_request_host_without_literal_host_header() {
        let request = pingora::http::RequestHeader::build("GET", b"/index.php", None).unwrap();
        let mut params = fastcgi_client::Params::default();

        add_php_request_header_params(&mut params, &request);
        assert!(!params.contains_key("HTTP_HOST"));

        add_php_host_param(&mut params, "example.test");
        assert_eq!(
            params.get("HTTP_HOST").map(|value| value.as_ref()),
            Some("example.test")
        );
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_header_param_name_is_bounded_and_predictable() {
        assert_eq!(
            php_header_param_name("x-request-id").as_deref(),
            Some("HTTP_X_REQUEST_ID")
        );
        assert_eq!(php_header_param_name("proxy"), None);
        assert_eq!(php_header_param_name("content-length"), None);
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn parse_php_response_accepts_status_and_headers() {
        let (response, body) = parse_php_response(
            b"Status: 201 Created\r\nContent-Type: text/plain\r\n\r\nok",
            64 * 1024 * 1024,
            64 * 1024,
        )
        .unwrap();

        assert_eq!(response.status.as_u16(), 201);
        assert_eq!(
            response
                .headers
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "text/plain"
        );
        assert_eq!(body, b"ok");
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn parse_php_response_preserves_headers_before_status() {
        let (response, body) = parse_php_response(
            b"Set-Cookie: wordpress_test_cookie=WP%20Cookie%20check; path=/\r\nStatus: 302 Found\r\nLocation: /wp-admin/\r\n\r\n",
            64 * 1024 * 1024,
            64 * 1024,
        )
        .unwrap();

        assert_eq!(response.status.as_u16(), 302);
        assert_eq!(
            response.headers.get("location").unwrap().to_str().unwrap(),
            "/wp-admin/"
        );
        let cookies = response
            .headers
            .get_all("set-cookie")
            .iter()
            .collect::<Vec<_>>();
        assert_eq!(cookies.len(), 1);
        assert_eq!(
            cookies[0].to_str().unwrap(),
            "wordpress_test_cookie=WP%20Cookie%20check; path=/"
        );
        assert!(body.is_empty());
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn parse_php_response_rejects_header_injection() {
        let error = parse_php_response(b"X-Test: ok\rbad\r\n\r\nbody", 64 * 1024 * 1024, 64 * 1024)
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn parse_php_response_enforces_configured_size_limit() {
        let error =
            parse_php_response(b"Content-Type: text/plain\r\n\r\nbody", 8, 64 * 1024).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn parse_php_response_enforces_configured_header_size_limit() {
        let error = parse_php_response(
            b"Content-Type: text/plain\r\nX-Test: abc\r\n\r\nbody",
            64 * 1024 * 1024,
            8,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_fpm_error_outcomes_are_bounded() {
        assert_eq!(
            php_fpm_error_outcome(&io::Error::new(
                io::ErrorKind::TimedOut,
                "php-fpm connect timed out",
            )),
            "connect_timeout"
        );
        assert_eq!(
            php_fpm_error_outcome(&io::Error::new(
                io::ErrorKind::TimedOut,
                "php-fpm request timed out",
            )),
            "request_timeout"
        );
        assert_eq!(
            php_fpm_error_outcome(&io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "connection refused",
            )),
            "connection_error"
        );
        assert_eq!(
            php_fpm_error_outcome(&io::Error::new(io::ErrorKind::InvalidInput, "missing fpm")),
            "configuration_error"
        );
        assert_eq!(
            php_fpm_error_outcome(&io::Error::other("backend failed")),
            "fpm_error"
        );
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_fpm_retry_policy_is_bounded_and_safe_by_method() {
        let mut fpm = crate::config::PhpFpmConfig {
            max_retries: 2,
            retry_methods: vec!["GET".to_owned(), "HEAD".to_owned()],
            ..crate::config::PhpFpmConfig::default()
        };

        assert_eq!(php_fpm_retry_attempts(&fpm, "GET"), 2);
        assert_eq!(php_fpm_retry_attempts(&fpm, "POST"), 0);
        fpm.max_retries = 0;
        assert_eq!(php_fpm_retry_attempts(&fpm, "GET"), 0);
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_fpm_retryable_errors_exclude_request_timeouts() {
        assert!(php_fpm_retryable_error(&io::Error::new(
            io::ErrorKind::TimedOut,
            "php-fpm connect timed out",
        )));
        assert!(php_fpm_retryable_error(&io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "connection refused",
        )));
        assert!(!php_fpm_retryable_error(&io::Error::new(
            io::ErrorKind::TimedOut,
            "php-fpm request timed out",
        )));
        assert!(!php_fpm_retryable_error(&io::Error::new(
            io::ErrorKind::InvalidInput,
            "bad config",
        )));
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_stderr_sanitizer_truncates_and_removes_controls() {
        assert_eq!(sanitized_php_stderr(b"warn\nnext", 64), "warn next");
        assert_eq!(sanitized_php_stderr(b"abcdef", 3), "abc ... <truncated>");
        assert_eq!(php_stderr_metric_state(b"warn", 64), "emitted");
        assert_eq!(php_stderr_metric_state(b"abcdef", 3), "truncated");
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_hidden_response_headers_are_removed() {
        let mut response = ResponseHeader::build(200, None).unwrap();
        response
            .insert_header("connection", "x-hop, keep-alive")
            .unwrap();
        response
            .insert_header("transfer-encoding", "chunked")
            .unwrap();
        response.insert_header("x-hop", "secret").unwrap();
        response.insert_header("x-powered-by", "PHP/8.4").unwrap();
        response.insert_header("x-keep", "ok").unwrap();
        let config = crate::config::PhpConfig {
            hide_response_headers: vec!["x-powered-by".to_owned()],
            ..crate::config::PhpConfig::default()
        };

        strip_php_response_headers(&mut response, &config);

        assert!(!response.headers.contains_key("x-powered-by"));
        assert!(!response.headers.contains_key("connection"));
        assert!(!response.headers.contains_key("transfer-encoding"));
        assert!(!response.headers.contains_key("x-hop"));
        assert_eq!(
            response
                .headers
                .get("x-keep")
                .and_then(|value| value.to_str().ok()),
            Some("ok")
        );
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_static_offload_resolves_x_accel_redirect_under_php_root() {
        let php = php_test_runtime("php-x-accel-redirect");
        let mut response = ResponseHeader::build(200, None).unwrap();
        response
            .insert_header("x-accel-redirect", "/style.css")
            .unwrap();

        let file = php_static_offload_file(&mut response, &php)
            .unwrap()
            .unwrap();

        assert_eq!(
            file.path.file_name().and_then(|name| name.to_str()),
            Some("style.css")
        );
        assert!(!response.headers.contains_key("x-accel-redirect"));
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_static_offload_resolves_x_sendfile_under_php_root() {
        let php = php_test_runtime("php-x-sendfile");
        let target = php.root.join("style.css");
        let mut response = ResponseHeader::build(200, None).unwrap();
        response
            .insert_header("x-sendfile", target.to_string_lossy().to_string())
            .unwrap();

        let file = php_static_offload_file(&mut response, &php)
            .unwrap()
            .unwrap();

        assert_eq!(file.path, target);
        assert!(!response.headers.contains_key("x-sendfile"));
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_static_offload_maps_x_sendfile_from_fpm_root() {
        let mut php = php_test_runtime("php-x-sendfile-fpm-root");
        php.fpm_root = std::path::PathBuf::from("/app");
        let mut response = ResponseHeader::build(200, None).unwrap();
        response
            .insert_header("x-sendfile", "/app/style.css")
            .unwrap();

        let file = php_static_offload_file(&mut response, &php)
            .unwrap()
            .unwrap();

        assert_eq!(file.path, php.root.join("style.css"));
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_static_offload_rejects_scripts_and_escape_paths() {
        let php = php_test_runtime("php-static-offload-rejects");
        let mut script = ResponseHeader::build(200, None).unwrap();
        script
            .insert_header("x-accel-redirect", "/app.php")
            .unwrap();
        let error = php_static_offload_file(&mut script, &php).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        let mut escape = ResponseHeader::build(200, None).unwrap();
        escape
            .insert_header("x-accel-redirect", "/../style.css")
            .unwrap();
        let error = php_static_offload_file(&mut escape, &php).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_x_accel_expires_maps_positive_ttl_to_cache_headers() {
        let mut response = ResponseHeader::build(200, None).unwrap();
        response.insert_header("x-accel-expires", "60").unwrap();
        response.insert_header("cache-control", "no-cache").unwrap();
        response.insert_header("pragma", "no-cache").unwrap();

        apply_php_x_accel_expires(&mut response).unwrap();

        assert!(!response.headers.contains_key("x-accel-expires"));
        assert!(!response.headers.contains_key("pragma"));
        assert_eq!(
            response
                .headers
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("public, max-age=60")
        );
        assert!(response.headers.contains_key("expires"));
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_x_accel_expires_uses_private_cache_for_cookie_responses() {
        let mut response = ResponseHeader::build(200, None).unwrap();
        response.insert_header("set-cookie", "wordpress=1").unwrap();
        response.insert_header("x-accel-expires", "120").unwrap();

        apply_php_x_accel_expires(&mut response).unwrap();

        assert_eq!(
            response
                .headers
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("private, max-age=120")
        );
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_x_accel_expires_zero_disables_cache() {
        let mut response = ResponseHeader::build(200, None).unwrap();
        response.insert_header("x-accel-expires", "0").unwrap();

        apply_php_x_accel_expires(&mut response).unwrap();

        assert_eq!(
            response
                .headers
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store, private")
        );
        assert!(!response.headers.contains_key("x-accel-expires"));
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_x_accel_expires_parses_absolute_epoch() {
        let future = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        let ttl = php_x_accel_expires_ttl_secs(&format!("@{}", future)).unwrap();

        assert!(ttl <= 60);
        assert!(ttl > 0);
        assert_eq!(php_x_accel_expires_ttl_secs("-1"), Some(0));
        assert_eq!(php_x_accel_expires_ttl_secs("bad"), None);
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_intercept_error_statuses_are_explicit() {
        let mut php = php_test_runtime("php-intercept-error-statuses");
        php.config.intercept_error_statuses = vec![404, 500];

        assert!(php_should_intercept_error_status(
            StatusCode::NOT_FOUND,
            &php
        ));
        assert!(php_should_intercept_error_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            &php
        ));
        assert!(!php_should_intercept_error_status(
            StatusCode::BAD_GATEWAY,
            &php
        ));
    }

    #[cfg(all(feature = "php-fpm", feature = "web"))]
    #[test]
    fn php_error_pages_imply_status_interception() {
        let root = unique_temp_path("php-error-page");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("502.html"), "bad gateway").unwrap();
        let config = crate::config::PhpConfig {
            enabled: true,
            root: Some(root.clone()),
            error_pages: vec![crate::config::ProxyErrorPageConfig {
                status: 502,
                path: "/502.html".to_owned(),
                web: WebConfig {
                    root: Some(root.clone()),
                    ..WebConfig::default()
                },
            }],
            fpm: crate::config::PhpFpmConfig {
                tcp: Some("127.0.0.1:9000".to_owned()),
                ..crate::config::PhpFpmConfig::default()
            },
            ..crate::config::PhpConfig::default()
        };

        let php = RuntimePhp::from_config("test php", "test", "default", &config)
            .unwrap()
            .unwrap();

        assert!(php.error_page(502).is_some());
        assert!(php_should_intercept_error_status(
            StatusCode::BAD_GATEWAY,
            &php
        ));
        assert!(!php_should_intercept_error_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            &php
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn routes_known_hosts() {
        let config = Config {
            server: ServerConfig {
                listen: vec!["127.0.0.1:8080".to_owned()],
                tls_listen: Vec::new(),
                default_vhost: Some("exact".to_owned()),
                trusted_proxies: Vec::new(),
                limits: ServerLimitsConfig::default(),
                ..ServerConfig::default()
            },
            vhosts: vec![
                VhostConfig {
                    name: "one".to_owned(),
                    hosts: vec!["one.example".to_owned()],
                    max_request_body_bytes: None,
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig {
                        upstream: Some("127.0.0.1:3001".to_owned()),
                        ..ProxyConfig::default()
                    },
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
                VhostConfig {
                    name: "two".to_owned(),
                    hosts: vec!["two.example".to_owned()],
                    max_request_body_bytes: None,
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig {
                        upstream: Some("127.0.0.1:3002".to_owned()),
                        ..ProxyConfig::default()
                    },
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
            ],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();

        assert_eq!(proxy.route_host(Some("one.example")), "one");
        assert_eq!(proxy.route_host(Some("two.example:443")), "two");
    }

    #[test]
    fn falls_back_to_first_vhost() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "default.example".to_owned(),
                hosts: vec!["default.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();

        assert_eq!(proxy.route_host(Some("missing.example")), "default.example");
        assert_eq!(proxy.route_host(None), "default.example");
        assert_eq!(proxy.route_host(Some("not a host")), "default.example");
    }

    #[test]
    fn strict_host_routing_rejects_missing_invalid_and_unknown_hosts() {
        let config = Config {
            server: ServerConfig {
                host_routing: HostRoutingConfig { strict: true },
                ..ServerConfig::default()
            },
            vhosts: vec![VhostConfig {
                name: "default.example".to_owned(),
                hosts: vec!["default.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let snapshot = FluxProxy::from_config(&config).unwrap().snapshot();

        assert_eq!(
            snapshot.state.request_vhost_index(Some("default.example")),
            Ok(0)
        );
        assert_eq!(
            snapshot.state.request_vhost_index(None),
            Err(HostRoutingRejectReason::Missing)
        );
        assert_eq!(
            snapshot.state.request_vhost_index(Some("not a host")),
            Err(HostRoutingRejectReason::Invalid)
        );
        assert_eq!(
            snapshot.state.request_vhost_index(Some("unknown.example")),
            Err(HostRoutingRejectReason::Unknown)
        );
    }

    #[test]
    fn reload_swaps_new_snapshot_without_invalidating_old_snapshot() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "old".to_owned(),
                hosts: vec!["old.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let old_snapshot = proxy.snapshot();

        let new_config = Config {
            vhosts: vec![VhostConfig {
                name: "new".to_owned(),
                hosts: vec!["new.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        proxy.reload_from_config(&new_config).unwrap();

        assert_eq!(old_snapshot.route_host(Some("old.example")), "old");
        assert_eq!(proxy.route_host(Some("new.example")), "new");
        assert_eq!(proxy.route_host(Some("old.example")), "new");
    }

    #[test]
    fn uses_explicit_default_vhost() {
        let config = Config {
            server: ServerConfig {
                listen: vec!["127.0.0.1:8080".to_owned()],
                tls_listen: Vec::new(),
                default_vhost: Some("two".to_owned()),
                trusted_proxies: Vec::new(),
                limits: ServerLimitsConfig::default(),
                ..ServerConfig::default()
            },
            vhosts: vec![
                VhostConfig {
                    name: "one".to_owned(),
                    hosts: vec!["one.example".to_owned()],
                    max_request_body_bytes: None,
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
                VhostConfig {
                    name: "two".to_owned(),
                    hosts: vec!["two.example".to_owned()],
                    max_request_body_bytes: None,
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
            ],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();

        assert_eq!(proxy.route_host(Some("missing.example")), "two");
    }

    #[cfg(feature = "acme")]
    #[test]
    fn managed_acme_http_01_route_is_local_and_redirect_exempt() {
        let config = Config {
            tls: crate::config::TlsConfig {
                enabled: true,
                acme: crate::config::AcmeConfig {
                    enabled: true,
                    storage: Some(std::path::PathBuf::from("/var/lib/fluxheim/acme")),
                    contact_email: Some("admin@example.test".to_owned()),
                    challenge: crate::config::AcmeChallenge::Http01,
                    ..crate::config::AcmeConfig::default()
                },
                ..crate::config::TlsConfig::default()
            },
            vhosts: vec![VhostConfig {
                name: "example".to_owned(),
                hosts: vec!["example.test".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig {
                    enabled: true,
                    acme: crate::config::VhostAcmeConfig {
                        enabled: true,
                        issuer: None,
                        domains: Vec::new(),
                    },
                    ..crate::config::VhostTlsConfig::default()
                },
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };

        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost = snapshot
            .state
            .vhost(snapshot.state.vhost_index(Some("example.test")));
        let route_index = vhost
            .route_index("/.well-known/acme-challenge/token_123")
            .unwrap();
        let route = vhost.route(route_index);

        assert!(route.https_redirect_exempt);
        assert!(matches!(
            route.action,
            super::RuntimeRouteAction::AcmeHttp01(_)
        ));
        assert_eq!(vhost.route_index("/other"), None);
    }

    #[cfg(feature = "acme")]
    #[test]
    fn managed_acme_http_01_route_covers_redirect_alias_vhost() {
        let config = Config {
            tls: crate::config::TlsConfig {
                enabled: true,
                acme: crate::config::AcmeConfig {
                    enabled: true,
                    storage: Some(std::path::PathBuf::from("/var/lib/fluxheim/acme")),
                    contact_email: Some("admin@example.test".to_owned()),
                    challenge: crate::config::AcmeChallenge::Http01,
                    ..crate::config::AcmeConfig::default()
                },
                ..crate::config::TlsConfig::default()
            },
            vhosts: vec![
                VhostConfig {
                    name: "example".to_owned(),
                    hosts: vec!["example.test".to_owned()],
                    max_request_body_bytes: None,
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig {
                        enabled: true,
                        acme: crate::config::VhostAcmeConfig {
                            enabled: true,
                            issuer: None,
                            domains: vec!["example.test".to_owned(), "www.example.test".to_owned()],
                        },
                        ..crate::config::VhostTlsConfig::default()
                    },
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
                VhostConfig {
                    name: "example-www-redirect".to_owned(),
                    hosts: vec!["www.example.test".to_owned()],
                    max_request_body_bytes: None,
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig {
                        enabled: true,
                        to: Some("https://example.test{uri}".to_owned()),
                        status: 308,
                    },
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
            ],
            ..Config::default()
        };

        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost = snapshot
            .state
            .vhost(snapshot.state.vhost_index(Some("www.example.test")));
        let route_index = vhost
            .route_index("/.well-known/acme-challenge/token_123")
            .unwrap();
        let route = vhost.route(route_index);

        assert!(route.https_redirect_exempt);
        assert!(matches!(
            route.action,
            super::RuntimeRouteAction::AcmeHttp01(_)
        ));
    }

    #[test]
    fn routes_one_label_wildcards() {
        let config = Config {
            server: ServerConfig {
                listen: vec!["127.0.0.1:8080".to_owned()],
                tls_listen: Vec::new(),
                default_vhost: Some("exact".to_owned()),
                trusted_proxies: Vec::new(),
                limits: ServerLimitsConfig::default(),
                ..ServerConfig::default()
            },
            vhosts: vec![
                VhostConfig {
                    name: "wild".to_owned(),
                    hosts: vec!["*.example.com".to_owned()],
                    max_request_body_bytes: None,
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
                VhostConfig {
                    name: "exact".to_owned(),
                    hosts: vec!["api.example.com".to_owned()],
                    max_request_body_bytes: None,
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
            ],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();

        assert_eq!(proxy.route_host(Some("www.example.com")), "wild");
        assert_eq!(proxy.route_host(Some("api.example.com")), "exact");
        assert_eq!(proxy.route_host(Some("deep.www.example.com")), "exact");
    }

    #[test]
    fn builds_safe_https_redirect_location() {
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/shop/item?id=42", None).unwrap();
        request.insert_header("host", "Example.Test:8080").unwrap();
        let config = HttpsRedirectConfig {
            enabled: true,
            status: 308,
            target_port: Some(8443),
        };

        assert_eq!(
            https_redirect_location(&request, &config).as_deref(),
            Some("https://example.test:8443/shop/item?id=42")
        );
    }

    #[test]
    fn default_https_redirect_drops_source_http_port() {
        let mut request = pingora::http::RequestHeader::build("GET", b"/docs", None).unwrap();
        request.insert_header("host", "example.test:8080").unwrap();

        assert_eq!(
            https_redirect_location(&request, &HttpsRedirectConfig::default()).as_deref(),
            Some("https://example.test/docs")
        );
    }

    #[test]
    fn redirect_target_port_443_uses_default_authority() {
        assert_eq!(
            redirect_authority("example.test", Some(443)).as_deref(),
            Some("example.test")
        );
    }

    #[test]
    fn rejects_redirect_location_without_safe_host() {
        let mut request = pingora::http::RequestHeader::build("GET", b"/", None).unwrap();
        request.insert_header("host", "example.test/bad").unwrap();

        assert_eq!(
            https_redirect_location(&request, &HttpsRedirectConfig::default()),
            None
        );
    }

    #[test]
    fn wraps_ipv6_redirect_authority() {
        assert_eq!(
            redirect_authority("2001:db8::1", Some(8443)).as_deref(),
            Some("[2001:db8::1]:8443")
        );
    }

    #[test]
    fn vhost_routes_pick_exact_then_longest_prefix_then_fallback() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "gateway".to_owned(),
                hosts: vec!["gateway.example".to_owned()],
                max_request_body_bytes: Some(ByteSize::from_bytes(64 * 1024 * 1024)),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: vec![
                    RouteConfig {
                        name: "fallback".to_owned(),
                        fallback: true,
                        redirect: Some(RouteRedirectConfig {
                            to: "https://gateway.example{uri}".to_owned(),
                            status: 308,
                        }),
                        path_exact: None,
                        path_prefix: None,
                        strip_prefix: None,
                        https_redirect_exempt: false,
                        max_request_body_bytes: None,
                        proxy: None,
                        web: None,
                        php: None,
                        cache: None,
                        headers: crate::config::VhostHeaderPolicyConfig::default(),
                    },
                    RouteConfig {
                        name: "api".to_owned(),
                        path_prefix: Some("/api/".to_owned()),
                        proxy: Some(ProxyConfig {
                            upstreams: vec!["127.0.0.1:6001".to_owned()],
                            upstream: None,
                            ..ProxyConfig::default()
                        }),
                        path_exact: None,
                        fallback: false,
                        strip_prefix: None,
                        https_redirect_exempt: false,
                        max_request_body_bytes: None,
                        redirect: None,
                        web: None,
                        php: None,
                        cache: None,
                        headers: crate::config::VhostHeaderPolicyConfig::default(),
                    },
                    RouteConfig {
                        name: "api-v2".to_owned(),
                        path_prefix: Some("/api/v2/".to_owned()),
                        proxy: Some(ProxyConfig {
                            upstreams: vec!["127.0.0.1:6002".to_owned()],
                            upstream: None,
                            ..ProxyConfig::default()
                        }),
                        path_exact: None,
                        fallback: false,
                        strip_prefix: None,
                        https_redirect_exempt: false,
                        max_request_body_bytes: None,
                        redirect: None,
                        web: None,
                        php: None,
                        cache: None,
                        headers: crate::config::VhostHeaderPolicyConfig::default(),
                    },
                    RouteConfig {
                        name: "exact".to_owned(),
                        path_exact: Some("/api/v2/status".to_owned()),
                        proxy: Some(ProxyConfig {
                            upstreams: vec!["127.0.0.1:6003".to_owned()],
                            upstream: None,
                            ..ProxyConfig::default()
                        }),
                        path_prefix: None,
                        fallback: false,
                        strip_prefix: None,
                        https_redirect_exempt: false,
                        max_request_body_bytes: None,
                        redirect: None,
                        web: None,
                        php: None,
                        cache: None,
                        headers: crate::config::VhostHeaderPolicyConfig::default(),
                    },
                ],
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost = snapshot
            .state
            .vhost(snapshot.state.vhost_index(Some("gateway.example")));

        assert_eq!(
            vhost.max_request_body_bytes,
            Some(ByteSize::from_bytes(64 * 1024 * 1024))
        );
        assert_eq!(vhost.route_index("/api/v2/status"), Some(3));
        assert_eq!(vhost.route_index("/api/v2/users"), Some(2));
        assert_eq!(vhost.route_index("/api/users"), Some(1));
        assert_eq!(vhost.route_index("/missing"), Some(0));
    }

    #[test]
    fn route_redirect_templates_preserve_safe_uri() {
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/old/path?x=1", None).unwrap();
        request.insert_header("host", "www.example.test").unwrap();
        let redirect = RouteRedirectConfig {
            to: "https://example.test{uri}".to_owned(),
            status: 301,
        };

        assert_eq!(
            route_redirect_location(&request, &redirect).as_deref(),
            Some("https://example.test/old/path?x=1")
        );
    }

    #[test]
    fn route_strip_prefix_rewrites_path_and_preserves_query() {
        let request = pingora::http::RequestHeader::build("GET", b"/chat/room?id=7", None).unwrap();
        let route = super::RuntimeRoute {
            matcher: super::RuntimeRouteMatcher::Prefix("/chat/".to_owned()),
            https_redirect_exempt: false,
            strip_prefix: Some("/chat/".to_owned()),
            max_request_body_bytes: None,
            action: super::RuntimeRouteAction::Proxy(
                super::RuntimeProxy::from_config(&ProxyConfig::default(), "test proxy").unwrap(),
            ),
            #[cfg(feature = "cache")]
            cache: None,
            request_headers: crate::config::RequestHeaderPolicyConfig::default(),
            response_headers: crate::config::ResponseHeaderPolicyConfig::default(),
        };

        assert_eq!(
            route_rewritten_path_and_query(&request, &route).as_deref(),
            Some("/room?id=7")
        );
    }

    #[test]
    fn route_strip_prefix_rejects_traversal_suffixes() {
        let route = super::RuntimeRoute {
            matcher: super::RuntimeRouteMatcher::Prefix("/api/".to_owned()),
            https_redirect_exempt: false,
            strip_prefix: Some("/api/".to_owned()),
            max_request_body_bytes: None,
            action: super::RuntimeRouteAction::Proxy(
                super::RuntimeProxy::from_config(&ProxyConfig::default(), "test proxy").unwrap(),
            ),
            #[cfg(feature = "cache")]
            cache: None,
            request_headers: crate::config::RequestHeaderPolicyConfig::default(),
            response_headers: crate::config::ResponseHeaderPolicyConfig::default(),
        };

        let raw = pingora::http::RequestHeader::build("GET", b"/api/../admin", None).unwrap();
        assert_eq!(route_rewritten_path_and_query(&raw, &route), None);

        let encoded =
            pingora::http::RequestHeader::build("GET", b"/api/%2e%2e/admin", None).unwrap();
        assert_eq!(route_rewritten_path_and_query(&encoded, &route), None);

        let encoded_separator =
            pingora::http::RequestHeader::build("GET", b"/api/safe%2f..%2fadmin", None).unwrap();
        assert_eq!(
            route_rewritten_path_and_query(&encoded_separator, &route),
            None
        );
    }

    #[test]
    fn proxy_timeout_config_maps_to_pingora_peer_options() {
        let proxy = ProxyConfig {
            upstream: Some("127.0.0.1:6010".to_owned()),
            connect_timeout_secs: Some(5),
            read_timeout_secs: Some(600),
            send_timeout_secs: Some(30),
            ..ProxyConfig::default()
        };

        let peer = http_peer_for_proxy(proxy.primary_upstream(), &proxy).unwrap();

        assert_eq!(
            peer.options.connection_timeout,
            Some(Duration::from_secs(5))
        );
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(600)));
        assert_eq!(peer.options.write_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn proxy_downstream_flow_control_maps_from_config() {
        let proxy = ProxyConfig {
            downstream_write_timeout_secs: Some(20),
            downstream_min_send_rate_bytes_per_sec: Some(8192),
            ..ProxyConfig::default()
        };

        assert_eq!(
            super::downstream_flow_control(&proxy),
            super::DownstreamFlowControl {
                write_timeout: Some(Duration::from_secs(20)),
                min_send_rate: Some(8192),
            }
        );
    }

    #[cfg(feature = "web")]
    #[test]
    fn runtime_proxy_builds_static_error_pages() {
        let root = unique_temp_path("proxy-error-page");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("502.html"), "bad gateway").unwrap();
        let proxy = ProxyConfig {
            error_pages: vec![crate::config::ProxyErrorPageConfig {
                status: 502,
                path: "/502.html".to_owned(),
                web: WebConfig {
                    root: Some(root.clone()),
                    ..WebConfig::default()
                },
            }],
            ..ProxyConfig::default()
        };

        let runtime = super::RuntimeProxy::from_config(&proxy, "test proxy").unwrap();

        assert!(runtime.error_page(502).is_some());
        assert!(runtime.error_page(503).is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn vhost_header_policy_overlays_global_policy() {
        let config = Config {
            headers: crate::config::HeaderPolicyConfig {
                request: crate::config::RequestHeaderPolicyConfig {
                    set: std::collections::BTreeMap::from([(
                        "x-global-request".to_owned(),
                        "global".to_owned(),
                    )]),
                    append: std::collections::BTreeMap::from([(
                        "via".to_owned(),
                        crate::config::HeaderValues::One("global".to_owned()),
                    )]),
                    ..crate::config::RequestHeaderPolicyConfig::default()
                },
                response: crate::config::ResponseHeaderPolicyConfig {
                    set: std::collections::BTreeMap::from([(
                        "cache-control".to_owned(),
                        "public, max-age=60".to_owned(),
                    )]),
                    append: std::collections::BTreeMap::from([(
                        "vary".to_owned(),
                        crate::config::HeaderValues::One("Accept-Encoding".to_owned()),
                    )]),
                    ..crate::config::ResponseHeaderPolicyConfig::default()
                },
            },
            vhosts: vec![VhostConfig {
                name: "api".to_owned(),
                hosts: vec!["api.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                headers: crate::config::VhostHeaderPolicyConfig {
                    request: crate::config::RequestHeaderPolicyOverlayConfig {
                        x_forwarded_for: Some(crate::config::ForwardedClientIpHeaderMode::Off),
                        set: std::collections::BTreeMap::from([(
                            "x-vhost-request".to_owned(),
                            "api".to_owned(),
                        )]),
                        append: std::collections::BTreeMap::from([(
                            "via".to_owned(),
                            crate::config::HeaderValues::One("api".to_owned()),
                        )]),
                        ..crate::config::RequestHeaderPolicyOverlayConfig::default()
                    },
                    response: crate::config::ResponseHeaderPolicyOverlayConfig {
                        x_frame_options: Some(Some("SAMEORIGIN".to_owned())),
                        set: std::collections::BTreeMap::from([(
                            "access-control-allow-origin".to_owned(),
                            "https://app.example".to_owned(),
                        )]),
                        append: std::collections::BTreeMap::from([(
                            "vary".to_owned(),
                            crate::config::HeaderValues::One("Origin".to_owned()),
                        )]),
                        ..crate::config::ResponseHeaderPolicyOverlayConfig::default()
                    },
                },
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };

        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost = snapshot
            .state
            .vhost(snapshot.state.vhost_index(Some("api.example")));

        assert_eq!(
            vhost.request_headers.x_forwarded_for,
            crate::config::ForwardedClientIpHeaderMode::Off
        );
        assert_eq!(
            vhost
                .request_headers
                .set
                .get("x-global-request")
                .map(String::as_str),
            Some("global")
        );
        assert_eq!(
            vhost
                .request_headers
                .set
                .get("x-vhost-request")
                .map(String::as_str),
            Some("api")
        );
        assert_eq!(
            vhost
                .request_headers
                .append
                .get("via")
                .map(|values| values.iter().collect::<Vec<_>>()),
            Some(vec!["global", "api"])
        );
        assert_eq!(
            vhost.response_headers.x_frame_options.as_deref(),
            Some("SAMEORIGIN")
        );
        assert_eq!(
            vhost
                .response_headers
                .set
                .get("cache-control")
                .map(String::as_str),
            Some("public, max-age=60")
        );
        assert_eq!(
            vhost
                .response_headers
                .set
                .get("access-control-allow-origin")
                .map(String::as_str),
            Some("https://app.example")
        );
        assert_eq!(
            vhost
                .response_headers
                .append
                .get("vary")
                .map(|values| values.iter().collect::<Vec<_>>()),
            Some(vec!["Accept-Encoding", "Origin"])
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn builds_image_cache_key_from_routed_vhost_policy() {
        let config = Config {
            vhosts: vec![
                VhostConfig {
                    name: "cached".to_owned(),
                    hosts: vec!["cached.example".to_owned()],
                    max_request_body_bytes: None,
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig {
                        enabled: true,
                        memory: crate::config::CacheMemoryConfig {
                            enabled: true,
                            ..crate::config::CacheMemoryConfig::default()
                        },
                        ..CacheConfig::default()
                    },
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
                VhostConfig {
                    name: "uncached".to_owned(),
                    hosts: vec!["uncached.example".to_owned()],
                    max_request_body_bytes: None,
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
            ],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png?v=1", None).unwrap();
        request.insert_header("host", "cached.example").unwrap();
        let snapshot = proxy.snapshot();

        let key = snapshot
            .image_cache_key_for_request_header(
                &request,
                snapshot.state.vhost_index(Some("cached.example")),
            )
            .unwrap();

        assert_eq!(
            key.as_str(),
            "fluxheim-image-v1;method:3:GET;host:14:cached.example;path:13:/img/logo.png;query:3:v=1;"
        );

        request.insert_header("host", "uncached.example").unwrap();
        assert_eq!(
            snapshot.image_cache_key_for_request_header(
                &request,
                snapshot.state.vhost_index(Some("uncached.example"))
            ),
            None
        );
    }

    #[cfg(all(feature = "cache", feature = "web"))]
    #[test]
    fn cache_key_preview_uses_local_static_key_when_enabled() {
        let root = unique_temp_path("local-static-cache-preview");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("asset.webp"), "local-static").unwrap();

        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    local_static: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(2048),
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig {
                    root: Some(root.clone()),
                    ..WebConfig::default()
                },
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/asset.webp?v=1", None).unwrap();
        request.insert_header("host", "cached.example").unwrap();

        let preview = proxy
            .snapshot()
            .pingora_image_cache_key_preview_for_request_header(&request);

        assert!(preview.eligible);
        assert_eq!(preview.namespace.as_deref(), Some("fluxheim-static-v1"));
        assert_eq!(preview.user_tag.as_deref(), Some("cached"));
        assert!(
            preview
                .primary_key
                .as_deref()
                .is_some_and(|key| key.contains("file:"))
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(feature = "cache", feature = "web"))]
    #[test]
    fn exact_purge_uses_local_static_key_when_enabled() {
        let root = unique_temp_path("local-static-cache-purge");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("asset.webp"), "local-static").unwrap();

        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    local_static: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(2048),
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig {
                    root: Some(root.clone()),
                    ..WebConfig::default()
                },
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost = snapshot
            .state
            .vhost(snapshot.state.vhost_index(Some("cached.example")));

        let key = snapshot
            .state
            .static_cache_key_for_purge_request(
                vhost,
                None,
                &CachePurgeRequest {
                    vhost: None,
                    route: None,
                    host: "cached.example",
                    method: "GET",
                    path: "/asset.webp",
                    query: Some("v=1"),
                },
            )
            .unwrap();

        assert_eq!(key.namespace_str(), Some("fluxheim-static-v1"));
        assert_eq!(key.user_tag, "cached");
        assert!(
            key.primary_key_str()
                .is_some_and(|primary| primary.contains("file:"))
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(feature = "cache")]
    #[test]
    fn route_cache_policy_overrides_disabled_vhost_cache() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: vec![RouteConfig {
                    name: "assets".to_owned(),
                    path_exact: None,
                    path_prefix: Some("/assets/".to_owned()),
                    fallback: false,
                    https_redirect_exempt: false,
                    strip_prefix: None,
                    max_request_body_bytes: None,
                    redirect: None,
                    proxy: Some(ProxyConfig {
                        upstream: Some("127.0.0.1:3000".to_owned()),
                        ..ProxyConfig::default()
                    }),
                    web: None,
                    php: None,
                    cache: Some(CacheConfig {
                        enabled: true,
                        memory: crate::config::CacheMemoryConfig {
                            enabled: true,
                            max_size_bytes: ByteSize::from_bytes(2048),
                        },
                        predictor: crate::config::CachePredictorConfig {
                            enabled: true,
                            ..crate::config::CachePredictorConfig::default()
                        },
                        max_object_bytes: ByteSize::from_bytes(512),
                        ..CacheConfig::default()
                    }),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                }],
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let vhost = snapshot.state.vhost(vhost_index);
        let route_index = vhost.route_index("/assets/logo.png").unwrap();
        let route_cache = vhost.route(route_index).cache.as_ref().unwrap();
        assert!(route_cache.pingora_memory_storage.is_some());
        assert!(route_cache.pingora_cache_lock.is_some());

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/assets/logo.png?v=1", None).unwrap();
        request.insert_header("host", "cached.example").unwrap();
        let key = snapshot
            .state
            .pingora_image_cache_key_for_request_header(&request, vhost_index, Some(route_index))
            .unwrap();

        assert_eq!(key.user_tag, "cached:route:assets");
        assert_eq!(
            key.primary_key_str(),
            Some(
                "fluxheim-image-v1;method:3:GET;host:14:cached.example;path:16:/assets/logo.png;query:3:v=1;"
            )
        );

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png?v=1", None).unwrap();
        request.insert_header("host", "cached.example").unwrap();
        assert!(
            snapshot
                .state
                .pingora_image_cache_key_for_request_header(&request, vhost_index, None)
                .is_none()
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_key_preview_reports_selected_route_key() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: vec![RouteConfig {
                    name: "assets".to_owned(),
                    path_exact: None,
                    path_prefix: Some("/assets/".to_owned()),
                    fallback: false,
                    https_redirect_exempt: false,
                    strip_prefix: None,
                    max_request_body_bytes: None,
                    redirect: None,
                    proxy: Some(ProxyConfig {
                        upstream: Some("127.0.0.1:3000".to_owned()),
                        ..ProxyConfig::default()
                    }),
                    web: None,
                    php: None,
                    cache: Some(CacheConfig {
                        enabled: true,
                        memory: crate::config::CacheMemoryConfig {
                            enabled: true,
                            max_size_bytes: ByteSize::from_bytes(2048),
                        },
                        predictor: crate::config::CachePredictorConfig {
                            enabled: true,
                            ..crate::config::CachePredictorConfig::default()
                        },
                        max_object_bytes: ByteSize::from_bytes(512),
                        ..CacheConfig::default()
                    }),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                }],
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/assets/logo.png?v=1", None).unwrap();
        request.insert_header("host", "cached.example").unwrap();

        let preview = proxy
            .snapshot()
            .pingora_image_cache_key_preview_for_request_header(&request);

        assert!(preview.eligible);
        assert_eq!(preview.vhost, "cached");
        assert_eq!(preview.route.as_deref(), Some("assets"));
        assert_eq!(preview.scope, super::CacheKeyPreviewScope::Route);
        assert!(preview.cache_lock_enabled);
        assert_eq!(preview.cache_lock_wait_timeout_secs, 30);
        assert!(preview.cache_predictor_enabled);
        assert!(preview.memory_tier_enabled);
        assert!(!preview.disk_tier_enabled);
        assert_eq!(preview.storage_tiers, 1);
        assert_eq!(preview.namespace.as_deref(), Some("fluxheim-image-v1"));
        assert_eq!(preview.user_tag.as_deref(), Some("cached:route:assets"));
        assert_eq!(
            preview.primary_key.as_deref(),
            Some(
                "fluxheim-image-v1;method:3:GET;host:14:cached.example;path:16:/assets/logo.png;query:3:v=1;"
            )
        );
        assert!(preview.primary_hash.is_some());
        assert_eq!(preview.combined_hash, preview.primary_hash);
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_key_preview_reports_selected_range_key() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    range: crate::config::CacheRangeConfig {
                        enabled: true,
                        max_bytes: ByteSize::from_bytes(1024),
                        ..crate::config::CacheRangeConfig::default()
                    },
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(2048),
                    },
                    image_extensions: vec!["bin".to_owned()],
                    max_object_bytes: ByteSize::from_bytes(2048),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/assets/video.bin", None).unwrap();
        request.insert_header("host", "cached.example").unwrap();
        request.insert_header("range", "bytes=4-11").unwrap();

        let preview = proxy
            .snapshot()
            .pingora_image_cache_key_preview_for_request_header(&request);

        assert!(preview.eligible);
        assert_eq!(preview.scope, super::CacheKeyPreviewScope::Vhost);
        assert_eq!(preview.user_tag.as_deref(), Some("cached"));
        assert!(
            preview
                .primary_key
                .as_deref()
                .is_some_and(|primary| primary.ends_with("range:10:bytes=4-11;"))
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_key_preview_reports_ineligible_reason() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        ..crate::config::CacheMemoryConfig::default()
                    },
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let mut request =
            pingora::http::RequestHeader::build("POST", b"/assets/logo.png", None).unwrap();
        request.insert_header("host", "cached.example").unwrap();

        let preview = proxy
            .snapshot()
            .pingora_image_cache_key_preview_for_request_header(&request);

        assert!(!preview.eligible);
        assert_eq!(preview.scope, super::CacheKeyPreviewScope::Vhost);
        assert!(preview.cache_lock_enabled);
        assert_eq!(preview.cache_lock_wait_timeout_secs, 30);
        assert!(!preview.cache_predictor_enabled);
        assert!(preview.memory_tier_enabled);
        assert!(!preview.disk_tier_enabled);
        assert_eq!(preview.storage_tiers, 1);
        assert_eq!(
            preview.reason.as_deref(),
            Some("method POST is not allowed by selected cache policy")
        );
        assert_eq!(preview.primary_key, None);

        let mut request =
            pingora::http::RequestHeader::build("HEAD", b"/assets/logo.png", None).unwrap();
        request.insert_header("host", "cached.example").unwrap();

        let preview = proxy
            .snapshot()
            .pingora_image_cache_key_preview_for_request_header(&request);

        assert!(!preview.eligible);
        assert_eq!(
            preview.reason.as_deref(),
            Some("method HEAD currently bypasses proxy cache storage")
        );
        assert_eq!(preview.primary_key, None);
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_object_lookup_reports_memory_metadata() {
        use pingora::cache::Storage;

        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(2048),
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let vhost = snapshot.state.vhost(vhost_index);
        let storage = vhost.pingora_memory_storage.unwrap();
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png?v=1", None).unwrap();
        request.insert_header("host", "cached.example").unwrap();
        let key = snapshot
            .state
            .pingora_image_cache_key_for_request_header(&request, vhost_index, None)
            .unwrap();
        let span = pingora::cache::trace::Span::inactive().handle();
        let mut meta = pingora_meta("max-age=60");
        meta.response_header_mut()
            .insert_header("Surrogate-Key", "asset:logo")
            .unwrap();

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
        block_on(miss.finish()).unwrap();

        let lookup = snapshot
            .pingora_image_cache_object_lookup_for_request_header(&request)
            .unwrap();

        assert!(lookup.preview.eligible);
        assert_eq!(lookup.objects.len(), 1);
        let object = &lookup.objects[0];
        assert_eq!(object.tier, crate::cache::CacheObjectTier::Memory);
        assert!(object.purge_indexed);
        assert_eq!(object.status, 200);
        assert!(object.fresh);
        assert_eq!(
            object.freshness_state,
            crate::cache::CacheObjectFreshnessState::Fresh
        );
        assert!(!object.serve_stale_while_revalidate);
        assert!(!object.serve_stale_if_error);
        assert_eq!(object.body_bytes, 4);
        assert!(object.weight_bytes >= 4);
        assert_eq!(object.cache_tags, vec!["asset:logo"]);
        assert!(
            object
                .header_names
                .iter()
                .any(|name| name == "cache-control")
        );
        assert!(object.created_unix_secs.is_some());
        assert!(object.fresh_until_unix_secs.is_some());
    }

    #[cfg(feature = "cache")]
    #[test]
    fn proxy_cache_only_lookup_respects_vary_variants() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(2048),
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let vhost = snapshot.state.vhost(vhost_index);
        let storage =
            vhost.pingora_memory_storage.unwrap() as &'static (dyn pingora::cache::Storage + Sync);
        let span = pingora::cache::trace::Span::inactive().handle();

        let mut gzip_request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        gzip_request
            .insert_header("host", "cached.example")
            .unwrap();
        gzip_request
            .insert_header("accept-encoding", "gzip")
            .unwrap();
        let gzip_key = snapshot
            .state
            .pingora_image_cache_key_for_request_header(&gzip_request, vhost_index, None)
            .unwrap();
        let gzip_variance = vary_request_hash(&["accept-encoding".to_owned()], &gzip_request);
        let mut gzip_meta = pingora_meta("max-age=60");
        gzip_meta
            .response_header_mut()
            .insert_header("vary", "accept-encoding")
            .unwrap();
        gzip_meta.set_variance(gzip_variance);

        let mut miss = block_on(storage.get_miss_handler(&gzip_key, &gzip_meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"gzip-body"), true)).unwrap();
        block_on(miss.finish()).unwrap();

        let mut br_request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        br_request.insert_header("host", "cached.example").unwrap();
        br_request.insert_header("accept-encoding", "br").unwrap();
        let br_key = snapshot
            .state
            .pingora_image_cache_key_for_request_header(&br_request, vhost_index, None)
            .unwrap();
        assert!(
            block_on(lookup_proxy_cache_only_object(
                storage,
                br_key.clone(),
                &br_request,
                &vhost.cache,
                &span
            ))
            .unwrap()
            .is_none()
        );

        let mut br_store_key = br_key.clone();
        let br_variance = vary_request_hash(&["accept-encoding".to_owned()], &br_request);
        br_store_key.set_variance_key(br_variance);
        let mut br_meta = pingora_meta("max-age=60");
        br_meta
            .response_header_mut()
            .insert_header("vary", "accept-encoding")
            .unwrap();
        br_meta.set_variance(br_variance);
        let mut miss = block_on(storage.get_miss_handler(&br_store_key, &br_meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"br-body"), true)).unwrap();
        block_on(miss.finish()).unwrap();

        let (meta, hit, key) = block_on(lookup_proxy_cache_only_object(
            storage,
            br_key,
            &br_request,
            &vhost.cache,
            &span,
        ))
        .unwrap()
        .unwrap();
        assert_eq!(meta.variance(), Some(br_variance));
        let body = block_on(read_cache_hit_body(hit, storage, &key, &span, 512)).unwrap();
        assert_eq!(body, Bytes::from_static(b"br-body"));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_object_lookup_reports_disk_metadata() {
        use pingora::cache::Storage;

        let cache_path = unique_test_cache_dir("proxy-disk-lookup");
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    disk: crate::config::CacheDiskConfig {
                        enabled: true,
                        path: Some(cache_path.clone()),
                        max_size_bytes: ByteSize::from_bytes(4096),
                        ..crate::config::CacheDiskConfig::default()
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let vhost = snapshot.state.vhost(vhost_index);
        let storage = vhost.pingora_disk_storage.unwrap();
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png?v=1", None).unwrap();
        request.insert_header("host", "cached.example").unwrap();
        let key = snapshot
            .state
            .pingora_image_cache_key_for_request_header(&request, vhost_index, None)
            .unwrap();
        let span = pingora::cache::trace::Span::inactive().handle();
        let mut meta = pingora_meta("max-age=60");
        meta.response_header_mut()
            .insert_header("Surrogate-Key", "asset:logo")
            .unwrap();

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"disk-body"), true)).unwrap();
        block_on(miss.finish()).unwrap();

        let lookup = snapshot
            .pingora_image_cache_object_lookup_for_request_header(&request)
            .unwrap();

        assert!(lookup.preview.eligible);
        assert_eq!(lookup.objects.len(), 1);
        let object = &lookup.objects[0];
        assert_eq!(object.tier, crate::cache::CacheObjectTier::Disk);
        assert!(object.purge_indexed);
        assert_eq!(object.status, 200);
        assert!(object.fresh);
        assert_eq!(
            object.freshness_state,
            crate::cache::CacheObjectFreshnessState::Fresh
        );
        assert!(!object.serve_stale_while_revalidate);
        assert!(!object.serve_stale_if_error);
        assert_eq!(object.body_bytes, 9);
        assert!(object.weight_bytes >= 9);
        assert_eq!(object.cache_tags, vec!["asset:logo"]);
        assert!(
            object
                .header_names
                .iter()
                .any(|name| name == "cache-control")
        );
        assert!(object.created_unix_secs.is_some());
        assert!(object.fresh_until_unix_secs.is_some());

        std::fs::remove_dir_all(cache_path).unwrap();
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_object_lookup_reports_route_disk_metadata() {
        use pingora::cache::Storage;

        let cache_path = unique_test_cache_dir("proxy-route-disk-lookup");
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: vec![RouteConfig {
                    name: "assets".to_owned(),
                    path_exact: None,
                    path_prefix: Some("/assets/".to_owned()),
                    fallback: false,
                    https_redirect_exempt: false,
                    strip_prefix: None,
                    max_request_body_bytes: None,
                    redirect: None,
                    proxy: Some(ProxyConfig {
                        upstream: Some("127.0.0.1:3000".to_owned()),
                        ..ProxyConfig::default()
                    }),
                    web: None,
                    php: None,
                    cache: Some(CacheConfig {
                        enabled: true,
                        disk: crate::config::CacheDiskConfig {
                            enabled: true,
                            path: Some(cache_path.clone()),
                            max_size_bytes: ByteSize::from_bytes(4096),
                            ..crate::config::CacheDiskConfig::default()
                        },
                        max_object_bytes: ByteSize::from_bytes(512),
                        ..CacheConfig::default()
                    }),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                }],
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let vhost = snapshot.state.vhost(vhost_index);
        let route_index = vhost.route_index("/assets/logo.png").unwrap();
        let route = vhost.route(route_index);
        let route_cache = route.cache.as_ref().unwrap();
        let storage = route_cache.pingora_disk_storage.unwrap();
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/assets/logo.png?v=1", None).unwrap();
        request.insert_header("host", "cached.example").unwrap();
        let key = snapshot
            .state
            .pingora_image_cache_key_for_request_header(&request, vhost_index, Some(route_index))
            .unwrap();
        let span = pingora::cache::trace::Span::inactive().handle();
        let mut meta = pingora_meta("max-age=60");
        meta.response_header_mut()
            .insert_header("Surrogate-Key", "asset:route-logo")
            .unwrap();

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"route-disk-body"), true)).unwrap();
        block_on(miss.finish()).unwrap();

        let lookup = snapshot
            .pingora_image_cache_object_lookup_for_request_header(&request)
            .unwrap();

        assert!(lookup.preview.eligible);
        assert_eq!(lookup.preview.route.as_deref(), Some("assets"));
        assert_eq!(lookup.preview.scope, super::CacheKeyPreviewScope::Route);
        assert_eq!(lookup.objects.len(), 1);
        let object = &lookup.objects[0];
        assert_eq!(object.tier, crate::cache::CacheObjectTier::Disk);
        assert!(object.purge_indexed);
        assert_eq!(object.status, 200);
        assert!(object.fresh);
        assert_eq!(object.body_bytes, 15);
        assert_eq!(object.cache_tags, vec!["asset:route-logo"]);

        std::fs::remove_dir_all(cache_path).unwrap();
    }

    #[cfg(feature = "cache")]
    #[test]
    fn builds_memory_cache_from_routed_vhost_policy() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(1024),
                    },
                    max_object_bytes: ByteSize::from_bytes(128),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        request.insert_header("host", "cached.example").unwrap();
        let snapshot = proxy.snapshot();

        let (key, memory_cache) = snapshot
            .image_memory_cache_for_request_header(
                &request,
                snapshot.state.vhost_index(Some("cached.example")),
            )
            .unwrap();

        assert_eq!(
            key.as_str(),
            "fluxheim-image-v1;method:3:GET;host:14:cached.example;path:13:/img/logo.png;query:0:;"
        );
        memory_cache
            .put(
                &key,
                crate::cache::CachedImageObject {
                    status: 200,
                    headers: vec![crate::cache::CachedHeader {
                        name: "content-type".to_owned(),
                        value: b"image/png".to_vec(),
                    }],
                    body: std::sync::Arc::from(&b"png"[..]),
                    fresh_until_unix_secs: 1,
                },
            )
            .unwrap();
        assert!(memory_cache.get(&key).is_some());
    }

    #[cfg(feature = "cache")]
    #[test]
    fn builds_pingora_memory_storage_from_routed_vhost_policy() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(2048),
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        request.insert_header("host", "cached.example").unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));

        let stats = snapshot
            .pingora_memory_storage_stats_for_request_header(&request, vhost_index)
            .unwrap();

        assert_eq!(stats.max_size_bytes, ByteSize::from_bytes(2048));
        assert_eq!(stats.max_object_bytes, ByteSize::from_bytes(512));
        assert!(
            snapshot
                .state
                .vhost(vhost_index)
                .pingora_cache_lock
                .is_some()
        );
        assert_eq!(
            snapshot.state.vhost(vhost_index).cache_lock_wait_timeout,
            std::time::Duration::from_secs(30)
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_lock_policy_can_disable_request_collapsing() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(2048),
                    },
                    lock: crate::config::CacheLockConfig {
                        enabled: false,
                        ..crate::config::CacheLockConfig::default()
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let vhost = snapshot.state.vhost(vhost_index);

        assert!(vhost.pingora_memory_storage.is_some());
        assert!(vhost.pingora_cache_lock.is_none());
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_lock_policy_maps_wait_timeout() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(2048),
                    },
                    lock: crate::config::CacheLockConfig {
                        wait_timeout_secs: 7,
                        ..crate::config::CacheLockConfig::default()
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let vhost = snapshot.state.vhost(vhost_index);

        assert!(vhost.pingora_cache_lock.is_some());
        assert_eq!(
            vhost.cache_lock_wait_timeout,
            std::time::Duration::from_secs(7)
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_predictor_policy_remembers_origin_uncacheable_keys() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(2048),
                    },
                    predictor: crate::config::CachePredictorConfig {
                        enabled: true,
                        capacity: 128,
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let predictor = snapshot
            .state
            .vhost(vhost_index)
            .pingora_cache_predictor
            .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "origin-private", "cached");

        assert!(predictor.cacheable_prediction(&key));
        predictor.mark_uncacheable(&key, pingora::cache::NoCacheReason::OriginNotCache);
        assert!(!predictor.cacheable_prediction(&key));
        predictor.mark_cacheable(&key);
        assert!(predictor.cacheable_prediction(&key));

        let custom_key =
            pingora::cache::CacheKey::new("fluxheim-test", "fluxheim-custom-policy", "cached");
        predictor.mark_uncacheable(
            &custom_key,
            pingora::cache::NoCacheReason::Custom("set-cookie"),
        );
        assert!(predictor.cacheable_prediction(&custom_key));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn builds_pingora_disk_storage_from_routed_vhost_policy() {
        let cache_path = unique_test_cache_dir("proxy-disk");
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    disk: crate::config::CacheDiskConfig {
                        enabled: true,
                        path: Some(cache_path.clone()),
                        max_size_bytes: ByteSize::from_bytes(4096),
                        ..crate::config::CacheDiskConfig::default()
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let vhost = snapshot.state.vhost(vhost_index);

        assert!(vhost.pingora_memory_storage.is_none());
        assert!(vhost.pingora_disk_storage.is_some());
        assert!(vhost.pingora_cache_lock.is_some());
        assert_eq!(vhost.pingora_disk_storage.unwrap().root(), cache_path);

        std::fs::remove_dir_all(cache_path).unwrap();
    }

    #[cfg(feature = "cache")]
    #[test]
    fn builds_pingora_tiered_storage_when_memory_and_disk_are_enabled() {
        let cache_path = unique_test_cache_dir("proxy-tiered");
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(2048),
                    },
                    disk: crate::config::CacheDiskConfig {
                        enabled: true,
                        path: Some(cache_path.clone()),
                        max_size_bytes: ByteSize::from_bytes(4096),
                        ..crate::config::CacheDiskConfig::default()
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let vhost = snapshot.state.vhost(vhost_index);

        assert!(vhost.pingora_memory_storage.is_some());
        assert!(vhost.pingora_disk_storage.is_some());
        assert!(vhost.pingora_tiered_storage.is_some());
        assert!(vhost.pingora_cache_lock.is_some());
        assert_eq!(
            vhost.pingora_tiered_storage.unwrap().disk().root(),
            cache_path
        );

        std::fs::remove_dir_all(cache_path).unwrap();
    }

    #[cfg(feature = "cache")]
    #[test]
    fn purge_image_cache_removes_pingora_memory_entry() {
        use bytes::Bytes;
        use pingora::cache::Storage;

        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(2048),
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let vhost = snapshot.state.vhost(vhost_index);
        let storage = vhost.pingora_memory_storage.unwrap();
        let cache_request = crate::cache::CacheRequest {
            method: "GET",
            host: Some("cached.example"),
            path: "/img/logo.png",
            query: Some("v=1"),
        };
        let key = crate::cache::pingora_image_cache_key(
            "fluxheim-image-v1",
            &vhost.cache,
            &cache_request,
            &vhost.name,
        )
        .unwrap();
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
        block_on(miss.finish()).unwrap();
        assert!(block_on(storage.lookup(&key, &span)).unwrap().is_some());

        let result = proxy
            .purge_image_cache(CachePurgeRequest {
                vhost: Some("cached"),
                route: None,
                host: "cached.example",
                method: "GET",
                path: "/img/logo.png",
                query: Some("v=1"),
            })
            .unwrap();

        assert!(result.memory_purged);
        assert!(result.purged());
        assert_eq!(result.host, "cached.example");
        assert_eq!(result.method, "GET");
        assert_eq!(result.path, "/img/logo.png");
        assert_eq!(result.query.as_deref(), Some("v=1"));
        assert!(block_on(storage.lookup(&key, &span)).unwrap().is_none());
    }

    #[cfg(feature = "cache")]
    #[test]
    fn purge_image_cache_removes_slice_cache_entries_for_same_path() {
        use bytes::Bytes;
        use pingora::cache::Storage;

        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(4096),
                    },
                    range: crate::config::CacheRangeConfig {
                        enabled: true,
                        max_bytes: ByteSize::from_bytes(1024),
                        slice: crate::config::CacheRangeSliceConfig {
                            enabled: true,
                            size_bytes: ByteSize::from_bytes(512),
                            max_slices: 4,
                            fill_missing: true,
                        },
                    },
                    max_object_bytes: ByteSize::from_bytes(1024),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let vhost = snapshot.state.vhost(vhost_index);
        let storage = vhost.pingora_memory_storage.unwrap();
        let cache_request = crate::cache::CacheRequest {
            method: "GET",
            host: Some("cached.example"),
            path: "/media/video.png",
            query: None,
        };
        let base_key = crate::cache::pingora_image_cache_key(
            "fluxheim-image-v1",
            &vhost.cache,
            &cache_request,
            &vhost.name,
        )
        .unwrap();
        let first_slice =
            slice_cache_key(base_key.clone(), CacheRangeRequest { start: 0, end: 511 }).unwrap();
        let second_slice = slice_cache_key(
            base_key,
            CacheRangeRequest {
                start: 512,
                end: 1023,
            },
        )
        .unwrap();
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        for key in [&first_slice, &second_slice] {
            let mut miss = block_on(storage.get_miss_handler(key, &meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::from_static(b"slice"), true)).unwrap();
            block_on(miss.finish()).unwrap();
            assert!(block_on(storage.lookup(key, &span)).unwrap().is_some());
        }

        let result = proxy
            .purge_image_cache(CachePurgeRequest {
                vhost: Some("cached"),
                route: None,
                host: "cached.example",
                method: "GET",
                path: "/media/video.png",
                query: None,
            })
            .unwrap();

        assert!(result.memory_purged);
        assert!(
            block_on(storage.lookup(&first_slice, &span))
                .unwrap()
                .is_none()
        );
        assert!(
            block_on(storage.lookup(&second_slice, &span))
                .unwrap()
                .is_none()
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn purge_image_cache_can_target_route_cache() {
        use bytes::Bytes;
        use pingora::cache::Storage;

        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: vec![RouteConfig {
                    name: "assets".to_owned(),
                    path_exact: None,
                    path_prefix: Some("/assets/".to_owned()),
                    fallback: false,
                    https_redirect_exempt: false,
                    strip_prefix: None,
                    max_request_body_bytes: None,
                    redirect: None,
                    proxy: Some(ProxyConfig {
                        upstream: Some("127.0.0.1:3000".to_owned()),
                        ..ProxyConfig::default()
                    }),
                    web: None,
                    php: None,
                    cache: Some(CacheConfig {
                        enabled: true,
                        memory: crate::config::CacheMemoryConfig {
                            enabled: true,
                            max_size_bytes: ByteSize::from_bytes(2048),
                        },
                        max_object_bytes: ByteSize::from_bytes(512),
                        ..CacheConfig::default()
                    }),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                }],
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let vhost = snapshot.state.vhost(vhost_index);
        let route_cache = vhost.routes[0].cache.as_ref().unwrap();
        let storage = route_cache.pingora_memory_storage.unwrap();
        let cache_request = crate::cache::CacheRequest {
            method: "GET",
            host: Some("cached.example"),
            path: "/assets/logo.png",
            query: None,
        };
        let key = crate::cache::pingora_image_cache_key(
            "fluxheim-image-v1",
            &route_cache.config,
            &cache_request,
            "cached:route:assets",
        )
        .unwrap();
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
        block_on(miss.finish()).unwrap();
        assert!(block_on(storage.lookup(&key, &span)).unwrap().is_some());

        let result = proxy
            .purge_image_cache(CachePurgeRequest {
                vhost: Some("cached"),
                route: Some("assets"),
                host: "cached.example",
                method: "GET",
                path: "/assets/logo.png",
                query: None,
            })
            .unwrap();

        assert_eq!(result.vhost, "cached");
        assert_eq!(result.route.as_deref(), Some("assets"));
        assert!(result.memory_purged);
        assert!(result.purged());
        assert!(block_on(storage.lookup(&key, &span)).unwrap().is_none());
    }

    #[cfg(feature = "cache")]
    #[test]
    fn background_stale_disk_purge_scans_vhost_and_route_caches() {
        use pingora::cache::Storage;

        let vhost_cache_path = unique_test_cache_dir("proxy-background-vhost-disk-purge");
        let route_cache_path = unique_test_cache_dir("proxy-background-route-disk-purge");
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    disk: crate::config::CacheDiskConfig {
                        enabled: true,
                        path: Some(vhost_cache_path.clone()),
                        max_size_bytes: ByteSize::from_bytes(4096),
                        ..crate::config::CacheDiskConfig::default()
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: vec![RouteConfig {
                    name: "assets".to_owned(),
                    path_exact: None,
                    path_prefix: Some("/assets/".to_owned()),
                    fallback: false,
                    https_redirect_exempt: false,
                    strip_prefix: None,
                    max_request_body_bytes: None,
                    redirect: None,
                    proxy: Some(ProxyConfig {
                        upstream: Some("127.0.0.1:3000".to_owned()),
                        ..ProxyConfig::default()
                    }),
                    web: None,
                    php: None,
                    cache: Some(CacheConfig {
                        enabled: true,
                        disk: crate::config::CacheDiskConfig {
                            enabled: true,
                            path: Some(route_cache_path.clone()),
                            max_size_bytes: ByteSize::from_bytes(4096),
                            ..crate::config::CacheDiskConfig::default()
                        },
                        max_object_bytes: ByteSize::from_bytes(512),
                        ..CacheConfig::default()
                    }),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                }],
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let vhost = snapshot.state.vhost(vhost_index);
        let vhost_storage = vhost.pingora_disk_storage.unwrap();
        let route_cache = vhost.routes[0].cache.as_ref().unwrap();
        let route_storage = route_cache.pingora_disk_storage.unwrap();
        let span = pingora::cache::trace::Span::inactive().handle();

        let vhost_stale_key = crate::cache::pingora_image_cache_key(
            "fluxheim-image-v1",
            &vhost.cache,
            &crate::cache::CacheRequest {
                method: "GET",
                host: Some("cached.example"),
                path: "/img/stale.png",
                query: None,
            },
            &vhost.name,
        )
        .unwrap();
        let vhost_fresh_key = crate::cache::pingora_image_cache_key(
            "fluxheim-image-v1",
            &vhost.cache,
            &crate::cache::CacheRequest {
                method: "GET",
                host: Some("cached.example"),
                path: "/img/fresh.png",
                query: None,
            },
            &vhost.name,
        )
        .unwrap();
        let route_stale_key = crate::cache::pingora_image_cache_key(
            "fluxheim-image-v1",
            &route_cache.config,
            &crate::cache::CacheRequest {
                method: "GET",
                host: Some("cached.example"),
                path: "/assets/stale.png",
                query: None,
            },
            "cached:route:assets",
        )
        .unwrap();
        let route_fresh_key = crate::cache::pingora_image_cache_key(
            "fluxheim-image-v1",
            &route_cache.config,
            &crate::cache::CacheRequest {
                method: "GET",
                host: Some("cached.example"),
                path: "/assets/fresh.png",
                query: None,
            },
            "cached:route:assets",
        )
        .unwrap();

        for (storage, key, meta) in [
            (
                vhost_storage,
                &vhost_stale_key,
                stale_pingora_meta("max-age=60"),
            ),
            (vhost_storage, &vhost_fresh_key, pingora_meta("max-age=60")),
            (
                route_storage,
                &route_stale_key,
                stale_pingora_meta("max-age=60"),
            ),
            (route_storage, &route_fresh_key, pingora_meta("max-age=60")),
        ] {
            let mut miss = block_on(storage.get_miss_handler(key, &meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
            block_on(miss.finish()).unwrap();
        }

        let result = proxy.purge_stale_disk_cache_once(8, 1).unwrap();

        assert_eq!(result.targets, 2);
        assert_eq!(result.scanned, 4);
        assert_eq!(result.stale, 2);
        assert_eq!(result.purged, 2);
        assert!(!result.truncated);
        assert!(
            block_on(vhost_storage.lookup(&vhost_stale_key, &span))
                .unwrap()
                .is_none()
        );
        assert!(
            block_on(vhost_storage.lookup(&vhost_fresh_key, &span))
                .unwrap()
                .is_some()
        );
        assert!(
            block_on(route_storage.lookup(&route_stale_key, &span))
                .unwrap()
                .is_none()
        );
        assert!(
            block_on(route_storage.lookup(&route_fresh_key, &span))
                .unwrap()
                .is_some()
        );

        std::fs::remove_dir_all(vhost_cache_path).unwrap();
        std::fs::remove_dir_all(route_cache_path).unwrap();
    }

    #[cfg(feature = "cache")]
    #[test]
    fn background_stale_disk_purge_advances_past_fresh_entries() {
        use pingora::cache::Storage;

        let cache_path = unique_test_cache_dir("proxy-background-disk-purge-advance");
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    disk: crate::config::CacheDiskConfig {
                        enabled: true,
                        path: Some(cache_path.clone()),
                        max_size_bytes: ByteSize::from_bytes(4096),
                        ..crate::config::CacheDiskConfig::default()
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let storage = snapshot
            .state
            .vhost(vhost_index)
            .pingora_disk_storage
            .unwrap();
        let fresh_first =
            pingora::cache::CacheKey::new("fluxheim-test", "background-fresh-first", "cached");
        let fresh_second =
            pingora::cache::CacheKey::new("fluxheim-test", "background-fresh-second", "cached");
        let stale_key =
            pingora::cache::CacheKey::new("fluxheim-test", "background-stale-third", "cached");
        let span = pingora::cache::trace::Span::inactive().handle();
        let fresh = pingora_meta("max-age=60");
        let stale = stale_pingora_meta("max-age=60");

        for (key, meta) in [
            (&fresh_first, &fresh),
            (&fresh_second, &fresh),
            (&stale_key, &stale),
        ] {
            let mut miss = block_on(storage.get_miss_handler(key, meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
            block_on(miss.finish()).unwrap();
        }

        let result = proxy.purge_stale_disk_cache_once(1, 3).unwrap();

        assert_eq!(result.targets, 1);
        assert_eq!(result.scanned, 3);
        assert_eq!(result.stale, 1);
        assert_eq!(result.purged, 1);
        assert!(result.truncated);
        assert!(
            block_on(storage.lookup(&stale_key, &span))
                .unwrap()
                .is_none()
        );
        assert!(
            block_on(storage.lookup(&fresh_first, &span))
                .unwrap()
                .is_some()
        );
        assert!(
            block_on(storage.lookup(&fresh_second, &span))
                .unwrap()
                .is_some()
        );

        std::fs::remove_dir_all(cache_path).unwrap();
    }

    #[cfg(feature = "cache")]
    #[test]
    fn purge_image_cache_bulk_removes_multiple_memory_entries() {
        use bytes::Bytes;
        use pingora::cache::Storage;

        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(2048),
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let vhost = snapshot.state.vhost(vhost_index);
        let storage = vhost.pingora_memory_storage.unwrap();
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");
        let paths = ["/img/one.png", "/img/two.png"];
        let keys = paths
            .iter()
            .map(|path| {
                crate::cache::pingora_image_cache_key(
                    "fluxheim-image-v1",
                    &vhost.cache,
                    &crate::cache::CacheRequest {
                        method: "GET",
                        host: Some("cached.example"),
                        path,
                        query: None,
                    },
                    &vhost.name,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        for key in &keys {
            let mut miss = block_on(storage.get_miss_handler(key, &meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
            block_on(miss.finish()).unwrap();
            assert!(block_on(storage.lookup(key, &span)).unwrap().is_some());
        }

        let result = proxy
            .purge_image_cache_bulk(CacheBulkPurgeRequest {
                vhost: Some("cached"),
                route: None,
                host: "cached.example",
                method: "GET",
                paths: paths.to_vec(),
                query: None,
            })
            .unwrap();

        assert_eq!(result.requested(), 2);
        assert_eq!(result.purged(), 2);
        for key in &keys {
            assert!(block_on(storage.lookup(key, &span)).unwrap().is_none());
        }
    }

    #[cfg(feature = "load-balancer")]
    #[test]
    fn builds_load_balancer_background_services_for_configured_pools() {
        #[cfg(feature = "tls-rustls")]
        crate::tls::install_rustls_crypto_provider();

        let config = Config {
            vhosts: vec![
                VhostConfig {
                    name: "one".to_owned(),
                    hosts: vec!["one.example".to_owned()],
                    max_request_body_bytes: None,
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig {
                        upstreams: vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()],
                        ..ProxyConfig::default()
                    },
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
                VhostConfig {
                    name: "two".to_owned(),
                    hosts: vec!["two.example".to_owned()],
                    max_request_body_bytes: None,
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig {
                        upstreams: vec!["127.0.0.1:3003".to_owned(), "127.0.0.1:3004".to_owned()],
                        ..ProxyConfig::default()
                    },
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
            ],
            ..Config::default()
        };

        let (proxy, services) = FluxProxy::from_config_with_background_services(&config).unwrap();

        assert_eq!(proxy.route_host(Some("one.example")), "one");
        assert_eq!(services.len(), 2);
    }

    #[test]
    fn accepts_requests_within_global_limits() {
        let limits = ServerLimitsConfig {
            max_request_header_bytes: ByteSize::from_bytes(512),
            max_uri_bytes: ByteSize::from_bytes(128),
            max_request_headers: 8,
            max_request_body_bytes: ByteSize::from_bytes(1024),
        };
        let mut request = pingora::http::RequestHeader::build("GET", b"/ok", None).unwrap();
        request.insert_header("host", "example.test").unwrap();

        assert_eq!(request_limit_status(&limits, None, &request), None);
    }

    #[test]
    fn rejects_uri_over_global_limit() {
        let limits = ServerLimitsConfig {
            max_request_header_bytes: ByteSize::from_bytes(512),
            max_uri_bytes: ByteSize::from_bytes(4),
            max_request_headers: 8,
            max_request_body_bytes: ByteSize::from_bytes(1024),
        };
        let request = pingora::http::RequestHeader::build("GET", b"/too-long", None).unwrap();

        assert_eq!(request_limit_status(&limits, None, &request), Some(414));
    }

    #[test]
    fn rejects_header_count_over_global_limit() {
        let limits = ServerLimitsConfig {
            max_request_header_bytes: ByteSize::from_bytes(512),
            max_uri_bytes: ByteSize::from_bytes(128),
            max_request_headers: 1,
            max_request_body_bytes: ByteSize::from_bytes(1024),
        };
        let mut request = pingora::http::RequestHeader::build("GET", b"/ok", None).unwrap();
        request.append_header("x-one", "1").unwrap();
        request.append_header("x-two", "2").unwrap();

        assert_eq!(request_limit_status(&limits, None, &request), Some(431));
    }

    #[test]
    fn rejects_header_bytes_over_global_limit() {
        let limits = ServerLimitsConfig {
            max_request_header_bytes: ByteSize::from_bytes(32),
            max_uri_bytes: ByteSize::from_bytes(128),
            max_request_headers: 8,
            max_request_body_bytes: ByteSize::from_bytes(1024),
        };
        let mut request = pingora::http::RequestHeader::build("GET", b"/ok", None).unwrap();
        request
            .insert_header("x-long-header", "this-value-is-too-large")
            .unwrap();

        assert_eq!(request_limit_status(&limits, None, &request), Some(431));
    }

    #[test]
    fn request_header_byte_estimate_counts_request_line_and_headers() {
        let mut request = pingora::http::RequestHeader::build("GET", b"/ok", None).unwrap();
        request.insert_header("host", "example.test").unwrap();

        assert!(approximate_request_header_bytes(&request) >= "GET /ok HTTP/1.1\r\n".len());
        assert!(approximate_request_header_bytes(&request) >= "host: example.test\r\n".len());
    }

    #[test]
    fn rejects_content_length_over_global_limit() {
        let limits = ServerLimitsConfig {
            max_request_header_bytes: ByteSize::from_bytes(512),
            max_uri_bytes: ByteSize::from_bytes(128),
            max_request_headers: 8,
            max_request_body_bytes: ByteSize::from_bytes(16),
        };
        let mut request = pingora::http::RequestHeader::build("POST", b"/upload", None).unwrap();
        request.insert_header("content-length", "17").unwrap();

        assert_eq!(request_limit_status(&limits, None, &request), Some(413));
    }

    #[test]
    fn route_body_limit_overrides_global_body_limit() {
        let limits = ServerLimitsConfig {
            max_request_header_bytes: ByteSize::from_bytes(512),
            max_uri_bytes: ByteSize::from_bytes(128),
            max_request_headers: 8,
            max_request_body_bytes: ByteSize::from_bytes(1024),
        };
        let mut request = pingora::http::RequestHeader::build("POST", b"/upload", None).unwrap();
        request.insert_header("content-length", "64").unwrap();

        assert_eq!(request_limit_status(&limits, Some(32), &request), Some(413));
        assert_eq!(request_limit_status(&limits, Some(128), &request), None);
    }

    #[test]
    fn rejects_invalid_content_length() {
        let limits = ServerLimitsConfig {
            max_request_header_bytes: ByteSize::from_bytes(512),
            max_uri_bytes: ByteSize::from_bytes(128),
            max_request_headers: 8,
            max_request_body_bytes: ByteSize::from_bytes(16),
        };
        let mut request = pingora::http::RequestHeader::build("POST", b"/upload", None).unwrap();
        request.insert_header("content-length", "invalid").unwrap();

        assert_eq!(request_limit_status(&limits, None, &request), Some(400));
    }

    #[test]
    fn rejects_ambiguous_transfer_encoding_and_content_length() {
        let limits = ServerLimitsConfig {
            max_request_header_bytes: ByteSize::from_bytes(512),
            max_uri_bytes: ByteSize::from_bytes(128),
            max_request_headers: 8,
            max_request_body_bytes: ByteSize::from_bytes(16),
        };
        let mut request = pingora::http::RequestHeader::build("POST", b"/upload", None).unwrap();
        request.insert_header("content-length", "4").unwrap();
        request
            .insert_header("transfer-encoding", "chunked")
            .unwrap();

        assert_eq!(request_limit_status(&limits, None, &request), Some(400));
    }

    #[test]
    fn rejects_chunked_body_without_content_length() {
        let limits = ServerLimitsConfig {
            max_request_header_bytes: ByteSize::from_bytes(512),
            max_uri_bytes: ByteSize::from_bytes(128),
            max_request_headers: 8,
            max_request_body_bytes: ByteSize::from_bytes(16),
        };
        let mut request = pingora::http::RequestHeader::build("POST", b"/upload", None).unwrap();
        request
            .insert_header("transfer-encoding", "chunked")
            .unwrap();

        assert_eq!(request_limit_status(&limits, None, &request), Some(411));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn request_cache_bypass_honors_client_no_store_header() {
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        request.insert_header("cache-control", "no-store").unwrap();

        assert!(request_cache_bypass(&request, &CacheConfig::default()));
        assert_eq!(
            request_cache_bypass_reason(&request, &CacheConfig::default()),
            Some("request-no-store")
        );
        assert!(!request_cache_revalidation_requested(
            &request,
            &CacheConfig::default()
        ));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn request_cache_refresh_headers_are_ignored_by_default() {
        for (name, value) in [
            ("cache-control", "no-cache"),
            ("cache-control", "max-age = 0"),
            ("cache-control", "public, max-age=0"),
            ("pragma", "no-cache"),
        ] {
            let mut request =
                pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
            request.insert_header(name, value).unwrap();

            assert!(
                !request_cache_bypass(&request, &CacheConfig::default()),
                "{name}: {value}"
            );
            assert_eq!(
                request_cache_bypass_reason(&request, &CacheConfig::default()),
                None,
                "{name}: {value}"
            );
            assert!(
                !request_cache_revalidation_requested(&request, &CacheConfig::default()),
                "{name}: {value}"
            );
        }
    }

    #[cfg(feature = "cache")]
    #[test]
    fn request_cache_refresh_headers_force_revalidation_when_enabled() {
        let cache = CacheConfig {
            allow_client_cache_refresh: true,
            ..CacheConfig::default()
        };
        for (name, value) in [
            ("cache-control", "no-cache"),
            ("cache-control", "max-age = 0"),
            ("cache-control", "public, max-age=0"),
            ("pragma", "no-cache"),
        ] {
            let mut request =
                pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
            request.insert_header(name, value).unwrap();

            assert!(!request_cache_bypass(&request, &cache), "{name}: {value}");
            assert_eq!(
                request_cache_bypass_reason(&request, &cache),
                None,
                "{name}: {value}"
            );
            assert!(
                request_cache_revalidation_requested(&request, &cache),
                "{name}: {value}"
            );
        }

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        request
            .insert_header("cache-control", "public, max-age=60")
            .unwrap();

        assert!(!request_cache_bypass(&request, &CacheConfig::default()));
        assert_eq!(
            request_cache_bypass_reason(&request, &CacheConfig::default()),
            None
        );
        assert!(!request_cache_revalidation_requested(&request, &cache));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn request_cache_bypass_checks_repeated_headers() {
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        request
            .append_header("cache-control", "public, max-age=60")
            .unwrap();
        request.append_header("cache-control", "no-cache").unwrap();

        assert!(!request_cache_bypass(&request, &CacheConfig::default()));
        assert!(!request_cache_revalidation_requested(
            &request,
            &CacheConfig::default()
        ));

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        request.append_header("pragma", "ignored").unwrap();
        request.append_header("pragma", "no-cache").unwrap();

        assert!(!request_cache_bypass(&request, &CacheConfig::default()));
        assert!(!request_cache_revalidation_requested(
            &request,
            &CacheConfig::default()
        ));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn request_cache_only_if_cached_detects_cache_control_directive() {
        for value in [
            "only-if-cached",
            "public, only-if-cached",
            "max-age=60, Only-If-Cached",
            "only-if-cached=true",
        ] {
            let mut request =
                pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
            request.insert_header("cache-control", value).unwrap();
            assert!(request_cache_only_if_cached(&request), "{value}");
        }

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        request
            .append_header("cache-control", "public, max-age=60")
            .unwrap();
        request
            .append_header("cache-control", "only-if-cached")
            .unwrap();
        assert!(request_cache_only_if_cached(&request));

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        request
            .insert_header("cache-control", "public, max-age=60")
            .unwrap();
        assert!(!request_cache_only_if_cached(&request));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn peer_fill_store_metadata_records_response_vary_variance() {
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.webp", None).unwrap();
        request.insert_header("accept-language", "de").unwrap();
        let fields = vec!["accept-language".to_owned()];
        let expected = vary_request_hash(&fields, &request);

        let mut response = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
        response
            .insert_header("cache-control", "public, max-age=120")
            .unwrap();
        response
            .insert_header("content-type", "image/webp")
            .unwrap();
        response.insert_header("vary", "Accept-Language").unwrap();
        let meta = pingora::cache::CacheMeta::new(
            std::time::SystemTime::now(),
            std::time::SystemTime::now(),
            0,
            0,
            response,
        );

        assert_eq!(
            response_vary_variance(&meta, &request, &CacheConfig::default()),
            Some(expected)
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn peer_fill_ttl_accounting_subtracts_response_age() {
        assert_eq!(remaining_fresh_ttl_secs(120, 0), Some(120));
        assert_eq!(remaining_fresh_ttl_secs(120, 119), Some(1));
        assert_eq!(remaining_fresh_ttl_secs(120, 120), None);
        assert_eq!(remaining_fresh_ttl_secs(120, 121), None);

        let mut response = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
        response.insert_header("age", "42").unwrap();
        assert_eq!(response_age_secs(&response), 42);

        let mut invalid = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
        invalid.insert_header("age", "not-a-number").unwrap();
        assert_eq!(response_age_secs(&invalid), 0);
    }

    #[cfg(feature = "cache")]
    #[test]
    fn peer_fill_concurrency_permit_respects_policy_limit() {
        let key = peer_fill_concurrency_key("concurrency.test", Some(7));
        let first =
            acquire_peer_fill_concurrency_permit(key.clone(), 1).expect("first permit available");

        assert!(acquire_peer_fill_concurrency_permit(key.clone(), 1).is_none());

        drop(first);

        let second =
            acquire_peer_fill_concurrency_permit(key.clone(), 1).expect("permit released on drop");
        drop(second);

        let route_key = peer_fill_concurrency_key("concurrency.test", Some(8));
        let route_permit = acquire_peer_fill_concurrency_permit(route_key, 1)
            .expect("different route has separate concurrency budget");
        drop(route_permit);
    }

    #[cfg(feature = "cache")]
    #[test]
    fn peer_fill_concurrency_prunes_inactive_counters_at_capacity() {
        let mut counters = std::collections::HashMap::new();
        counters.insert(
            "active".to_owned(),
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1)),
        );
        counters.insert(
            "inactive".to_owned(),
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        );

        prune_inactive_peer_fill_concurrency_counters(&mut counters, 2);

        assert!(counters.contains_key("active"));
        assert!(!counters.contains_key("inactive"));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn peer_fill_request_keeps_only_safe_negotiation_headers() {
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.webp?v=1", None).unwrap();
        request.insert_header("host", "site.example").unwrap();
        request.insert_header("accept", "image/webp").unwrap();
        request.insert_header("accept-encoding", "br").unwrap();
        request.insert_header("accept-language", "en").unwrap();
        request
            .insert_header("authorization", "Bearer secret")
            .unwrap();
        request.insert_header("cookie", "session=private").unwrap();

        let peer_request = peer_fill_request_from_header(&request);

        assert_eq!(peer_request.uri_path_and_query, "/img/logo.webp?v=1");
        assert_eq!(peer_request.host.as_deref(), Some("site.example"));
        assert_eq!(
            peer_request.headers,
            vec![
                ("accept", "image/webp".to_owned()),
                ("accept-encoding", "br".to_owned()),
                ("accept-language", "en".to_owned()),
            ]
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn peer_fill_url_requires_absolute_request_path() {
        assert_eq!(
            peer_fill_url("https://edge.example:8443/", "/img/logo.webp?v=1")
                .unwrap()
                .as_str(),
            "https://edge.example:8443/img/logo.webp?v=1"
        );
        assert!(peer_fill_url("https://edge.example:8443", "relative").is_err());
        assert!(peer_fill_url("https://edge.example:8443", "/../admin").is_err());
        assert!(peer_fill_url("https://edge.example:8443", "/%2e%2e/admin").is_err());
        assert!(peer_fill_url("https://edge.example:8443", "/safe%2f..%2fadmin").is_err());
    }

    #[cfg(feature = "cache")]
    #[test]
    fn peer_fill_response_header_strips_hop_by_hop_headers() {
        let response = PeerFillResponse {
            status: 200,
            headers: vec![
                ("content-type".to_owned(), "image/webp".to_owned()),
                ("connection".to_owned(), "close".to_owned()),
                ("transfer-encoding".to_owned(), "chunked".to_owned()),
            ],
            body: Bytes::from_static(b"body"),
        };

        let header = response.to_response_header().unwrap();
        assert_eq!(header.status.as_u16(), 200);
        assert_eq!(
            header
                .headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("image/webp")
        );
        assert_eq!(
            header
                .headers
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            Some("4")
        );
        assert!(!header.headers.contains_key("connection"));
        assert!(!header.headers.contains_key("transfer-encoding"));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn request_cache_bypass_honors_configured_request_headers() {
        let cache = CacheConfig {
            bypass_request_headers: vec!["cookie".to_owned(), "authorization".to_owned()],
            ..CacheConfig::default()
        };

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js", None).unwrap();
        assert!(!request_cache_bypass(&request, &cache));

        request.insert_header("cookie", "session=private").unwrap();
        assert!(request_cache_bypass(&request, &cache));
        assert_eq!(
            request_cache_bypass_reason(&request, &cache),
            Some("request-header")
        );

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js", None).unwrap();
        request
            .insert_header("authorization", "Bearer secret")
            .unwrap();
        assert!(request_cache_bypass(&request, &cache));
        assert_eq!(
            request_cache_bypass_reason(&request, &cache),
            Some("request-header")
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn request_cache_bypass_honors_configured_request_header_values() {
        let cache = CacheConfig {
            bypass_request_header_values: [("x-preview-mode".to_owned(), "1".to_owned())].into(),
            ..CacheConfig::default()
        };

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js", None).unwrap();
        assert!(!request_cache_bypass(&request, &cache));

        request.insert_header("x-preview-mode", "0").unwrap();
        assert!(!request_cache_bypass(&request, &cache));

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js", None).unwrap();
        request.append_header("x-preview-mode", "0").unwrap();
        request.append_header("x-preview-mode", "1").unwrap();
        assert!(request_cache_bypass(&request, &cache));
        assert_eq!(
            request_cache_bypass_reason(&request, &cache),
            Some("request-header-value")
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn request_cache_bypass_honors_configured_cookie_names() {
        let cache = CacheConfig {
            bypass_cookie_names: vec!["sessionid".to_owned(), "wordpress_logged_in".to_owned()],
            ..CacheConfig::default()
        };

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js", None).unwrap();
        assert!(!request_cache_bypass(&request, &cache));

        request
            .insert_header("cookie", "theme=dark; sessionid=abc")
            .unwrap();
        assert!(request_cache_bypass(&request, &cache));
        assert_eq!(
            request_cache_bypass_reason(&request, &cache),
            Some("request-cookie")
        );

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js", None).unwrap();
        request.insert_header("cookie", "session=abc").unwrap();
        assert!(!request_cache_bypass(&request, &cache));

        request
            .append_header("cookie", "wordpress_logged_in=1")
            .unwrap();
        assert!(request_cache_bypass(&request, &cache));
        assert_eq!(
            request_cache_bypass_reason(&request, &cache),
            Some("request-cookie")
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn request_cache_bypass_honors_configured_cookie_values() {
        let cache = CacheConfig {
            bypass_cookie_values: [("preview".to_owned(), "1".to_owned())].into(),
            ..CacheConfig::default()
        };

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js", None).unwrap();
        assert!(!request_cache_bypass(&request, &cache));

        request.insert_header("cookie", "preview=0").unwrap();
        assert!(!request_cache_bypass(&request, &cache));

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js", None).unwrap();
        request
            .insert_header("cookie", "theme=dark; preview=1")
            .unwrap();
        assert!(request_cache_bypass(&request, &cache));
        assert_eq!(
            request_cache_bypass_reason(&request, &cache),
            Some("request-cookie")
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn request_cache_bypass_honors_configured_query_params() {
        let cache = CacheConfig {
            bypass_query_params: vec!["preview".to_owned(), "token".to_owned()],
            ..CacheConfig::default()
        };

        let request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js?v=1", None).unwrap();
        assert!(!request_cache_bypass(&request, &cache));

        let request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js?v=1&preview=true", None)
                .unwrap();
        assert!(request_cache_bypass(&request, &cache));
        assert_eq!(
            request_cache_bypass_reason(&request, &cache),
            Some("request-query")
        );

        let request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js?token", None).unwrap();
        assert!(request_cache_bypass(&request, &cache));
        assert_eq!(
            request_cache_bypass_reason(&request, &cache),
            Some("request-query")
        );

        let request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js?previewed=true", None)
                .unwrap();
        assert!(!request_cache_bypass(&request, &cache));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn request_cache_bypass_honors_configured_query_values() {
        let cache = CacheConfig {
            bypass_query_values: [("mode".to_owned(), "private".to_owned())].into(),
            ..CacheConfig::default()
        };

        let request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js?mode=public", None)
                .unwrap();
        assert!(!request_cache_bypass(&request, &cache));

        let request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js?v=1&mode=private", None)
                .unwrap();
        assert!(request_cache_bypass(&request, &cache));
        assert_eq!(
            request_cache_bypass_reason(&request, &cache),
            Some("request-query")
        );

        let request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js?moder=private", None)
                .unwrap();
        assert!(!request_cache_bypass(&request, &cache));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_status_header_values_are_common_debug_tokens() {
        use pingora::cache::{CachePhase, NoCacheReason};

        assert_eq!(
            cache_status_header_value(CachePhase::Disabled(NoCacheReason::NeverEnabled), None),
            None
        );
        assert_eq!(cache_status_header_value(CachePhase::Uninit, None), None);
        assert_eq!(cache_status_header_value(CachePhase::CacheKey, None), None);
        assert_eq!(
            cache_status_header_value(CachePhase::Bypass, None),
            Some("BYPASS")
        );
        assert_eq!(
            cache_status_header_value(CachePhase::Hit, None),
            Some("HIT")
        );
        assert_eq!(
            cache_status_header_value(CachePhase::Miss, None),
            Some("MISS")
        );
        assert_eq!(
            cache_status_header_value(CachePhase::Stale, None),
            Some("STALE")
        );
        assert_eq!(
            cache_status_header_value(CachePhase::StaleUpdating, None),
            Some("STALE-UPDATING")
        );
        assert_eq!(
            cache_status_header_value(CachePhase::Expired, None),
            Some("EXPIRED")
        );
        assert_eq!(
            cache_status_header_value(CachePhase::Revalidated, None),
            Some("REVALIDATED")
        );
        assert_eq!(
            cache_status_header_value(
                CachePhase::RevalidatedNoCache(NoCacheReason::OriginNotCache),
                None
            ),
            Some("REVALIDATED-NOCACHE")
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_status_reason_header_values_explain_uncacheable_phases() {
        use pingora::cache::{CachePhase, NoCacheReason};

        assert_eq!(
            cache_status_reason_header_value(
                CachePhase::Disabled(NoCacheReason::NeverEnabled),
                None
            ),
            None
        );
        assert_eq!(
            cache_status_reason_header_value(CachePhase::Bypass, None),
            None
        );
        assert_eq!(
            cache_status_reason_header_value(
                CachePhase::Disabled(NoCacheReason::OriginNotCache),
                None
            ),
            Some("OriginNotCache")
        );
        assert_eq!(
            cache_status_reason_header_value(
                CachePhase::Disabled(NoCacheReason::Custom("cache-min-uses")),
                None
            ),
            Some("cache-min-uses")
        );
        assert_eq!(
            cache_status_reason_header_value(
                CachePhase::RevalidatedNoCache(NoCacheReason::ResponseTooLarge),
                None
            ),
            Some("ResponseTooLarge")
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_status_override_reports_policy_bypass_reason() {
        use pingora::cache::CachePhase;

        let override_status = Some(CacheStatusOverride {
            status: "BYPASS",
            reason: Some(CACHE_PASS_REASON),
        });

        assert_eq!(
            cache_status_header_value(CachePhase::Uninit, override_status),
            Some("BYPASS")
        );
        assert_eq!(
            cache_status_reason_header_value(CachePhase::Uninit, override_status),
            Some("cache-pass")
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn revalidation_304_headers_preserve_last_modified_and_detect_vary_changes() {
        let mut merged = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
        merged
            .insert_header("last-modified", "Sun, 10 May 2026 00:00:00 GMT")
            .unwrap();
        merged.insert_header("vary", "Accept-Encoding").unwrap();

        let mut not_modified = pingora::http::ResponseHeader::build(304, Some(1)).unwrap();
        not_modified
            .insert_header("last-modified", "Mon, 11 May 2026 00:00:00 GMT")
            .unwrap();
        not_modified
            .insert_header("vary", "Accept-Encoding")
            .unwrap();

        let captured = capture_revalidation_304_headers(&not_modified).unwrap();
        assert!(!revalidation_304_vary_changed(&merged, &captured));

        let adjusted = response_with_revalidation_304_headers(&merged, &captured).unwrap();
        assert_eq!(
            adjusted
                .headers
                .get("last-modified")
                .and_then(|value| value.to_str().ok()),
            Some("Mon, 11 May 2026 00:00:00 GMT")
        );

        let mut changed_vary = pingora::http::ResponseHeader::build(304, Some(1)).unwrap();
        changed_vary
            .insert_header("vary", "Accept-Language")
            .unwrap();
        let captured = capture_revalidation_304_headers(&changed_vary).unwrap();
        assert!(revalidation_304_vary_changed(&merged, &captured));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_min_uses_delays_store_until_threshold() {
        let counter = moka::sync::Cache::builder().max_capacity(16).build();
        let cache = CacheConfig {
            min_uses: 3,
            ..CacheConfig::default()
        };

        assert!(!cache_min_uses_allows_store(&counter, &cache, "key"));
        assert!(!cache_min_uses_allows_store(&counter, &cache, "key"));
        assert!(cache_min_uses_allows_store(&counter, &cache, "key"));
        assert!(!cache_min_uses_allows_store(&counter, &cache, "key"));

        let default_cache = CacheConfig::default();
        assert!(cache_min_uses_allows_store(
            &counter,
            &default_cache,
            "other-key"
        ));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_pass_bypasses_repeated_uncacheable_keys() {
        let counter = moka::sync::Cache::builder().max_capacity(16).build();
        let cache = CacheConfig {
            pass_uncacheable_after: 2,
            ..CacheConfig::default()
        };

        assert!(!cache_pass_should_bypass(&counter, &cache, "key"));
        cache_pass_record_uncacheable(&counter, &cache, "key");
        assert!(!cache_pass_should_bypass(&counter, &cache, "key"));
        cache_pass_record_uncacheable(&counter, &cache, "key");
        assert!(cache_pass_should_bypass(&counter, &cache, "key"));
        cache_pass_record_uncacheable(&counter, &cache, "key");
        assert_eq!(counter.get("key"), Some(2));

        cache_pass_record_cacheable(&counter, "key");
        assert!(!cache_pass_should_bypass(&counter, &cache, "key"));

        let disabled = CacheConfig::default();
        cache_pass_record_uncacheable(&counter, &disabled, "disabled-key");
        assert!(!cache_pass_should_bypass(
            &counter,
            &disabled,
            "disabled-key"
        ));
        assert_eq!(counter.get("disabled-key"), None);
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_stale_error_policy_requires_stale_if_error_window() {
        let default_cache = CacheConfig::default();
        assert!(!cache_should_serve_stale(
            &default_cache,
            CacheStaleEvent::UpstreamError(crate::config::CacheStaleErrorKind::Connect)
        ));

        let cache = CacheConfig {
            stale_if_error_secs: Some(120),
            ..CacheConfig::default()
        };
        assert!(cache_should_serve_stale(
            &cache,
            CacheStaleEvent::UpstreamError(crate::config::CacheStaleErrorKind::Connect)
        ));
        assert!(!cache_should_serve_stale(
            &cache,
            CacheStaleEvent::OtherError
        ));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_stale_error_policy_filters_upstream_error_kinds() {
        let cache = CacheConfig {
            stale_if_error_secs: Some(120),
            stale_if_error_on: vec![crate::config::CacheStaleErrorKind::Timeout],
            ..CacheConfig::default()
        };

        assert!(cache_should_serve_stale(
            &cache,
            CacheStaleEvent::UpstreamError(crate::config::CacheStaleErrorKind::Timeout)
        ));
        assert!(!cache_should_serve_stale(
            &cache,
            CacheStaleEvent::UpstreamError(crate::config::CacheStaleErrorKind::Connect)
        ));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_stale_error_policy_filters_http_statuses() {
        let default_cache = CacheConfig {
            stale_if_error_secs: Some(120),
            ..CacheConfig::default()
        };
        assert!(cache_should_serve_stale(
            &default_cache,
            CacheStaleEvent::UpstreamHttpStatus(500)
        ));
        assert!(cache_should_serve_stale(
            &default_cache,
            CacheStaleEvent::UpstreamHttpStatus(599)
        ));
        assert!(!cache_should_serve_stale(
            &default_cache,
            CacheStaleEvent::UpstreamHttpStatus(404)
        ));

        let narrowed_cache = CacheConfig {
            stale_if_error_secs: Some(120),
            stale_if_error_statuses: vec![502, 503],
            ..CacheConfig::default()
        };
        assert!(cache_stale_status_allows(&narrowed_cache, 502));
        assert!(!cache_stale_status_allows(&narrowed_cache, 500));
        assert!(cache_should_serve_stale(
            &narrowed_cache,
            CacheStaleEvent::UpstreamHttpStatus(503)
        ));
        assert!(!cache_should_serve_stale(
            &narrowed_cache,
            CacheStaleEvent::UpstreamHttpStatus(500)
        ));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_stale_updating_policy_requires_stale_while_revalidate_window() {
        let default_cache = CacheConfig::default();
        assert!(!cache_should_serve_stale(
            &default_cache,
            CacheStaleEvent::Updating
        ));

        let cache = CacheConfig {
            stale_while_revalidate_secs: Some(30),
            ..CacheConfig::default()
        };
        assert!(cache_should_serve_stale(&cache, CacheStaleEvent::Updating));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_policy_can_strip_origin_response_headers_before_admission() {
        use pingora::cache::CachePhase;

        let cache = CacheConfig {
            hide_response_headers: vec!["set-cookie".to_owned(), "x-internal".to_owned()],
            ..CacheConfig::default()
        };
        let mut response = pingora::http::ResponseHeader::build(200, Some(3)).unwrap();
        response.insert_header("content-type", "image/png").unwrap();
        response
            .insert_header("set-cookie", "session=abc; HttpOnly; Secure")
            .unwrap();
        response.insert_header("x-internal", "origin").unwrap();

        assert_eq!(
            response_cache_admission_rejection(&response, &cache),
            Some("set-cookie")
        );

        strip_cache_response_headers(&mut response, &cache, CachePhase::Miss);

        assert!(!response.headers.contains_key("set-cookie"));
        assert!(!response.headers.contains_key("x-internal"));
        assert_eq!(response_cache_admission_rejection(&response, &cache), None);
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_policy_does_not_strip_non_participating_responses() {
        use pingora::cache::{CachePhase, NoCacheReason};

        let cache = CacheConfig {
            hide_response_headers: vec!["set-cookie".to_owned()],
            ..CacheConfig::default()
        };
        let mut response = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
        response.insert_header("set-cookie", "session=abc").unwrap();

        strip_cache_response_headers(
            &mut response,
            &cache,
            CachePhase::Disabled(NoCacheReason::NeverEnabled),
        );

        assert!(response.headers.contains_key("set-cookie"));
        assert!(!cache_request_participated(CachePhase::Bypass));
        assert!(cache_request_participated(CachePhase::Miss));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_policy_can_ignore_origin_cache_headers_before_admission() {
        use pingora::cache::CachePhase;

        let cache = CacheConfig {
            ignore_origin_cache_headers: true,
            ..CacheConfig::default()
        };
        let mut response = pingora::http::ResponseHeader::build(200, Some(3)).unwrap();
        response.insert_header("content-type", "text/css").unwrap();
        response
            .insert_header("cache-control", "private, no-store")
            .unwrap();
        response
            .insert_header("expires", "Wed, 21 Oct 2015 07:28:00 GMT")
            .unwrap();

        assert_eq!(
            response_cache_admission_rejection(&response, &cache),
            Some("cache-control-private")
        );

        ignore_origin_cache_headers(&mut response, &cache, CachePhase::Miss);

        assert!(!response.headers.contains_key("cache-control"));
        assert!(!response.headers.contains_key("expires"));
        assert_eq!(response_cache_admission_rejection(&response, &cache), None);
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_policy_does_not_ignore_origin_cache_headers_for_non_participating_responses() {
        use pingora::cache::{CachePhase, NoCacheReason};

        let cache = CacheConfig {
            ignore_origin_cache_headers: true,
            ..CacheConfig::default()
        };
        let mut response = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
        response.insert_header("cache-control", "private").unwrap();
        response
            .insert_header("expires", "Wed, 21 Oct 2015 07:28:00 GMT")
            .unwrap();

        ignore_origin_cache_headers(
            &mut response,
            &cache,
            CachePhase::Disabled(NoCacheReason::NeverEnabled),
        );

        assert!(response.headers.contains_key("cache-control"));
        assert!(response.headers.contains_key("expires"));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_policy_applies_status_ttl_before_admission() {
        use std::collections::BTreeMap;

        use pingora::cache::CachePhase;

        let cache = CacheConfig {
            status_ttls: BTreeMap::from([(200, 3600), (404, 60)]),
            stale_while_revalidate_secs: Some(30),
            stale_if_error_secs: Some(120),
            ..CacheConfig::default()
        };
        let mut response = pingora::http::ResponseHeader::build(200, Some(3)).unwrap();
        response.insert_header("content-type", "image/png").unwrap();
        response
            .insert_header("expires", "Wed, 21 Oct 2015 07:28:00 GMT")
            .unwrap();
        response
            .insert_header("cache-control", "private, no-store")
            .unwrap();

        assert_eq!(
            response_cache_admission_rejection(&response, &cache),
            Some("cache-control-private")
        );

        apply_cache_status_ttl(&mut response, &cache, CachePhase::Miss).unwrap();

        assert!(!response.headers.contains_key("expires"));
        assert_eq!(
            response.headers.get("cache-control").unwrap().to_str().ok(),
            Some("public, max-age=3600, stale-while-revalidate=30, stale-if-error=120")
        );
        assert_eq!(response_cache_admission_rejection(&response, &cache), None);
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_policy_applies_default_status_ttl_fallback() {
        use pingora::cache::CachePhase;

        let cache = CacheConfig {
            default_status_ttl_secs: Some(15),
            stale_if_error_secs: Some(60),
            ..CacheConfig::default()
        };
        let mut response = pingora::http::ResponseHeader::build(418, Some(1)).unwrap();
        response
            .insert_header("cache-control", "private, no-store")
            .unwrap();

        assert_eq!(
            response_cache_admission_rejection(&response, &cache),
            Some("cache-control-private")
        );
        apply_cache_status_ttl(&mut response, &cache, CachePhase::Miss).unwrap();
        assert_eq!(
            response.headers.get("cache-control").unwrap().to_str().ok(),
            Some("public, max-age=15, stale-if-error=60")
        );
        assert_eq!(response_cache_admission_rejection(&response, &cache), None);
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_policy_adds_stale_directives_without_status_ttl() {
        use pingora::cache::CachePhase;

        let cache = CacheConfig {
            stale_while_revalidate_secs: Some(15),
            stale_if_error_secs: Some(45),
            ..CacheConfig::default()
        };
        let mut response = pingora::http::ResponseHeader::build(200, Some(3)).unwrap();
        response.insert_header("content-type", "image/png").unwrap();
        response
            .append_header("cache-control", "public, max-age=60")
            .unwrap();
        response
            .append_header("cache-control", "stale-if-error=10")
            .unwrap();
        response
            .append_header("cache-control", "stale-while-revalidate=5")
            .unwrap();

        apply_cache_status_ttl(&mut response, &cache, CachePhase::Miss).unwrap();

        assert_eq!(
            response.headers.get("cache-control").unwrap().to_str().ok(),
            Some("public, max-age=60, stale-while-revalidate=15, stale-if-error=45")
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_policy_does_not_add_stale_directives_to_rejected_origin_response() {
        use pingora::cache::CachePhase;

        let cache = CacheConfig {
            stale_while_revalidate_secs: Some(15),
            stale_if_error_secs: Some(45),
            ..CacheConfig::default()
        };
        let mut response = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
        response.insert_header("content-type", "image/png").unwrap();
        response.insert_header("cache-control", "private").unwrap();

        apply_cache_status_ttl(&mut response, &cache, CachePhase::Miss).unwrap();

        assert_eq!(
            response.headers.get("cache-control").unwrap().to_str().ok(),
            Some("private")
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_policy_does_not_apply_status_ttl_to_non_participating_responses() {
        use std::collections::BTreeMap;

        use pingora::cache::{CachePhase, NoCacheReason};

        let cache = CacheConfig {
            status_ttls: BTreeMap::from([(200, 3600)]),
            ..CacheConfig::default()
        };
        let mut response = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
        response.insert_header("cache-control", "private").unwrap();

        apply_cache_status_ttl(
            &mut response,
            &cache,
            CachePhase::Disabled(NoCacheReason::NeverEnabled),
        )
        .unwrap();

        assert_eq!(
            response.headers.get("cache-control").unwrap().to_str().ok(),
            Some("private")
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn vary_cache_policy_rejects_unsafe_vary_headers() {
        let mut response = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
        assert_eq!(vary_cache_policy(&response.headers), VaryCachePolicy::None);

        response.insert_header("vary", "*").unwrap();
        assert_eq!(
            vary_cache_policy(&response.headers),
            VaryCachePolicy::Uncacheable("vary-star")
        );

        let mut response = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
        response.insert_header("vary", "accept-encoding,").unwrap();
        assert_eq!(
            vary_cache_policy(&response.headers),
            VaryCachePolicy::Uncacheable("vary-invalid")
        );

        let mut response = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
        response.insert_header("vary", "x-one").unwrap();
        for index in 0..MAX_VARY_FIELDS {
            response
                .append_header("vary", format!("x-extra-{index}"))
                .unwrap();
        }
        assert_eq!(
            vary_cache_policy(&response.headers),
            VaryCachePolicy::Uncacheable("vary-too-many-fields")
        );

        let mut response = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
        response.insert_header("vary", "cookie").unwrap();
        assert_eq!(
            vary_cache_policy(&response.headers),
            VaryCachePolicy::Uncacheable("vary-sensitive-field")
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn response_cache_admission_rejects_set_cookie() {
        let mut response = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
        response
            .insert_header("cache-control", "public, max-age=60")
            .unwrap();
        response.insert_header("content-type", "image/png").unwrap();
        assert_eq!(
            response_cache_admission_rejection(&response, &CacheConfig::default()),
            None
        );

        response
            .insert_header("set-cookie", "session=abc; HttpOnly; Secure")
            .unwrap();
        assert_eq!(
            response_cache_admission_rejection(&response, &CacheConfig::default()),
            Some("set-cookie")
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn response_cache_admission_rejects_configured_no_store_response_header() {
        let cache = CacheConfig {
            no_store_response_headers: vec!["x-app-no-store".to_owned()],
            ..CacheConfig::default()
        };
        let mut response = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
        response
            .insert_header("cache-control", "public, max-age=60")
            .unwrap();
        response.insert_header("content-type", "image/png").unwrap();
        assert_eq!(response_cache_admission_rejection(&response, &cache), None);

        response.insert_header("x-app-no-store", "1").unwrap();
        assert_eq!(
            response_cache_admission_rejection(&response, &cache),
            Some("configured-no-store-response-header")
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn response_cache_admission_rejects_configured_no_store_response_header_value() {
        let cache = CacheConfig {
            no_store_response_header_values: [("x-app-cache".to_owned(), "private".to_owned())]
                .into(),
            ..CacheConfig::default()
        };
        let mut response = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
        response
            .insert_header("cache-control", "public, max-age=60")
            .unwrap();
        response.insert_header("content-type", "image/png").unwrap();
        response.insert_header("x-app-cache", "public").unwrap();
        assert_eq!(response_cache_admission_rejection(&response, &cache), None);

        let mut response = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
        response
            .insert_header("cache-control", "public, max-age=60")
            .unwrap();
        response.insert_header("content-type", "image/png").unwrap();
        response.append_header("x-app-cache", "public").unwrap();
        response.append_header("x-app-cache", "private").unwrap();
        assert_eq!(
            response_cache_admission_rejection(&response, &cache),
            Some("configured-no-store-response-header-value")
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn response_cache_admission_rejects_uncacheable_response_cache_control() {
        for (value, reason) in [
            ("no-store", "cache-control-no-store"),
            ("private", "cache-control-private"),
            ("public, no-cache", "cache-control-no-cache"),
            ("max-age=0", "cache-control-zero-freshness"),
            ("s-maxage=0", "cache-control-zero-freshness"),
        ] {
            let mut response = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
            response.insert_header("content-type", "image/png").unwrap();
            response.insert_header("cache-control", value).unwrap();

            assert_eq!(
                response_cache_admission_rejection(&response, &CacheConfig::default()),
                Some(reason),
                "cache-control: {value}"
            );
        }
    }

    #[cfg(feature = "cache")]
    #[test]
    fn response_cache_admission_requires_allowed_content_type() {
        use std::collections::BTreeMap;

        let mut redirect = pingora::http::ResponseHeader::build(302, Some(2)).unwrap();
        redirect
            .insert_header("cache-control", "public, max-age=60")
            .unwrap();
        redirect.insert_header("content-type", "image/png").unwrap();
        assert_eq!(
            response_cache_admission_rejection(&redirect, &CacheConfig::default()),
            Some("status-not-cacheable")
        );

        let cache_302 = CacheConfig {
            status_ttls: BTreeMap::from([(302, 3600)]),
            ..CacheConfig::default()
        };
        assert_eq!(
            response_cache_admission_rejection(&redirect, &cache_302),
            None
        );

        let mut missing = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
        missing
            .insert_header("cache-control", "public, max-age=60")
            .unwrap();
        assert_eq!(
            response_cache_admission_rejection(&missing, &CacheConfig::default()),
            Some("content-type-missing")
        );

        let mut html = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
        html.insert_header("cache-control", "public, max-age=60")
            .unwrap();
        html.insert_header("content-type", "text/html; charset=utf-8")
            .unwrap();
        assert_eq!(
            response_cache_admission_rejection(&html, &CacheConfig::default()),
            Some("content-type-not-cacheable")
        );

        let mut css = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
        css.insert_header("cache-control", "public, max-age=60")
            .unwrap();
        css.insert_header("content-type", "TEXT/CSS; charset=utf-8")
            .unwrap();
        assert_eq!(
            response_cache_admission_rejection(&css, &CacheConfig::default()),
            None
        );

        let mut image = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
        image
            .insert_header("cache-control", "public, max-age=60")
            .unwrap();
        image
            .insert_header("content-type", "IMAGE/WebP; charset=binary")
            .unwrap();
        assert_eq!(
            response_cache_admission_rejection(&image, &CacheConfig::default()),
            None
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn vary_cache_policy_normalizes_repeated_vary_fields() {
        let mut response = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
        response
            .append_header("vary", "Accept-Encoding, Accept-Language")
            .unwrap();
        response.append_header("vary", "accept-encoding").unwrap();

        assert_eq!(
            vary_cache_policy(&response.headers),
            VaryCachePolicy::Fields(vec![
                "accept-encoding".to_owned(),
                "accept-language".to_owned()
            ])
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_vary_policy_merges_configured_request_headers() {
        let mut response = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
        response.append_header("vary", "Accept-Encoding").unwrap();
        let cache = CacheConfig {
            vary_request_headers: vec!["accept-language".to_owned(), "accept-encoding".to_owned()],
            ..CacheConfig::default()
        };

        assert_eq!(
            cache_vary_policy(&response.headers, &cache),
            VaryCachePolicy::Fields(vec![
                "accept-encoding".to_owned(),
                "accept-language".to_owned()
            ])
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_vary_policy_uses_configured_request_headers_without_origin_vary() {
        let response = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
        let cache = CacheConfig {
            vary_request_headers: vec!["accept-encoding".to_owned()],
            ..CacheConfig::default()
        };

        assert_eq!(
            cache_vary_policy(&response.headers, &cache),
            VaryCachePolicy::Fields(vec!["accept-encoding".to_owned()])
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn bounded_range_parser_accepts_safe_single_ranges() {
        assert_eq!(
            parse_bounded_single_range("bytes=0-1023"),
            Some(CacheRangeRequest {
                start: 0,
                end: 1023,
            })
        );
        assert_eq!(
            parse_bounded_single_range(" bytes=12-12 "),
            Some(CacheRangeRequest { start: 12, end: 12 })
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn bounded_range_parser_rejects_ambiguous_or_unbounded_ranges() {
        assert_eq!(parse_bounded_single_range("bytes=0-1023,2048-4095"), None);
        assert_eq!(parse_bounded_single_range("bytes=0-"), None);
        assert_eq!(parse_bounded_single_range("bytes=-1024"), None);
        assert_eq!(parse_bounded_single_range("bytes=20-10"), None);
        assert_eq!(parse_bounded_single_range("items=0-10"), None);
    }

    #[cfg(feature = "cache")]
    #[test]
    fn selected_cache_range_request_requires_opt_in_get_and_size_bound() {
        let cache = CacheConfig {
            range: crate::config::CacheRangeConfig {
                enabled: true,
                max_bytes: ByteSize::from_bytes(16),
                ..crate::config::CacheRangeConfig::default()
            },
            ..CacheConfig::default()
        };
        let mut request = pingora::http::RequestHeader::build("GET", b"/video.bin", None).unwrap();
        request.append_header("range", "bytes=0-15").unwrap();
        assert_eq!(
            selected_cache_range_request(&request, &cache),
            Some(CacheRangeRequest { start: 0, end: 15 })
        );

        let mut too_large =
            pingora::http::RequestHeader::build("GET", b"/video.bin", None).unwrap();
        too_large.append_header("range", "bytes=0-16").unwrap();
        assert_eq!(selected_cache_range_request(&too_large, &cache), None);

        let mut repeated = pingora::http::RequestHeader::build("GET", b"/video.bin", None).unwrap();
        repeated.append_header("range", "bytes=0-15").unwrap();
        repeated.append_header("range", "bytes=16-31").unwrap();
        assert_eq!(selected_cache_range_request(&repeated, &cache), None);

        let mut if_range = pingora::http::RequestHeader::build("GET", b"/video.bin", None).unwrap();
        if_range.append_header("range", "bytes=0-15").unwrap();
        if_range
            .append_header("if-range", "\"strong-validator\"")
            .unwrap();
        assert_eq!(selected_cache_range_request(&if_range, &cache), None);

        let mut head = pingora::http::RequestHeader::build("HEAD", b"/video.bin", None).unwrap();
        head.append_header("range", "bytes=0-15").unwrap();
        assert_eq!(selected_cache_range_request(&head, &cache), None);
    }

    #[cfg(feature = "cache")]
    #[test]
    fn slice_range_parser_accepts_bounded_open_suffix_and_multi_ranges() {
        assert_eq!(
            parse_cache_client_ranges("bytes=0-9, 20-, -5"),
            Some(vec![
                CacheClientRange::Bounded { start: 0, end: 9 },
                CacheClientRange::OpenEnded { start: 20 },
                CacheClientRange::Suffix { len: 5 },
            ])
        );
        assert_eq!(parse_cache_client_ranges("bytes=10-5"), None);
        assert_eq!(parse_cache_client_ranges("bytes=-0"), None);
        assert_eq!(parse_cache_client_ranges("items=0-5"), None);
    }

    #[cfg(feature = "cache")]
    #[test]
    fn slice_ranges_resolve_against_known_total_and_skip_unsatisfied_parts() {
        let ranges = vec![
            CacheClientRange::Bounded { start: 2, end: 8 },
            CacheClientRange::OpenEnded { start: 8 },
            CacheClientRange::Suffix { len: 4 },
            CacheClientRange::Bounded { start: 20, end: 30 },
        ];
        assert_eq!(
            resolve_client_slice_ranges(&ranges, 12),
            Some(vec![
                CacheSliceBounds { start: 2, end: 8 },
                CacheSliceBounds { start: 8, end: 11 },
                CacheSliceBounds { start: 8, end: 11 },
            ])
        );
        assert_eq!(resolve_client_slice_ranges(&ranges, 0), Some(Vec::new()));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn slice_planner_normalizes_to_fixed_slice_boundaries() {
        let ranges = vec![
            CacheSliceBounds { start: 3, end: 18 },
            CacheSliceBounds { start: 30, end: 31 },
        ];
        assert_eq!(
            required_slice_bounds(&ranges, 8, 32),
            vec![
                CacheSliceBounds { start: 0, end: 7 },
                CacheSliceBounds { start: 8, end: 15 },
                CacheSliceBounds { start: 16, end: 23 },
                CacheSliceBounds { start: 24, end: 31 },
            ]
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn slice_policy_bounds_assembled_bytes_and_slice_count() {
        let cache = CacheConfig {
            range: crate::config::CacheRangeConfig {
                enabled: true,
                max_bytes: ByteSize::from_bytes(16),
                slice: crate::config::CacheRangeSliceConfig {
                    enabled: true,
                    size_bytes: ByteSize::from_bytes(8),
                    max_slices: 2,
                    fill_missing: true,
                },
            },
            ..CacheConfig::default()
        };
        assert!(slice_request_within_policy(
            &[CacheSliceBounds { start: 0, end: 15 }],
            &cache,
            8
        ));
        assert!(!slice_request_within_policy(
            &[CacheSliceBounds { start: 0, end: 16 }],
            &cache,
            8
        ));
        assert!(!slice_request_within_policy(
            &[CacheSliceBounds { start: 0, end: 23 }],
            &cache,
            8
        ));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn range_cache_key_extends_primary_key_and_preserves_user_tag() {
        let base = pingora::cache::CacheKey::new(
            "fluxheim-cache-v1",
            "method:3:GET;host:11:example.test;path:10:/video.bin;",
            "vhost-a",
        );

        let key = range_cache_key(
            base,
            CacheRangeRequest {
                start: 0,
                end: 1023,
            },
        )
        .unwrap();

        assert_eq!(key.namespace_str(), Some("fluxheim-cache-v1"));
        assert_eq!(key.user_tag, "vhost-a");
        assert!(
            key.primary_key_str()
                .is_some_and(|primary| primary.ends_with("range:12:bytes=0-1023;"))
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn range_cache_admission_rejects_unkeyed_partial_responses() {
        let mut response = pingora::http::ResponseHeader::build(206, Some(2)).unwrap();
        response
            .insert_header("content-range", "bytes 0-15/1024")
            .unwrap();
        response.insert_header("content-length", "16").unwrap();

        assert_eq!(
            range_response_cache_admission_rejection(&response, None),
            Some("range-response")
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn range_cache_admission_accepts_matching_partial_response() {
        let mut response = pingora::http::ResponseHeader::build(206, Some(2)).unwrap();
        response
            .insert_header("content-range", "bytes 0-15/1024")
            .unwrap();
        response.insert_header("content-length", "16").unwrap();

        assert_eq!(
            range_response_cache_admission_rejection(
                &response,
                Some(CacheRangeRequest { start: 0, end: 15 }),
            ),
            None
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn range_cache_admission_rejects_mismatched_partial_metadata() {
        let mut ok_status = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
        ok_status.insert_header("content-length", "16").unwrap();
        assert_eq!(
            range_response_cache_admission_rejection(
                &ok_status,
                Some(CacheRangeRequest { start: 0, end: 15 }),
            ),
            Some("range-cache-non-partial")
        );

        let mut bad_range = pingora::http::ResponseHeader::build(206, Some(2)).unwrap();
        bad_range
            .insert_header("content-range", "bytes 16-31/1024")
            .unwrap();
        bad_range.insert_header("content-length", "16").unwrap();
        assert_eq!(
            range_response_cache_admission_rejection(
                &bad_range,
                Some(CacheRangeRequest { start: 0, end: 15 }),
            ),
            Some("range-cache-content-range")
        );

        let mut bad_length = pingora::http::ResponseHeader::build(206, Some(2)).unwrap();
        bad_length
            .insert_header("content-range", "bytes 0-15/1024")
            .unwrap();
        bad_length.insert_header("content-length", "17").unwrap();
        assert_eq!(
            range_response_cache_admission_rejection(
                &bad_length,
                Some(CacheRangeRequest { start: 0, end: 15 }),
            ),
            Some("range-cache-content-length")
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn vary_request_hash_tracks_negotiated_request_headers() {
        let fields = vec!["accept-encoding".to_owned(), "accept-language".to_owned()];

        let mut br = pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        br.insert_header("accept-encoding", "br").unwrap();
        br.insert_header("accept-language", "en").unwrap();

        let mut gzip = pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        gzip.insert_header("accept-encoding", "gzip").unwrap();
        gzip.insert_header("accept-language", "en").unwrap();

        let mut repeated =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        repeated.append_header("accept-encoding", "br").unwrap();
        repeated.append_header("accept-encoding", "zstd").unwrap();
        repeated.insert_header("accept-language", "en").unwrap();

        assert_ne!(
            vary_request_hash(&fields, &br),
            vary_request_hash(&fields, &gzip)
        );
        assert_ne!(
            vary_request_hash(&fields, &br),
            vary_request_hash(&fields, &repeated)
        );
        assert_eq!(
            vary_request_hash(&fields, &br),
            vary_request_hash(&fields, &br)
        );
    }

    #[cfg(feature = "web")]
    #[test]
    fn request_header_values_joined_preserves_repeated_static_conditions() {
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        request.append_header("if-none-match", "\"one\"").unwrap();
        request.append_header("if-none-match", "\"two\"").unwrap();
        request.append_header("range", "bytes=0-9").unwrap();
        request.append_header("range", "bytes=20-29").unwrap();

        assert_eq!(
            super::request_header_values_joined(&request, "if-none-match").as_deref(),
            Some("\"one\", \"two\"")
        );
        assert_eq!(
            super::request_header_values_joined(&request, "range").as_deref(),
            Some("bytes=0-9, bytes=20-29")
        );
        assert_eq!(
            super::request_header_values_joined(&request, "missing").as_deref(),
            None
        );
    }

    #[test]
    fn request_host_header_falls_back_to_uri_authority() {
        let mut request = pingora::http::RequestHeader::build("GET", b"/tls/check", None).unwrap();
        request.uri = "https://app.example.test/tls/check".parse().unwrap();

        assert_eq!(
            super::request_host_header(&request),
            Some("app.example.test")
        );
    }

    #[test]
    fn request_host_header_prefers_explicit_host_header() {
        let mut request = pingora::http::RequestHeader::build("GET", b"/check", None).unwrap();
        request.uri = "https://authority.example.test/check".parse().unwrap();
        request.insert_header("host", "host.example.test").unwrap();

        assert_eq!(
            super::request_host_header(&request),
            Some("host.example.test")
        );
    }

    #[test]
    fn streaming_body_chunks_are_counted_against_global_limit() {
        let limits = ServerLimitsConfig {
            max_request_header_bytes: ByteSize::from_bytes(512),
            max_uri_bytes: ByteSize::from_bytes(128),
            max_request_headers: 8,
            max_request_body_bytes: ByteSize::from_bytes(16),
        };
        let mut seen = 0;

        assert_eq!(
            request_body_chunk_limit_status(limits.max_request_body_bytes.as_u64(), &mut seen, 8),
            None
        );
        assert_eq!(
            request_body_chunk_limit_status(limits.max_request_body_bytes.as_u64(), &mut seen, 8),
            None
        );
        assert_eq!(
            request_body_chunk_limit_status(limits.max_request_body_bytes.as_u64(), &mut seen, 1),
            Some(413)
        );
    }

    #[test]
    fn streaming_body_limit_counter_saturates() {
        let limits = ServerLimitsConfig {
            max_request_header_bytes: ByteSize::from_bytes(512),
            max_uri_bytes: ByteSize::from_bytes(128),
            max_request_headers: 8,
            max_request_body_bytes: ByteSize::from_bytes(16),
        };
        let mut seen = u64::MAX - 1;

        assert_eq!(
            request_body_chunk_limit_status(limits.max_request_body_bytes.as_u64(), &mut seen, 8),
            Some(413)
        );
        assert_eq!(seen, u64::MAX);
    }

    #[test]
    fn trusted_proxy_ranges_match_expected_addresses() {
        let proxies =
            super::parse_trusted_proxies(&["10.0.0.0/8".to_owned(), "2001:db8::/32".to_owned()])
                .unwrap();

        assert!(
            proxies
                .iter()
                .any(|proxy| proxy.contains("10.20.30.40".parse::<std::net::IpAddr>().unwrap()))
        );
        assert!(
            !proxies
                .iter()
                .any(|proxy| proxy.contains("11.20.30.40".parse::<std::net::IpAddr>().unwrap()))
        );
        assert!(
            proxies
                .iter()
                .any(|proxy| proxy.contains("2001:db8::1".parse::<std::net::IpAddr>().unwrap()))
        );
        assert!(
            !proxies
                .iter()
                .any(|proxy| proxy.contains("2001:db9::1".parse::<std::net::IpAddr>().unwrap()))
        );
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn access_log_json_escapes_values_and_omits_query_when_given_path() {
        let log = super::access_log_json(super::AccessLogEvent {
            method: "GET",
            host: Some("example.test"),
            vhost: "main\"site",
            path: Some("/asset path/one.js"),
            status: Some(200),
            status_class: Some(super::status_class(200)),
            error: false,
            request_id: Some("req-123"),
            #[cfg(feature = "otel-tracing")]
            trace_id: None,
            request_body_bytes: 42,
            response_body_bytes: 2048,
            latency_ms: 7,
        });

        assert!(log.contains("\"event\":\"access\""));
        assert!(log.contains("\"host\":\"example.test\""));
        assert!(log.contains("\"vhost\":\"main\\\"site\""));
        assert!(log.contains("\"path\":\"/asset path/one.js\""));
        assert!(log.contains("\"status_class\":\"2xx\""));
        assert!(log.contains("\"request_id\":\"req-123\""));
        assert!(log.contains("\"response_body_bytes\":2048"));
        assert!(!log.contains("secret="));
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn access_log_json_can_omit_path() {
        let log = super::access_log_json(super::AccessLogEvent {
            method: "GET",
            host: Some("example.test"),
            vhost: "main",
            path: None,
            status: Some(204),
            status_class: Some(super::status_class(204)),
            error: false,
            request_id: None,
            #[cfg(feature = "otel-tracing")]
            trace_id: None,
            request_body_bytes: 0,
            response_body_bytes: 0,
            latency_ms: 1,
        });

        assert!(log.contains("\"path\":\"\""));
        assert!(!log.contains("/private"));
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn access_log_json_can_omit_host() {
        let log = super::access_log_json(super::AccessLogEvent {
            method: "GET",
            host: None,
            vhost: "main",
            path: Some("/"),
            status: Some(204),
            status_class: Some(super::status_class(204)),
            error: false,
            request_id: None,
            #[cfg(feature = "otel-tracing")]
            trace_id: None,
            request_body_bytes: 0,
            response_body_bytes: 0,
            latency_ms: 1,
        });

        assert!(log.contains("\"host\":\"\""));
        assert!(!log.contains("tenant.example"));
    }

    #[cfg(all(not(feature = "privacy-mode"), feature = "otel-tracing"))]
    #[test]
    fn access_log_json_can_include_trace_id() {
        let log = super::access_log_json(super::AccessLogEvent {
            method: "GET",
            host: Some("example.test"),
            vhost: "main",
            path: Some("/"),
            status: Some(200),
            status_class: Some(super::status_class(200)),
            error: false,
            request_id: None,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_owned()),
            request_body_bytes: 0,
            response_body_bytes: 0,
            latency_ms: 1,
        });

        assert!(log.contains(r#""trace_id":"4bf92f3577b34da6a3ce929d0e0e4736""#));
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn access_log_status_class_is_low_cardinality() {
        assert_eq!(super::status_class(101), "1xx");
        assert_eq!(super::status_class(204), "2xx");
        assert_eq!(super::status_class(304), "3xx");
        assert_eq!(super::status_class(404), "4xx");
        assert_eq!(super::status_class(503), "5xx");
        assert_eq!(super::status_class(700), "other");
    }

    #[test]
    fn response_body_chunks_are_counted_for_access_logs() {
        let mut seen = 0;

        count_response_body_chunk(&mut seen, Some(&Bytes::from_static(b"hello")));
        count_response_body_chunk(&mut seen, None);
        count_response_body_chunk(&mut seen, Some(&Bytes::from_static(b" world")));

        assert_eq!(seen, 11);
    }

    #[test]
    fn response_body_byte_counter_saturates() {
        let mut seen = u64::MAX - 1;

        count_response_body_chunk(&mut seen, Some(&Bytes::from_static(b"abcd")));

        assert_eq!(seen, u64::MAX);
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn access_log_request_id_reuses_valid_inbound_value() {
        let mut request = pingora::http::RequestHeader::build("GET", b"/", None).unwrap();
        request
            .insert_header("x-request-id", "edge-req-123")
            .unwrap();

        assert_eq!(
            super::access_log_request_id(&crate::config::AccessLoggingConfig::default(), &request)
                .as_deref(),
            Some("edge-req-123")
        );
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn access_log_request_id_generates_for_missing_or_invalid_value() {
        let missing = pingora::http::RequestHeader::build("GET", b"/", None).unwrap();
        let generated =
            super::access_log_request_id(&crate::config::AccessLoggingConfig::default(), &missing)
                .unwrap();
        assert!(generated.starts_with("fh-"));

        let mut invalid = pingora::http::RequestHeader::build("GET", b"/", None).unwrap();
        invalid.insert_header("x-request-id", "bad value").unwrap();
        let regenerated =
            super::access_log_request_id(&crate::config::AccessLoggingConfig::default(), &invalid)
                .unwrap();
        assert!(regenerated.starts_with("fh-"));
        assert_ne!(regenerated, "bad value");
    }

    #[cfg(feature = "cache")]
    fn unique_test_cache_dir(label: &str) -> std::path::PathBuf {
        unique_temp_path(label)
    }

    #[cfg(feature = "cache")]
    fn pingora_meta(cache_control: &str) -> pingora::cache::CacheMeta {
        let mut header = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
        header
            .insert_header("cache-control", cache_control)
            .unwrap();
        let now = std::time::SystemTime::now();
        pingora::cache::CacheMeta::new(
            now.checked_add(std::time::Duration::from_secs(60)).unwrap(),
            now,
            0,
            0,
            header,
        )
    }

    #[cfg(feature = "cache")]
    fn stale_pingora_meta(cache_control: &str) -> pingora::cache::CacheMeta {
        let mut header = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
        header
            .insert_header("cache-control", cache_control)
            .unwrap();
        let now = std::time::SystemTime::now();
        pingora::cache::CacheMeta::new(
            now.checked_sub(std::time::Duration::from_secs(60)).unwrap(),
            now.checked_sub(std::time::Duration::from_secs(120))
                .unwrap(),
            0,
            0,
            header,
        )
    }

    #[cfg(feature = "cache")]
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        use std::pin::pin;
        use std::task::{Context, Poll, Waker};

        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
