use std::cmp::Reverse;
use std::collections::HashMap;
#[cfg(any(
    feature = "tls-rustls-backend",
    feature = "tls-openssl",
    feature = "tls-boringssl"
))]
use std::fs::OpenOptions;
use std::io;
use std::net::{IpAddr, Ipv6Addr, ToSocketAddrs};
#[cfg(all(
    unix,
    any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl"
    )
))]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(feature = "php-fpm")]
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(any(feature = "cache", feature = "load-balancer"))]
use std::sync::Mutex;
#[cfg(feature = "cache")]
use std::sync::OnceLock;
#[cfg(any(feature = "cache", feature = "php-fpm"))]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

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
use pingora::protocols::TcpKeepalive;
#[cfg(feature = "cache")]
use pingora::proxy::RangeType;
use pingora::proxy::{FailToProxy, ProxyHttp, Session};
use pingora::{Error, ErrorType};
#[cfg(feature = "cache")]
use pingora::{
    cache::CacheMeta, cache::CacheOptionOverrides, cache::CachePhase, cache::ForcedFreshness,
    cache::HitHandler, cache::NoCacheReason, cache::RespCacheable,
};

use crate::access_log::count_response_body_chunk;
#[cfg(feature = "otel-otlp")]
use crate::access_log::unix_time_nanos;
#[cfg(not(feature = "privacy-mode"))]
use crate::access_log::{AccessLogEvent, access_log_json, access_log_request_id, status_class};
#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
use crate::compression::ResponseCompressionEncoder;
#[cfg(not(feature = "privacy-mode"))]
use crate::config::AccessLoggingConfig;
use crate::config::{
    Config, HostRoutingConfig, HttpsRedirectConfig, ProxyConfig, RouteRedirectConfig,
    ServerLimitsConfig, UpstreamHttpVersion, UpstreamProxyProtocol, normalize_host,
};
use crate::edge_policy::{
    InFlightPermit, RateLimitDecision, RuntimeAccessPolicy, RuntimeConcurrencyLimit,
    RuntimeRateLimit, TrustedProxy, parse_trusted_proxies,
};
#[cfg(feature = "load-balancer")]
use crate::load_balancer::{
    LoadBalancedUpstreamOutcome, UpstreamLoadBalancer, UpstreamLoadBalancerService,
};
#[cfg(feature = "php-fpm")]
use crate::php_fpm::{
    ManagedPhpFpmProcess, PhpFpmParsedResponse, PhpFpmPool, PhpRequestBody,
    create_php_request_body_spool_file, execute_php_fpm_once, parse_php_response,
    php_fpm_effective_connect_timeout, php_fpm_effective_request_timeout,
    php_fpm_endpoints_from_config, php_fpm_error_outcome, php_fpm_keepalive_pools_from_config,
    php_fpm_retry_attempts_for_endpoint_count, php_fpm_retry_deadline,
    php_fpm_retry_deadline_allows, php_fpm_retryable_error, php_fpm_retryable_response,
};
#[cfg(feature = "cache")]
use crate::proxy_cache::{
    VaryCachePolicy, cache_request_from_header, cache_vary_policy, request_cache_bypass_reason,
    request_cache_revalidation_requested, response_cache_admission_rejection,
    response_range_cache_admission_rejection, vary_request_hash,
};
use crate::route_policy::{RuntimeRouteMatcher, route_method_matches};
#[cfg(feature = "web")]
use crate::web::{ResolveResult, StaticFileServer};
use tokio::io::AsyncWriteExt as _;

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
const SLICE_FILL_CONCURRENCY_MAX_KEYS: usize = 4096;
#[cfg(feature = "cache")]
static PEER_FILL_CONCURRENCY: OnceLock<Mutex<HashMap<String, Arc<AtomicUsize>>>> = OnceLock::new();
#[cfg(feature = "cache")]
static CACHE_PREDICTOR_REGISTRY: OnceLock<
    Mutex<HashMap<usize, &'static (dyn CacheablePredictor + Sync)>>,
> = OnceLock::new();
#[cfg(all(
    any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl"
    ),
    target_os = "linux"
))]
const UPSTREAM_TLS_O_NOFOLLOW: i32 = 0o400000;
#[cfg(all(
    any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl"
    ),
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )
))]
const UPSTREAM_TLS_O_NOFOLLOW: i32 = 0x0100;
#[cfg(all(
    unix,
    any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl"
    ),
    not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!(
    "O_NOFOLLOW is unknown on this Unix platform; audit upstream TLS file opening before building Fluxheim"
);
#[cfg(any(
    feature = "tls-rustls-backend",
    feature = "tls-openssl",
    feature = "tls-boringssl"
))]
const MAX_UPSTREAM_TLS_FILE_BYTES: u64 = 1024 * 1024;

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
        let route = ctx
            .vhost_index
            .and_then(|vhost_index| state.vhosts.get(vhost_index))
            .and_then(|vhost| {
                ctx.route_index
                    .and_then(|route_index| vhost.routes.get(route_index))
            })
            .map(|route| route.name.as_str())
            .unwrap_or("");
        let status = session
            .response_written()
            .map(|response| response.status.as_u16());
        let tls_identity = downstream_tls_client_identity(session);
        let latency_ms = ctx
            .started_at
            .map(|started_at| started_at.elapsed().as_millis())
            .unwrap_or(0);
        #[cfg(feature = "load-balancer")]
        let upstream_alias = ctx.upstream_load_balancer_alias.as_deref();
        #[cfg(not(feature = "load-balancer"))]
        let upstream_alias = None;
        #[cfg(feature = "load-balancer")]
        let upstream_retries = ctx.upstream_load_balancer_retries;
        #[cfg(not(feature = "load-balancer"))]
        let upstream_retries = 0;

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
                client_ip: if state.access_log.include_client_ip {
                    effective_acl_client_ip(session, &state)
                        .map(|client_ip| client_ip.to_string())
                } else {
                    None
                },
                #[cfg(feature = "cache")]
                cache_phase: if state.access_log.include_cache_phase {
                    Some(effective_cache_phase(session, ctx).as_str())
                } else {
                    None
                },
                #[cfg(any(
                    feature = "compression-brotli",
                    feature = "compression-gzip",
                    feature = "compression-zstd"
                ))]
                compression_encoding: ctx
                    .compression
                    .as_ref()
                    .map(|compression| compression.encoding),
                tls_version: tls_identity
                    .as_ref()
                    .and_then(|identity| identity.version.as_deref()),
                tls_cipher: tls_identity
                    .as_ref()
                    .and_then(|identity| identity.cipher.as_deref()),
                tls_client_cert_sha256: tls_identity
                    .as_ref()
                    .and_then(|identity| identity.cert_sha256.as_deref()),
                tls_client_cert_serial: tls_identity
                    .as_ref()
                    .and_then(|identity| identity.serial_number.as_deref()),
                tls_client_cert_organization: tls_identity
                    .as_ref()
                    .and_then(|identity| identity.organization.as_deref()),
                vhost,
                route: if state.access_log.include_route {
                    route
                } else {
                    ""
                },
                upstream: state
                    .access_log
                    .include_upstream
                    .then_some(ctx.upstream.as_deref())
                    .flatten(),
                upstream_alias: state
                    .access_log
                    .include_upstream
                    .then_some(upstream_alias)
                    .flatten(),
                upstream_retries,
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
        let route = ctx.route_index.map(|route_index| {
            state
                .vhosts
                .get(
                    ctx.vhost_index
                        .unwrap_or_else(|| state.vhost_index(request_host(session))),
                )
                .and_then(|vhost| vhost.routes.get(route_index))
                .map(|route| route.name.clone())
                .unwrap_or_else(|| format!("route-{route_index}"))
        });
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
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        let compression_encoding = ctx
            .compression
            .as_ref()
            .map(|compression| compression.encoding.to_owned());
        #[cfg(not(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        )))]
        let compression_encoding = None;
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
            compression_encoding,
            #[cfg(feature = "php-fpm")]
            php_runtime: ctx.php_outcome.map(|_| "php-fpm".to_owned()),
            #[cfg(not(feature = "php-fpm"))]
            php_runtime: None,
            #[cfg(feature = "php-fpm")]
            php_outcome: ctx.php_outcome.map(str::to_owned),
            #[cfg(not(feature = "php-fpm"))]
            php_outcome: None,
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
        let route_index = vhost.route_index(request.method.as_str(), request.uri.path());
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
        let route_index = vhost.route_index(request.method.as_str(), request.uri.path());
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

#[cfg(feature = "load-balancer")]
fn configured_route_load_balancers<F>(
    vhost: &crate::config::VhostConfig,
    mut load_balancer: F,
) -> io::Result<Vec<Option<UpstreamLoadBalancer>>>
where
    F: FnMut(&str, &ProxyConfig) -> io::Result<Option<UpstreamLoadBalancer>>,
{
    vhost
        .acme_challenge
        .route_config()
        .into_iter()
        .chain(vhost.routes.iter().cloned())
        .chain(vhost.redirect.route_config())
        .map(|route| {
            route
                .proxy
                .as_ref()
                .map(|proxy| load_balancer(&route.name, proxy))
                .unwrap_or(Ok(None))
        })
        .collect()
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
                #[cfg(feature = "compression")]
                config.compression.clone(),
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
                let route_load_balancers =
                    configured_route_load_balancers(configured, |route_name, proxy| {
                        load_balancer(&format!("{} route {route_name}", configured.name), proxy)
                    })?;
                let runtime = RuntimeVhost::from_config(
                    config,
                    configured,
                    &config.headers,
                    load_balancer(&configured.name, &configured.proxy)?,
                    route_load_balancers,
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
                #[cfg(feature = "compression")]
                config.compression.clone(),
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

fn request_denied_by_access_policy(
    session: &Session,
    state: &ProxyRuntimeState,
    vhost: &RuntimeVhost,
    route_index: Option<usize>,
) -> bool {
    let client_ip = effective_acl_client_ip(session, state);
    let tls_identity = downstream_tls_client_identity(session);
    if !vhost.access.allows(client_ip, tls_identity.as_ref()) {
        return true;
    }
    route_index
        .map(|route_index| {
            !vhost
                .route(route_index)
                .access
                .allows(client_ip, tls_identity.as_ref())
        })
        .unwrap_or(false)
}

fn request_limited_by_rate_policy(
    session: &Session,
    state: &ProxyRuntimeState,
    vhost: &RuntimeVhost,
    route_index: Option<usize>,
) -> RateLimitDecision {
    let client_ip = effective_acl_client_ip(session, state);
    let mut delay = None;
    match vhost.rate_limit.check(client_ip) {
        RateLimitDecision::Allow => {}
        RateLimitDecision::Delay(vhost_delay) => delay = Some(vhost_delay),
        decision => return decision,
    }
    if let Some(route_index) = route_index {
        match vhost.route(route_index).rate_limit.check(client_ip) {
            RateLimitDecision::Allow => {}
            RateLimitDecision::Delay(route_delay) => {
                delay = Some(delay.map_or(route_delay, |current| current.max(route_delay)));
            }
            decision => return decision,
        }
    }

    delay
        .map(RateLimitDecision::Delay)
        .unwrap_or(RateLimitDecision::Allow)
}

async fn acquire_request_concurrency_permits(
    vhost: &RuntimeVhost,
    route_index: Option<usize>,
) -> std::result::Result<Vec<InFlightPermit>, u16> {
    let mut permits = Vec::with_capacity(2);
    if let Some(permit) = vhost.concurrency.acquire().await? {
        permits.push(permit);
    }
    if let Some(route_index) = route_index {
        let route = vhost.route(route_index);
        if let Some(permit) = route.concurrency.acquire().await? {
            permits.push(permit);
        }
    }
    Ok(permits)
}

fn effective_acl_client_ip(session: &Session, state: &ProxyRuntimeState) -> Option<IpAddr> {
    let direct_ip = session.client_addr().and_then(|addr| addr.as_inet())?.ip();
    let trusted_direct_peer = state.trusted_proxy(direct_ip);
    let forwarded_for = joined_header_values(session.req_header(), "x-forwarded-for");
    Some(effective_client_ip_from_forwarded_for(
        direct_ip,
        trusted_direct_peer,
        forwarded_for.as_deref(),
        |ip| state.trusted_proxy(ip),
    ))
}

fn effective_client_ip_from_forwarded_for(
    direct_ip: IpAddr,
    trusted_direct_peer: bool,
    forwarded_for: Option<&str>,
    trusted_proxy: impl Fn(IpAddr) -> bool,
) -> IpAddr {
    if !trusted_direct_peer {
        return direct_ip;
    }

    let Some(forwarded_for) = forwarded_for else {
        return direct_ip;
    };

    let mut last_valid_hop = None;
    for hop in forwarded_for
        .split(',')
        .rev()
        .filter_map(parse_forwarded_for_ip)
    {
        last_valid_hop.get_or_insert(hop);
        if !trusted_proxy(hop) {
            return hop;
        }
    }

    last_valid_hop.unwrap_or(direct_ip)
}

fn parse_forwarded_for_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim().trim_matches('"');
    if value.is_empty() {
        return None;
    }
    if let Some(value) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        return value.parse().ok();
    }
    value.parse().ok()
}

fn joined_header_values(request: &RequestHeader, name: &str) -> Option<String> {
    let mut values = request
        .headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok());
    let first = values.next()?.to_owned();
    Some(values.fold(first, |mut joined, value| {
        joined.push_str(", ");
        joined.push_str(value);
        joined
    }))
}

#[derive(Clone)]
struct RuntimeVhost {
    name: String,
    hosts: Vec<String>,
    max_request_body_bytes: Option<crate::config::ByteSize>,
    access: RuntimeAccessPolicy,
    rate_limit: RuntimeRateLimit,
    concurrency: RuntimeConcurrencyLimit,
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
    #[cfg(feature = "compression")]
    compression: crate::config::CompressionConfig,
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
            .field("access", &self.access)
            .field("rate_limit", &self.rate_limit)
            .field("concurrency", &self.concurrency)
            .field("proxy", &self.proxy)
            .field("request_headers", &self.request_headers)
            .field("response_headers", &self.response_headers);
        #[cfg(feature = "compression")]
        debug.field("compression", &self.compression);

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
    #[cfg_attr(feature = "privacy-mode", allow(dead_code))]
    name: String,
    matcher: RuntimeRouteMatcher,
    methods: Vec<String>,
    https_redirect_exempt: bool,
    strip_prefix: Option<String>,
    rewrite_prefix: Option<String>,
    rewrite_template: Option<String>,
    max_request_body_bytes: Option<crate::config::ByteSize>,
    access: RuntimeAccessPolicy,
    rate_limit: RuntimeRateLimit,
    concurrency: RuntimeConcurrencyLimit,
    grpc: crate::config::GrpcRouteConfig,
    action: RuntimeRouteAction,
    #[cfg(feature = "load-balancer")]
    load_balancer: Option<UpstreamLoadBalancer>,
    #[cfg(feature = "cache")]
    cache: Option<RuntimeRouteCache>,
    #[cfg(feature = "compression")]
    compression: Option<crate::config::CompressionConfig>,
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
        let config = config.with_presets();
        let pingora_memory_storage =
            crate::cache::pingora_memory_storage_from_config_with_metric_scope(
                &config,
                vhost_name,
                Some(name),
            );
        let pingora_disk_storage =
            crate::cache::pingora_disk_storage_backend_from_config_with_metric_scope(
                &config,
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
            &config,
            pingora_memory_storage.is_some() || pingora_disk_storage.is_some(),
        );
        let pingora_cache_predictor = cache_predictor_from_config(
            &config,
            pingora_memory_storage.is_some() || pingora_disk_storage.is_some(),
        );

        Ok(Self {
            name: name.to_owned(),
            config: config.clone(),
            memory_cache: crate::cache::memory_image_cache_from_config(&config),
            pingora_memory_storage,
            pingora_disk_storage,
            pingora_tiered_storage,
            pingora_cache_lock,
            pingora_cache_predictor,
            cache_lock_wait_timeout: cache_lock_wait_timeout(&config),
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
    let registry = CACHE_PREDICTOR_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut predictors = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = predictors.get(&shard_capacity) {
        return Some(*existing);
    }
    let created = Box::leak(Box::new(FluxCachePredictor::new(
        shard_capacity,
        Some(skip_fluxheim_predictor_custom_reason),
    ))) as &'static (dyn CacheablePredictor + Sync);
    predictors.insert(shard_capacity, created);
    Some(created)
}

#[cfg(feature = "cache")]
fn skip_fluxheim_predictor_custom_reason(_reason: &'static str) -> bool {
    true
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
    #[cfg(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl"
    ))]
    upstream_tls: RuntimeUpstreamTls,
    #[cfg(feature = "load-balancer")]
    retry_budget: Option<RuntimeRetryBudget>,
    error_pages: Vec<RuntimeErrorPage>,
}

#[cfg(any(
    feature = "tls-rustls-backend",
    feature = "tls-openssl",
    feature = "tls-boringssl"
))]
#[derive(Debug, Clone, Default)]
struct RuntimeUpstreamTls {
    ca: Option<Arc<pingora::protocols::tls::CaType>>,
    client_cert_key: Option<Arc<pingora::utils::tls::CertKey>>,
}

#[cfg(not(any(
    feature = "tls-rustls-backend",
    feature = "tls-openssl",
    feature = "tls-boringssl"
)))]
struct RuntimeUpstreamTls;

#[cfg(feature = "load-balancer")]
#[derive(Debug, Clone)]
struct RuntimeRetryBudget {
    inner: Arc<Mutex<RuntimeRetryBudgetState>>,
    max_per_window: u32,
    window: Duration,
}

#[cfg(feature = "load-balancer")]
#[derive(Debug)]
struct RuntimeRetryBudgetState {
    window_started_at: Instant,
    used: u32,
}

#[cfg(feature = "php-fpm")]
#[derive(Debug, Clone)]
struct RuntimePhp {
    config: crate::config::PhpConfig,
    root: std::path::PathBuf,
    fpm_root: std::path::PathBuf,
    files: StaticFileServer,
    error_pages: Vec<RuntimeErrorPage>,
    fpm_pools: Vec<Arc<PhpFpmPool>>,
    fpm_next: Arc<AtomicUsize>,
    _managed_fpm: Option<Arc<ManagedPhpFpmProcess>>,
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
            #[cfg(any(
                feature = "tls-rustls-backend",
                feature = "tls-openssl",
                feature = "tls-boringssl"
            ))]
            upstream_tls: RuntimeUpstreamTls::from_config(config).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("{scope}: upstream TLS material: {error}"),
                )
            })?,
            #[cfg(feature = "load-balancer")]
            retry_budget: RuntimeRetryBudget::from_config(&config.load_balance.retry),
            error_pages,
        })
    }

    fn error_page(&self, status: u16) -> Option<&RuntimeErrorPage> {
        self.error_pages.iter().find(|page| page.status == status)
    }
}

#[cfg(any(
    feature = "tls-rustls-backend",
    feature = "tls-openssl",
    feature = "tls-boringssl"
))]
impl RuntimeUpstreamTls {
    fn from_config(config: &ProxyConfig) -> io::Result<Self> {
        Ok(Self {
            ca: config
                .upstream_ca_path
                .as_deref()
                .map(load_upstream_ca_bundle)
                .transpose()?,
            client_cert_key: match (
                config.upstream_client_cert_path.as_deref(),
                config.upstream_client_key_path.as_deref(),
            ) {
                (Some(cert), Some(key)) => Some(load_upstream_client_cert_key(cert, key)?),
                _ => None,
            },
        })
    }
}

#[cfg(any(
    feature = "tls-rustls-backend",
    feature = "tls-openssl",
    feature = "tls-boringssl"
))]
fn read_upstream_tls_file(path: &std::path::Path) -> io::Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "upstream TLS path is not a regular file: {}",
                path.display()
            ),
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(UPSTREAM_TLS_O_NOFOLLOW);

    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "upstream TLS path is not a regular file: {}",
                path.display()
            ),
        ));
    }
    if metadata.len() > MAX_UPSTREAM_TLS_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream TLS file {} exceeds {} bytes",
                path.display(),
                MAX_UPSTREAM_TLS_FILE_BYTES
            ),
        ));
    }

    let mut contents = Vec::new();
    let mut limited = std::io::Read::take(file, MAX_UPSTREAM_TLS_FILE_BYTES.saturating_add(1));
    std::io::Read::read_to_end(&mut limited, &mut contents)?;
    if contents.len() as u64 > MAX_UPSTREAM_TLS_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream TLS file {} exceeds {} bytes",
                path.display(),
                MAX_UPSTREAM_TLS_FILE_BYTES
            ),
        ));
    }
    Ok(contents)
}

#[cfg(all(
    feature = "tls-rustls-backend",
    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
))]
fn load_upstream_ca_bundle(
    path: &std::path::Path,
) -> io::Result<Arc<pingora::protocols::tls::CaType>> {
    let contents = read_upstream_tls_file(path)?;
    use rustls::pki_types::{CertificateDer, pem::PemObject};

    let certs = CertificateDer::pem_slice_iter(&contents)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse upstream CA bundle {}: {error}",
                    path.display()
                ),
            )
        })?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream CA bundle {} contains no certificates",
                path.display()
            ),
        ));
    }
    let wrapped = certs
        .into_iter()
        .map(|cert| pingora::utils::tls::WrappedX509::try_from_der(cert.as_ref().to_vec()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse upstream CA bundle {}: {error}",
                    path.display()
                ),
            )
        })?;
    Ok(Arc::from(wrapped.into_boxed_slice()))
}

#[cfg(all(
    any(feature = "tls-openssl", feature = "tls-boringssl"),
    not(feature = "tls-rustls-backend")
))]
fn load_upstream_ca_bundle(
    path: &std::path::Path,
) -> io::Result<Arc<pingora::protocols::tls::CaType>> {
    let contents = read_upstream_tls_file(path)?;
    let certs = pingora::tls::x509::X509::stack_from_pem(&contents).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to parse upstream CA bundle {}: {error}",
                path.display()
            ),
        )
    })?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream CA bundle {} contains no certificates",
                path.display()
            ),
        ));
    }
    Ok(Arc::from(certs.into_boxed_slice()))
}

#[cfg(all(
    feature = "tls-rustls-backend",
    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
))]
fn load_upstream_client_cert_key(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> io::Result<Arc<pingora::utils::tls::CertKey>> {
    let cert_contents = read_upstream_tls_file(cert_path)?;
    let key_contents = read_upstream_tls_file(key_path)?;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    let certs = CertificateDer::pem_slice_iter(&cert_contents)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse upstream client certificate {}: {error}",
                    cert_path.display()
                ),
            )
        })?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream client certificate {} contains no certificates",
                cert_path.display()
            ),
        ));
    }

    let key = PrivateKeyDer::from_pem_slice(&key_contents).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to parse upstream client private key {}: {error}",
                key_path.display()
            ),
        )
    })?;

    let cert_key = pingora::utils::tls::CertKey::try_new(
        certs
            .into_iter()
            .map(|cert| cert.as_ref().to_vec())
            .collect(),
        key.secret_der().to_vec(),
    )
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to parse upstream client certificate {}: {error}",
                cert_path.display()
            ),
        )
    })?;
    Ok(Arc::new(cert_key))
}

#[cfg(all(
    any(feature = "tls-openssl", feature = "tls-boringssl"),
    not(feature = "tls-rustls-backend")
))]
fn load_upstream_client_cert_key(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> io::Result<Arc<pingora::utils::tls::CertKey>> {
    let cert_contents = read_upstream_tls_file(cert_path)?;
    let key_contents = read_upstream_tls_file(key_path)?;
    let certs = pingora::tls::x509::X509::stack_from_pem(&cert_contents).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to parse upstream client certificate {}: {error}",
                cert_path.display()
            ),
        )
    })?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream client certificate {} contains no certificates",
                cert_path.display()
            ),
        ));
    }
    let key = pingora::tls::pkey::PKey::private_key_from_pem(&key_contents).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to parse upstream client private key {}: {error}",
                key_path.display()
            ),
        )
    })?;
    Ok(Arc::new(pingora::utils::tls::CertKey::new(certs, key)))
}

#[cfg(feature = "load-balancer")]
impl RuntimeRetryBudget {
    fn from_config(retry: &crate::config::LoadBalanceRetryConfig) -> Option<Self> {
        if !retry.enabled || retry.budget_per_window == 0 {
            return None;
        }
        Some(Self {
            inner: Arc::new(Mutex::new(RuntimeRetryBudgetState {
                window_started_at: Instant::now(),
                used: 0,
            })),
            max_per_window: retry.budget_per_window,
            window: Duration::from_secs(retry.budget_window_secs),
        })
    }

    fn try_acquire(&self) -> bool {
        let now = Instant::now();
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if now.saturating_duration_since(state.window_started_at) >= self.window {
            state.window_started_at = now;
            state.used = 0;
        }
        if state.used >= self.max_per_window {
            return false;
        }
        state.used = state.used.saturating_add(1);
        true
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
        let configured_root = root;
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
        let fpm_root = if let Some(configured_fpm_root) = &config.fpm_root {
            match configured_fpm_root.canonicalize() {
                Ok(resolved) => resolved,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    configured_fpm_root.clone()
                }
                Err(error) => {
                    return Err(io::Error::new(
                        error.kind(),
                        format!(
                            "{scope}: php fpm_root {}: {error}",
                            configured_fpm_root.display()
                        ),
                    ));
                }
            }
        } else {
            root.clone()
        };
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
        let mut runtime_config = config.clone();
        let managed_fpm =
            crate::php_fpm::managed_php_fpm_from_config(&scope, metric_pool, &mut runtime_config)?;
        let fpm_pools =
            php_fpm_keepalive_pools_from_config(&runtime_config, metric_vhost, metric_pool);
        Ok(Some(Self {
            fpm_pools,
            fpm_next: Arc::new(AtomicUsize::new(0)),
            _managed_fpm: managed_fpm,
            config: runtime_config,
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
        #[cfg(feature = "load-balancer")] load_balancer: Option<UpstreamLoadBalancer>,
    ) -> io::Result<Self> {
        #[cfg(not(feature = "cache"))]
        let _ = vhost_name;

        let headers = base_headers.with_vhost_overlay(&route.headers);
        let matcher = RuntimeRouteMatcher::from_config(vhost_name, route)?;
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
            name: route.name.clone(),
            matcher,
            methods: route.methods.clone(),
            https_redirect_exempt: route.https_redirect_exempt,
            strip_prefix: route.strip_prefix.clone(),
            rewrite_prefix: route.rewrite_prefix.clone(),
            rewrite_template: route.rewrite_template.clone(),
            max_request_body_bytes: route.max_request_body_bytes,
            access: RuntimeAccessPolicy::from_config(&route.access)?,
            rate_limit: RuntimeRateLimit::from_config(&route.rate_limit),
            concurrency: RuntimeConcurrencyLimit::from_config(&route.concurrency),
            grpc: route.grpc,
            action,
            #[cfg(feature = "load-balancer")]
            load_balancer,
            #[cfg(feature = "cache")]
            cache: route
                .cache
                .as_ref()
                .map(|cache| RuntimeRouteCache::from_config(vhost_name, &route.name, cache))
                .transpose()?,
            #[cfg(feature = "compression")]
            compression: route.compression.clone(),
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
            name: "acme-http-01".to_owned(),
            matcher: RuntimeRouteMatcher::Prefix("/.well-known/acme-challenge/".to_owned()),
            methods: Vec::new(),
            https_redirect_exempt: true,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: RuntimeAccessPolicy::default(),
            rate_limit: RuntimeRateLimit::default(),
            concurrency: RuntimeConcurrencyLimit::default(),
            grpc: crate::config::GrpcRouteConfig::default(),
            action: RuntimeRouteAction::AcmeHttp01(crate::acme::AcmeHttp01ChallengeStore::new(
                storage, vhost_name,
            )),
            #[cfg(feature = "load-balancer")]
            load_balancer: None,
            #[cfg(feature = "cache")]
            cache: None,
            #[cfg(feature = "compression")]
            compression: None,
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
    fn route_index(&self, method: &str, path: &str) -> Option<usize> {
        let mut fallback = None;
        let mut best_prefix: Option<(usize, usize)> = None;
        let mut first_regex = None;

        for (index, route) in self.routes.iter().enumerate() {
            if !route_method_matches(&route.methods, method) {
                continue;
            }
            match &route.matcher {
                RuntimeRouteMatcher::Exact(_) if route.matcher.matches_path(path) => {
                    return Some(index);
                }
                RuntimeRouteMatcher::Prefix(_) if route.matcher.matches_path(path) => {
                    let prefix_len = route.matcher.prefix_len().unwrap_or(0);
                    if best_prefix.is_none_or(|(_, len)| prefix_len > len) {
                        best_prefix = Some((index, prefix_len));
                    }
                }
                RuntimeRouteMatcher::Regex(_)
                    if first_regex.is_none() && route.matcher.matches_path(path) =>
                {
                    first_regex = Some(index);
                }
                RuntimeRouteMatcher::Fallback => fallback = Some(index),
                _ => {}
            }
        }

        best_prefix
            .map(|(index, _)| index)
            .or(first_regex)
            .or(fallback)
    }

    fn route(&self, index: usize) -> &RuntimeRoute {
        &self.routes[index]
    }

    fn route_regex_captures(
        &self,
        route_index: Option<usize>,
        path: &str,
    ) -> Option<crate::headers::RouteRegexCaptures> {
        let route = route_index.and_then(|index| self.routes.get(index))?;
        crate::route_policy::route_regex_captures(&route.matcher, path)
    }

    #[cfg(test)]
    fn route_index_by_path_for_tests(&self, path: &str) -> Option<usize> {
        self.route_index("GET", path)
    }

    fn from_legacy(
        proxy: ProxyConfig,
        #[cfg_attr(not(feature = "cache"), allow(unused_variables))]
        cache: crate::config::CacheConfig,
        #[cfg(feature = "compression")] compression: crate::config::CompressionConfig,
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
            access: RuntimeAccessPolicy::default(),
            rate_limit: RuntimeRateLimit::default(),
            concurrency: RuntimeConcurrencyLimit::default(),
            #[cfg(feature = "load-balancer")]
            load_balancer,
            proxy: RuntimeProxy::from_config(&proxy, "default proxy")?,
            request_headers: headers.request,
            response_headers: headers.response,
            #[cfg(feature = "compression")]
            compression,
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
        #[cfg(feature = "load-balancer")] mut route_load_balancers: Vec<
            Option<UpstreamLoadBalancer>,
        >,
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
                .enumerate()
                .map(|(index, route)| {
                    #[cfg(feature = "load-balancer")]
                    let route_load_balancer =
                        route_load_balancers.get_mut(index).and_then(Option::take);
                    #[cfg(not(feature = "load-balancer"))]
                    let _ = index;
                    RuntimeRoute::from_config(
                        &vhost.name,
                        &route,
                        &route_base_headers,
                        #[cfg(feature = "load-balancer")]
                        route_load_balancer,
                    )
                })
                .collect::<io::Result<Vec<_>>>()
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("vhost {:?} routes: {error}", vhost.name),
                    )
                })?,
        );
        #[cfg(feature = "cache")]
        let cache_config = vhost.cache.with_presets();
        #[cfg(feature = "cache")]
        let pingora_memory_storage =
            crate::cache::pingora_memory_storage_from_config_with_metric_scope(
                &cache_config,
                &vhost.name,
                None,
            );
        #[cfg(feature = "cache")]
        let pingora_disk_storage =
            crate::cache::pingora_disk_storage_backend_from_config_with_metric_scope(
                &cache_config,
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
            &cache_config,
            pingora_memory_storage.is_some() || pingora_disk_storage.is_some(),
        );
        #[cfg(feature = "cache")]
        let pingora_cache_predictor = cache_predictor_from_config(
            &cache_config,
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
            access: RuntimeAccessPolicy::from_config(&vhost.access)?,
            rate_limit: RuntimeRateLimit::from_config(&vhost.rate_limit),
            concurrency: RuntimeConcurrencyLimit::from_config(&vhost.concurrency),
            #[cfg(feature = "load-balancer")]
            load_balancer,
            proxy: RuntimeProxy::from_config(&vhost.proxy, &proxy_scope)?,
            request_headers: headers.request,
            response_headers: headers.response,
            #[cfg(feature = "compression")]
            compression: vhost
                .compression
                .clone()
                .unwrap_or_else(|| config.compression.clone()),
            #[cfg(feature = "cache")]
            memory_cache: crate::cache::memory_image_cache_from_config(&cache_config),
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
            cache_lock_wait_timeout: cache_lock_wait_timeout(&cache_config),
            #[cfg(feature = "cache")]
            cache: cache_config,
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
    in_flight_permits: Vec<InFlightPermit>,
    #[cfg(feature = "load-balancer")]
    upstream_load_balancer_permit: Option<crate::load_balancer::LoadBalancedConnectionPermit>,
    #[cfg(feature = "load-balancer")]
    upstream_load_balancer_reporter: Option<crate::load_balancer::LoadBalancedUpstreamReporter>,
    #[cfg(feature = "load-balancer")]
    upstream_load_balancer_outcome_recorded: bool,
    #[cfg(feature = "load-balancer")]
    upstream_load_balancer_selected_at: Option<Instant>,
    #[cfg(feature = "load-balancer")]
    upstream_load_balancer_retries: u8,
    #[cfg(feature = "load-balancer")]
    upstream_load_balancer_alias: Option<std::sync::Arc<str>>,
    request_body_bytes_seen: u64,
    response_body_bytes_seen: u64,
    health_signal_recorded: bool,
    #[cfg(not(feature = "privacy-mode"))]
    started_at: Option<Instant>,
    #[cfg(not(feature = "privacy-mode"))]
    request_id: Option<String>,
    #[cfg(not(feature = "privacy-mode"))]
    upstream: Option<String>,
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
    auth_request_headers: Vec<(String, String)>,
    #[cfg(all(feature = "php-fpm", feature = "otel-otlp"))]
    php_outcome: Option<&'static str>,
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    compression: Option<ResponseCompressionEncoder>,
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
        ctx.route_index = vhost.route_index(
            session.req_header().method.as_str(),
            session.req_header().uri.path(),
        );
        #[cfg(feature = "metrics")]
        let edge_policy_route = ctx
            .route_index
            .and_then(|route_index| vhost.routes.get(route_index))
            .map(|route| route.name.as_str());
        if request_denied_by_access_policy(session, &state, vhost, ctx.route_index) {
            #[cfg(feature = "metrics")]
            crate::metrics::record_edge_policy_event(
                vhost.name.as_str(),
                edge_policy_route,
                "access",
                "deny",
            );
            respond_text_error(session, 403, Bytes::from_static(b"forbidden")).await?;
            return Ok(true);
        }
        match request_limited_by_rate_policy(session, &state, vhost, ctx.route_index) {
            RateLimitDecision::Allow => {}
            RateLimitDecision::Delay(delay) => {
                #[cfg(feature = "metrics")]
                crate::metrics::record_edge_policy_event(
                    vhost.name.as_str(),
                    edge_policy_route,
                    "rate_limit",
                    "delay",
                );
                tokio::time::sleep(delay).await;
            }
            RateLimitDecision::Reject(status) => {
                #[cfg(feature = "metrics")]
                crate::metrics::record_edge_policy_event(
                    vhost.name.as_str(),
                    edge_policy_route,
                    "rate_limit",
                    "reject",
                );
                respond_text_error(session, status, Bytes::from_static(b"rate limited")).await?;
                return Ok(true);
            }
        }
        match acquire_request_concurrency_permits(vhost, ctx.route_index).await {
            Ok(permits) => ctx.in_flight_permits = permits,
            Err(status) => {
                #[cfg(feature = "metrics")]
                crate::metrics::record_edge_policy_event(
                    vhost.name.as_str(),
                    edge_policy_route,
                    "concurrency",
                    "reject",
                );
                respond_text_error(session, status, Bytes::from_static(b"too many requests"))
                    .await?;
                return Ok(true);
            }
        }
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
                        respond_text_error(
                            session,
                            502,
                            Bytes::from_static(b"proxy upstream not configured"),
                        )
                        .await?;
                        return Ok(true);
                    }
                    if let Some(status) =
                        grpc_route_rejection_status(&route.grpc, session.req_header())
                    {
                        match status {
                            GrpcRouteRejectionStatus::MethodNotAllowed => {
                                respond_method_not_allowed(
                                    session,
                                    &route.response_headers,
                                    "POST",
                                )
                                .await?;
                            }
                            GrpcRouteRejectionStatus::UnsupportedMediaType => {
                                respond_text_error(
                                    session,
                                    415,
                                    Bytes::from_static(b"unsupported media type"),
                                )
                                .await?;
                            }
                        }
                        return Ok(true);
                    }
                    if authorize_proxy_request(session, ctx, vhost).await? {
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
                    spawn_proxy_mirror_if_enabled(session.req_header(), vhost, ctx);
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
                        respond_text_error(
                            session,
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
                    respond_text_error(session, 403, Bytes::from_static(b"forbidden")).await?;
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
                    respond_text_error(session, 500, Bytes::from_static(b"internal server error"))
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
        {
            ctx.upstream_load_balancer_permit = None;
            ctx.upstream_load_balancer_reporter = None;
            ctx.upstream_load_balancer_outcome_recorded = false;
            ctx.upstream_load_balancer_selected_at = None;
            ctx.upstream_load_balancer_alias = None;
        }

        #[cfg(feature = "load-balancer")]
        if let Some(load_balancer) = selected_upstream_load_balancer(vhost, ctx)
            && let Some(selected) = load_balancer.select(
                session.req_header(),
                effective_acl_client_ip(session, &state),
            )
        {
            ctx.upstream_load_balancer_alias = selected.alias.clone();
            #[cfg(feature = "metrics")]
            record_load_balancer_metric(vhost, ctx, "selected");
            #[cfg(not(feature = "privacy-mode"))]
            {
                ctx.upstream = Some(selected.backend.addr.to_string());
            }
            ctx.upstream_load_balancer_permit = selected.permit;
            ctx.upstream_load_balancer_reporter = selected.reporter;
            ctx.upstream_load_balancer_selected_at = Some(Instant::now());
            let mut peer = http_peer_for_runtime_proxy(selected.backend, proxy)?;
            apply_upstream_proxy_protocol(&mut peer, &proxy.config, session, &state);
            return Ok(Box::new(peer));
        }
        #[cfg(feature = "load-balancer")]
        if selected_upstream_load_balancer(vhost, ctx).is_some() {
            #[cfg(feature = "metrics")]
            record_load_balancer_metric(vhost, ctx, "unavailable");
            return Error::e_explain(
                ErrorType::ConnectError,
                "no healthy load-balanced upstream is available",
            );
        }

        let upstream = proxy.config.configured_primary_upstream().ok_or_else(|| {
            Error::explain(
                ErrorType::ConnectError,
                "proxy upstream is not configured for selected vhost or route",
            )
        })?;
        #[cfg(not(feature = "privacy-mode"))]
        {
            ctx.upstream = Some(upstream.to_owned());
        }
        let mut peer = http_peer_for_runtime_proxy(upstream, proxy)?;
        apply_upstream_proxy_protocol(&mut peer, &proxy.config, session, &state);

        Ok(Box::new(peer))
    }

    fn fail_to_connect(
        &self,
        #[cfg_attr(not(feature = "load-balancer"), allow(unused_variables))] session: &mut Session,
        _peer: &HttpPeer,
        #[cfg_attr(not(feature = "load-balancer"), allow(unused_variables))] ctx: &mut Self::CTX,
        error: Box<Error>,
    ) -> Box<Error> {
        #[cfg(feature = "load-balancer")]
        {
            let mut error = error;
            let state = ctx.state.clone().unwrap_or_else(|| self.state.load_full());
            let vhost_index = ctx
                .vhost_index
                .unwrap_or_else(|| state.vhost_index(request_host(session)));
            let vhost = state.vhost(vhost_index);
            if let Some(outcome) = record_load_balanced_upstream_failure(ctx) {
                #[cfg(feature = "metrics")]
                {
                    record_load_balancer_metric(vhost, ctx, "failure");
                    if outcome.ejected {
                        record_load_balancer_metric(vhost, ctx, "ejected");
                    }
                }
                #[cfg(not(feature = "metrics"))]
                let _ = outcome;
            }
            let proxy = selected_runtime_proxy(vhost, ctx);
            let retry = &proxy.config.load_balance.retry;
            if selected_upstream_load_balancer(vhost, ctx).is_some()
                && retry.enabled
                && ctx.upstream_load_balancer_retries < retry.max_retries
                && load_balance_retry_method_allowed(retry, session.req_header().method.as_str())
                && proxy
                    .retry_budget
                    .as_ref()
                    .is_none_or(RuntimeRetryBudget::try_acquire)
            {
                ctx.upstream_load_balancer_retries =
                    ctx.upstream_load_balancer_retries.saturating_add(1);
                #[cfg(feature = "metrics")]
                record_load_balancer_metric(vhost, ctx, "retry");
                error.set_retry(true);
            }
            error
        }
        #[cfg(not(feature = "load-balancer"))]
        {
            error
        }
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
        let tls_identity = downstream_tls_client_identity(session);
        let route_regex_captures =
            vhost.route_regex_captures(ctx.route_index, session.req_header().uri.path());
        crate::headers::apply_upstream_request_policy(
            upstream_request,
            request_headers,
            crate::headers::UpstreamRequestPolicyContext {
                client_addr,
                trusted_proxy,
                trusted_proxy_matcher: Some(&trusted_proxy_matcher),
                downstream_tls,
                request_id,
                tls_identity: tls_identity.as_ref(),
                route_regex_captures: route_regex_captures.as_ref(),
            },
        )?;
        for (name, value) in &ctx.auth_request_headers {
            upstream_request.insert_header(name.clone(), value.clone())?;
        }
        apply_websocket_upgrade_headers_if_enabled(
            session.req_header(),
            upstream_request,
            &selected_runtime_proxy(vhost, ctx).config,
        )?;
        normalize_cookie_headers(upstream_request)?;
        append_fluxheim_via_to_request(upstream_request)?;

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
        crate::headers::apply_response_policy(response, response_headers)?;
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        prepare_response_compression(
            session.req_header(),
            response,
            selected_compression_config(vhost, ctx),
            ctx,
        )?;
        #[cfg(all(
            feature = "metrics",
            any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            )
        ))]
        if let Some(compression) = ctx.compression.as_ref() {
            let route = ctx
                .route_index
                .and_then(|route_index| vhost.routes.get(route_index))
                .map(|route| route.name.as_str());
            crate::metrics::record_response_compression(
                vhost.name.as_str(),
                route,
                compression.encoding,
            );
        }
        #[cfg(feature = "load-balancer")]
        if let Some(outcome) = record_load_balanced_upstream_status(ctx, response.status.as_u16()) {
            #[cfg(feature = "metrics")]
            {
                record_load_balancer_metric(
                    vhost,
                    ctx,
                    if outcome.failed { "failure" } else { "success" },
                );
                if outcome.ejected {
                    record_load_balancer_metric(vhost, ctx, "ejected");
                }
            }
            #[cfg(not(feature = "metrics"))]
            let _ = outcome;
        }
        append_fluxheim_via_to_response(response)
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
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        if let Some(compression) = &mut ctx.compression {
            let encoded = compression
                .encode_chunk(body.as_ref(), _end_of_stream)
                .map_err(|error| {
                    Error::because(
                        ErrorType::InternalError,
                        "response compression failed",
                        error,
                    )
                })?;
            *body = (!encoded.is_empty()).then_some(encoded);
        }

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
        #[cfg(feature = "load-balancer")]
        record_load_balanced_upstream_failure(ctx);
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

        if proxy_upgrade_request_allowed(
            session.req_header(),
            &selected_runtime_proxy(vhost, ctx).config,
        ) {
            #[cfg(feature = "metrics")]
            record_cache_policy_activity(vhost, ctx.route_index, "bypass");
            ctx.cache_status_override = Some(CacheStatusOverride {
                status: "BYPASS",
                reason: Some(CACHE_UPGRADE_BYPASS_REASON),
            });
            return Ok(());
        }

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

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn prepare_response_compression(
    request: &RequestHeader,
    response: &mut ResponseHeader,
    config: &crate::config::CompressionConfig,
    ctx: &mut RequestContext,
) -> Result<()> {
    ctx.compression = crate::compression::prepare_response_compression(request, response, config)?;
    Ok(())
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
        let mut counters = match SLICE_FILL_CONCURRENCY
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            Ok(guard) => guard,
            Err(_) => {
                log::error!(
                    target: "fluxheim::security",
                    "slice-fill concurrency lock poisoned; aborting to avoid inconsistent cache-fill limits"
                );
                std::process::abort();
            }
        };
        prune_inactive_cache_fill_concurrency_counters(
            &mut counters,
            SLICE_FILL_CONCURRENCY_MAX_KEYS,
        );
        if counters.len() >= SLICE_FILL_CONCURRENCY_MAX_KEYS && !counters.contains_key(&key) {
            return None;
        }
        counters
            .entry(key.clone())
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
        let mut counters = match PEER_FILL_CONCURRENCY
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            Ok(guard) => guard,
            Err(_) => {
                log::error!(
                    target: "fluxheim::security",
                    "peer-fill concurrency lock poisoned; aborting to avoid inconsistent cache-fill limits"
                );
                std::process::abort();
            }
        };
        prune_inactive_cache_fill_concurrency_counters(
            &mut counters,
            PEER_FILL_CONCURRENCY_MAX_KEYS,
        );
        if counters.len() >= PEER_FILL_CONCURRENCY_MAX_KEYS && !counters.contains_key(&key) {
            return None;
        }
        counters
            .entry(key.clone())
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone()
    };

    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= max_concurrent_requests {
            return None;
        }
        let Some(next) = current.checked_add(1) else {
            log::error!(
                target: "fluxheim::security",
                "peer-fill concurrency counter saturated for {key}; refusing permit"
            );
            return None;
        };
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(PeerFillConcurrencyPermit { counter }),
            Err(observed) => current = observed,
        }
    }
}

#[cfg(feature = "cache")]
fn prune_inactive_cache_fill_concurrency_counters(
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

fn downstream_tls_client_identity(
    session: &Session,
) -> Option<crate::headers::RequestTlsClientIdentity> {
    session
        .digest()
        .and_then(|digest| digest.ssl_digest.as_deref())
        .map(crate::headers::RequestTlsClientIdentity::from_ssl_digest)
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
    respond_text_error(
        session,
        reason.status(),
        Bytes::from_static(reason.response_body()),
    )
    .await
}

async fn respond_text_error(session: &mut Session, status: u16, body: Bytes) -> Result<()> {
    let mut response = ResponseHeader::build(status, Some(4))?;
    response.insert_header("content-type", "text/plain; charset=utf-8")?;
    response.insert_header("cache-control", "no-store")?;
    response.insert_header("content-length", body.len().to_string())?;
    let send_body = !body.is_empty() && session.req_header().method.as_str() != "HEAD";
    session
        .write_response_header(Box::new(response), !send_body)
        .await?;
    if send_body {
        session.write_response_body(Some(body), true).await
    } else {
        Ok(())
    }
}

#[cfg(feature = "php-fpm")]
const MAX_PHP_PARAM_VALUE_BYTES: usize = 16 * 1024;
#[cfg(feature = "php-fpm")]
const DEFAULT_PHP_REQUEST_BODY_LIMIT_BYTES: u64 = 64 * 1024 * 1024;

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
    ctx: &mut RequestContext,
    vhost: &RuntimeVhost,
    method: &str,
    status: Option<u16>,
    outcome: &'static str,
    started_at: Instant,
) {
    #[cfg(feature = "otel-otlp")]
    {
        ctx.php_outcome = Some(outcome);
    }
    #[cfg(not(feature = "otel-otlp"))]
    {
        let _ = ctx;
    }
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

#[cfg(feature = "php-fpm")]
fn php_server_port(session: &Session, is_tls: bool) -> u16 {
    request_host(session)
        .and_then(explicit_authority_port)
        .unwrap_or(if is_tls { 443 } else { 80 })
}

#[cfg(feature = "php-fpm")]
fn explicit_authority_port(authority: &str) -> Option<u16> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (_, after_host) = rest.split_once(']')?;
        return after_host.strip_prefix(':')?.parse().ok();
    }
    let (_, port) = authority.rsplit_once(':')?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    port.parse().ok()
}

#[cfg(feature = "php-fpm")]
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
            record_php_request_metrics(ctx, vhost, &method, Some(308), "redirect", started_at);
            return Ok(true);
        }
        PhpResolveOutcome::Decline => {
            record_php_request_metrics(ctx, vhost, &method, None, "declined", started_at);
            return Ok(false);
        }
        PhpResolveOutcome::Forbidden => {
            respond_text_error(session, 403, Bytes::from_static(b"forbidden")).await?;
            record_php_request_metrics(ctx, vhost, &method, Some(403), "forbidden", started_at);
            return Ok(true);
        }
        PhpResolveOutcome::NotFound => {
            respond_text_error(session, 404, Bytes::from_static(b"not found")).await?;
            record_php_request_metrics(ctx, vhost, &method, Some(404), "not_found", started_at);
            return Ok(true);
        }
    };

    let body_limit = php
        .config
        .max_request_body_bytes
        .map(|bytes| bytes.as_u64())
        .or(ctx.request_body_limit_bytes)
        .unwrap_or(DEFAULT_PHP_REQUEST_BODY_LIMIT_BYTES);
    let request_body = if php.config.pass_request_body {
        read_php_request_body(session, ctx, &php.config, body_limit).await?
    } else {
        drain_php_request_body(session, ctx, body_limit).await?;
        PhpRequestBody::memory(Vec::new())
    };
    let content_type = if php.config.pass_request_body {
        php_content_type_param(session.req_header())
    } else {
        String::new()
    };
    let is_tls = downstream_tls(session);
    let request_scheme = if is_tls { "https" } else { "http" };
    let server_port = php
        .config
        .server_port
        .unwrap_or_else(|| php_server_port(session, is_tls));
    let remote = session.client_addr().and_then(|address| address.as_inet());
    let Some(remote) = remote else {
        return Err(Error::because(
            ErrorType::HTTPStatus(502),
            "php-fpm: cannot determine client address",
            io::Error::new(io::ErrorKind::AddrNotAvailable, "no client address"),
        ));
    };
    let remote_addr = remote.ip().to_string();
    let remote_port = remote.port();
    let document_root = php
        .fpm_root
        .to_str()
        .ok_or_else(|| {
            Error::because(
                ErrorType::InternalError,
                "php-fpm: fpm_root is not valid UTF-8",
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "php fpm_root is not valid UTF-8",
                ),
            )
        })?
        .to_owned();
    let script_filename = php_fpm_script_filename(php, &resolution.file.path).ok_or_else(|| {
        Error::because(
            ErrorType::InternalError,
            "php-fpm: script path is not valid UTF-8 or outside php.root",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "php script path is not valid UTF-8",
            ),
        )
    })?;
    let host = request_host(session).unwrap_or(vhost.name.as_str());
    let server_name = php_server_name_param(host, vhost.name.as_str());

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
        .server_name(server_name)
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
        let path_translated =
            php_fpm_path_translated(php, &resolution.path_info).ok_or_else(|| {
                Error::because(
                    ErrorType::InternalError,
                    "php-fpm: translated path is not valid UTF-8",
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "php translated path is not valid UTF-8",
                    ),
                )
            })?;
        params = params.custom("PATH_TRANSLATED", path_translated);
    }

    let timeout = std::time::Duration::from_secs(php.config.request_timeout_secs);
    let parsed = match execute_php_fpm(
        php,
        params,
        request_body,
        timeout,
        &method,
        vhost.name.as_str(),
    )
    .await
    {
        Ok(parsed) => parsed,
        Err(error) => {
            record_php_request_metrics(
                ctx,
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
    if let Some(stderr) = parsed.stderr.as_deref()
        && !stderr.is_empty()
    {
        #[cfg(feature = "metrics")]
        crate::metrics::record_php_stderr(
            vhost.name.as_str(),
            php_stderr_metric_state(stderr, php.config.stderr_max_bytes.as_u64() as usize),
        );
        log_php_stderr_if_enabled(&php.config, stderr);
    }
    let PhpFpmParsedResponse {
        mut response, body, ..
    } = parsed;
    apply_php_x_accel_expires(&mut response).map_err(|error| {
        Error::because(
            ErrorType::HTTPStatus(502),
            "php-fpm response cache controls were invalid",
            error,
        )
    })?;
    ignore_php_origin_cache_headers(&mut response, &php.config);
    if response.status == StatusCode::OK {
        match php_static_offload_file(&mut response, php) {
            Ok(Some(file)) => {
                let status =
                    respond_php_static_offload(session, ctx, php, &file, &method, response_headers)
                        .await?;
                record_php_request_metrics(
                    ctx,
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
                    ctx,
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
        record_php_request_metrics(ctx, vhost, &method, Some(status), "intercepted", started_at);
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
        ctx,
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
        respond_text_error(
            session,
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
        respond_text_error(session, 400, Bytes::from_static(b"invalid redirect target")).await?;
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
    php.fpm_root.join(relative).to_str().map(str::to_owned)
}

#[cfg(feature = "php-fpm")]
fn php_fpm_path_translated(php: &RuntimePhp, path_info: &str) -> Option<String> {
    let mut translated = php.fpm_root.clone();
    for segment in path_info.trim_start_matches('/').split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.starts_with('.')
            || segment.contains('\\')
            || segment.contains('\0')
        {
            return None;
        }
        translated.push(segment);
    }
    translated.to_str().map(str::to_owned)
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
                let separator = if name.as_str().eq_ignore_ascii_case("cookie") {
                    "; "
                } else {
                    ", "
                };
                if existing
                    .len()
                    .saturating_add(separator.len())
                    .saturating_add(value.len())
                    <= MAX_PHP_PARAM_VALUE_BYTES
                {
                    existing.push_str(separator);
                    existing.push_str(value);
                }
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
fn php_server_name_param(host: &str, fallback: &str) -> String {
    if safe_php_param_value(host) && !host.is_empty() {
        return host.to_owned();
    }
    if safe_php_param_value(fallback) && !fallback.is_empty() {
        return fallback.to_owned();
    }
    "localhost".to_owned()
}

#[cfg(feature = "php-fpm")]
fn php_content_type_param(request: &RequestHeader) -> String {
    request_header_values_joined(request, "content-type")
        .filter(|value| safe_php_param_value(value))
        .unwrap_or_default()
}

#[cfg(feature = "php-fpm")]
fn add_php_custom_params(
    params: &mut fastcgi_client::Params<'_>,
    custom: &std::collections::BTreeMap<String, String>,
) {
    for (name, value) in custom {
        if crate::config::protected_php_param_name(name) || !safe_php_param_value(value) {
            log::warn!("dropping invalid custom FastCGI param: {name}");
            continue;
        }
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
fn php_spool_error(context: &'static str, error: io::Error) -> Box<Error> {
    Error::because(ErrorType::InternalError, context, error)
}

#[cfg(feature = "php-fpm")]
async fn read_php_request_body(
    session: &mut Session,
    ctx: &mut RequestContext,
    config: &crate::config::PhpConfig,
    limit_bytes: u64,
) -> Result<PhpRequestBody> {
    use tokio::io::AsyncWriteExt;

    let spool_threshold = config
        .request_body_spool_threshold_bytes
        .map(|bytes| usize::try_from(bytes.as_u64()).unwrap_or(usize::MAX));
    let spool_dir = config.request_body_spool_dir.as_deref();
    let mut body = Vec::new();
    let mut spool: Option<(PathBuf, tokio::fs::File)> = None;
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
        if let Some((_, file)) = &mut spool {
            file.write_all(&chunk).await.map_err(|error| {
                php_spool_error("failed to write PHP request body spool file", error)
            })?;
            continue;
        }
        if let (Some(threshold), Some(spool_dir)) = (spool_threshold, spool_dir)
            && body.len().saturating_add(chunk.len()) > threshold
        {
            let (path, mut file) = create_php_request_body_spool_file(spool_dir)
                .await
                .map_err(|error| {
                    php_spool_error("failed to create PHP request body spool file", error)
                })?;
            if !body.is_empty() {
                file.write_all(&body).await.map_err(|error| {
                    php_spool_error("failed to write PHP request body spool file", error)
                })?;
                body.clear();
            }
            file.write_all(&chunk).await.map_err(|error| {
                php_spool_error("failed to write PHP request body spool file", error)
            })?;
            spool = Some((path, file));
        } else {
            body.extend_from_slice(&chunk);
        }
    }
    if let Some((path, mut file)) = spool {
        file.flush().await.map_err(|error| {
            php_spool_error("failed to flush PHP request body spool file", error)
        })?;
        Ok(PhpRequestBody::spooled(
            path,
            ctx.request_body_bytes_seen.min(usize::MAX as u64) as usize,
        ))
    } else {
        Ok(PhpRequestBody::memory(body))
    }
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
async fn execute_php_fpm(
    php: &RuntimePhp,
    params: fastcgi_client::Params<'_>,
    body: PhpRequestBody,
    timeout: std::time::Duration,
    method: &str,
    vhost_name: &str,
) -> io::Result<PhpFpmParsedResponse> {
    #[cfg(not(feature = "metrics"))]
    let _ = vhost_name;

    let fpm = &php.config.fpm;
    let endpoints = php_fpm_endpoints_from_config(fpm);
    if endpoints.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "php-fpm socket, tcp, or tcp_upstreams is required",
        ));
    }

    let connect_timeout = php_fpm_effective_connect_timeout(fpm, timeout);
    let request_timeout = php_fpm_effective_request_timeout(fpm, timeout);
    let max_retries = php_fpm_retry_attempts_for_endpoint_count(fpm, method, endpoints.len());
    let retry_deadline = php_fpm_retry_deadline(fpm.retry_timeout_secs);
    let start_index = php_fpm_select_endpoint_index(php, endpoints.len());
    let mut attempts = 0_u8;
    loop {
        let endpoint_index = (start_index + usize::from(attempts)) % endpoints.len();
        let pool = php.fpm_pools.get(endpoint_index).map(Arc::as_ref);
        let result = execute_php_fpm_once(
            pool,
            &endpoints[endpoint_index],
            params.clone(),
            &body,
            connect_timeout,
            request_timeout,
            php.config.max_response_bytes.as_u64(),
        )
        .await;
        match result {
            Ok(output) => match parse_php_fpm_output(php, output) {
                Ok(parsed)
                    if php_fpm_retryable_response(&php.config.fpm, parsed.response.status) =>
                {
                    if attempts < max_retries && php_fpm_retry_deadline_allows(retry_deadline) {
                        attempts += 1;
                        #[cfg(feature = "metrics")]
                        crate::metrics::record_php_fpm_retry(vhost_name, "response_status");
                        log::debug!(
                            "retrying php-fpm request after retryable status {}",
                            parsed.response.status.as_u16()
                        );
                        continue;
                    }
                    return Ok(parsed);
                }
                Ok(parsed) => return Ok(parsed),
                Err(error)
                    if php.config.fpm.retry_invalid_response
                        && attempts < max_retries
                        && php_fpm_retry_deadline_allows(retry_deadline) =>
                {
                    attempts += 1;
                    #[cfg(feature = "metrics")]
                    crate::metrics::record_php_fpm_retry(vhost_name, "invalid_response");
                    log::debug!("retrying php-fpm request after invalid response: {}", error);
                }
                Err(error) => return Err(error),
            },
            Err(error)
                if attempts < max_retries
                    && php_fpm_retryable_error(&error)
                    && php_fpm_retry_deadline_allows(retry_deadline) =>
            {
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
fn php_fpm_select_endpoint_index(php: &RuntimePhp, endpoint_count: usize) -> usize {
    if endpoint_count <= 1 {
        return 0;
    }
    php.fpm_next.fetch_add(1, Ordering::Relaxed) % endpoint_count
}

#[cfg(feature = "php-fpm")]
fn parse_php_fpm_output(
    php: &RuntimePhp,
    output: fastcgi_client::Response,
) -> io::Result<PhpFpmParsedResponse> {
    let stdout = output.stdout.unwrap_or_default();
    let (response, body) = parse_php_response(
        &stdout,
        php.config.max_response_bytes.as_u64(),
        php.config.max_response_header_bytes.as_u64(),
    )?;
    if let Some(stderr) = output.stderr.as_deref()
        && php_stderr_matches_failure_pattern(stderr, &php.config)
    {
        log_php_stderr_if_enabled(&php.config, stderr);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "php-fpm stderr matched configured failure pattern",
        ));
    }
    Ok(PhpFpmParsedResponse {
        response,
        body,
        stderr: output.stderr,
    })
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
#[doc(hidden)]
pub fn fuzz_parse_php_response(stdout: &[u8]) -> io::Result<()> {
    crate::php_fpm::fuzz_parse_php_response(stdout)
}

#[cfg(all(feature = "php-fpm", any(feature = "metrics", test)))]
fn php_stderr_metric_state(stderr: &[u8], max_bytes: usize) -> &'static str {
    if stderr.len() > max_bytes {
        "truncated"
    } else {
        "emitted"
    }
}

#[cfg(feature = "php-fpm")]
fn log_php_stderr(level: crate::config::PhpStderrLogLevel, message: &str) {
    match level {
        crate::config::PhpStderrLogLevel::Error => log::error!("php-fpm stderr: {message}"),
        crate::config::PhpStderrLogLevel::Warn => log::warn!("php-fpm stderr: {message}"),
        crate::config::PhpStderrLogLevel::Info => log::info!("php-fpm stderr: {message}"),
        crate::config::PhpStderrLogLevel::Debug => log::debug!("php-fpm stderr: {message}"),
    }
}

#[cfg(feature = "php-fpm")]
fn log_php_stderr_if_enabled(config: &crate::config::PhpConfig, stderr: &[u8]) {
    if config.stderr_log {
        log_php_stderr(
            config.stderr_log_level,
            &sanitized_php_stderr(stderr, config.stderr_max_bytes.as_u64() as usize),
        );
    }
}

#[cfg(feature = "php-fpm")]
fn php_stderr_matches_failure_pattern(stderr: &[u8], config: &crate::config::PhpConfig) -> bool {
    config.stderr_failure_patterns.iter().any(|pattern| {
        let pattern = pattern.as_bytes();
        !pattern.is_empty()
            && stderr
                .windows(pattern.len())
                .any(|window| window == pattern)
    })
}

#[cfg(feature = "php-fpm")]
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
                respond_text_error(
                    session,
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
            respond_text_error(session, 403, Bytes::from_static(b"forbidden")).await?;
            Ok(true)
        }
        Ok(ResolveResult::NotFound) => Ok(false),
        Err(error) => {
            log::error!("static route resolver failed: {error}");
            respond_text_error(session, 500, Bytes::from_static(b"internal server error")).await?;
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

#[cfg(feature = "load-balancer")]
fn selected_upstream_load_balancer<'a>(
    vhost: &'a RuntimeVhost,
    ctx: &RequestContext,
) -> Option<&'a UpstreamLoadBalancer> {
    if let Some(route_index) = ctx.route_index {
        let route = vhost.route(route_index);
        if matches!(route.action, RuntimeRouteAction::Proxy(_)) {
            return route.load_balancer.as_ref();
        }
    }
    vhost.load_balancer.as_ref()
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

#[cfg_attr(not(feature = "cache"), allow(dead_code))]
fn proxy_upgrade_request_allowed(request: &RequestHeader, proxy: &ProxyConfig) -> bool {
    proxy.websocket && http_upgrade_request_value(request).is_some()
}

fn apply_websocket_upgrade_headers_if_enabled(
    downstream_request: &RequestHeader,
    upstream_request: &mut RequestHeader,
    proxy: &ProxyConfig,
) -> Result<()> {
    let Some(upgrade) = http_upgrade_request_value(downstream_request) else {
        return Ok(());
    };
    if !proxy.websocket {
        return Ok(());
    }

    upstream_request.remove_header("connection");
    upstream_request.remove_header("upgrade");
    upstream_request.insert_header("connection", "upgrade")?;
    upstream_request.insert_header("upgrade", upgrade)?;
    Ok(())
}

fn http_upgrade_request_value(request: &RequestHeader) -> Option<&str> {
    if !request_header_values(request, "connection")
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|token| token.eq_ignore_ascii_case("upgrade"))
    {
        return None;
    }
    request_header_values(request, "upgrade")
        .map(str::trim)
        .find(|value| valid_http_upgrade_token(value))
}

fn valid_http_upgrade_token(value: &str) -> bool {
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
                    | b'a'..=b'z'
            )
        })
}

async fn authorize_proxy_request(
    session: &mut Session,
    ctx: &mut RequestContext,
    vhost: &RuntimeVhost,
) -> Result<bool> {
    let auth = &selected_runtime_proxy(vhost, ctx).config.auth_request;
    if !auth.enabled {
        return Ok(false);
    }
    #[cfg(feature = "metrics")]
    let edge_policy_route = ctx
        .route_index
        .and_then(|route_index| vhost.routes.get(route_index))
        .map(|route| route.name.as_str());
    let input = crate::auth_request::auth_request_input(session.req_header(), auth);
    let auth = auth.clone();
    let decision = match tokio::task::spawn_blocking(move || {
        crate::auth_request::fetch_auth_request_decision(&auth, &input)
    })
    .await
    {
        Ok(Ok(decision)) => decision,
        Ok(Err(error)) => {
            #[cfg(feature = "metrics")]
            crate::metrics::record_edge_policy_event(
                vhost.name.as_str(),
                edge_policy_route,
                "auth_request",
                "error",
            );
            return Err(Error::because(
                ErrorType::HTTPStatus(502),
                "auth_request subrequest failed",
                error,
            ));
        }
        Err(error) => {
            #[cfg(feature = "metrics")]
            crate::metrics::record_edge_policy_event(
                vhost.name.as_str(),
                edge_policy_route,
                "auth_request",
                "error",
            );
            return Err(Error::because(
                ErrorType::InternalError,
                "auth_request worker task failed",
                error,
            ));
        }
    };

    match decision {
        crate::auth_request::AuthRequestDecision::Allow { headers } => {
            #[cfg(feature = "metrics")]
            crate::metrics::record_edge_policy_event(
                vhost.name.as_str(),
                edge_policy_route,
                "auth_request",
                "allow",
            );
            ctx.auth_request_headers = headers;
            Ok(false)
        }
        crate::auth_request::AuthRequestDecision::Deny { status, body } => {
            #[cfg(feature = "metrics")]
            crate::metrics::record_edge_policy_event(
                vhost.name.as_str(),
                edge_policy_route,
                "auth_request",
                "deny",
            );
            respond_text_error(session, status, body).await?;
            Ok(true)
        }
    }
}

fn spawn_proxy_mirror_if_enabled(
    request: &RequestHeader,
    vhost: &RuntimeVhost,
    ctx: &RequestContext,
) {
    #[cfg(not(feature = "traffic-mirror"))]
    {
        let _ = request;
        let _ = vhost;
        let _ = ctx;
    }

    #[cfg(feature = "traffic-mirror")]
    {
        let mirror = &selected_runtime_proxy(vhost, ctx).config.mirror;
        let route_name = ctx
            .route_index
            .and_then(|route_index| vhost.routes.get(route_index))
            .map(|route| route.name.as_str());
        crate::traffic_mirror::spawn_proxy_mirror_if_enabled(
            request,
            mirror,
            crate::traffic_mirror::TrafficMirrorRouteContext {
                vhost_name: vhost.name.as_str(),
                route_name,
            },
        );
    }
}

async fn continue_to_proxy_or_not_found(
    session: &mut Session,
    vhost: &RuntimeVhost,
    ctx: &mut RequestContext,
) -> Result<bool> {
    if selected_runtime_proxy(vhost, ctx).enabled {
        if authorize_proxy_request(session, ctx, vhost).await? {
            return Ok(true);
        }
        spawn_proxy_mirror_if_enabled(session.req_header(), vhost, ctx);
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

#[cfg(feature = "compression")]
fn selected_compression_config<'a>(
    vhost: &'a RuntimeVhost,
    ctx: &RequestContext,
) -> &'a crate::config::CompressionConfig {
    ctx.route_index
        .and_then(|route_index| vhost.route(route_index).compression.as_ref())
        .unwrap_or(&vhost.compression)
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
fn ignore_php_origin_cache_headers(response: &mut ResponseHeader, php: &crate::config::PhpConfig) {
    if !php.ignore_origin_cache_headers {
        return;
    }
    response.remove_header("cache-control");
    response.remove_header("expires");
    response.remove_header("pragma");
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
    let relative = target_path.strip_prefix(&php.fpm_root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "php X-Sendfile target is outside php.fpm_root",
        )
    })?;
    if relative
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "php X-Sendfile target escapes php root",
        ));
    }
    let local_path = php.root.join(relative);
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
const CACHE_UPGRADE_BYPASS_REASON: &str = "upgrade";

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
        respond_method_not_allowed(session, &route.response_headers, "GET, HEAD").await?;
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
            respond_text_error(session, 500, Bytes::from_static(b"internal server error")).await?;
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

async fn respond_method_not_allowed(
    session: &mut Session,
    response_policy: &crate::config::ResponseHeaderPolicyConfig,
    allow: &str,
) -> Result<()> {
    let mut response = ResponseHeader::build(405, Some(4))?;
    response.insert_header("allow", allow)?;
    response.insert_header("content-length", "0")?;
    crate::headers::apply_response_policy(&mut response, response_policy)?;
    session
        .write_response_header(Box::new(response), true)
        .await
}

const FLUXHEIM_VIA_VALUE: &str = "1.1 fluxheim";

fn append_fluxheim_via_value(existing: &str) -> String {
    if existing.trim().is_empty() {
        FLUXHEIM_VIA_VALUE.to_owned()
    } else {
        format!("{}, {}", existing.trim(), FLUXHEIM_VIA_VALUE)
    }
}

fn append_fluxheim_via_to_request(request: &mut RequestHeader) -> Result<()> {
    let existing = request
        .headers
        .get_all("via")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ");
    request.remove_header("via");
    request.insert_header("via", append_fluxheim_via_value(&existing))
}

fn append_fluxheim_via_to_response(response: &mut ResponseHeader) -> Result<()> {
    let existing = response
        .headers
        .get_all("via")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ");
    response.remove_header("via");
    response.insert_header("via", append_fluxheim_via_value(&existing))
}

#[cfg(feature = "load-balancer")]
fn record_load_balanced_upstream_status(
    ctx: &mut RequestContext,
    status: u16,
) -> Option<LoadBalancedUpstreamOutcome> {
    if ctx.upstream_load_balancer_outcome_recorded {
        return None;
    }
    let latency = ctx
        .upstream_load_balancer_selected_at
        .map(|selected_at| selected_at.elapsed());
    if let Some(reporter) = &ctx.upstream_load_balancer_reporter {
        let outcome = reporter.record_status(status, latency);
        ctx.upstream_load_balancer_outcome_recorded = true;
        return Some(outcome);
    }
    if ctx.upstream_load_balancer_selected_at.is_some() {
        ctx.upstream_load_balancer_outcome_recorded = true;
        return Some(LoadBalancedUpstreamOutcome {
            failed: (500..=599).contains(&status),
            ejected: false,
        });
    }
    None
}

#[cfg(feature = "load-balancer")]
fn record_load_balanced_upstream_failure(
    ctx: &mut RequestContext,
) -> Option<LoadBalancedUpstreamOutcome> {
    if ctx.upstream_load_balancer_outcome_recorded {
        return None;
    }
    if let Some(reporter) = &ctx.upstream_load_balancer_reporter {
        let outcome = reporter.record_failure();
        ctx.upstream_load_balancer_outcome_recorded = true;
        return Some(outcome);
    }
    if ctx.upstream_load_balancer_selected_at.is_some() {
        ctx.upstream_load_balancer_outcome_recorded = true;
        return Some(LoadBalancedUpstreamOutcome {
            failed: true,
            ejected: false,
        });
    }
    None
}

#[cfg(all(feature = "load-balancer", feature = "metrics"))]
fn record_load_balancer_metric(vhost: &RuntimeVhost, ctx: &RequestContext, event: &str) {
    let route = ctx
        .route_index
        .and_then(|route_index| vhost.routes.get(route_index))
        .map(|route| route.name.as_str());
    crate::metrics::record_load_balancer_event(
        vhost.name.as_str(),
        route,
        ctx.upstream_load_balancer_alias.as_deref(),
        event,
    );
}

#[cfg(feature = "load-balancer")]
fn load_balance_retry_method_allowed(
    retry: &crate::config::LoadBalanceRetryConfig,
    method: &str,
) -> bool {
    retry
        .methods
        .iter()
        .any(|configured| configured.eq_ignore_ascii_case(method))
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
        respond_text_error(session, 400, Bytes::from_static(b"invalid redirect target")).await?;
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
        respond_text_error(session, 400, Bytes::from_static(b"missing or invalid host")).await?;
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
    crate::route_policy::route_rewritten_path_and_query(
        request,
        &route.matcher,
        route.strip_prefix.as_deref(),
        route.rewrite_prefix.as_deref(),
        route.rewrite_template.as_deref(),
    )
}

#[cfg(feature = "cache")]
fn safe_forward_path_and_query(path_and_query: &str) -> bool {
    let path = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _)| path);
    safe_forward_path(path)
}

#[cfg(feature = "cache")]
fn safe_forward_path(path: &str) -> bool {
    if !path.starts_with('/')
        || path.chars().any(char::is_control)
        || path.as_bytes().contains(&b'\\')
    {
        return false;
    }

    path.split('/').all(safe_forward_path_segment)
}

#[cfg(feature = "cache")]
fn safe_forward_path_segment(segment: &str) -> bool {
    if segment == ".." {
        return false;
    }

    let Some(decoded_once) = percent_decode_path_segment(segment) else {
        return false;
    };
    if unsafe_decoded_forward_path_segment(&decoded_once) {
        return false;
    }
    if let Ok(decoded_once_text) = std::str::from_utf8(&decoded_once)
        && decoded_once_text.contains('%')
    {
        let Some(decoded_twice) = percent_decode_path_segment(decoded_once_text) else {
            return false;
        };
        if unsafe_decoded_forward_path_segment(&decoded_twice) {
            return false;
        }
    }
    true
}

#[cfg(feature = "cache")]
fn unsafe_decoded_forward_path_segment(segment: &[u8]) -> bool {
    segment == b".."
        || segment
            .iter()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'\\'))
}

#[cfg(feature = "cache")]
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

#[cfg(feature = "cache")]
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
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

#[allow(dead_code)]
fn request_header_values_joined(request: &RequestHeader, name: &str) -> Option<String> {
    let mut values = request_header_values(request, name);
    let first = values.next()?.to_owned();
    Some(values.fold(first, |mut joined, value| {
        joined.push_str(", ");
        joined.push_str(value);
        joined
    }))
}

#[cfg(test)]
fn http_peer_for_proxy<A>(address: A, proxy: &ProxyConfig) -> Result<HttpPeer>
where
    A: ToSocketAddrs + std::fmt::Debug,
{
    http_peer_for_proxy_with_tls(address, proxy, None)
}

fn http_peer_for_runtime_proxy<A>(address: A, proxy: &RuntimeProxy) -> Result<HttpPeer>
where
    A: ToSocketAddrs + std::fmt::Debug,
{
    #[cfg(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl"
    ))]
    {
        http_peer_for_proxy_with_tls(address, &proxy.config, Some(&proxy.upstream_tls))
    }

    #[cfg(not(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl"
    )))]
    {
        http_peer_for_proxy_with_tls(address, &proxy.config, None)
    }
}

fn apply_upstream_proxy_protocol(
    peer: &mut HttpPeer,
    proxy: &ProxyConfig,
    session: &Session,
    state: &ProxyRuntimeState,
) {
    let source = effective_proxy_protocol_source_addr(session, state);
    let destination = session
        .server_addr()
        .and_then(|address| address.as_inet())
        .copied();
    let header = match proxy.upstream_proxy_protocol {
        UpstreamProxyProtocol::Off => return,
        UpstreamProxyProtocol::V1 => proxy_protocol_v1_header(source, destination),
        UpstreamProxyProtocol::V2 => proxy_protocol_v2_header(source, destination),
    };
    peer.options.custom_l4 = Some(Arc::new(ProxyProtocolConnector {
        header,
        connect_timeout: proxy
            .connect_timeout_secs
            .map(std::time::Duration::from_secs),
    }));
}

fn effective_proxy_protocol_source_addr(
    session: &Session,
    state: &ProxyRuntimeState,
) -> Option<std::net::SocketAddr> {
    let direct = session
        .client_addr()
        .and_then(|address| address.as_inet())
        .copied();
    let Some(effective_ip) = effective_acl_client_ip(session, state) else {
        return direct;
    };
    let port = direct
        .filter(|direct| direct.ip() == effective_ip)
        .map(|direct| direct.port())
        .unwrap_or(0);
    Some(std::net::SocketAddr::new(effective_ip, port))
}

fn proxy_protocol_v1_header(
    source: Option<std::net::SocketAddr>,
    destination: Option<std::net::SocketAddr>,
) -> Vec<u8> {
    let Some(source) = source else {
        return b"PROXY UNKNOWN\r\n".to_vec();
    };
    let Some(destination) = destination else {
        return b"PROXY UNKNOWN\r\n".to_vec();
    };

    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => format!(
            "PROXY TCP4 {source_ip} {destination_ip} {} {}\r\n",
            source.port(),
            destination.port()
        )
        .into_bytes(),
        (IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => format!(
            "PROXY TCP6 {source_ip} {destination_ip} {} {}\r\n",
            source.port(),
            destination.port()
        )
        .into_bytes(),
        _ => b"PROXY UNKNOWN\r\n".to_vec(),
    }
}

const PROXY_PROTOCOL_V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

fn proxy_protocol_v2_header(
    source: Option<std::net::SocketAddr>,
    destination: Option<std::net::SocketAddr>,
) -> Vec<u8> {
    let mut header = Vec::from(&PROXY_PROTOCOL_V2_SIGNATURE[..]);
    let Some(source) = source else {
        header.extend_from_slice(&[0x21, 0x00, 0x00, 0x00]);
        return header;
    };
    let Some(destination) = destination else {
        header.extend_from_slice(&[0x21, 0x00, 0x00, 0x00]);
        return header;
    };

    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
            header.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
            header.extend_from_slice(&source_ip.octets());
            header.extend_from_slice(&destination_ip.octets());
            header.extend_from_slice(&source.port().to_be_bytes());
            header.extend_from_slice(&destination.port().to_be_bytes());
        }
        (IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
            header.extend_from_slice(&[0x21, 0x21, 0x00, 0x24]);
            header.extend_from_slice(&source_ip.octets());
            header.extend_from_slice(&destination_ip.octets());
            header.extend_from_slice(&source.port().to_be_bytes());
            header.extend_from_slice(&destination.port().to_be_bytes());
        }
        _ => header.extend_from_slice(&[0x21, 0x00, 0x00, 0x00]),
    }
    header
}

#[derive(Debug)]
struct ProxyProtocolConnector {
    header: Vec<u8>,
    connect_timeout: Option<Duration>,
}

#[async_trait]
impl pingora::connectors::L4Connect for ProxyProtocolConnector {
    async fn connect(
        &self,
        addr: &pingora::protocols::l4::socket::SocketAddr,
    ) -> Result<pingora::protocols::l4::stream::Stream> {
        let connect = async {
            match addr {
                pingora::protocols::l4::socket::SocketAddr::Inet(addr) => {
                    tokio::net::TcpStream::connect(addr).await.map(Into::into)
                }
                #[cfg(unix)]
                pingora::protocols::l4::socket::SocketAddr::Unix(addr) => {
                    let path = addr.as_pathname().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "non-pathname Unix upstreams cannot use PROXY protocol",
                        )
                    })?;
                    tokio::net::UnixStream::connect(path).await.map(Into::into)
                }
            }
        };

        let mut stream: pingora::protocols::l4::stream::Stream = match self.connect_timeout {
            Some(timeout) => match tokio::time::timeout(timeout, connect).await {
                Ok(result) => result,
                Err(_) => {
                    return Error::e_explain(
                        ErrorType::ConnectTimedout,
                        format!("timeout {timeout:?} connecting to server {addr}"),
                    );
                }
            },
            None => connect.await,
        }
        .map_err(|error| Error::because(ErrorType::ConnectError, "upstream connect", error))?;

        stream
            .write_all(&self.header)
            .await
            .map_err(|error| Error::because(ErrorType::WriteError, "write PROXY header", error))?;
        Ok(stream)
    }
}

fn http_peer_for_proxy_with_tls<A>(
    address: A,
    proxy: &ProxyConfig,
    #[cfg_attr(
        not(any(
            feature = "tls-rustls-backend",
            feature = "tls-openssl",
            feature = "tls-boringssl"
        )),
        allow(unused_variables)
    )]
    upstream_tls: Option<&RuntimeUpstreamTls>,
) -> Result<HttpPeer>
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
    #[cfg(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl"
    ))]
    if let Some(upstream_tls) = upstream_tls {
        peer.options.ca = upstream_tls.ca.clone();
        peer.client_cert_key = upstream_tls.client_cert_key.clone();
    }
    apply_proxy_timeouts(&mut peer, proxy);
    apply_proxy_upstream_socket_policy(&mut peer, proxy);
    apply_proxy_upstream_http_policy(&mut peer, proxy);
    apply_proxy_upstream_tls_policy(&mut peer, proxy);
    Ok(peer)
}

fn apply_proxy_timeouts(peer: &mut HttpPeer, proxy: &ProxyConfig) {
    peer.options.connection_timeout = proxy
        .connect_timeout_secs
        .map(std::time::Duration::from_secs);
    peer.options.total_connection_timeout = proxy
        .upstream_total_connection_timeout_secs
        .map(std::time::Duration::from_secs);
    peer.options.idle_timeout = proxy
        .upstream_idle_timeout_secs
        .map(std::time::Duration::from_secs);
    peer.options.read_timeout = proxy.read_timeout_secs.map(std::time::Duration::from_secs);
    peer.options.write_timeout = proxy.send_timeout_secs.map(std::time::Duration::from_secs);
}

fn apply_proxy_upstream_socket_policy(peer: &mut HttpPeer, proxy: &ProxyConfig) {
    if let (Some(idle_secs), Some(interval_secs), Some(count)) = (
        proxy.upstream_tcp_keepalive_idle_secs,
        proxy.upstream_tcp_keepalive_interval_secs,
        proxy.upstream_tcp_keepalive_count,
    ) {
        peer.options.tcp_keepalive = Some(TcpKeepalive {
            idle: Duration::from_secs(idle_secs),
            interval: Duration::from_secs(interval_secs),
            count,
            #[cfg(target_os = "linux")]
            user_timeout: Duration::from_millis(
                proxy.upstream_tcp_user_timeout_ms.unwrap_or_default(),
            ),
        });
    }
    peer.options.tcp_recv_buf = proxy
        .upstream_tcp_recv_buffer_bytes
        .map(crate::config::ByteSize::as_usize);
    peer.options.dscp = proxy.upstream_dscp;
    peer.options.tcp_fast_open = proxy.upstream_tcp_fast_open;
}

fn apply_proxy_upstream_tls_policy(peer: &mut HttpPeer, proxy: &ProxyConfig) {
    peer.options.verify_cert = proxy.upstream_verify_cert;
    peer.options.verify_hostname = proxy.upstream_verify_hostname;
    peer.options.alternative_cn = proxy.upstream_alternative_cn.clone();
}

fn apply_proxy_upstream_http_policy(peer: &mut HttpPeer, proxy: &ProxyConfig) {
    match proxy.upstream_http_version {
        UpstreamHttpVersion::Http1 => peer.options.set_http_version(1, 1),
        UpstreamHttpVersion::Http2 => peer.options.set_http_version(2, 2),
        UpstreamHttpVersion::Http1AndHttp2 => peer.options.set_http_version(2, 1),
    }
    if let Some(max_streams) = proxy.upstream_h2_max_streams {
        peer.options.max_h2_streams = max_streams;
    }
    peer.options.h2_ping_interval = proxy
        .upstream_h2_ping_interval_secs
        .map(Duration::from_secs);
}

fn request_host_header(request: &RequestHeader) -> Option<&str> {
    request
        .headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .or_else(|| request.uri.authority().map(|authority| authority.as_str()))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum GrpcRouteRejectionStatus {
    MethodNotAllowed,
    UnsupportedMediaType,
}

fn grpc_route_rejection_status(
    grpc: &crate::config::GrpcRouteConfig,
    request: &RequestHeader,
) -> Option<GrpcRouteRejectionStatus> {
    if !grpc.enabled {
        return None;
    }
    if request.method.as_str() != "POST" {
        return Some(GrpcRouteRejectionStatus::MethodNotAllowed);
    }
    if grpc.require_content_type
        && !request_header_values(request, "content-type").any(grpc_content_type)
    {
        return Some(GrpcRouteRejectionStatus::UnsupportedMediaType);
    }

    None
}

fn grpc_content_type(value: &str) -> bool {
    let media_type = value
        .split_once(';')
        .map(|(media_type, _)| media_type)
        .unwrap_or(value)
        .trim();
    media_type == "application/grpc" || media_type.starts_with("application/grpc+")
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

    if has_non_identity_transfer_encoding(request) && content_length.is_some() {
        return Some(400);
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
    #[cfg(any(feature = "php-fpm", feature = "compression-gzip"))]
    use std::io;
    #[cfg(feature = "compression-gzip")]
    use std::io::Read as _;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    #[cfg(feature = "php-fpm")]
    use std::sync::Arc;
    #[cfg(feature = "php-fpm")]
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    #[allow(unused_imports)]
    use bytes::Bytes;
    #[cfg(any(feature = "php-fpm", feature = "compression-gzip"))]
    use pingora::http::{ResponseHeader, StatusCode};

    #[cfg(feature = "compression-gzip")]
    use crate::config::CompressionConfig;
    #[cfg(feature = "load-balancer")]
    use crate::config::LoadBalanceRetryConfig;
    #[cfg(feature = "traffic-mirror")]
    use crate::config::TrafficMirrorConfig;
    use crate::config::{
        AuthRequestConfig, ByteSize, CacheConfig, Config, GrpcRouteConfig, HostRoutingConfig,
        HttpsRedirectConfig, ProxyConfig, RateLimitMode, RouteConfig, RouteRedirectConfig,
        ServerConfig, ServerLimitsConfig, UpstreamHttpVersion, VhostConfig, WebConfig,
    };
    #[cfg(any(feature = "cache", feature = "web"))]
    use crate::test_support::unique_temp_path;

    #[cfg(feature = "cache")]
    use super::CacheRangeRequest;
    #[cfg(feature = "compression-gzip")]
    use super::ProxyRuntimeState;
    #[cfg(feature = "load-balancer")]
    use super::RuntimeRetryBudget;
    #[cfg(feature = "cache")]
    use super::{
        CACHE_PASS_REASON, CacheClientRange, CacheSliceBounds, CacheStaleEvent,
        CacheStatusOverride, apply_cache_status_ttl, cache_min_uses_allows_store,
        cache_pass_record_cacheable, cache_pass_record_uncacheable, cache_pass_should_bypass,
        cache_request_participated, cache_should_serve_stale, cache_stale_status_allows,
        cache_status_header_value, cache_status_reason_header_value, ignore_origin_cache_headers,
        lookup_proxy_cache_only_object, parse_bounded_single_range, parse_cache_client_ranges,
        range_cache_key, range_response_cache_admission_rejection, read_cache_hit_body,
        remaining_fresh_ttl_secs, required_slice_bounds, resolve_client_slice_ranges,
        response_age_secs, response_vary_variance, selected_cache_range_request, slice_cache_key,
        slice_request_within_policy, strip_cache_response_headers,
    };
    #[cfg(feature = "cache")]
    use super::{CacheBulkPurgeRequest, CachePurgeRequest};
    #[allow(unused_imports)]
    use super::{
        FluxProxy, HostRoutingRejectReason, RuntimeProxy, append_fluxheim_via_to_request,
        append_fluxheim_via_to_response, apply_websocket_upgrade_headers_if_enabled,
        approximate_request_header_bytes, count_response_body_chunk,
        effective_client_ip_from_forwarded_for, grpc_content_type, grpc_route_rejection_status,
        http_peer_for_proxy, http_peer_for_runtime_proxy, https_redirect_location,
        normalize_cookie_headers, proxy_protocol_v1_header, proxy_protocol_v2_header,
        proxy_upgrade_request_allowed, redirect_authority, request_body_chunk_limit_status,
        request_limit_status, route_redirect_location, route_rewritten_path_and_query,
    };
    #[cfg(feature = "php-fpm")]
    use super::{
        MAX_PHP_PARAM_VALUE_BYTES, PhpResolveOutcome, RuntimePhp, add_php_custom_params,
        add_php_host_param, add_php_request_header_params, apply_php_x_accel_expires,
        directory_slash_redirect_location, explicit_authority_port,
        ignore_php_origin_cache_headers, parse_php_fpm_output, php_content_type_param,
        php_fpm_path_translated, php_fpm_script_filename, php_header_param_name,
        php_script_name_denied, php_script_name_for_request, php_server_name_param,
        php_should_intercept_error_status, php_static_offload_file,
        php_stderr_matches_failure_pattern, php_stderr_metric_state, php_x_accel_expires_ttl_secs,
        resolve_php_script, sanitized_php_stderr, strip_php_response_headers,
    };
    #[cfg(feature = "cache")]
    use super::{
        PeerFillResponse, acquire_peer_fill_concurrency_permit, peer_fill_concurrency_key,
        peer_fill_request_from_header, peer_fill_url,
        prune_inactive_cache_fill_concurrency_counters,
    };
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    use super::{RequestContext, prepare_response_compression, selected_compression_config};
    #[cfg(feature = "cache")]
    use super::{
        capture_revalidation_304_headers, request_cache_only_if_cached,
        response_with_revalidation_304_headers, revalidation_304_vary_changed,
    };
    use crate::auth_request::auth_request_input;
    #[cfg(feature = "compression-gzip")]
    use crate::compression::{
        ResponseCompressionEncoder, ResponseCompressionEncoding, gzip_response_eligible,
        request_accepts_gzip, selected_response_compression,
    };
    use crate::edge_policy::{
        RateLimitDecision, RuntimeAccessPolicy, RuntimeConcurrencyLimit, RuntimeRateLimit,
    };
    #[cfg(feature = "php-fpm")]
    use crate::php_fpm::{
        PhpFpmEndpoint, PhpFpmTimeoutKind, PhpRequestBody, create_php_request_body_spool_file,
        parse_php_response, php_fpm_effective_connect_timeout, php_fpm_effective_request_timeout,
        php_fpm_endpoints_from_config, php_fpm_error_outcome, php_fpm_keepalive_pools_from_config,
        php_fpm_retry_attempts, php_fpm_retry_attempts_for_endpoint_count, php_fpm_retryable_error,
        php_fpm_retryable_response, php_fpm_timeout_error, push_php_fpm_stream_chunk,
        safe_php_header_value,
    };
    #[cfg(all(feature = "php-fpm", unix))]
    use crate::php_fpm::{
        create_php_request_body_spool_dir_sync, managed_php_fpm_config,
        managed_php_fpm_path_env_from, managed_php_fpm_restart_backoff_secs,
    };
    #[cfg(feature = "cache")]
    use crate::proxy_cache::{
        MAX_VARY_FIELDS, VaryCachePolicy, cache_vary_policy, request_cache_bypass,
        request_cache_bypass_reason, request_cache_revalidation_requested,
        response_cache_admission_rejection, vary_cache_policy, vary_request_hash,
    };
    #[cfg(feature = "traffic-mirror")]
    use crate::traffic_mirror::{
        acquire_traffic_mirror_slot, traffic_mirror_forwarded_headers,
        traffic_mirror_sample_selected, traffic_mirror_url,
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

    #[cfg(feature = "compression-gzip")]
    fn compression_request() -> pingora::http::RequestHeader {
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js", None).unwrap();
        request
            .insert_header("accept-encoding", "br, gzip")
            .unwrap();
        request
    }

    #[cfg(feature = "compression-gzip")]
    fn compression_response() -> ResponseHeader {
        let mut response = ResponseHeader::build(StatusCode::OK, Some(3)).unwrap();
        response
            .insert_header("content-type", "application/javascript; charset=utf-8")
            .unwrap();
        response.insert_header("content-length", "2048").unwrap();
        response.insert_header("etag", "\"abc\"").unwrap();
        response
    }

    #[cfg(feature = "compression-gzip")]
    fn compression_config() -> CompressionConfig {
        CompressionConfig {
            enabled: true,
            min_bytes: ByteSize::from_bytes(1024),
            max_input_bytes: ByteSize::from_bytes(4096),
            gzip_level: 4,
            ..CompressionConfig::default()
        }
    }

    #[cfg(feature = "compression-gzip")]
    #[test]
    fn vhost_compression_overrides_global_disabled_policy() {
        let config: Config = toml::from_str(
            r#"
            [compression]
            enabled = false

            [[vhosts]]
            name = "docs"
            hosts = ["docs.example"]

            [vhosts.compression]
            enabled = true
            gzip = true
            min_bytes = "1KiB"
            max_input_bytes = "4KiB"
            "#,
        )
        .unwrap();
        config.validate().unwrap();
        let state = ProxyRuntimeState::from_config(&config).unwrap();
        let vhost = state.vhost(state.vhost_index(Some("docs.example")));

        assert!(!config.compression.enabled);
        assert_eq!(
            selected_response_compression(
                &compression_request(),
                &compression_response(),
                &vhost.compression
            ),
            Some(ResponseCompressionEncoding::Gzip)
        );
    }

    #[cfg(feature = "compression-gzip")]
    #[test]
    fn route_compression_overrides_vhost_disabled_policy() {
        let config: Config = toml::from_str(
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
            max_input_bytes = "4KiB"
            "#,
        )
        .unwrap();
        config.validate().unwrap();
        let state = ProxyRuntimeState::from_config(&config).unwrap();
        let vhost = state.vhost(state.vhost_index(Some("site.example")));
        let ctx = RequestContext {
            route_index: Some(0),
            ..RequestContext::default()
        };

        assert!(!vhost.compression.enabled);
        assert_eq!(
            selected_response_compression(
                &compression_request(),
                &compression_response(),
                selected_compression_config(vhost, &ctx)
            ),
            Some(ResponseCompressionEncoding::Gzip)
        );
    }

    #[cfg(feature = "compression-gzip")]
    #[test]
    fn gzip_response_compression_sets_safe_headers() {
        let request = compression_request();
        let mut response = compression_response();
        response.insert_header("vary", "accept-language").unwrap();
        let mut ctx = RequestContext::default();

        prepare_response_compression(&request, &mut response, &compression_config(), &mut ctx)
            .unwrap();

        assert_eq!(response.headers.get("content-encoding").unwrap(), "gzip");
        assert!(!response.headers.contains_key("content-length"));
        assert!(!response.headers.contains_key("etag"));
        let vary = response
            .headers
            .get_all("vary")
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert!(vary.contains(&"accept-language".to_owned()));
        assert!(vary.contains(&"accept-encoding".to_owned()));
        assert!(ctx.compression.is_some());
        assert_eq!(
            ctx.compression
                .as_ref()
                .map(|compression| compression.encoding),
            Some("gzip")
        );
    }

    #[cfg(feature = "compression-gzip")]
    #[test]
    fn gzip_response_compression_rejects_private_or_unknown_length_responses() {
        let request = compression_request();
        let config = compression_config();

        let mut private_response = compression_response();
        private_response
            .insert_header("cache-control", "private")
            .unwrap();
        assert!(!gzip_response_eligible(
            &request,
            &private_response,
            &config
        ));

        let mut no_transform = compression_response();
        no_transform
            .insert_header("cache-control", "public, no-transform")
            .unwrap();
        assert!(!gzip_response_eligible(&request, &no_transform, &config));

        let mut unknown_length = compression_response();
        unknown_length.remove_header("content-length");
        assert!(!gzip_response_eligible(&request, &unknown_length, &config));
    }

    #[cfg(feature = "compression-gzip")]
    #[test]
    fn gzip_accept_encoding_honors_q_zero() {
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js", None).unwrap();
        request
            .insert_header("accept-encoding", "br, gzip;q=0")
            .unwrap();
        assert!(!request_accepts_gzip(&request));

        let mut wildcard =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js", None).unwrap();
        wildcard
            .insert_header("accept-encoding", "*;q=0.5")
            .unwrap();
        assert!(request_accepts_gzip(&wildcard));
    }

    #[cfg(feature = "compression-gzip")]
    #[test]
    fn gzip_encoder_emits_decodable_stream() {
        let mut encoder = ResponseCompressionEncoder::gzip(4, 1024);
        let mut compressed = Vec::new();
        compressed.extend_from_slice(
            &encoder
                .encode_chunk(Some(&Bytes::from_static(b"hello ")), false)
                .unwrap(),
        );
        compressed.extend_from_slice(
            &encoder
                .encode_chunk(Some(&Bytes::from_static(b"fluxheim")), true)
                .unwrap(),
        );

        assert_eq!(&compressed[..2], &[0x1f, 0x8b]);
        let mut decoded = String::new();
        flate2::read::GzDecoder::new(&compressed[..])
            .read_to_string(&mut decoded)
            .unwrap();
        assert_eq!(decoded, "hello fluxheim");
    }

    #[cfg(feature = "compression-brotli")]
    #[test]
    fn brotli_encoder_emits_decodable_stream() {
        let mut encoder = ResponseCompressionEncoder::brotli(4, 1024);
        let mut compressed = Vec::new();
        compressed.extend_from_slice(
            &encoder
                .encode_chunk(Some(&Bytes::from_static(b"hello ")), false)
                .unwrap(),
        );
        compressed.extend_from_slice(
            &encoder
                .encode_chunk(Some(&Bytes::from_static(b"fluxheim")), true)
                .unwrap(),
        );

        let mut decoded = String::new();
        brotli::Decompressor::new(&compressed[..], 4096)
            .read_to_string(&mut decoded)
            .unwrap();
        assert_eq!(decoded, "hello fluxheim");
    }

    #[cfg(feature = "compression-zstd")]
    #[test]
    fn zstd_encoder_emits_decodable_stream() {
        let mut encoder = ResponseCompressionEncoder::zstd(3, 1024).unwrap();
        let mut compressed = Vec::new();
        compressed.extend_from_slice(
            &encoder
                .encode_chunk(Some(&Bytes::from_static(b"hello ")), false)
                .unwrap(),
        );
        compressed.extend_from_slice(
            &encoder
                .encode_chunk(Some(&Bytes::from_static(b"fluxheim")), true)
                .unwrap(),
        );

        let decoded = zstd::stream::decode_all(&compressed[..]).unwrap();
        assert_eq!(decoded, b"hello fluxheim");
    }

    #[cfg(feature = "compression-gzip")]
    #[test]
    fn gzip_encoder_enforces_output_limit() {
        let mut encoder = ResponseCompressionEncoder::gzip(0, 1);
        let error = encoder
            .encode_chunk(Some(&Bytes::from_static(b"hello fluxheim")), true)
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(all(feature = "compression-brotli", feature = "compression-gzip"))]
    #[test]
    fn brotli_is_preferred_when_enabled_and_accepted() {
        let request = compression_request();
        let response = compression_response();
        let config = CompressionConfig {
            brotli: true,
            ..compression_config()
        };

        assert_eq!(
            selected_response_compression(&request, &response, &config),
            Some(ResponseCompressionEncoding::Brotli)
        );
    }

    #[cfg(all(feature = "compression-gzip", feature = "compression-zstd"))]
    #[test]
    fn zstd_is_preferred_over_gzip_when_enabled_and_accepted() {
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js", None).unwrap();
        request
            .insert_header("accept-encoding", "zstd, gzip")
            .unwrap();
        let response = compression_response();
        let config = CompressionConfig {
            zstd: true,
            ..compression_config()
        };

        assert_eq!(
            selected_response_compression(&request, &response, &config),
            Some(ResponseCompressionEncoding::Zstd)
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

    #[test]
    fn access_policy_denies_before_allowing() {
        let policy = RuntimeAccessPolicy::from_config(&crate::config::AccessPolicyConfig {
            enabled: true,
            allow: vec!["10.0.0.0/8".to_owned()],
            deny: vec!["10.9.0.0/16".to_owned()],
            ..crate::config::AccessPolicyConfig::default()
        })
        .unwrap();

        assert!(policy.allows(Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))), None));
        assert!(!policy.allows(Some(IpAddr::V4(Ipv4Addr::new(10, 9, 2, 3))), None));
        assert!(!policy.allows(Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))), None));
        assert!(!policy.allows(None, None));
    }

    #[test]
    fn access_policy_can_require_client_certificate_fingerprint() {
        let allowed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let denied = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let policy = RuntimeAccessPolicy::from_config(&crate::config::AccessPolicyConfig {
            enabled: true,
            require_client_cert: true,
            allow_client_cert_sha256: vec![allowed.to_owned()],
            deny_client_cert_sha256: vec![denied.to_owned()],
            ..crate::config::AccessPolicyConfig::default()
        })
        .unwrap();
        let client_ip = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));
        let allowed_identity = crate::headers::RequestTlsClientIdentity {
            cert_sha256: Some(allowed.to_ascii_uppercase()),
            ..crate::headers::RequestTlsClientIdentity::default()
        };
        let denied_identity = crate::headers::RequestTlsClientIdentity {
            cert_sha256: Some(denied.to_owned()),
            ..crate::headers::RequestTlsClientIdentity::default()
        };
        let unknown_identity = crate::headers::RequestTlsClientIdentity {
            cert_sha256: Some(
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
            ),
            ..crate::headers::RequestTlsClientIdentity::default()
        };

        assert!(policy.allows(client_ip, Some(&allowed_identity)));
        assert!(!policy.allows(client_ip, Some(&denied_identity)));
        assert!(!policy.allows(client_ip, Some(&unknown_identity)));
        assert!(!policy.allows(client_ip, None));
    }

    #[test]
    fn access_policy_restores_client_ip_from_trusted_forwarded_chain() {
        let direct = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254));
        let restored = effective_client_ip_from_forwarded_for(
            direct,
            true,
            Some("203.0.113.10, 10.0.0.253"),
            |ip| matches!(ip, IpAddr::V4(ip) if ip.octets()[0] == 10),
        );

        assert_eq!(restored, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));
    }

    #[test]
    fn access_policy_parses_bracketed_ipv6_forwarded_for() {
        let direct = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let restored = effective_client_ip_from_forwarded_for(
            direct,
            true,
            Some("\"[2001:db8::10]\", \"[::1]\""),
            |ip| ip == IpAddr::V6(Ipv6Addr::LOCALHOST),
        );

        assert_eq!(
            restored,
            "2001:db8::10".parse::<IpAddr>().expect("valid IPv6")
        );
    }

    #[test]
    fn rate_limit_consumes_burst_per_client_ip() {
        let policy = RuntimeRateLimit::from_config(&crate::config::RateLimitConfig {
            enabled: true,
            requests_per_second: 1,
            burst: 2,
            status: 429,
            table_max_entries: 16,
            entry_ttl_secs: 60,
            mode: RateLimitMode::Nodelay,
            max_delay_ms: 1000,
            reject_indeterminate: false,
        });
        let client = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));

        assert_eq!(policy.check(client), RateLimitDecision::Allow);
        assert_eq!(policy.check(client), RateLimitDecision::Allow);
        assert_eq!(policy.check(client), RateLimitDecision::Reject(429));
        assert_eq!(
            policy.check(Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)))),
            RateLimitDecision::Allow
        );
    }

    #[test]
    fn rate_limit_delay_mode_reserves_future_tokens() {
        let policy = RuntimeRateLimit::from_config(&crate::config::RateLimitConfig {
            enabled: true,
            requests_per_second: 1,
            burst: 1,
            status: 429,
            table_max_entries: 16,
            entry_ttl_secs: 60,
            mode: RateLimitMode::Delay,
            max_delay_ms: 1500,
            reject_indeterminate: false,
        });
        let client = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));

        assert_eq!(policy.check(client), RateLimitDecision::Allow);
        match policy.check(client) {
            RateLimitDecision::Delay(delay) => {
                assert!(delay >= Duration::from_millis(90), "{delay:?}");
                assert!(delay <= Duration::from_millis(1100), "{delay:?}");
            }
            decision => panic!("expected delay decision, got {decision:?}"),
        }
        assert_eq!(policy.check(client), RateLimitDecision::Reject(429));
    }

    #[test]
    fn rate_limit_can_reject_indeterminate_client_ip() {
        let policy = RuntimeRateLimit::from_config(&crate::config::RateLimitConfig {
            enabled: true,
            requests_per_second: 1,
            burst: 1,
            status: 429,
            table_max_entries: 16,
            entry_ttl_secs: 60,
            mode: RateLimitMode::Nodelay,
            max_delay_ms: 1000,
            reject_indeterminate: true,
        });

        assert_eq!(policy.check(None), RateLimitDecision::Reject(429));
    }

    #[test]
    fn concurrency_limit_releases_permit_on_drop() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let policy =
                RuntimeConcurrencyLimit::from_config(&crate::config::ConcurrencyLimitConfig {
                    enabled: true,
                    max_in_flight: 1,
                    max_queue: 0,
                    status: 503,
                    queue_timeout_ms: 0,
                });

            let first = policy.acquire().await.unwrap().expect("first permit");
            assert!(policy.acquire().await.is_err());
            drop(first);
            assert!(policy.acquire().await.unwrap().is_some());
        });
    }

    #[test]
    fn concurrency_limit_waits_for_bounded_queue() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let policy =
                RuntimeConcurrencyLimit::from_config(&crate::config::ConcurrencyLimitConfig {
                    enabled: true,
                    max_in_flight: 1,
                    max_queue: 1,
                    status: 503,
                    queue_timeout_ms: 250,
                });

            let first = policy.acquire().await.unwrap().expect("first permit");
            let queued_policy = policy.clone();
            let queued = tokio::spawn(async move { queued_policy.acquire().await });

            tokio::time::sleep(Duration::from_millis(25)).await;
            drop(first);

            assert!(queued.await.unwrap().unwrap().is_some());
        });
    }

    #[test]
    fn concurrency_limit_rejects_when_queue_is_full() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let policy =
                RuntimeConcurrencyLimit::from_config(&crate::config::ConcurrencyLimitConfig {
                    enabled: true,
                    max_in_flight: 1,
                    max_queue: 1,
                    status: 503,
                    queue_timeout_ms: 250,
                });

            let _first = policy.acquire().await.unwrap().expect("first permit");
            let queued_policy = policy.clone();
            let queued = tokio::spawn(async move { queued_policy.acquire().await });

            tokio::time::sleep(Duration::from_millis(25)).await;
            assert_eq!(policy.acquire().await.unwrap_err(), 503);
            queued.abort();
            let _ = queued.await;
        });
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
            fpm_pools: Vec::new(),
            fpm_next: Arc::new(AtomicUsize::new(0)),
            _managed_fpm: None,
        }
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_spooled_request_body_replays_and_cleans_up_file() {
        let spool_dir = unique_temp_path("php-spooled-request-body");
        fs::create_dir_all(&spool_dir).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let (path, mut file) = runtime
            .block_on(create_php_request_body_spool_file(&spool_dir))
            .unwrap();
        runtime.block_on(async {
            use tokio::io::AsyncWriteExt;

            file.write_all(b"spooled-body").await.unwrap();
            file.flush().await.unwrap();
        });

        let body = PhpRequestBody::spooled(path.clone(), "spooled-body".len());
        assert_eq!(body.len(), "spooled-body".len());

        let mut reader = runtime.block_on(body.reader()).unwrap();
        let mut replayed = Vec::new();
        runtime
            .block_on(fastcgi_client::io::AsyncReadExt::read_to_end(
                &mut reader,
                &mut replayed,
            ))
            .unwrap();
        assert_eq!(replayed, b"spooled-body");
        assert!(path.exists());

        drop(reader);
        drop(body);
        assert!(!path.exists());
    }

    #[cfg(all(feature = "php-fpm", unix))]
    #[test]
    fn php_spool_file_creation_rejects_insecure_directory() {
        use std::os::unix::fs::PermissionsExt;

        let spool_dir = unique_temp_path("php-spooled-request-body-insecure");
        fs::create_dir_all(&spool_dir).unwrap();
        fs::set_permissions(&spool_dir, fs::Permissions::from_mode(0o777)).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let error = runtime
            .block_on(create_php_request_body_spool_file(&spool_dir))
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            error
                .to_string()
                .contains("spool directory is group/world writable"),
            "{error}"
        );
    }

    #[cfg(all(feature = "php-fpm", unix))]
    #[test]
    fn php_spool_dir_creation_uses_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let spool_dir = unique_temp_path("php-spooled-request-body-created-private");
        create_php_request_body_spool_dir_sync(&spool_dir).unwrap();

        let mode = fs::metadata(&spool_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[cfg(all(feature = "php-fpm", unix))]
    #[test]
    fn php_spool_file_creation_rejects_symlinked_directory() {
        use std::os::unix::fs::symlink;

        let target = unique_temp_path("php-spooled-request-body-target");
        let spool_dir = unique_temp_path("php-spooled-request-body-symlink");
        fs::create_dir_all(&target).unwrap();
        symlink(&target, &spool_dir).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let error = runtime
            .block_on(create_php_request_body_spool_file(&spool_dir))
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("not a directory"), "{error}");
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
            php_fpm_path_translated(&php, "/uploads/file.txt").as_deref(),
            Some("/app/public/uploads/file.txt")
        );
        assert!(php_fpm_path_translated(&php, "/uploads/../wp-config.php").is_none());
        assert!(php_fpm_path_translated(&php, "/uploads/.secret").is_none());
        assert!(php_fpm_path_translated(&php, "/uploads\\wp-config.php").is_none());
    }

    #[cfg(all(feature = "php-fpm", unix))]
    #[test]
    fn php_runtime_canonicalizes_existing_fpm_root() {
        use std::os::unix::fs::symlink;

        let root = unique_temp_path("php-fpm-root-canonical-local");
        let fpm_target = unique_temp_path("php-fpm-root-canonical-target");
        let fpm_link = unique_temp_path("php-fpm-root-canonical-link");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("index.php"), "<?php echo 'index';").unwrap();
        fs::create_dir_all(&fpm_target).unwrap();
        symlink(&fpm_target, &fpm_link).unwrap();

        let config = crate::config::PhpConfig {
            enabled: true,
            root: Some(root),
            fpm_root: Some(fpm_link),
            fpm: crate::config::PhpFpmConfig {
                tcp: Some("127.0.0.1:9000".to_owned()),
                ..crate::config::PhpFpmConfig::default()
            },
            ..crate::config::PhpConfig::default()
        };

        let php = RuntimePhp::from_config("test php", "test", "default", &config)
            .unwrap()
            .unwrap();
        assert_eq!(php.fpm_root, fpm_target.canonicalize().unwrap());
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

    #[cfg(all(feature = "php-fpm", unix))]
    #[test]
    fn php_runtime_resolves_final_root_symlink_when_enabled() {
        let parent = unique_temp_path("proxy-php-root-symlink");
        let real_root = parent.join("releases").join("current");
        let linked_root = parent.join("public");
        fs::create_dir_all(&real_root).unwrap();
        fs::write(real_root.join("index.php"), "<?php echo 'index';").unwrap();
        std::os::unix::fs::symlink(&real_root, &linked_root).unwrap();

        let config = crate::config::PhpConfig {
            enabled: true,
            root: Some(linked_root.clone()),
            resolve_root_symlink: true,
            fpm: crate::config::PhpFpmConfig {
                tcp: Some("127.0.0.1:9000".to_owned()),
                ..crate::config::PhpFpmConfig::default()
            },
            ..crate::config::PhpConfig::default()
        };

        let php = RuntimePhp::from_config("test php", "test", "default", &config)
            .unwrap()
            .unwrap();

        assert_eq!(php.root, real_root.canonicalize().unwrap());
        assert_eq!(php.fpm_root, real_root.canonicalize().unwrap());
    }

    #[cfg(all(feature = "php-fpm", unix))]
    #[test]
    fn php_runtime_rejects_final_root_symlink_by_default() {
        let parent = unique_temp_path("proxy-php-root-symlink-reject");
        let real_root = parent.join("releases").join("current");
        let linked_root = parent.join("public");
        fs::create_dir_all(&real_root).unwrap();
        std::os::unix::fs::symlink(&real_root, &linked_root).unwrap();

        let config = crate::config::PhpConfig {
            enabled: true,
            root: Some(linked_root.clone()),
            fpm: crate::config::PhpFpmConfig {
                tcp: Some("127.0.0.1:9000".to_owned()),
                ..crate::config::PhpFpmConfig::default()
            },
            ..crate::config::PhpConfig::default()
        };

        let error = RuntimePhp::from_config("test php", "test", "default", &config)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("php root is not a real directory"),
            "{error}"
        );
        assert!(
            error.contains(&linked_root.display().to_string()),
            "{error}"
        );
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
    fn php_header_param_translation_caps_joined_header_values() {
        let mut request = pingora::http::RequestHeader::build("GET", b"/index.php", None).unwrap();
        let cookie = "a".repeat(MAX_PHP_PARAM_VALUE_BYTES / 2);
        request.append_header("cookie", cookie.as_str()).unwrap();
        request.append_header("cookie", cookie.as_str()).unwrap();
        request.append_header("cookie", cookie.as_str()).unwrap();

        let mut params = fastcgi_client::Params::default();
        add_php_request_header_params(&mut params, &request);

        let value = params.get("HTTP_COOKIE").unwrap();
        assert!(value.as_ref().len() <= MAX_PHP_PARAM_VALUE_BYTES);
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_custom_params_drop_runtime_invalid_values() {
        let mut params = fastcgi_client::Params::default();
        let mut custom = std::collections::BTreeMap::new();
        custom.insert("SAFE_PARAM".to_owned(), "ok".to_owned());
        custom.insert("SCRIPT_FILENAME".to_owned(), "/tmp/bypass.php".to_owned());
        custom.insert("BAD_VALUE".to_owned(), "bad\nvalue".to_owned());

        add_php_custom_params(&mut params, &custom);

        assert_eq!(
            params.get("SAFE_PARAM").map(|value| value.as_ref()),
            Some("ok")
        );
        assert!(!params.contains_key("SCRIPT_FILENAME"));
        assert!(!params.contains_key("BAD_VALUE"));
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
    fn php_server_name_param_falls_back_on_unsafe_host() {
        assert_eq!(
            php_server_name_param("example.test", "fallback.test"),
            "example.test"
        );
        assert_eq!(
            php_server_name_param("bad\nhost", "fallback.test"),
            "fallback.test"
        );
        assert_eq!(
            php_server_name_param("bad\nhost", "bad\rfallback"),
            "localhost"
        );
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_content_type_param_rejects_unsafe_values() {
        let mut request = pingora::http::RequestHeader::build("POST", b"/index.php", None).unwrap();
        request
            .insert_header("content-type", "application/x-www-form-urlencoded")
            .unwrap();
        assert_eq!(
            php_content_type_param(&request),
            "application/x-www-form-urlencoded"
        );

        let mut request = pingora::http::RequestHeader::build("POST", b"/index.php", None).unwrap();
        let content_type = "a".repeat(MAX_PHP_PARAM_VALUE_BYTES + 1);
        request
            .insert_header("content-type", content_type.as_str())
            .unwrap();
        assert_eq!(php_content_type_param(&request), "");
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
            php_fpm_error_outcome(&php_fpm_timeout_error(PhpFpmTimeoutKind::Connect)),
            "connect_timeout"
        );
        assert_eq!(
            php_fpm_error_outcome(&php_fpm_timeout_error(PhpFpmTimeoutKind::Request)),
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
    fn php_fpm_effective_connect_timeout_obeys_request_timeout_cap() {
        let mut fpm = crate::config::PhpFpmConfig::default();
        let request_timeout = Duration::from_secs(30);

        assert_eq!(
            php_fpm_effective_connect_timeout(&fpm, request_timeout),
            request_timeout
        );

        fpm.connect_timeout_secs = Some(5);
        assert_eq!(
            php_fpm_effective_connect_timeout(&fpm, request_timeout),
            Duration::from_secs(5)
        );

        fpm.connect_timeout_secs = Some(60);
        assert_eq!(
            php_fpm_effective_connect_timeout(&fpm, request_timeout),
            request_timeout
        );
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_fpm_effective_request_timeout_uses_shortest_io_timeout() {
        let mut fpm = crate::config::PhpFpmConfig::default();
        let request_timeout = Duration::from_secs(30);

        assert_eq!(
            php_fpm_effective_request_timeout(&fpm, request_timeout),
            request_timeout
        );

        fpm.read_timeout_secs = Some(20);
        assert_eq!(
            php_fpm_effective_request_timeout(&fpm, request_timeout),
            Duration::from_secs(20)
        );

        fpm.write_timeout_secs = Some(5);
        assert_eq!(
            php_fpm_effective_request_timeout(&fpm, request_timeout),
            Duration::from_secs(5)
        );
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_fpm_endpoints_include_tcp_upstreams() {
        let fpm = crate::config::PhpFpmConfig {
            tcp_upstreams: vec!["127.0.0.1:9000".to_owned(), "127.0.0.1:9001".to_owned()],
            ..crate::config::PhpFpmConfig::default()
        };

        assert_eq!(
            php_fpm_endpoints_from_config(&fpm),
            vec![
                PhpFpmEndpoint::Tcp("127.0.0.1:9000".to_owned()),
                PhpFpmEndpoint::Tcp("127.0.0.1:9001".to_owned()),
            ]
        );
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_fpm_keepalive_pool_labels_are_distinct_for_tcp_upstreams() {
        let php = crate::config::PhpConfig {
            fpm: crate::config::PhpFpmConfig {
                tcp_upstreams: vec!["127.0.0.1:9000".to_owned(), "127.0.0.1:9001".to_owned()],
                keepalive: true,
                ..crate::config::PhpFpmConfig::default()
            },
            ..crate::config::PhpConfig::default()
        };

        let pools = php_fpm_keepalive_pools_from_config(&php, "vhost", "default");

        assert_eq!(pools.len(), 2);
        assert_eq!(pools[0].metric_pool(), "default-0");
        assert_eq!(pools[1].metric_pool(), "default-1");
    }

    #[cfg(all(feature = "php-fpm", unix))]
    #[test]
    fn managed_php_fpm_config_contains_private_pool_settings() {
        let fpm = crate::config::PhpFpmConfig {
            mode: crate::config::PhpFpmMode::Managed,
            user: Some("fluxheim".to_owned()),
            group: Some("fluxheim".to_owned()),
            workers: 4,
            max_requests_per_worker: 250,
            process_manager: crate::config::PhpFpmProcessManager::Dynamic,
            start_servers: Some(2),
            min_spare_servers: Some(1),
            max_spare_servers: Some(3),
            max_spawn_rate: Some(8),
            listen_backlog: Some(128),
            listen_owner: Some("fluxheim".to_owned()),
            listen_group: Some("php".to_owned()),
            listen_mode: Some("0660".to_owned()),
            request_terminate_timeout_secs: Some(30),
            request_terminate_timeout_track_finished: true,
            request_slowlog_timeout_secs: Some(5),
            request_slowlog_trace_depth: 16,
            decorate_workers_output: false,
            session_save_path: Some(std::path::PathBuf::from("/run/fluxheim/php/session")),
            upload_tmp_dir: Some(std::path::PathBuf::from("/run/fluxheim/php/upload")),
            ..crate::config::PhpFpmConfig::default()
        };
        let config = managed_php_fpm_config(
            std::path::Path::new("/run/fluxheim/php/site.sock"),
            std::path::Path::new("/run/fluxheim/php/site.pid"),
            std::path::Path::new("/run/fluxheim/php/site.log"),
            Some(std::path::Path::new("/run/fluxheim/php/site.slow.log")),
            &fpm,
        )
        .unwrap();

        assert!(config.contains("daemonize = no"));
        assert!(config.contains("listen = /run/fluxheim/php/site.sock"));
        assert!(config.contains("listen.mode = 0660"));
        assert!(config.contains("listen.owner = fluxheim"));
        assert!(config.contains("listen.group = php"));
        assert!(config.contains("listen.backlog = 128"));
        assert!(config.contains("user = fluxheim"));
        assert!(config.contains("group = fluxheim"));
        assert!(config.contains("pm = dynamic"));
        assert!(config.contains("pm.max_children = 4"));
        assert!(config.contains("pm.start_servers = 2"));
        assert!(config.contains("pm.min_spare_servers = 1"));
        assert!(config.contains("pm.max_spare_servers = 3"));
        assert!(config.contains("pm.max_spawn_rate = 8"));
        assert!(config.contains("pm.max_requests = 250"));
        assert!(config.contains("request_terminate_timeout = 30s"));
        assert!(config.contains("request_terminate_timeout_track_finished = yes"));
        assert!(config.contains("slowlog = /run/fluxheim/php/site.slow.log"));
        assert!(config.contains("request_slowlog_timeout = 5s"));
        assert!(config.contains("request_slowlog_trace_depth = 16"));
        assert!(config.contains("clear_env = yes"));
        assert!(config.contains("catch_workers_output = yes"));
        assert!(config.contains("decorate_workers_output = no"));
        assert!(config.contains("security.limit_extensions = .php"));
        assert!(config.contains("php_value[session.save_path] = /run/fluxheim/php/session"));
        assert!(config.contains("php_admin_value[upload_tmp_dir] = /run/fluxheim/php/upload"));
    }

    #[cfg(all(feature = "php-fpm", unix))]
    #[test]
    fn managed_php_fpm_config_rejects_unsafe_path_bytes() {
        let fpm = crate::config::PhpFpmConfig {
            mode: crate::config::PhpFpmMode::Managed,
            ..crate::config::PhpFpmConfig::default()
        };
        let error = managed_php_fpm_config(
            std::path::Path::new("/run/fluxheim/php/bad\"site.sock"),
            std::path::Path::new("/run/fluxheim/php/site.pid"),
            std::path::Path::new("/run/fluxheim/php/site.log"),
            None,
            &fpm,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("unsafe for php-fpm config"), "{error}");
    }

    #[cfg(all(feature = "php-fpm", unix))]
    #[test]
    fn managed_php_fpm_path_env_falls_back_for_control_bytes() {
        assert_eq!(
            managed_php_fpm_path_env_from(Some("/usr/bin\n/tmp".to_owned())),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        );
    }

    #[cfg(all(feature = "php-fpm", unix))]
    #[test]
    fn managed_php_fpm_restart_backoff_is_bounded() {
        assert_eq!(managed_php_fpm_restart_backoff_secs(0), 1);
        assert_eq!(managed_php_fpm_restart_backoff_secs(1), 2);
        assert_eq!(managed_php_fpm_restart_backoff_secs(4), 16);
        assert_eq!(managed_php_fpm_restart_backoff_secs(64), 30);
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_fpm_failover_attempts_cover_safe_tcp_upstreams() {
        let fpm = crate::config::PhpFpmConfig {
            max_retries: 0,
            retry_methods: vec!["GET".to_owned(), "HEAD".to_owned()],
            ..crate::config::PhpFpmConfig::default()
        };

        assert_eq!(php_fpm_retry_attempts_for_endpoint_count(&fpm, "GET", 3), 2);
        assert_eq!(
            php_fpm_retry_attempts_for_endpoint_count(&fpm, "POST", 3),
            0
        );
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_fpm_retryable_errors_exclude_request_timeouts() {
        assert!(php_fpm_retryable_error(&php_fpm_timeout_error(
            PhpFpmTimeoutKind::Connect
        )));
        assert!(php_fpm_retryable_error(&io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "connection refused",
        )));
        assert!(!php_fpm_retryable_error(&php_fpm_timeout_error(
            PhpFpmTimeoutKind::Request
        )));
        assert!(!php_fpm_retryable_error(&io::Error::new(
            io::ErrorKind::TimedOut,
            "php-fpm connect timed out",
        )));
        assert!(!php_fpm_retryable_error(&io::Error::new(
            io::ErrorKind::InvalidInput,
            "bad config",
        )));
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_fpm_stream_chunk_limit_counts_stdout_and_stderr() {
        let mut total = 0;
        let mut stdout = Vec::new();
        push_php_fpm_stream_chunk(&mut stdout, b"1234", &mut total, 6).unwrap();
        let mut stderr = Vec::new();
        let error = push_php_fpm_stream_chunk(&mut stderr, b"567", &mut total, 6)
            .expect_err("combined FastCGI output should be bounded");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(stdout, b"1234");
        assert!(stderr.is_empty());
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_header_values_reject_all_disallowed_controls() {
        assert!(safe_php_header_value(b"session=ok; Path=/"));
        assert!(safe_php_header_value(b"tab\tallowed"));
        assert!(!safe_php_header_value(b"bad\x0binject"));
        assert!(!safe_php_header_value(b"bad\x7fdelete"));
        assert!(!safe_php_header_value(b"bad\r\ninject"));
        assert!(!safe_php_header_value("bad-é".as_bytes()));
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn explicit_authority_port_reads_host_header_ports() {
        assert_eq!(explicit_authority_port("example.test:8443"), Some(8443));
        assert_eq!(explicit_authority_port("[2001:db8::1]:8443"), Some(8443));
        assert_eq!(explicit_authority_port("example.test"), None);
        assert_eq!(explicit_authority_port("example.test:https"), None);
    }

    #[cfg(feature = "php-fpm")]
    #[test]
    fn php_fpm_retryable_response_statuses_are_explicit() {
        let mut fpm = crate::config::PhpFpmConfig::default();
        assert!(!php_fpm_retryable_response(
            &fpm,
            StatusCode::INTERNAL_SERVER_ERROR
        ));

        fpm.retry_statuses = vec![500, 502, 503];
        assert!(php_fpm_retryable_response(
            &fpm,
            StatusCode::INTERNAL_SERVER_ERROR
        ));
        assert!(php_fpm_retryable_response(&fpm, StatusCode::BAD_GATEWAY));
        assert!(!php_fpm_retryable_response(&fpm, StatusCode::NOT_FOUND));
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
    fn php_stderr_failure_patterns_mark_response_invalid() {
        let mut php = php_test_runtime("php-stderr-failure-pattern");
        php.config.stderr_failure_patterns = vec!["PHP Fatal error:".to_owned()];

        assert!(php_stderr_matches_failure_pattern(
            b"PHP message: PHP Fatal error: Uncaught Error",
            &php.config
        ));
        assert!(!php_stderr_matches_failure_pattern(
            b"PHP message: PHP Warning: notice",
            &php.config
        ));

        let mut output = fastcgi_client::Response::default();
        output.stdout = Some(b"Content-Type: text/plain\r\n\r\nok".to_vec());
        output.stderr = Some(b"PHP message: PHP Fatal error: boom".to_vec());
        let error = match parse_php_fpm_output(&php, output) {
            Ok(_) => panic!("expected stderr failure pattern to reject response"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("failure pattern"));
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
    fn php_static_offload_rejects_x_sendfile_outside_fpm_root() {
        let mut php = php_test_runtime("php-x-sendfile-outside-fpm-root");
        php.fpm_root = std::path::PathBuf::from("/app/public");
        let mut outside = ResponseHeader::build(200, None).unwrap();
        outside
            .insert_header("x-sendfile", "/other/style.css")
            .unwrap();

        let error = php_static_offload_file(&mut outside, &php).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        let mut traversal = ResponseHeader::build(200, None).unwrap();
        traversal
            .insert_header("x-sendfile", "/app/public/../secret.txt")
            .unwrap();

        let error = php_static_offload_file(&mut traversal, &php).unwrap_err();
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
    fn php_can_ignore_origin_cache_headers() {
        let mut php = crate::config::PhpConfig {
            ignore_origin_cache_headers: true,
            ..crate::config::PhpConfig::default()
        };
        let mut response = ResponseHeader::build(200, None).unwrap();
        response
            .insert_header("cache-control", "public, max-age=60")
            .unwrap();
        response
            .insert_header("expires", "Wed, 21 Oct 2026 07:28:00 GMT")
            .unwrap();
        response.insert_header("pragma", "no-cache").unwrap();
        response.insert_header("etag", "abc").unwrap();

        ignore_php_origin_cache_headers(&mut response, &php);

        assert!(!response.headers.contains_key("cache-control"));
        assert!(!response.headers.contains_key("expires"));
        assert!(!response.headers.contains_key("pragma"));
        assert!(response.headers.contains_key("etag"));

        php.ignore_origin_cache_headers = false;
        response
            .insert_header("cache-control", "public, max-age=60")
            .unwrap();
        ignore_php_origin_cache_headers(&mut response, &php);
        assert!(response.headers.contains_key("cache-control"));
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
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig {
                        upstream: Some("127.0.0.1:3001".to_owned()),
                        ..ProxyConfig::default()
                    },
                    cache: CacheConfig::default(),
                    compression: None,
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
                VhostConfig {
                    name: "two".to_owned(),
                    hosts: vec!["two.example".to_owned()],
                    max_request_body_bytes: None,
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig {
                        upstream: Some("127.0.0.1:3002".to_owned()),
                        ..ProxyConfig::default()
                    },
                    cache: CacheConfig::default(),
                    compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
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
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    compression: None,
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
                VhostConfig {
                    name: "two".to_owned(),
                    hosts: vec!["two.example".to_owned()],
                    max_request_body_bytes: None,
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
            .route_index_by_path_for_tests("/.well-known/acme-challenge/token_123")
            .unwrap();
        let route = vhost.route(route_index);

        assert!(route.https_redirect_exempt);
        assert!(matches!(
            route.action,
            super::RuntimeRouteAction::AcmeHttp01(_)
        ));
        assert_eq!(vhost.route_index_by_path_for_tests("/other"), None);
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
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
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
                    compression: None,
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
                VhostConfig {
                    name: "example-www-redirect".to_owned(),
                    hosts: vec!["www.example.test".to_owned()],
                    max_request_body_bytes: None,
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig {
                        enabled: true,
                        to: Some("https://example.test{uri}".to_owned()),
                        status: 308,
                    },
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    compression: None,
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
            .route_index_by_path_for_tests("/.well-known/acme-challenge/token_123")
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
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    compression: None,
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
                VhostConfig {
                    name: "exact".to_owned(),
                    hosts: vec!["api.example.com".to_owned()],
                    max_request_body_bytes: None,
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    compression: None,
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
            server: crate::config::ServerConfig {
                regex_enabled: true,
                ..crate::config::ServerConfig::default()
            },
            vhosts: vec![VhostConfig {
                name: "gateway".to_owned(),
                hosts: vec!["gateway.example".to_owned()],
                max_request_body_bytes: Some(ByteSize::from_bytes(64 * 1024 * 1024)),
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
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
                        path_regex: None,
                        methods: Vec::new(),
                        strip_prefix: None,
                        rewrite_prefix: None,
                        rewrite_template: None,
                        https_redirect_exempt: false,
                        max_request_body_bytes: None,
                        access: Default::default(),
                        rate_limit: Default::default(),
                        concurrency: Default::default(),
                        grpc: Default::default(),
                        proxy: None,
                        web: None,
                        php: None,
                        cache: None,
                        compression: None,
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
                        path_regex: None,
                        methods: Vec::new(),
                        fallback: false,
                        strip_prefix: None,
                        rewrite_prefix: None,
                        rewrite_template: None,
                        https_redirect_exempt: false,
                        max_request_body_bytes: None,
                        access: Default::default(),
                        rate_limit: Default::default(),
                        concurrency: Default::default(),
                        grpc: Default::default(),
                        redirect: None,
                        web: None,
                        php: None,
                        cache: None,
                        compression: None,
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
                        path_regex: None,
                        methods: Vec::new(),
                        fallback: false,
                        strip_prefix: None,
                        rewrite_prefix: None,
                        rewrite_template: None,
                        https_redirect_exempt: false,
                        max_request_body_bytes: None,
                        access: Default::default(),
                        rate_limit: Default::default(),
                        concurrency: Default::default(),
                        grpc: Default::default(),
                        redirect: None,
                        web: None,
                        php: None,
                        cache: None,
                        compression: None,
                        headers: crate::config::VhostHeaderPolicyConfig::default(),
                    },
                    RouteConfig {
                        name: "regex-assets".to_owned(),
                        path_regex: Some(r"^/asset-[0-9]+\.txt$".to_owned()),
                        methods: Vec::new(),
                        proxy: Some(ProxyConfig {
                            upstreams: vec!["127.0.0.1:6004".to_owned()],
                            upstream: None,
                            ..ProxyConfig::default()
                        }),
                        path_exact: None,
                        path_prefix: None,
                        fallback: false,
                        strip_prefix: None,
                        rewrite_prefix: None,
                        rewrite_template: None,
                        https_redirect_exempt: false,
                        max_request_body_bytes: None,
                        access: Default::default(),
                        rate_limit: Default::default(),
                        concurrency: Default::default(),
                        grpc: Default::default(),
                        redirect: None,
                        web: None,
                        php: None,
                        cache: None,
                        compression: None,
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
                        path_regex: None,
                        methods: Vec::new(),
                        fallback: false,
                        strip_prefix: None,
                        rewrite_prefix: None,
                        rewrite_template: None,
                        https_redirect_exempt: false,
                        max_request_body_bytes: None,
                        access: Default::default(),
                        rate_limit: Default::default(),
                        concurrency: Default::default(),
                        grpc: Default::default(),
                        redirect: None,
                        web: None,
                        php: None,
                        cache: None,
                        compression: None,
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
        assert_eq!(
            vhost.route_index_by_path_for_tests("/api/v2/status"),
            Some(4)
        );
        assert_eq!(
            vhost.route_index_by_path_for_tests("/api/v2/users"),
            Some(2)
        );
        assert_eq!(vhost.route_index_by_path_for_tests("/api/users"), Some(1));
        assert_eq!(
            vhost.route_index_by_path_for_tests("/asset-42.txt"),
            Some(3)
        );
        assert_eq!(vhost.route_index_by_path_for_tests("/missing"), Some(0));
    }

    #[test]
    fn vhost_routes_can_match_by_method() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "gateway".to_owned(),
                hosts: vec!["gateway.example".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: vec![
                    RouteConfig {
                        name: "fallback".to_owned(),
                        path_exact: None,
                        path_prefix: None,
                        path_regex: None,
                        methods: Vec::new(),
                        fallback: true,
                        https_redirect_exempt: false,
                        strip_prefix: None,
                        rewrite_prefix: None,
                        rewrite_template: None,
                        max_request_body_bytes: None,
                        access: Default::default(),
                        rate_limit: Default::default(),
                        concurrency: Default::default(),
                        grpc: Default::default(),
                        redirect: Some(RouteRedirectConfig {
                            to: "https://gateway.example{uri}".to_owned(),
                            status: 308,
                        }),
                        proxy: None,
                        web: None,
                        php: None,
                        cache: None,
                        compression: None,
                        headers: crate::config::VhostHeaderPolicyConfig::default(),
                    },
                    RouteConfig {
                        name: "read".to_owned(),
                        path_exact: Some("/resource".to_owned()),
                        path_prefix: None,
                        path_regex: None,
                        methods: vec!["GET".to_owned(), "HEAD".to_owned()],
                        fallback: false,
                        https_redirect_exempt: false,
                        strip_prefix: None,
                        rewrite_prefix: None,
                        rewrite_template: None,
                        max_request_body_bytes: None,
                        access: Default::default(),
                        rate_limit: Default::default(),
                        concurrency: Default::default(),
                        grpc: Default::default(),
                        redirect: None,
                        proxy: Some(ProxyConfig {
                            upstreams: vec!["127.0.0.1:6001".to_owned()],
                            upstream: None,
                            ..ProxyConfig::default()
                        }),
                        web: None,
                        php: None,
                        cache: None,
                        compression: None,
                        headers: crate::config::VhostHeaderPolicyConfig::default(),
                    },
                    RouteConfig {
                        name: "write".to_owned(),
                        path_exact: Some("/resource".to_owned()),
                        path_prefix: None,
                        path_regex: None,
                        methods: vec!["POST".to_owned()],
                        fallback: false,
                        https_redirect_exempt: false,
                        strip_prefix: None,
                        rewrite_prefix: None,
                        rewrite_template: None,
                        max_request_body_bytes: None,
                        access: Default::default(),
                        rate_limit: Default::default(),
                        concurrency: Default::default(),
                        grpc: Default::default(),
                        redirect: None,
                        proxy: Some(ProxyConfig {
                            upstreams: vec!["127.0.0.1:6002".to_owned()],
                            upstream: None,
                            ..ProxyConfig::default()
                        }),
                        web: None,
                        php: None,
                        cache: None,
                        compression: None,
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

        assert_eq!(vhost.route_index("GET", "/resource"), Some(1));
        assert_eq!(vhost.route_index("HEAD", "/resource"), Some(1));
        assert_eq!(vhost.route_index("POST", "/resource"), Some(2));
        assert_eq!(vhost.route_index("PUT", "/resource"), Some(0));
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
    fn websocket_upgrade_policy_preserves_required_hop_by_hop_headers() {
        let mut downstream = pingora::http::RequestHeader::build("GET", b"/chat", None).unwrap();
        downstream
            .insert_header("connection", "keep-alive, Upgrade")
            .unwrap();
        downstream.insert_header("upgrade", "websocket").unwrap();

        let mut upstream = pingora::http::RequestHeader::build("GET", b"/chat", None).unwrap();
        upstream.insert_header("connection", "close").unwrap();
        upstream.insert_header("upgrade", "h2c").unwrap();
        let proxy = ProxyConfig {
            websocket: true,
            ..ProxyConfig::default()
        };

        assert!(proxy_upgrade_request_allowed(&downstream, &proxy));
        apply_websocket_upgrade_headers_if_enabled(&downstream, &mut upstream, &proxy).unwrap();

        assert_eq!(
            upstream
                .headers
                .get("connection")
                .and_then(|v| v.to_str().ok()),
            Some("upgrade")
        );
        assert_eq!(
            upstream
                .headers
                .get("upgrade")
                .and_then(|v| v.to_str().ok()),
            Some("websocket")
        );
    }

    #[test]
    fn websocket_upgrade_policy_is_explicit_opt_in() {
        let mut downstream = pingora::http::RequestHeader::build("GET", b"/chat", None).unwrap();
        downstream.insert_header("connection", "upgrade").unwrap();
        downstream.insert_header("upgrade", "websocket").unwrap();
        let proxy = ProxyConfig::default();

        assert!(!proxy_upgrade_request_allowed(&downstream, &proxy));
    }

    #[test]
    fn websocket_upgrade_policy_rejects_invalid_upgrade_tokens() {
        let mut downstream = pingora::http::RequestHeader::build("GET", b"/chat", None).unwrap();
        downstream.insert_header("connection", "upgrade").unwrap();
        downstream.insert_header("upgrade", "web socket").unwrap();
        let proxy = ProxyConfig {
            websocket: true,
            ..ProxyConfig::default()
        };

        assert!(!proxy_upgrade_request_allowed(&downstream, &proxy));
    }

    #[test]
    fn auth_request_input_forwards_only_configured_headers() {
        let mut request = pingora::http::RequestHeader::build("GET", b"/private", None).unwrap();
        request
            .insert_header("authorization", "Bearer abc")
            .unwrap();
        request.insert_header("cookie", "a=1").unwrap();
        request.insert_header("x-ignored", "no").unwrap();
        let auth = AuthRequestConfig {
            enabled: true,
            url: Some("http://127.0.0.1:4180/auth".to_owned()),
            forward_headers: vec!["authorization".to_owned(), "cookie".to_owned()],
            ..AuthRequestConfig::default()
        };

        assert_eq!(
            auth_request_input(&request, &auth).headers,
            [
                ("authorization".to_owned(), "Bearer abc".to_owned()),
                ("cookie".to_owned(), "a=1".to_owned())
            ]
        );
    }

    #[test]
    #[cfg(feature = "traffic-mirror")]
    fn traffic_mirror_builds_shadow_url_and_forwarded_headers() {
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/api/items?q=1", None).unwrap();
        request.insert_header("host", "example.test").unwrap();
        request
            .insert_header("user-agent", "fluxheim-test")
            .unwrap();
        request.insert_header("cookie", "secret=1").unwrap();
        let mirror = TrafficMirrorConfig {
            enabled: true,
            base_url: Some("http://127.0.0.1:9000/shadow".to_owned()),
            forward_headers: vec!["user-agent".to_owned()],
            ..TrafficMirrorConfig::default()
        };

        assert_eq!(
            traffic_mirror_url(
                mirror.base_url.as_deref().unwrap(),
                request.uri.path_and_query().unwrap().as_str()
            )
            .as_deref(),
            Some("http://127.0.0.1:9000/shadow/api/items?q=1")
        );
        assert_eq!(
            traffic_mirror_forwarded_headers(&request, &mirror),
            [("user-agent".to_owned(), "fluxheim-test".to_owned())]
        );
    }

    #[test]
    #[cfg(feature = "traffic-mirror")]
    fn traffic_mirror_slots_enforce_per_key_limit() {
        let key = "traffic-mirror-slot-test";
        let first = acquire_traffic_mirror_slot(key, 1);
        assert!(first.is_some());
        assert!(acquire_traffic_mirror_slot(key, 1).is_none());
        drop(first);
        assert!(acquire_traffic_mirror_slot(key, 1).is_some());
    }

    #[test]
    #[cfg(feature = "traffic-mirror")]
    fn traffic_mirror_sampling_is_deterministic() {
        let request = pingora::http::RequestHeader::build("GET", b"/api/items?q=1", None).unwrap();

        assert!(traffic_mirror_sample_selected(&request, 1000));
        assert!(!traffic_mirror_sample_selected(&request, 0));
        assert_eq!(
            traffic_mirror_sample_selected(&request, 125),
            traffic_mirror_sample_selected(&request, 125)
        );
        assert_eq!(
            traffic_mirror_url("http://127.0.0.1:9000/base/", "/path?q=1").as_deref(),
            Some("http://127.0.0.1:9000/base/path?q=1")
        );
    }

    #[test]
    fn route_strip_prefix_rewrites_path_and_preserves_query() {
        let request = pingora::http::RequestHeader::build("GET", b"/chat/room?id=7", None).unwrap();
        let route = super::RuntimeRoute {
            name: "chat".to_owned(),
            matcher: super::RuntimeRouteMatcher::Prefix("/chat/".to_owned()),
            methods: Vec::new(),
            https_redirect_exempt: false,
            strip_prefix: Some("/chat/".to_owned()),
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: Default::default(),
            action: super::RuntimeRouteAction::Proxy(
                super::RuntimeProxy::from_config(&ProxyConfig::default(), "test proxy").unwrap(),
            ),
            #[cfg(feature = "load-balancer")]
            load_balancer: None,
            #[cfg(feature = "cache")]
            cache: None,
            #[cfg(feature = "compression")]
            compression: None,
            request_headers: crate::config::RequestHeaderPolicyConfig::default(),
            response_headers: crate::config::ResponseHeaderPolicyConfig::default(),
        };

        assert_eq!(
            route_rewritten_path_and_query(&request, &route).as_deref(),
            Some("/room?id=7")
        );
    }

    #[test]
    fn route_rewrite_prefix_rewrites_to_upstream_prefix() {
        let request =
            pingora::http::RequestHeader::build("GET", b"/public/api/users?id=7", None).unwrap();
        let route = super::RuntimeRoute {
            name: "api".to_owned(),
            matcher: super::RuntimeRouteMatcher::Prefix("/public/api/".to_owned()),
            methods: Vec::new(),
            https_redirect_exempt: false,
            strip_prefix: Some("/public/api/".to_owned()),
            rewrite_prefix: Some("/internal/v1/".to_owned()),
            rewrite_template: None,
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: Default::default(),
            action: super::RuntimeRouteAction::Proxy(
                super::RuntimeProxy::from_config(&ProxyConfig::default(), "test proxy").unwrap(),
            ),
            #[cfg(feature = "load-balancer")]
            load_balancer: None,
            #[cfg(feature = "cache")]
            cache: None,
            #[cfg(feature = "compression")]
            compression: None,
            request_headers: crate::config::RequestHeaderPolicyConfig::default(),
            response_headers: crate::config::ResponseHeaderPolicyConfig::default(),
        };

        assert_eq!(
            route_rewritten_path_and_query(&request, &route).as_deref(),
            Some("/internal/v1/users?id=7")
        );
    }

    #[test]
    fn route_rewrite_template_uses_regex_captures() {
        let request =
            pingora::http::RequestHeader::build("GET", b"/api/v2/users?id=7", None).unwrap();
        let route = super::RuntimeRoute {
            name: "api".to_owned(),
            matcher: super::RuntimeRouteMatcher::Regex(
                regex::Regex::new(r"^/api/v(?P<version>[0-9]+)/(?P<rest>.*)$").unwrap(),
            ),
            methods: Vec::new(),
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: Some(
                "/internal/v{route.regex.version}/{route.regex.rest}".to_owned(),
            ),
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: Default::default(),
            action: super::RuntimeRouteAction::Proxy(
                super::RuntimeProxy::from_config(&ProxyConfig::default(), "test proxy").unwrap(),
            ),
            #[cfg(feature = "load-balancer")]
            load_balancer: None,
            #[cfg(feature = "cache")]
            cache: None,
            #[cfg(feature = "compression")]
            compression: None,
            request_headers: crate::config::RequestHeaderPolicyConfig::default(),
            response_headers: crate::config::ResponseHeaderPolicyConfig::default(),
        };

        assert_eq!(
            route_rewritten_path_and_query(&request, &route).as_deref(),
            Some("/internal/v2/users?id=7")
        );

        let traversal =
            pingora::http::RequestHeader::build("GET", b"/api/v2/../admin", None).unwrap();
        assert_eq!(route_rewritten_path_and_query(&traversal, &route), None);

        let encoded_separator =
            pingora::http::RequestHeader::build("GET", b"/api/v2/users%2fadmin", None).unwrap();
        assert_eq!(
            route_rewritten_path_and_query(&encoded_separator, &route),
            None
        );
    }

    #[test]
    fn route_strip_prefix_rejects_traversal_suffixes() {
        let route = super::RuntimeRoute {
            name: "api".to_owned(),
            matcher: super::RuntimeRouteMatcher::Prefix("/api/".to_owned()),
            methods: Vec::new(),
            https_redirect_exempt: false,
            strip_prefix: Some("/api/".to_owned()),
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: Default::default(),
            action: super::RuntimeRouteAction::Proxy(
                super::RuntimeProxy::from_config(&ProxyConfig::default(), "test proxy").unwrap(),
            ),
            #[cfg(feature = "load-balancer")]
            load_balancer: None,
            #[cfg(feature = "cache")]
            cache: None,
            #[cfg(feature = "compression")]
            compression: None,
            request_headers: crate::config::RequestHeaderPolicyConfig::default(),
            response_headers: crate::config::ResponseHeaderPolicyConfig::default(),
        };

        let raw = pingora::http::RequestHeader::build("GET", b"/api/../admin", None).unwrap();
        assert_eq!(route_rewritten_path_and_query(&raw, &route), None);

        let encoded =
            pingora::http::RequestHeader::build("GET", b"/api/%2e%2e/admin", None).unwrap();
        assert_eq!(route_rewritten_path_and_query(&encoded, &route), None);

        let double_encoded =
            pingora::http::RequestHeader::build("GET", b"/api/%252e%252e/admin", None).unwrap();
        assert_eq!(
            route_rewritten_path_and_query(&double_encoded, &route),
            None
        );

        let encoded_separator =
            pingora::http::RequestHeader::build("GET", b"/api/safe%2f..%2fadmin", None).unwrap();
        assert_eq!(
            route_rewritten_path_and_query(&encoded_separator, &route),
            None
        );

        let encoded_null =
            pingora::http::RequestHeader::build("GET", b"/api/safe%00admin", None).unwrap();
        assert_eq!(route_rewritten_path_and_query(&encoded_null, &route), None);
    }

    #[test]
    fn proxy_timeout_config_maps_to_pingora_peer_options() {
        let proxy = ProxyConfig {
            upstream: Some("127.0.0.1:6010".to_owned()),
            connect_timeout_secs: Some(5),
            upstream_total_connection_timeout_secs: Some(10),
            upstream_idle_timeout_secs: Some(120),
            upstream_tcp_keepalive_idle_secs: Some(30),
            upstream_tcp_keepalive_interval_secs: Some(10),
            upstream_tcp_keepalive_count: Some(3),
            upstream_tcp_user_timeout_ms: Some(15000),
            upstream_tcp_recv_buffer_bytes: Some(crate::config::ByteSize::from_bytes(1024 * 1024)),
            upstream_dscp: Some(46),
            upstream_tcp_fast_open: true,
            read_timeout_secs: Some(600),
            send_timeout_secs: Some(30),
            ..ProxyConfig::default()
        };

        let peer = http_peer_for_proxy(proxy.primary_upstream(), &proxy).unwrap();

        assert_eq!(
            peer.options.connection_timeout,
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            peer.options.total_connection_timeout,
            Some(Duration::from_secs(10))
        );
        assert_eq!(peer.options.idle_timeout, Some(Duration::from_secs(120)));
        let keepalive = peer.options.tcp_keepalive.as_ref().unwrap();
        assert_eq!(keepalive.idle, Duration::from_secs(30));
        assert_eq!(keepalive.interval, Duration::from_secs(10));
        assert_eq!(keepalive.count, 3);
        #[cfg(target_os = "linux")]
        assert_eq!(keepalive.user_timeout, Duration::from_millis(15000));
        assert_eq!(peer.options.tcp_recv_buf, Some(1024 * 1024));
        assert_eq!(peer.options.dscp, Some(46));
        assert!(peer.options.tcp_fast_open);
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(600)));
        assert_eq!(peer.options.write_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn proxy_upstream_http_policy_maps_to_pingora_peer_options() {
        let proxy = ProxyConfig {
            upstream: Some("127.0.0.1:6010".to_owned()),
            upstream_http_version: UpstreamHttpVersion::Http2,
            upstream_h2_max_streams: Some(64),
            upstream_h2_ping_interval_secs: Some(30),
            ..ProxyConfig::default()
        };

        let peer = http_peer_for_proxy(proxy.primary_upstream(), &proxy).unwrap();

        assert_eq!(peer.options.alpn.get_min_http_version(), 2);
        assert_eq!(peer.options.alpn.get_max_http_version(), 2);
        assert_eq!(peer.options.max_h2_streams, 64);
        assert_eq!(peer.options.h2_ping_interval, Some(Duration::from_secs(30)));
    }

    #[test]
    fn proxy_upstream_http_policy_can_offer_h2_with_h1_fallback() {
        let proxy = ProxyConfig {
            upstream: Some("127.0.0.1:6010".to_owned()),
            upstream_http_version: UpstreamHttpVersion::Http1AndHttp2,
            ..ProxyConfig::default()
        };

        let peer = http_peer_for_proxy(proxy.primary_upstream(), &proxy).unwrap();

        assert_eq!(peer.options.alpn.get_min_http_version(), 1);
        assert_eq!(peer.options.alpn.get_max_http_version(), 2);
    }

    #[test]
    fn grpc_route_policy_accepts_grpc_content_types() {
        assert!(grpc_content_type("application/grpc"));
        assert!(grpc_content_type("application/grpc+proto"));
        assert!(grpc_content_type("application/grpc+json; charset=utf-8"));
        assert!(!grpc_content_type("application/json"));
        assert!(!grpc_content_type("text/plain"));
    }

    #[test]
    fn grpc_route_policy_rejects_non_post_or_missing_content_type() {
        let grpc = GrpcRouteConfig {
            enabled: true,
            require_content_type: true,
        };
        let get_request =
            pingora::http::RequestHeader::build("GET", b"/service.Method", None).unwrap();
        assert_eq!(
            grpc_route_rejection_status(&grpc, &get_request),
            Some(super::GrpcRouteRejectionStatus::MethodNotAllowed)
        );

        let post_request =
            pingora::http::RequestHeader::build("POST", b"/service.Method", None).unwrap();
        assert_eq!(
            grpc_route_rejection_status(&grpc, &post_request),
            Some(super::GrpcRouteRejectionStatus::UnsupportedMediaType)
        );

        let mut grpc_request =
            pingora::http::RequestHeader::build("POST", b"/service.Method", None).unwrap();
        grpc_request
            .insert_header("content-type", "application/grpc+proto")
            .unwrap();
        assert_eq!(grpc_route_rejection_status(&grpc, &grpc_request), None);
    }

    #[test]
    fn proxy_upstream_tls_policy_maps_to_pingora_peer_options() {
        let proxy = ProxyConfig {
            upstream: Some("127.0.0.1:6010".to_owned()),
            upstream_tls: true,
            upstream_sni: Some("origin.example.test".to_owned()),
            upstream_verify_cert: true,
            upstream_verify_hostname: false,
            upstream_alternative_cn: Some("fallback-origin.example.test".to_owned()),
            ..ProxyConfig::default()
        };

        let peer = http_peer_for_proxy(proxy.primary_upstream(), &proxy).unwrap();

        assert!(peer.is_tls());
        assert_eq!(peer.sni, "origin.example.test");
        assert!(peer.options.verify_cert);
        assert!(!peer.options.verify_hostname);
        assert_eq!(
            peer.options.alternative_cn.as_deref(),
            Some("fallback-origin.example.test")
        );
    }

    #[cfg(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl"
    ))]
    #[test]
    fn proxy_upstream_tls_material_maps_to_pingora_peer() {
        let proxy = ProxyConfig {
            upstream: Some("127.0.0.1:6010".to_owned()),
            upstream_tls: true,
            upstream_ca_path: Some("tests/fixtures/tls/localhost-cert.pem".into()),
            upstream_client_cert_path: Some("tests/fixtures/tls/localhost-cert.pem".into()),
            upstream_client_key_path: Some("tests/fixtures/tls/localhost-key.pem".into()),
            ..ProxyConfig::default()
        };
        let runtime = RuntimeProxy::from_config(&proxy, "test proxy").unwrap();

        let peer = http_peer_for_runtime_proxy(proxy.primary_upstream(), &runtime).unwrap();

        assert!(peer.options.ca.is_some());
        assert!(peer.client_cert_key.is_some());
    }

    #[test]
    fn proxy_protocol_v1_header_encodes_matching_ip_families() {
        let source = "203.0.113.10:42300".parse().unwrap();
        let destination = "192.0.2.20:443".parse().unwrap();
        assert_eq!(
            proxy_protocol_v1_header(Some(source), Some(destination)),
            b"PROXY TCP4 203.0.113.10 192.0.2.20 42300 443\r\n"
        );

        let source = "[2001:db8::10]:42300".parse().unwrap();
        let destination = "[2001:db8::20]:8443".parse().unwrap();
        assert_eq!(
            proxy_protocol_v1_header(Some(source), Some(destination)),
            b"PROXY TCP6 2001:db8::10 2001:db8::20 42300 8443\r\n"
        );
    }

    #[test]
    fn proxy_protocol_v1_header_falls_back_to_unknown_for_ambiguous_inputs() {
        let source = "203.0.113.10:42300".parse().unwrap();
        let destination = "[2001:db8::20]:8443".parse().unwrap();
        assert_eq!(
            proxy_protocol_v1_header(Some(source), Some(destination)),
            b"PROXY UNKNOWN\r\n"
        );
        assert_eq!(
            proxy_protocol_v1_header(None, Some(destination)),
            b"PROXY UNKNOWN\r\n"
        );
    }

    #[test]
    fn proxy_protocol_v2_header_encodes_matching_ip_families() {
        let source = "203.0.113.10:42300".parse().unwrap();
        let destination = "192.0.2.20:443".parse().unwrap();
        let header = proxy_protocol_v2_header(Some(source), Some(destination));
        assert_eq!(&header[..12], b"\r\n\r\n\0\r\nQUIT\n");
        assert_eq!(&header[12..16], &[0x21, 0x11, 0x00, 0x0c]);
        assert_eq!(&header[16..24], &[203, 0, 113, 10, 192, 0, 2, 20]);
        assert_eq!(&header[24..26], &42300u16.to_be_bytes());
        assert_eq!(&header[26..28], &443u16.to_be_bytes());

        let source = "[2001:db8::10]:42300".parse().unwrap();
        let destination = "[2001:db8::20]:8443".parse().unwrap();
        let header = proxy_protocol_v2_header(Some(source), Some(destination));
        assert_eq!(&header[12..16], &[0x21, 0x21, 0x00, 0x24]);
        assert_eq!(header.len(), 52);
    }

    #[test]
    fn proxy_protocol_v2_header_falls_back_to_unspec_for_ambiguous_inputs() {
        let source = "203.0.113.10:42300".parse().unwrap();
        let destination = "[2001:db8::20]:8443".parse().unwrap();
        assert_eq!(
            &proxy_protocol_v2_header(Some(source), Some(destination))[12..16],
            &[0x21, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            &proxy_protocol_v2_header(None, Some(destination))[12..16],
            &[0x21, 0x00, 0x00, 0x00]
        );
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
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
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
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
                    compression: None,
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: Vec::new(),
                },
                VhostConfig {
                    name: "uncached".to_owned(),
                    hosts: vec!["uncached.example".to_owned()],
                    max_request_body_bytes: None,
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: vec![RouteConfig {
                    name: "assets".to_owned(),
                    path_exact: None,
                    path_prefix: Some("/assets/".to_owned()),
                    path_regex: None,
                    methods: Vec::new(),
                    fallback: false,
                    https_redirect_exempt: false,
                    strip_prefix: None,
                    rewrite_prefix: None,
                    rewrite_template: None,
                    max_request_body_bytes: None,
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    grpc: Default::default(),
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
                    compression: None,
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                }],
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let vhost = snapshot.state.vhost(vhost_index);
        let route_index = vhost
            .route_index_by_path_for_tests("/assets/logo.png")
            .unwrap();
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: vec![RouteConfig {
                    name: "assets".to_owned(),
                    path_exact: None,
                    path_prefix: Some("/assets/".to_owned()),
                    path_regex: None,
                    methods: Vec::new(),
                    fallback: false,
                    https_redirect_exempt: false,
                    strip_prefix: None,
                    rewrite_prefix: None,
                    rewrite_template: None,
                    max_request_body_bytes: None,
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    grpc: Default::default(),
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
                    compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: vec![RouteConfig {
                    name: "assets".to_owned(),
                    path_exact: None,
                    path_prefix: Some("/assets/".to_owned()),
                    path_regex: None,
                    methods: Vec::new(),
                    fallback: false,
                    https_redirect_exempt: false,
                    strip_prefix: None,
                    rewrite_prefix: None,
                    rewrite_template: None,
                    max_request_body_bytes: None,
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    grpc: Default::default(),
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
                    compression: None,
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                }],
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost_index = snapshot.state.vhost_index(Some("cached.example"));
        let vhost = snapshot.state.vhost(vhost_index);
        let route_index = vhost
            .route_index_by_path_for_tests("/assets/logo.png")
            .unwrap();
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: vec![RouteConfig {
                    name: "assets".to_owned(),
                    path_exact: None,
                    path_prefix: Some("/assets/".to_owned()),
                    path_regex: None,
                    methods: Vec::new(),
                    fallback: false,
                    https_redirect_exempt: false,
                    strip_prefix: None,
                    rewrite_prefix: None,
                    rewrite_template: None,
                    max_request_body_bytes: None,
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    grpc: Default::default(),
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
                    compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: vec![RouteConfig {
                    name: "assets".to_owned(),
                    path_exact: None,
                    path_prefix: Some("/assets/".to_owned()),
                    path_regex: None,
                    methods: Vec::new(),
                    fallback: false,
                    https_redirect_exempt: false,
                    strip_prefix: None,
                    rewrite_prefix: None,
                    rewrite_template: None,
                    max_request_body_bytes: None,
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    grpc: Default::default(),
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
                    compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
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
                compression: None,
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
    fn load_balance_retry_budget_caps_window_attempts() {
        let budget = RuntimeRetryBudget::from_config(&LoadBalanceRetryConfig {
            enabled: true,
            max_retries: 3,
            methods: vec!["GET".to_owned()],
            budget_per_window: 2,
            budget_window_secs: 60,
        })
        .unwrap();

        assert!(budget.try_acquire());
        assert!(budget.try_acquire());
        assert!(!budget.try_acquire());
    }

    #[cfg(feature = "load-balancer")]
    #[test]
    fn builds_load_balancer_background_services_for_configured_pools() {
        #[cfg(feature = "tls-rustls-backend")]
        let _ = crate::tls::install_rustls_crypto_provider();

        let config = Config {
            vhosts: vec![
                VhostConfig {
                    name: "one".to_owned(),
                    hosts: vec!["one.example".to_owned()],
                    max_request_body_bytes: None,
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig {
                        upstreams: vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()],
                        ..ProxyConfig::default()
                    },
                    cache: CacheConfig::default(),
                    compression: None,
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    php: crate::config::PhpConfig::default(),
                    web: WebConfig::default(),
                    routes: vec![RouteConfig {
                        name: "api".to_owned(),
                        path_exact: None,
                        path_prefix: Some("/api/".to_owned()),
                        path_regex: None,
                        methods: Vec::new(),
                        fallback: false,
                        https_redirect_exempt: false,
                        strip_prefix: None,
                        rewrite_prefix: None,
                        rewrite_template: None,
                        max_request_body_bytes: None,
                        access: Default::default(),
                        rate_limit: Default::default(),
                        concurrency: Default::default(),
                        grpc: Default::default(),
                        redirect: None,
                        proxy: Some(ProxyConfig {
                            upstreams: vec![
                                "127.0.0.1:3011".to_owned(),
                                "127.0.0.1:3012".to_owned(),
                            ],
                            ..ProxyConfig::default()
                        }),
                        web: None,
                        php: None,
                        cache: None,
                        compression: None,
                        headers: crate::config::VhostHeaderPolicyConfig::default(),
                    }],
                },
                VhostConfig {
                    name: "two".to_owned(),
                    hosts: vec!["two.example".to_owned()],
                    max_request_body_bytes: None,
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                    redirect: crate::config::VhostRedirectConfig::default(),
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig {
                        upstreams: vec!["127.0.0.1:3003".to_owned(), "127.0.0.1:3004".to_owned()],
                        ..ProxyConfig::default()
                    },
                    cache: CacheConfig::default(),
                    compression: None,
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
        assert_eq!(services.len(), 3);
    }

    #[cfg(feature = "load-balancer")]
    #[test]
    fn route_single_proxy_does_not_inherit_vhost_load_balancer() {
        #[cfg(feature = "tls-rustls-backend")]
        let _ = crate::tls::install_rustls_crypto_provider();

        let config = Config {
            vhosts: vec![VhostConfig {
                name: "one".to_owned(),
                hosts: vec!["one.example".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig {
                    upstreams: vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()],
                    ..ProxyConfig::default()
                },
                cache: CacheConfig::default(),
                compression: None,
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: vec![RouteConfig {
                    name: "single".to_owned(),
                    path_exact: None,
                    path_prefix: Some("/single/".to_owned()),
                    path_regex: None,
                    methods: Vec::new(),
                    fallback: false,
                    https_redirect_exempt: false,
                    strip_prefix: None,
                    rewrite_prefix: None,
                    rewrite_template: None,
                    max_request_body_bytes: None,
                    access: Default::default(),
                    rate_limit: Default::default(),
                    concurrency: Default::default(),
                    grpc: Default::default(),
                    redirect: None,
                    proxy: Some(ProxyConfig {
                        upstream: Some("127.0.0.1:3010".to_owned()),
                        ..ProxyConfig::default()
                    }),
                    web: None,
                    php: None,
                    cache: None,
                    compression: None,
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                }],
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let snapshot = proxy.snapshot();
        let vhost = snapshot.state.vhost(0);
        let ctx = super::RequestContext {
            route_index: Some(0),
            ..super::RequestContext::default()
        };

        assert!(vhost.load_balancer.is_some());
        assert!(super::selected_upstream_load_balancer(vhost, &ctx).is_none());
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
    fn accepts_chunked_body_without_content_length() {
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

        assert_eq!(request_limit_status(&limits, None, &request), None);
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

        prune_inactive_cache_fill_concurrency_counters(&mut counters, 2);

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
    fn request_cache_bypass_honors_configured_paths_and_cookie_prefixes() {
        let cache = CacheConfig {
            bypass_path_prefixes: vec!["/wp-admin/".to_owned()],
            bypass_path_exact: vec!["/wp-login.php".to_owned()],
            bypass_cookie_name_prefixes: vec!["wordpress_logged_in_".to_owned()],
            ..CacheConfig::default()
        };

        let admin = pingora::http::RequestHeader::build("GET", b"/wp-admin/", None).unwrap();
        assert!(request_cache_bypass(&admin, &cache));
        assert_eq!(
            request_cache_bypass_reason(&admin, &cache),
            Some("request-path")
        );

        let login = pingora::http::RequestHeader::build("GET", b"/wp-login.php", None).unwrap();
        assert!(request_cache_bypass(&login, &cache));
        assert_eq!(
            request_cache_bypass_reason(&login, &cache),
            Some("request-path")
        );

        let mut cookie = pingora::http::RequestHeader::build("GET", b"/", None).unwrap();
        cookie
            .insert_header("cookie", "wordpress_logged_in_c71744=user")
            .unwrap();
        assert!(request_cache_bypass(&cookie, &cache));
        assert_eq!(
            request_cache_bypass_reason(&cookie, &cache),
            Some("request-cookie")
        );
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
    fn request_cache_bypass_honors_any_query_switch() {
        let cache = CacheConfig {
            bypass_query: true,
            ..CacheConfig::default()
        };

        let request = pingora::http::RequestHeader::build("GET", b"/assets/app.js", None).unwrap();
        assert!(!request_cache_bypass(&request, &cache));

        let request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js?v=1", None).unwrap();
        assert!(request_cache_bypass(&request, &cache));
        assert_eq!(
            request_cache_bypass_reason(&request, &cache),
            Some("request-query")
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
    fn appends_fluxheim_via_to_forwarded_request_and_response() {
        let mut request = pingora::http::RequestHeader::build("GET", b"/", None).unwrap();
        request.append_header("via", "1.0 edge").unwrap();
        request.append_header("via", "1.1 cache").unwrap();

        append_fluxheim_via_to_request(&mut request).unwrap();

        assert_eq!(
            request
                .headers
                .get("via")
                .and_then(|value| value.to_str().ok()),
            Some("1.0 edge, 1.1 cache, 1.1 fluxheim")
        );

        let mut response = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
        response.insert_header("via", "1.0 origin-proxy").unwrap();

        append_fluxheim_via_to_response(&mut response).unwrap();

        assert_eq!(
            response
                .headers
                .get("via")
                .and_then(|value| value.to_str().ok()),
            Some("1.0 origin-proxy, 1.1 fluxheim")
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
