use std::cmp::Reverse;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
#[cfg(feature = "cache")]
use std::sync::OnceLock;
use std::sync::{Arc, RwLock};
#[cfg(feature = "cache")]
use std::time::Duration;
#[cfg(not(feature = "privacy-mode"))]
use std::time::Instant;

use arc_swap::ArcSwap;
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
use pingora::http::RequestHeader;
use pingora::http::ResponseHeader;
use pingora::prelude::{HttpPeer, Result};
use pingora::proxy::{FailToProxy, ProxyHttp, Session};
use pingora::{Error, ErrorType};
#[cfg(feature = "cache")]
use pingora::{
    cache::CacheOptionOverrides, cache::CachePhase, cache::NoCacheReason, cache::RespCacheable,
    http::StatusCode,
};

#[cfg(not(feature = "privacy-mode"))]
use crate::config::AccessLoggingConfig;
use crate::config::{
    Config, HttpsRedirectConfig, ProxyConfig, RouteRedirectConfig, ServerLimitsConfig,
    normalize_host,
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

#[derive(Clone)]
pub struct FluxProxy {
    state: Arc<ArcSwap<ProxyRuntimeState>>,
    health_reporter: Arc<RwLock<Option<Arc<dyn ProxyHealthReporter>>>>,
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

#[derive(Debug, Clone)]
struct ProxyRuntimeState {
    vhosts: Vec<RuntimeVhost>,
    host_index: HashMap<String, usize>,
    wildcard_hosts: Vec<WildcardHost>,
    default_vhost: usize,
    trusted_proxies: Vec<TrustedProxy>,
    limits: ServerLimitsConfig,
    https_redirect: HttpsRedirectConfig,
    #[cfg(not(feature = "privacy-mode"))]
    access_log: AccessLoggingConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TrustedProxy {
    Exact(IpAddr),
    Cidr { network: IpAddr, prefix: u8 },
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
            health_reporter: Arc::new(RwLock::new(None)),
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
        let mut current = self.health_reporter.write().unwrap_or_else(|poisoned| {
            log::error!("proxy health reporter write lock poisoned; recovering state");
            poisoned.into_inner()
        });
        *current = Some(reporter);
    }

    pub(crate) fn has_health_reporter(&self) -> bool {
        self.health_reporter
            .read()
            .unwrap_or_else(|poisoned| {
                log::error!("proxy health reporter read lock poisoned; recovering state");
                poisoned.into_inner()
            })
            .is_some()
    }

    fn report_proxy_health_signal(&self, signal: ProxyHealthSignal, ctx: &mut RequestContext) {
        if ctx.health_signal_recorded {
            return;
        }
        ctx.health_signal_recorded = true;

        let reporter = self
            .health_reporter
            .read()
            .unwrap_or_else(|poisoned| {
                log::error!("proxy health reporter read lock poisoned; recovering state");
                poisoned.into_inner()
            })
            .clone();
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
                request_body_bytes: ctx.request_body_bytes_seen,
                response_body_bytes: ctx.response_body_bytes_seen,
                latency_ms,
            })
        );
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
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheIndexedPathPrefixPurgeRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub path_prefix: &'a str,
    pub limit: usize,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheIndexedPathPatternPurgeRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub path_pattern: &'a str,
    pub limit: usize,
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
    pub memory_tiers: u64,
    pub memory_entries: u64,
    pub memory_weighted_size_bytes: u64,
    pub memory_max_size_bytes: u64,
    pub memory_purge_index_entries: u64,
    pub memory_purge_index_max_entries: u64,
    pub disk_tiers: u64,
    pub disk_entries: u64,
    pub disk_size_bytes: u64,
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
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheVhostStats {
    pub name: String,
    pub enabled: bool,
    pub tiered: bool,
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
                    memory: route_memory,
                    disk: route_disk,
                });
            }

            vhosts.push(CacheVhostStats {
                name: vhost.name.clone(),
                enabled: vhost.cache.enabled,
                tiered: vhost.pingora_tiered_storage.is_some(),
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
        let key = crate::cache::pingora_image_cache_key(
            "fluxheim-image-v1",
            cache_config,
            &cache_request,
            user_tag,
        )
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
        let memory_purged = route_cache
            .and_then(|cache| cache.pingora_memory_storage)
            .or(vhost
                .pingora_memory_storage
                .filter(|_| route_cache.is_none()))
            .is_some_and(|storage| storage.purge_cache_key(&key));
        let disk_purged = route_cache
            .and_then(|cache| cache.pingora_disk_storage)
            .or(vhost.pingora_disk_storage.filter(|_| route_cache.is_none()))
            .map(|storage| storage.purge_cache_key(&key))
            .transpose()?
            .unwrap_or(false);
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
            .map(|storage| storage.purge_indexed_user_tag(&user_tag, request.limit))
            .unwrap_or_default();
        let disk = route_cache
            .and_then(|cache| cache.pingora_disk_storage)
            .or(vhost.pingora_disk_storage.filter(|_| route_cache.is_none()))
            .map(|storage| storage.purge_indexed_user_tag(&user_tag, request.limit))
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
                storage.purge_indexed_path_prefix(&user_tag, request.path_prefix, request.limit)
            })
            .unwrap_or_default();
        let disk = route_cache
            .and_then(|cache| cache.pingora_disk_storage)
            .or(vhost.pingora_disk_storage.filter(|_| route_cache.is_none()))
            .map(|storage| {
                storage.purge_indexed_path_prefix(&user_tag, request.path_prefix, request.limit)
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
                storage.purge_indexed_path_pattern(&user_tag, request.path_pattern, request.limit)
            })
            .unwrap_or_default();
        let disk = route_cache
            .and_then(|cache| cache.pingora_disk_storage)
            .or(vhost.pingora_disk_storage.filter(|_| route_cache.is_none()))
            .map(|storage| {
                storage.purge_indexed_path_pattern(&user_tag, request.path_pattern, request.limit)
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
            health_reporter: Arc::new(RwLock::new(None)),
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
            )?;
            vhosts.push(runtime);
        } else {
            for configured in &config.vhosts {
                let index = vhosts.len();
                let runtime = RuntimeVhost::from_config(
                    config,
                    configured,
                    &config.headers,
                    load_balancer(&configured.name, &configured.proxy)?,
                )?;
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
            )?;
            vhosts.push(runtime);
        } else {
            for configured in &config.vhosts {
                let index = vhosts.len();
                let runtime = RuntimeVhost::from_config(config, configured, &config.headers)?;
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
            #[cfg(not(feature = "privacy-mode"))]
            access_log: config.logging.access.clone(),
        })
    }

    fn vhost_index(&self, host: Option<&str>) -> usize {
        let Some(host) = host.and_then(normalize_host) else {
            return self.default_vhost;
        };

        if let Some(index) = self.host_index.get(&host) {
            return *index;
        }

        self.wildcard_hosts
            .iter()
            .find(|wildcard| wildcard.matches(&host))
            .map(|wildcard| wildcard.vhost_index)
            .unwrap_or(self.default_vhost)
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
    pingora_disk_storage: Option<&'static crate::cache::PingoraDiskStorage>,
    #[cfg(feature = "cache")]
    pingora_tiered_storage: Option<&'static crate::cache::PingoraTieredStorage>,
    #[cfg(feature = "cache")]
    pingora_cache_lock: Option<&'static CacheKeyLockImpl>,
    #[cfg(feature = "cache")]
    cache_lock_wait_timeout: std::time::Duration,
    #[cfg(feature = "load-balancer")]
    load_balancer: Option<UpstreamLoadBalancer>,
    #[cfg(feature = "web")]
    web: Option<StaticFileServer>,
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
            .field("cache_lock_wait_timeout", &self.cache_lock_wait_timeout);

        #[cfg(feature = "load-balancer")]
        debug.field("load_balancer", &self.load_balancer);

        #[cfg(feature = "web")]
        debug.field("web", &self.web);
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
    pingora_disk_storage: Option<&'static crate::cache::PingoraDiskStorage>,
    pingora_tiered_storage: Option<&'static crate::cache::PingoraTieredStorage>,
    pingora_cache_lock: Option<&'static CacheKeyLockImpl>,
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
            .field("cache_lock_wait_timeout", &self.cache_lock_wait_timeout)
            .finish()
    }
}

#[cfg(feature = "cache")]
impl RuntimeRouteCache {
    fn from_config(name: &str, config: &crate::config::CacheConfig) -> io::Result<Self> {
        let pingora_memory_storage = crate::cache::pingora_memory_storage_from_config(config);
        let pingora_disk_storage = crate::cache::pingora_disk_storage_from_config(config)?;
        let pingora_tiered_storage = pingora_memory_storage
            .zip(pingora_disk_storage)
            .map(|(memory, disk)| crate::cache::pingora_tiered_storage_from_parts(memory, disk));
        let pingora_cache_lock = cache_lock_from_config(
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
}

#[derive(Debug, Clone)]
struct RuntimeProxy {
    config: ProxyConfig,
    error_pages: Vec<RuntimeErrorPage>,
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
    fn from_config(config: &ProxyConfig) -> io::Result<Self> {
        let error_pages = config
            .error_pages
            .iter()
            .map(RuntimeErrorPage::from_config)
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            config: config.clone(),
            error_pages,
        })
    }

    fn error_page(&self, status: u16) -> Option<&RuntimeErrorPage> {
        self.error_pages.iter().find(|page| page.status == status)
    }
}

impl RuntimeErrorPage {
    fn from_config(config: &crate::config::ProxyErrorPageConfig) -> io::Result<Self> {
        #[cfg(feature = "web")]
        {
            let web = StaticFileServer::from_config(&config.web)?.ok_or_else(|| {
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
        route: &crate::config::RouteConfig,
        base_headers: &crate::config::HeaderPolicyConfig,
    ) -> io::Result<Self> {
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
            RuntimeRouteAction::Proxy(RuntimeProxy::from_config(proxy)?)
        } else if let Some(web) = &route.web {
            #[cfg(feature = "web")]
            {
                let web = StaticFileServer::from_config(web)?.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("route {:?} static web action requires web.root", route.name),
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
                .map(|cache| RuntimeRouteCache::from_config(&route.name, cache))
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
        let pingora_memory_storage = crate::cache::pingora_memory_storage_from_config(&cache);
        #[cfg(feature = "cache")]
        let pingora_disk_storage = crate::cache::pingora_disk_storage_from_config(&cache)?;
        #[cfg(feature = "cache")]
        let pingora_tiered_storage = pingora_memory_storage
            .zip(pingora_disk_storage)
            .map(|(memory, disk)| crate::cache::pingora_tiered_storage_from_parts(memory, disk));
        #[cfg(feature = "cache")]
        let pingora_cache_lock = cache_lock_from_config(
            &cache,
            pingora_memory_storage.is_some() || pingora_disk_storage.is_some(),
        );

        Ok(Self {
            name: "default".to_owned(),
            hosts: vec![],
            max_request_body_bytes: None,
            #[cfg(feature = "load-balancer")]
            load_balancer,
            proxy: RuntimeProxy::from_config(&proxy)?,
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
            cache_lock_wait_timeout: cache_lock_wait_timeout(&cache),
            #[cfg(feature = "cache")]
            cache,
            #[cfg(feature = "web")]
            web: StaticFileServer::from_config(&web)?,
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
                .map(|route| RuntimeRoute::from_config(&route, &route_base_headers))
                .collect::<io::Result<Vec<_>>>()?,
        );
        #[cfg(feature = "cache")]
        let pingora_memory_storage = crate::cache::pingora_memory_storage_from_config(&vhost.cache);
        #[cfg(feature = "cache")]
        let pingora_disk_storage = crate::cache::pingora_disk_storage_from_config(&vhost.cache)?;
        #[cfg(feature = "cache")]
        let pingora_tiered_storage = pingora_memory_storage
            .zip(pingora_disk_storage)
            .map(|(memory, disk)| crate::cache::pingora_tiered_storage_from_parts(memory, disk));
        #[cfg(feature = "cache")]
        let pingora_cache_lock = cache_lock_from_config(
            &vhost.cache,
            pingora_memory_storage.is_some() || pingora_disk_storage.is_some(),
        );

        Ok(Self {
            name: vhost.name.clone(),
            hosts: vhost.normalized_hosts(),
            max_request_body_bytes: vhost.max_request_body_bytes,
            #[cfg(feature = "load-balancer")]
            load_balancer,
            proxy: RuntimeProxy::from_config(&vhost.proxy)?,
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
            cache_lock_wait_timeout: cache_lock_wait_timeout(&vhost.cache),
            #[cfg(feature = "cache")]
            cache: vhost.cache.clone(),
            #[cfg(feature = "web")]
            web: StaticFileServer::from_config(&vhost.web)?,
            routes,
        })
    }
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
    #[cfg(feature = "cache")]
    cache_status_override: Option<CacheStatusOverride>,
}

#[cfg(feature = "cache")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CacheStatusOverride {
    status: &'static str,
    reason: Option<&'static str>,
}

#[async_trait]
impl ProxyHttp for FluxProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        #[cfg(not(feature = "privacy-mode"))]
        let ctx = RequestContext {
            started_at: Some(Instant::now()),
            ..RequestContext::default()
        };

        #[cfg(feature = "privacy-mode")]
        let ctx = RequestContext::default();

        ctx
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let state = self.state.load_full();

        let vhost_index = state.vhost_index(request_host(session));
        ctx.state = Some(Arc::clone(&state));
        ctx.vhost_index = Some(vhost_index);
        let vhost = state.vhost(vhost_index);
        ctx.route_index = vhost.route_index(session.req_header().uri.path());
        ctx.request_body_limit_bytes = ctx
            .route_index
            .and_then(|route_index| vhost.route(route_index).max_request_body_bytes)
            .or(vhost.max_request_body_bytes)
            .map(|bytes| bytes.as_u64())
            .or(Some(state.limits.max_request_body_bytes.as_u64()));
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
                RuntimeRouteAction::Proxy(_) => return Ok(false),
                #[cfg(feature = "acme")]
                RuntimeRouteAction::AcmeHttp01(store) => {
                    respond_acme_http_01_challenge(session, ctx, store, route).await?;
                    return Ok(true);
                }
                #[cfg(feature = "web")]
                RuntimeRouteAction::Web(web) => {
                    if serve_static_route(session, ctx, web, route).await? {
                        return Ok(true);
                    }
                    return Ok(false);
                }
            }
        }

        #[cfg(feature = "web")]
        {
            let Some(web) = &vhost.web else {
                return Ok(false);
            };

            let method = session.req_header().method.as_str().to_owned();
            if method != "GET" && method != "HEAD" {
                return Ok(false);
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
                    ctx.response_body_bytes_seen = plan.response_body_bytes;
                    crate::web::serve_static_file(
                        session,
                        web,
                        &file,
                        &plan,
                        &vhost.response_headers,
                    )
                    .await?;
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
                Ok(ResolveResult::NotFound) => Ok(false),
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
            Ok(false)
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

        let peer = http_peer_for_proxy(proxy.config.primary_upstream(), &proxy.config)?;

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
        #[cfg(not(feature = "privacy-mode"))]
        if let Some(request_id) = ctx.request_id.as_deref() {
            upstream_request
                .insert_header(state.access_log.request_id_header.clone(), request_id)?;
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
            downstream_tls,
            request_id,
        )
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
            session,
            response,
            selected_cache_config(vhost, ctx),
            ctx.cache_status_override,
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

        #[cfg(not(feature = "privacy-mode"))]
        self.emit_access_log(session, error, ctx);

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

        if request_cache_bypass(session.req_header(), cache_config) {
            return Ok(());
        }

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
            crate::metrics::record_cache_activity("policy", "pass");
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
            None,
            cache_lock,
            Some(cache_option_overrides),
        );
        session
            .cache
            .set_max_file_size_bytes(cache_config.max_object_bytes.as_usize());
        Ok(())
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
        state
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
            })
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

        if let Some(reason) = response_cache_admission_rejection(response, cache) {
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
        cache_pass_record_cacheable(cache_pass_counter(), &cache_key);
        if !cache_min_uses_allows_store(cache_min_uses_counter(), cache, &cache_key) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                CACHE_MIN_USES_REASON,
            )));
        }
        Ok(decision)
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
        cache_should_serve_stale(selected_cache_config(vhost, ctx), event)
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

fn downstream_tls(session: &Session) -> bool {
    session
        .digest()
        .is_some_and(|digest| digest.ssl_digest.is_some())
}

#[cfg(feature = "web")]
async fn serve_static_route(
    session: &mut Session,
    ctx: &mut RequestContext,
    web: &StaticFileServer,
    route: &RuntimeRoute,
) -> Result<bool> {
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
            ctx.response_body_bytes_seen = plan.response_body_bytes;
            crate::web::serve_static_file(session, web, &file, &plan, &route.response_headers)
                .await?;
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

fn selected_runtime_proxy<'a>(vhost: &'a RuntimeVhost, ctx: &RequestContext) -> &'a RuntimeProxy {
    ctx.route_index
        .and_then(|route_index| match &vhost.route(route_index).action {
            RuntimeRouteAction::Proxy(proxy) => Some(proxy),
            _ => None,
        })
        .unwrap_or(&vhost.proxy)
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
fn insert_cache_status_headers(
    session: &Session,
    response: &mut ResponseHeader,
    cache: &crate::config::CacheConfig,
    override_status: Option<CacheStatusOverride>,
) -> Result<()> {
    let phase = session.cache.phase();

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
    if rewritten_path.chars().any(char::is_control) {
        return None;
    }
    match request.uri.query() {
        Some(query) => Some(format!("{rewritten_path}?{query}")),
        None => Some(rewritten_path),
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
    format!(
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
    )
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
fn request_cache_bypass(request: &RequestHeader, cache: &crate::config::CacheConfig) -> bool {
    if cache
        .bypass_request_headers
        .iter()
        .any(|header| request.headers.contains_key(header.as_str()))
    {
        return true;
    }
    if request_headers_match_cache_bypass_value(request, &cache.bypass_request_header_values) {
        return true;
    }
    if request_cookies_match_cache_bypass(
        request_header_values(request, "cookie"),
        &cache.bypass_cookie_names,
        &cache.bypass_cookie_values,
    ) {
        return true;
    }
    if request.uri.query().is_some_and(|query| {
        query_matches_cache_bypass(
            query,
            &cache.bypass_query_params,
            &cache.bypass_query_values,
        )
    }) {
        return true;
    }

    crate::cache_headers::request_values_force_cache_refresh(
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
    material.extend_from_slice(b"fluxheim-vary-v1\0");

    for field in fields {
        material.extend_from_slice(field.as_bytes());
        material.push(0);
        for value in request.headers.get_all(field.as_str()).iter() {
            material.extend_from_slice(value.as_bytes());
            material.push(0);
        }
        material.push(0xff);
    }

    pingora::cache::key::hash_key(material)
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

#[cfg(feature = "web")]
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
    let request_line_bytes = request.method.as_str().len()
        + 1
        + request.uri.to_string().len()
        + 1
        + "HTTP/1.1".len()
        + 2;

    request
        .headers
        .iter()
        .fold(request_line_bytes + 2, |total, (name, value)| {
            total
                .saturating_add(name.as_str().len())
                .saturating_add(2)
                .saturating_add(value.as_bytes().len())
                .saturating_add(2)
        })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;

    use crate::config::{
        ByteSize, CacheConfig, Config, HttpsRedirectConfig, ProxyConfig, RouteConfig,
        RouteRedirectConfig, ServerConfig, ServerLimitsConfig, VhostConfig, WebConfig,
    };
    #[cfg(any(feature = "cache", feature = "web"))]
    use crate::test_support::unique_temp_path;

    #[cfg(feature = "cache")]
    use super::request_cache_bypass;
    #[cfg(feature = "cache")]
    use super::{
        CACHE_PASS_REASON, CacheStaleEvent, CacheStatusOverride, MAX_VARY_FIELDS, VaryCachePolicy,
        apply_cache_status_ttl, cache_min_uses_allows_store, cache_pass_record_cacheable,
        cache_pass_record_uncacheable, cache_pass_should_bypass, cache_request_participated,
        cache_should_serve_stale, cache_stale_status_allows, cache_status_header_value,
        cache_status_reason_header_value, cache_vary_policy, ignore_origin_cache_headers,
        response_cache_admission_rejection, strip_cache_response_headers, vary_cache_policy,
        vary_request_hash,
    };
    #[cfg(feature = "cache")]
    use super::{CacheBulkPurgeRequest, CachePurgeRequest};
    use super::{
        FluxProxy, count_response_body_chunk, http_peer_for_proxy, https_redirect_location,
        redirect_authority, request_body_chunk_limit_status, request_limit_status,
        route_redirect_location, route_rewritten_path_and_query,
    };

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
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();

        assert_eq!(proxy.route_host(Some("missing.example")), "default.example");
        assert_eq!(proxy.route_host(None), "default.example");
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
                super::RuntimeProxy::from_config(&ProxyConfig::default()).unwrap(),
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

        let runtime = super::RuntimeProxy::from_config(&proxy).unwrap();

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
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
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
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                headers: crate::config::VhostHeaderPolicyConfig::default(),
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
                        upstreams: vec!["127.0.0.1:3001".to_owned()],
                        ..ProxyConfig::default()
                    },
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
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
                        upstreams: vec!["127.0.0.1:3002".to_owned()],
                        ..ProxyConfig::default()
                    },
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
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
    fn request_cache_bypass_honors_client_refresh_headers() {
        for (name, value) in [
            ("cache-control", "no-cache"),
            ("cache-control", "no-store"),
            ("cache-control", "max-age = 0"),
            ("cache-control", "public, max-age=0"),
            ("pragma", "no-cache"),
        ] {
            let mut request =
                pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
            request.insert_header(name, value).unwrap();

            assert!(
                request_cache_bypass(&request, &CacheConfig::default()),
                "{name}: {value}"
            );
        }

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        request
            .insert_header("cache-control", "public, max-age=60")
            .unwrap();

        assert!(!request_cache_bypass(&request, &CacheConfig::default()));
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

        assert!(request_cache_bypass(&request, &CacheConfig::default()));

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        request.append_header("pragma", "ignored").unwrap();
        request.append_header("pragma", "no-cache").unwrap();

        assert!(request_cache_bypass(&request, &CacheConfig::default()));
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

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js", None).unwrap();
        request
            .insert_header("authorization", "Bearer secret")
            .unwrap();
        assert!(request_cache_bypass(&request, &cache));
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

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js", None).unwrap();
        request.insert_header("cookie", "session=abc").unwrap();
        assert!(!request_cache_bypass(&request, &cache));

        request
            .append_header("cookie", "wordpress_logged_in=1")
            .unwrap();
        assert!(request_cache_bypass(&request, &cache));
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

        let request =
            pingora::http::RequestHeader::build("GET", b"/assets/app.js?token", None).unwrap();
        assert!(request_cache_bypass(&request, &cache));

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
            request_body_bytes: 0,
            response_body_bytes: 0,
            latency_ms: 1,
        });

        assert!(log.contains("\"host\":\"\""));
        assert!(!log.contains("tenant.example"));
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
