use std::cmp::Reverse;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(not(feature = "privacy-mode"))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
#[cfg(not(feature = "privacy-mode"))]
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
#[cfg(feature = "cache")]
use pingora::cache::CacheKey as PingoraCacheKey;
#[cfg(feature = "cache")]
use pingora::cache::key::{CacheHashKey, HashBinary};
#[cfg(feature = "cache")]
use pingora::cache::lock::CacheKeyLockImpl;
use pingora::http::RequestHeader;
use pingora::http::ResponseHeader;
use pingora::prelude::{HttpPeer, Result};
use pingora::proxy::{ProxyHttp, Session};
use pingora::{Error, ErrorType};
#[cfg(feature = "cache")]
use pingora::{
    cache::CacheOptionOverrides, cache::NoCacheReason, cache::RespCacheable, http::StatusCode,
};

#[cfg(not(feature = "privacy-mode"))]
use crate::config::AccessLoggingConfig;
use crate::config::{Config, ProxyConfig, ServerLimitsConfig, normalize_host};
#[cfg(feature = "load-balancer")]
use crate::load_balancer::{UpstreamLoadBalancer, UpstreamLoadBalancerService};
#[cfg(feature = "web")]
use crate::web::{ResolveResult, StaticFileServer};

#[cfg(feature = "cache")]
const CACHE_LOCK_AGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(feature = "cache")]
const CACHE_LOCK_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(feature = "cache")]
const MAX_VARY_HEADER_BYTES: usize = 2048;
#[cfg(feature = "cache")]
const MAX_VARY_FIELDS: usize = 16;

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
        let mut current = self
            .health_reporter
            .write()
            .expect("proxy health reporter lock poisoned");
        *current = Some(reporter);
    }

    pub(crate) fn has_health_reporter(&self) -> bool {
        self.health_reporter
            .read()
            .expect("proxy health reporter lock poisoned")
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
            .expect("proxy health reporter lock poisoned")
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
                host: request_host(session),
                vhost,
                path: session.req_header().uri.path(),
                status,
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
}

#[derive(Debug, Clone)]
pub struct ProxySnapshot {
    state: Arc<ProxyRuntimeState>,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CachePurgeRequest<'a> {
    pub vhost: Option<&'a str>,
    pub host: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheBulkPurgeRequest<'a> {
    pub vhost: Option<&'a str>,
    pub host: &'a str,
    pub method: &'a str,
    pub paths: Vec<&'a str>,
    pub query: Option<&'a str>,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CachePurgeResult {
    pub vhost: String,
    pub cache_key: String,
    pub memory_purged: bool,
    pub disk_purged: bool,
}

#[cfg(feature = "cache")]
impl CachePurgeResult {
    pub fn purged(&self) -> bool {
        self.memory_purged || self.disk_purged
    }
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheBulkPurgeResult {
    pub vhost: String,
    pub results: Vec<CachePurgeResult>,
}

#[cfg(feature = "cache")]
impl CacheBulkPurgeResult {
    pub fn requested(&self) -> usize {
        self.results.len()
    }

    pub fn purged(&self) -> usize {
        self.results.iter().filter(|result| result.purged()).count()
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
    pub memory_entries: u64,
    pub memory_weighted_size_bytes: u64,
    pub memory_max_size_bytes: u64,
    pub disk_entries: u64,
    pub disk_size_bytes: u64,
    pub disk_max_size_bytes: u64,
    pub hits: u64,
    pub misses: u64,
    pub stores: u64,
    pub store_refusals: u64,
    pub purges: u64,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheVhostStats {
    pub name: String,
    pub enabled: bool,
    pub tiered: bool,
    pub memory: Option<crate::cache::MemoryCacheStats>,
    pub disk: Option<crate::cache::DiskCacheStats>,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CacheActivityResetResult {
    pub memory_tiers: u64,
    pub disk_tiers: u64,
    pub tiered_vhosts: u64,
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

            let memory = vhost.pingora_memory_storage.map(|storage| storage.stats());
            if let Some(memory) = memory {
                totals.memory_entries = totals.memory_entries.saturating_add(memory.entries);
                totals.memory_weighted_size_bytes = totals
                    .memory_weighted_size_bytes
                    .saturating_add(memory.weighted_size_bytes);
                totals.memory_max_size_bytes = totals
                    .memory_max_size_bytes
                    .saturating_add(memory.max_size_bytes.as_u64());
                totals.hits = totals.hits.saturating_add(memory.activity.hits);
                totals.misses = totals.misses.saturating_add(memory.activity.misses);
                totals.stores = totals.stores.saturating_add(memory.activity.stores);
                totals.store_refusals = totals
                    .store_refusals
                    .saturating_add(memory.activity.store_refusals);
                totals.purges = totals.purges.saturating_add(memory.activity.purges);
            }

            let disk = vhost
                .pingora_disk_storage
                .map(|storage| storage.stats())
                .transpose()?;
            if let Some(disk) = disk {
                totals.disk_entries = totals.disk_entries.saturating_add(disk.entries);
                totals.disk_size_bytes = totals.disk_size_bytes.saturating_add(disk.size_bytes);
                totals.disk_max_size_bytes = totals
                    .disk_max_size_bytes
                    .saturating_add(disk.max_size_bytes.as_u64());
                totals.hits = totals.hits.saturating_add(disk.activity.hits);
                totals.misses = totals.misses.saturating_add(disk.activity.misses);
                totals.stores = totals.stores.saturating_add(disk.activity.stores);
                totals.store_refusals = totals
                    .store_refusals
                    .saturating_add(disk.activity.store_refusals);
                totals.purges = totals.purges.saturating_add(disk.activity.purges);
            }

            vhosts.push(CacheVhostStats {
                name: vhost.name.clone(),
                enabled: vhost.cache.enabled,
                tiered: vhost.pingora_tiered_storage.is_some(),
                memory,
                disk,
            });
        }
        Ok(CacheRuntimeStats { totals, vhosts })
    }

    #[cfg(feature = "cache")]
    pub fn reset_cache_activity(&self) -> CacheActivityResetResult {
        let mut result = CacheActivityResetResult {
            memory_tiers: 0,
            disk_tiers: 0,
            tiered_vhosts: 0,
        };
        for vhost in &self.state.vhosts {
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
        let cache_request = crate::cache::CacheRequest {
            method: request.method,
            host: Some(request.host),
            path: request.path,
            query: request.query,
        };
        let key = crate::cache::pingora_image_cache_key(
            "fluxheim-image-v1",
            &vhost.cache,
            &cache_request,
            &vhost.name,
        )
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "request is not eligible for this vhost cache policy",
            )
        })?;
        let cache_key = key.combined();
        let memory_purged = vhost
            .pingora_memory_storage
            .is_some_and(|storage| storage.purge_cache_key(&key));
        let disk_purged = vhost
            .pingora_disk_storage
            .map(|storage| storage.purge_cache_key(&key))
            .transpose()?
            .unwrap_or(false);
        Ok(CachePurgeResult {
            vhost: vhost.name.clone(),
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
                let runtime = RuntimeVhost::from_config(configured, &config.headers)?;
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
    ) -> Option<PingoraCacheKey> {
        let vhost = self.vhost(vhost_index);
        let cache_request = cache_request_from_header(request);
        crate::cache::pingora_image_cache_key(
            "fluxheim-image-v1",
            &vhost.cache,
            &cache_request,
            &vhost.name,
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
    proxy: ProxyConfig,
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
    #[cfg(feature = "load-balancer")]
    load_balancer: Option<UpstreamLoadBalancer>,
    #[cfg(feature = "web")]
    web: Option<StaticFileServer>,
}

impl std::fmt::Debug for RuntimeVhost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("RuntimeVhost");
        debug
            .field("name", &self.name)
            .field("hosts", &self.hosts)
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
            .field("pingora_cache_lock", &self.pingora_cache_lock.is_some());

        #[cfg(feature = "load-balancer")]
        debug.field("load_balancer", &self.load_balancer);

        #[cfg(feature = "web")]
        debug.field("web", &self.web);

        debug.finish()
    }
}

impl RuntimeVhost {
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
        let pingora_cache_lock = (pingora_memory_storage.is_some()
            || pingora_disk_storage.is_some())
        .then(|| crate::cache::pingora_cache_lock(CACHE_LOCK_AGE_TIMEOUT));

        Ok(Self {
            name: "default".to_owned(),
            hosts: vec![],
            #[cfg(feature = "load-balancer")]
            load_balancer,
            proxy,
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
            cache,
            #[cfg(feature = "web")]
            web: StaticFileServer::from_config(&web)?,
        })
    }

    fn from_config(
        vhost: &crate::config::VhostConfig,
        global_headers: &crate::config::HeaderPolicyConfig,
        #[cfg(feature = "load-balancer")] load_balancer: Option<UpstreamLoadBalancer>,
    ) -> io::Result<Self> {
        let headers = global_headers.with_vhost_overlay(&vhost.headers);
        #[cfg(feature = "cache")]
        let pingora_memory_storage = crate::cache::pingora_memory_storage_from_config(&vhost.cache);
        #[cfg(feature = "cache")]
        let pingora_disk_storage = crate::cache::pingora_disk_storage_from_config(&vhost.cache)?;
        #[cfg(feature = "cache")]
        let pingora_tiered_storage = pingora_memory_storage
            .zip(pingora_disk_storage)
            .map(|(memory, disk)| crate::cache::pingora_tiered_storage_from_parts(memory, disk));
        #[cfg(feature = "cache")]
        let pingora_cache_lock = (pingora_memory_storage.is_some()
            || pingora_disk_storage.is_some())
        .then(|| crate::cache::pingora_cache_lock(CACHE_LOCK_AGE_TIMEOUT));

        Ok(Self {
            name: vhost.name.clone(),
            hosts: vhost.normalized_hosts(),
            #[cfg(feature = "load-balancer")]
            load_balancer,
            proxy: vhost.proxy.clone(),
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
            cache: vhost.cache.clone(),
            #[cfg(feature = "web")]
            web: StaticFileServer::from_config(&vhost.web)?,
        })
    }
}

#[derive(Debug, Default)]
pub struct RequestContext {
    state: Option<Arc<ProxyRuntimeState>>,
    vhost_index: Option<usize>,
    request_body_bytes_seen: u64,
    response_body_bytes_seen: u64,
    health_signal_recorded: bool,
    #[cfg(not(feature = "privacy-mode"))]
    started_at: Option<Instant>,
    #[cfg(not(feature = "privacy-mode"))]
    request_id: Option<String>,
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

        if let Some(status) = request_limit_status(&state.limits, session.req_header()) {
            session.respond_error(status).await?;
            return Ok(true);
        }

        let vhost_index = state.vhost_index(request_host(session));
        ctx.state = Some(Arc::clone(&state));
        ctx.vhost_index = Some(vhost_index);
        #[cfg(not(feature = "privacy-mode"))]
        {
            ctx.request_id = access_log_request_id(&state.access_log, session.req_header());
        }

        #[cfg(feature = "web")]
        {
            let vhost = state.vhost(vhost_index);
            let Some(web) = &vhost.web else {
                return Ok(false);
            };

            let method = session.req_header().method.as_str();
            if method != "GET" && method != "HEAD" {
                return Ok(false);
            }

            match web.resolve(session.req_header().uri.path()) {
                Ok(ResolveResult::Found(file)) => {
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
                        method,
                        crate::web::StaticRequestConditions {
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
                    crate::web::serve_static_file(session, &file, &plan, &vhost.response_headers)
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
        let proxy = &vhost.proxy;

        #[cfg(feature = "load-balancer")]
        if let Some(load_balancer) = &vhost.load_balancer
            && let Some(upstream) = load_balancer.select()
        {
            let peer = HttpPeer::new(upstream, proxy.upstream_tls, proxy.upstream_sni());
            return Ok(Box::new(peer));
        }

        let peer = HttpPeer::new(
            proxy.upstream.as_str(),
            proxy.upstream_tls,
            proxy.upstream_sni(),
        );

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
        let downstream_tls = session
            .digest()
            .is_some_and(|digest| digest.ssl_digest.is_some());
        let client_addr = session.client_addr().and_then(|addr| addr.as_inet());
        let trusted_proxy = client_addr
            .map(|addr| state.trusted_proxy(addr.ip()))
            .unwrap_or(false);
        #[cfg(not(feature = "privacy-mode"))]
        if let Some(request_id) = ctx.request_id.as_deref() {
            upstream_request
                .insert_header(state.access_log.request_id_header.clone(), request_id)?;
        }
        crate::headers::apply_upstream_request_policy(
            upstream_request,
            &vhost.request_headers,
            client_addr,
            trusted_proxy,
            downstream_tls,
        )
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
            &state.limits,
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
        crate::headers::apply_response_policy(response, &state.vhost(vhost_index).response_headers)
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

    async fn logging(&self, session: &mut Session, error: Option<&Error>, ctx: &mut Self::CTX)
    where
        Self::CTX: Send + Sync,
    {
        #[cfg(feature = "metrics")]
        crate::metrics::record_proxy_outcome(
            proxy_metrics_vhost(ctx),
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

        if request_cache_bypass(session.req_header()) {
            return Ok(());
        }

        let storage: &'static (dyn pingora::cache::Storage + Sync) =
            if let Some(storage) = vhost.pingora_tiered_storage {
                storage
            } else if let Some(storage) = vhost.pingora_memory_storage {
                storage
            } else if let Some(storage) = vhost.pingora_disk_storage {
                storage
            } else {
                return Ok(());
            };

        let cache_request = cache_request_from_header(session.req_header());
        if crate::cache::image_cache_key(&vhost.cache, &cache_request).is_none() {
            return Ok(());
        }

        let mut cache_option_overrides = CacheOptionOverrides::default();
        cache_option_overrides.wait_timeout = Some(CACHE_LOCK_WAIT_TIMEOUT);
        session.cache.enable(
            storage,
            None,
            None,
            vhost.pingora_cache_lock,
            Some(cache_option_overrides),
        );
        session
            .cache
            .set_max_file_size_bytes(vhost.cache.max_object_bytes.as_usize());
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
            .pingora_image_cache_key_for_request_header(session.req_header(), vhost_index)
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
        _ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        if let Some(reason) = response_cache_admission_rejection(response) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(reason)));
        }

        let cache_control =
            pingora::cache::cache_control::CacheControl::from_resp_headers(response);
        let authorization_present = session.req_header().headers.contains_key("authorization");
        Ok(pingora::cache::filters::resp_cacheable(
            cache_control.as_ref(),
            response.clone(),
            authorization_present,
            &FLUXHEIM_CACHE_DEFAULTS,
        ))
    }

    #[cfg(feature = "cache")]
    fn cache_vary_filter(
        &self,
        meta: &pingora::cache::CacheMeta,
        _ctx: &mut Self::CTX,
        request: &RequestHeader,
    ) -> Option<HashBinary> {
        match vary_cache_policy(meta.headers()) {
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
    session
        .req_header()
        .headers
        .get("host")
        .and_then(|value| value.to_str().ok())
}

#[cfg(not(feature = "privacy-mode"))]
struct AccessLogEvent<'a> {
    method: &'a str,
    host: Option<&'a str>,
    vhost: &'a str,
    path: &'a str,
    status: Option<u16>,
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
    let host = event.host.unwrap_or("");
    let request_id = event.request_id.unwrap_or("");
    format!(
        "{{\"event\":\"access\",\"method\":\"{}\",\"host\":\"{}\",\"vhost\":\"{}\",\"path\":\"{}\",\"status\":{},\"error\":{},\"request_id\":\"{}\",\"request_body_bytes\":{},\"response_body_bytes\":{},\"latency_ms\":{}}}",
        json_escape(event.method),
        json_escape(host),
        json_escape(event.vhost),
        json_escape(event.path),
        status,
        event.error,
        json_escape(request_id),
        event.request_body_bytes,
        event.response_body_bytes,
        event.latency_ms,
    )
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
        .or_else(|| Some(generate_request_id()))
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
fn generate_request_id() -> String {
    static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

    let sequence = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("fh-{now:x}-{:x}-{sequence:x}", std::process::id())
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
fn request_cache_bypass(request: &RequestHeader) -> bool {
    crate::cache_headers::request_values_force_cache_refresh(
        request_header_values(request, "cache-control"),
        request_header_values(request, "pragma"),
    )
}

#[cfg(feature = "cache")]
fn response_cache_admission_rejection(response: &ResponseHeader) -> Option<&'static str> {
    let headers = &response.headers;
    if response.status != StatusCode::OK {
        return Some("status-not-ok");
    }

    if !response_content_type_is_image(headers) {
        return if headers.contains_key("content-type") {
            Some("content-type-not-image")
        } else {
            Some("content-type-missing")
        };
    }

    if headers.contains_key("set-cookie") {
        return Some("set-cookie");
    }
    match vary_cache_policy(headers) {
        VaryCachePolicy::Uncacheable(reason) => Some(reason),
        VaryCachePolicy::None | VaryCachePolicy::Fields(_) => None,
    }
}

#[cfg(feature = "cache")]
fn response_content_type_is_image(headers: &http::HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| {
            media_type.trim().eq_ignore_ascii_case("image/*")
                || media_type.trim().to_ascii_lowercase().starts_with("image/")
        })
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

#[cfg(feature = "cache")]
fn request_host_header(request: &RequestHeader) -> Option<&str> {
    request
        .headers
        .get("host")
        .and_then(|value| value.to_str().ok())
}

fn request_limit_status(limits: &ServerLimitsConfig, request: &RequestHeader) -> Option<u16> {
    if request.uri.to_string().len() > limits.max_uri_bytes.as_usize() {
        return Some(414);
    }

    if request.headers.len() > limits.max_request_headers {
        return Some(431);
    }

    if approximate_request_header_bytes(request) > limits.max_request_header_bytes.as_usize() {
        return Some(431);
    }

    if let Some(status) = request_body_limit_status(limits, request) {
        return Some(status);
    }

    None
}

fn request_body_limit_status(limits: &ServerLimitsConfig, request: &RequestHeader) -> Option<u16> {
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

    if content_length.is_some_and(|bytes| bytes > limits.max_request_body_bytes.as_u64()) {
        return Some(413);
    }

    None
}

fn request_body_chunk_limit_status(
    limits: &ServerLimitsConfig,
    bytes_seen: &mut u64,
    chunk_len: usize,
) -> Option<u16> {
    *bytes_seen = bytes_seen.saturating_add(chunk_len as u64);
    if *bytes_seen > limits.max_request_body_bytes.as_u64() {
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
    use bytes::Bytes;

    use crate::config::{
        ByteSize, CacheConfig, Config, ProxyConfig, ServerConfig, ServerLimitsConfig, VhostConfig,
        WebConfig,
    };

    #[cfg(feature = "cache")]
    use super::request_cache_bypass;
    #[cfg(feature = "cache")]
    use super::{CacheBulkPurgeRequest, CachePurgeRequest};
    use super::{
        FluxProxy, count_response_body_chunk, request_body_chunk_limit_status, request_limit_status,
    };
    #[cfg(feature = "cache")]
    use super::{
        MAX_VARY_FIELDS, VaryCachePolicy, response_cache_admission_rejection, vary_cache_policy,
        vary_request_hash,
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
            },
            vhosts: vec![
                VhostConfig {
                    name: "one".to_owned(),
                    hosts: vec!["one.example".to_owned()],
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig {
                        upstream: "127.0.0.1:3001".to_owned(),
                        ..ProxyConfig::default()
                    },
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    web: WebConfig::default(),
                },
                VhostConfig {
                    name: "two".to_owned(),
                    hosts: vec!["two.example".to_owned()],
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig {
                        upstream: "127.0.0.1:3002".to_owned(),
                        ..ProxyConfig::default()
                    },
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    web: WebConfig::default(),
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
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                web: WebConfig::default(),
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
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();
        let old_snapshot = proxy.snapshot();

        let new_config = Config {
            vhosts: vec![VhostConfig {
                name: "new".to_owned(),
                hosts: vec!["new.example".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                web: WebConfig::default(),
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
            },
            vhosts: vec![
                VhostConfig {
                    name: "one".to_owned(),
                    hosts: vec!["one.example".to_owned()],
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    web: WebConfig::default(),
                },
                VhostConfig {
                    name: "two".to_owned(),
                    hosts: vec!["two.example".to_owned()],
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    web: WebConfig::default(),
                },
            ],
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();

        assert_eq!(proxy.route_host(Some("missing.example")), "two");
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
            },
            vhosts: vec![
                VhostConfig {
                    name: "wild".to_owned(),
                    hosts: vec!["*.example.com".to_owned()],
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    web: WebConfig::default(),
                },
                VhostConfig {
                    name: "exact".to_owned(),
                    hosts: vec!["api.example.com".to_owned()],
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    web: WebConfig::default(),
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
                },
                VhostConfig {
                    name: "uncached".to_owned(),
                    hosts: vec!["uncached.example".to_owned()],
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    web: WebConfig::default(),
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
    fn builds_memory_cache_from_routed_vhost_policy() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
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
    }

    #[cfg(feature = "cache")]
    #[test]
    fn builds_pingora_disk_storage_from_routed_vhost_policy() {
        let cache_path = unique_test_cache_dir("proxy-disk");
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
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
                host: "cached.example",
                method: "GET",
                path: "/img/logo.png",
                query: Some("v=1"),
            })
            .unwrap();

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
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig {
                        upstreams: vec!["127.0.0.1:3001".to_owned()],
                        ..ProxyConfig::default()
                    },
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    web: WebConfig::default(),
                },
                VhostConfig {
                    name: "two".to_owned(),
                    hosts: vec!["two.example".to_owned()],
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig {
                        upstreams: vec!["127.0.0.1:3002".to_owned()],
                        ..ProxyConfig::default()
                    },
                    cache: CacheConfig::default(),
                    headers: crate::config::VhostHeaderPolicyConfig::default(),
                    web: WebConfig::default(),
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

        assert_eq!(request_limit_status(&limits, &request), None);
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

        assert_eq!(request_limit_status(&limits, &request), Some(414));
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

        assert_eq!(request_limit_status(&limits, &request), Some(431));
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

        assert_eq!(request_limit_status(&limits, &request), Some(431));
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

        assert_eq!(request_limit_status(&limits, &request), Some(413));
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

        assert_eq!(request_limit_status(&limits, &request), Some(400));
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

        assert_eq!(request_limit_status(&limits, &request), Some(400));
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

        assert_eq!(request_limit_status(&limits, &request), Some(411));
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

            assert!(request_cache_bypass(&request), "{name}: {value}");
        }

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        request
            .insert_header("cache-control", "public, max-age=60")
            .unwrap();

        assert!(!request_cache_bypass(&request));
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

        assert!(request_cache_bypass(&request));

        let mut request =
            pingora::http::RequestHeader::build("GET", b"/img/logo.png", None).unwrap();
        request.append_header("pragma", "ignored").unwrap();
        request.append_header("pragma", "no-cache").unwrap();

        assert!(request_cache_bypass(&request));
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
        assert_eq!(response_cache_admission_rejection(&response), None);

        response
            .insert_header("set-cookie", "session=abc; HttpOnly; Secure")
            .unwrap();
        assert_eq!(
            response_cache_admission_rejection(&response),
            Some("set-cookie")
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn response_cache_admission_requires_image_content_type() {
        let mut redirect = pingora::http::ResponseHeader::build(302, Some(2)).unwrap();
        redirect
            .insert_header("cache-control", "public, max-age=60")
            .unwrap();
        redirect.insert_header("content-type", "image/png").unwrap();
        assert_eq!(
            response_cache_admission_rejection(&redirect),
            Some("status-not-ok")
        );

        let mut missing = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
        missing
            .insert_header("cache-control", "public, max-age=60")
            .unwrap();
        assert_eq!(
            response_cache_admission_rejection(&missing),
            Some("content-type-missing")
        );

        let mut html = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
        html.insert_header("cache-control", "public, max-age=60")
            .unwrap();
        html.insert_header("content-type", "text/html; charset=utf-8")
            .unwrap();
        assert_eq!(
            response_cache_admission_rejection(&html),
            Some("content-type-not-image")
        );

        let mut image = pingora::http::ResponseHeader::build(200, Some(2)).unwrap();
        image
            .insert_header("cache-control", "public, max-age=60")
            .unwrap();
        image
            .insert_header("content-type", "IMAGE/WebP; charset=binary")
            .unwrap();
        assert_eq!(response_cache_admission_rejection(&image), None);
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
    fn streaming_body_chunks_are_counted_against_global_limit() {
        let limits = ServerLimitsConfig {
            max_request_header_bytes: ByteSize::from_bytes(512),
            max_uri_bytes: ByteSize::from_bytes(128),
            max_request_headers: 8,
            max_request_body_bytes: ByteSize::from_bytes(16),
        };
        let mut seen = 0;

        assert_eq!(request_body_chunk_limit_status(&limits, &mut seen, 8), None);
        assert_eq!(request_body_chunk_limit_status(&limits, &mut seen, 8), None);
        assert_eq!(
            request_body_chunk_limit_status(&limits, &mut seen, 1),
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
            request_body_chunk_limit_status(&limits, &mut seen, 8),
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
            path: "/asset path/one.js",
            status: Some(200),
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
        assert!(log.contains("\"request_id\":\"req-123\""));
        assert!(log.contains("\"response_body_bytes\":2048"));
        assert!(!log.contains("secret="));
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
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        std::env::temp_dir().join(format!(
            "fluxheim-proxy-cache-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
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
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        fn raw_waker() -> RawWaker {
            fn clone(_: *const ()) -> RawWaker {
                raw_waker()
            }
            fn wake(_: *const ()) {}
            fn wake_by_ref(_: *const ()) {}
            fn drop(_: *const ()) {}

            RawWaker::new(
                std::ptr::null(),
                &RawWakerVTable::new(clone, wake, wake_by_ref, drop),
            )
        }

        // SAFETY: `raw_waker` uses a no-op vtable and a null data pointer that is
        // never dereferenced. The waker is only used to poll immediately-ready
        // test futures in this thread.
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut context = Context::from_waker(&waker);
        let mut future = pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
