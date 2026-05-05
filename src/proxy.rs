use std::cmp::Reverse;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, RwLock};

use arc_swap::ArcSwap;
use async_trait::async_trait;
#[cfg(feature = "web")]
use bytes::Bytes;
use pingora::Error;
#[cfg(feature = "cache")]
use pingora::ErrorType;
#[cfg(feature = "cache")]
use pingora::cache::CacheKey as PingoraCacheKey;
#[cfg(feature = "cache")]
use pingora::cache::key::CacheHashKey;
#[cfg(feature = "cache")]
use pingora::cache::lock::CacheKeyLockImpl;
use pingora::http::RequestHeader;
#[cfg(feature = "cache")]
use pingora::http::ResponseHeader;
use pingora::prelude::{HttpPeer, Result};
use pingora::proxy::{ProxyHttp, Session};
#[cfg(feature = "cache")]
use pingora::{cache::CacheOptionOverrides, cache::RespCacheable, http::StatusCode};

use crate::config::{Config, ProxyConfig, ServerLimitsConfig, normalize_host};
#[cfg(feature = "load-balancer")]
use crate::load_balancer::{UpstreamLoadBalancer, UpstreamLoadBalancerService};
#[cfg(feature = "web")]
use crate::web::{ResolveResult, StaticFileServer};

#[cfg(feature = "cache")]
const CACHE_LOCK_AGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(feature = "cache")]
const CACHE_LOCK_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
    limits: ServerLimitsConfig,
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
                config.web.clone(),
                load_balancer("default", &config.proxy)?,
            )?;
            vhosts.push(runtime);
        } else {
            for configured in &config.vhosts {
                let index = vhosts.len();
                let runtime = RuntimeVhost::from_config(
                    configured,
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
            limits: config.server.limits,
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
                config.web.clone(),
            )?;
            vhosts.push(runtime);
        } else {
            for configured in &config.vhosts {
                let index = vhosts.len();
                let runtime = RuntimeVhost::from_config(configured)?;
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
            limits: config.server.limits,
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
            .field("proxy", &self.proxy);

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
        #[cfg(feature = "load-balancer")] load_balancer: Option<UpstreamLoadBalancer>,
    ) -> io::Result<Self> {
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
    health_signal_recorded: bool,
}

#[async_trait]
impl ProxyHttp for FluxProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext::default()
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

        #[cfg(feature = "web")]
        {
            let Some(web) = &state.vhost(vhost_index).web else {
                return Ok(false);
            };

            let method = session.req_header().method.as_str();
            if method != "GET" && method != "HEAD" {
                return Ok(false);
            }

            match web.resolve(session.req_header().uri.path()) {
                Ok(ResolveResult::Found(file)) => {
                    crate::web::serve_static_file(session, &file, method == "GET").await?;
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
fn cache_request_from_header(request: &RequestHeader) -> crate::cache::CacheRequest<'_> {
    crate::cache::CacheRequest {
        method: request.method.as_str(),
        host: request_host_header(request),
        path: request.uri.path(),
        query: request.uri.query(),
    }
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
    use crate::config::{
        ByteSize, CacheConfig, Config, ProxyConfig, ServerConfig, ServerLimitsConfig, VhostConfig,
        WebConfig,
    };

    #[cfg(feature = "cache")]
    use super::{CacheBulkPurgeRequest, CachePurgeRequest};
    use super::{FluxProxy, request_limit_status};

    #[test]
    fn routes_known_hosts() {
        let config = Config {
            server: ServerConfig {
                listen: vec!["127.0.0.1:8080".to_owned()],
                tls_listen: Vec::new(),
                default_vhost: Some("exact".to_owned()),
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
                limits: ServerLimitsConfig::default(),
            },
            vhosts: vec![
                VhostConfig {
                    name: "one".to_owned(),
                    hosts: vec!["one.example".to_owned()],
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    web: WebConfig::default(),
                },
                VhostConfig {
                    name: "two".to_owned(),
                    hosts: vec!["two.example".to_owned()],
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
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
                limits: ServerLimitsConfig::default(),
            },
            vhosts: vec![
                VhostConfig {
                    name: "wild".to_owned(),
                    hosts: vec!["*.example.com".to_owned()],
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
                    web: WebConfig::default(),
                },
                VhostConfig {
                    name: "exact".to_owned(),
                    hosts: vec!["api.example.com".to_owned()],
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
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
                    web: WebConfig::default(),
                },
                VhostConfig {
                    name: "uncached".to_owned(),
                    hosts: vec!["uncached.example".to_owned()],
                    tls: crate::config::VhostTlsConfig::default(),
                    proxy: ProxyConfig::default(),
                    cache: CacheConfig::default(),
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
