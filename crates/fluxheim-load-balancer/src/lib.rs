#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::fmt::{Debug, Formatter};
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fluxheim_common::FluxError;
use fluxheim_config::{
    LoadBalanceHealthCheckProtocol, LoadBalancePassiveHealthConfig, LoadBalancePersistenceConfig,
    LoadBalanceQueueConfig, LoadBalanceSelection, LoadBalanceSlowStartConfig, ProxyConfig,
};

mod api;
mod api_selection;
mod backend;
mod background;
mod crypto;
mod discovery;
mod health;
mod key;
#[cfg(feature = "metrics")]
mod metrics;
mod persistence;
mod persistence_cookie;
mod persistence_request;
mod policy;
mod policy_config;
mod policy_runtime;
mod policy_stats;
mod selection;
mod selection_candidate;
mod selection_consistent;
mod selection_fnv;
mod selection_hash;
mod selection_ketama;
mod selection_maglev;
mod selection_power;
mod selection_weight;
mod state;
mod state_file;

#[cfg(test)]
fn install_test_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

use self::api::LoadBalancerMetricLabels;
pub use self::api::{
    LoadBalancedUpstreamOutcome, LoadBalancerBackendRuntimeStats, LoadBalancerCircuitState,
    LoadBalancerDiscoveryMode, LoadBalancerDiscoveryRuntimeStats, LoadBalancerMemberAddRequest,
    LoadBalancerMemberRemoveRequest, LoadBalancerMemberSetMutationResult,
    LoadBalancerMemberStateRequest, LoadBalancerMemberStateResult, LoadBalancerMemberUpdateRequest,
    LoadBalancerMemberWeightRequest, LoadBalancerMemberWeightResult,
    LoadBalancerPersistenceClearRequest, LoadBalancerPersistenceClearResult,
    LoadBalancerPersistenceOutcome, LoadBalancerPersistenceRuntimeStats,
    LoadBalancerPoolRuntimeStats, LoadBalancerQueueOutcome, LoadBalancerQueueRuntimeStats,
    LoadBalancerRetryRuntimeStats, LoadBalancerRouteRuntimeStats,
    LoadBalancerRuntimeBackendMutation, LoadBalancerRuntimeBackendSetMutation,
    LoadBalancerRuntimeBackendSetOperation, LoadBalancerRuntimeBackendState,
    LoadBalancerRuntimeBackendWeightMutation, LoadBalancerRuntimeStateRestore,
    LoadBalancerRuntimeStateSnapshot, LoadBalancerRuntimeStats, LoadBalancerSelectionResult,
    LoadBalancerVhostRuntimeStats, SelectedUpstream, parse_load_balancer_member_weight,
    parse_load_balancer_runtime_weight,
};
#[cfg(test)]
use self::backend::BackendIdentity;
use self::backend::FluxBackend;
use self::backend::FluxBackendDiscoveryRuntimeStatus;
use self::backend::FluxLoadBalancerRuntime;
use self::backend::RuntimeBackend as Backend;
use self::backend::backend_container_snapshot;
use self::discovery::{
    background_maglev_service_for, background_service_for, configured_load_balancer,
    configured_maglev_table, configured_nginx_ketama_table,
};
pub(crate) use self::key::backend_key;
use self::persistence::{LoadBalanceKeySource, LoadBalancerPersistenceState};
use self::policy::BackendSelectionPolicy;
use self::policy_config::backend_aliases;
use self::policy_stats::{BackendStatsInputs, load_balancer_backend_stats};
use self::selection::{
    LoadBalancerSelectInputs, SelectionPass, select_least_connections, select_least_sessions,
    select_least_time, select_maglev, select_weighted_round_robin,
};
use self::selection_consistent::{
    select_bounded_load_consistent, select_consistent_hash, select_nginx_consistent_hash,
};
use self::selection_fnv::select_fnv_hash;
use self::selection_ketama::NginxKetamaTable;
use self::selection_maglev::MaglevTable;
use self::selection_power::select_power_of_two;
use self::state::{
    BackendConnectionCounters, BackendLatencyState, PassiveHealthState, SlowStartState,
};
pub use self::state::{LoadBalancedConnectionPermit, LoadBalancedUpstreamReporter};
use self::state_file::{load_runtime_state_file, write_runtime_state_file};

pub use self::background::{FluxBackgroundReady, FluxShutdown};
pub use self::crypto::set_admin_hmac_sha256;
#[cfg(feature = "metrics")]
pub use self::metrics::set_load_balancer_event_recorder;
pub use self::persistence::LoadBalancerRequestView;

pub struct UpstreamLoadBalancerService {
    inner: background::FluxBackgroundService<backend::FluxLoadBalancerRuntime>,
    load_balancer: UpstreamLoadBalancer,
}

impl UpstreamLoadBalancerService {
    fn new(
        inner: background::FluxBackgroundService<backend::FluxLoadBalancerRuntime>,
        load_balancer: UpstreamLoadBalancer,
    ) -> Self {
        Self {
            inner,
            load_balancer,
        }
    }

    pub async fn start(
        &self,
        shutdown: background::FluxShutdown,
        ready: background::FluxBackgroundReady,
    ) {
        self.inner.task().run(shutdown, ready).await;
    }

    pub fn into_native_service(self) -> fluxheim_runtime::FluxBackgroundService<Self> {
        let name = self.name().to_owned();
        fluxheim_runtime::FluxBackgroundService::with_kind(
            name,
            fluxheim_runtime::BackgroundTaskKind::LoadBalancerRefresh,
            self,
        )
    }

    pub fn name(&self) -> &str {
        self.inner.name()
    }

    pub fn load_balancer(&self) -> UpstreamLoadBalancer {
        self.load_balancer.clone()
    }

    #[allow(deprecated)]
    pub fn threads(&self) -> Option<usize> {
        self.inner.threads()
    }
}

#[async_trait::async_trait]
impl fluxheim_runtime::FluxBackgroundTask for UpstreamLoadBalancerService {
    async fn start(
        &self,
        shutdown: background::FluxShutdown,
        ready: background::FluxBackgroundReady,
    ) {
        self.inner.task().run(shutdown, ready).await;
    }
}

const BACKEND_STATE_PRUNE_INTERVAL: usize = 1024;
pub const MAX_RUNTIME_BACKEND_WEIGHT: usize = 1000;

#[derive(Clone)]
pub struct UpstreamLoadBalancer {
    inner: UpstreamLoadBalancerInner,
    selection: LoadBalanceSelection,
    key_source: LoadBalanceKeySource,
    backend_aliases: Arc<std::collections::HashMap<u64, Arc<str>>>,
    discovery_mode: LoadBalancerDiscoveryMode,
    passive_health: Option<Arc<PassiveHealthState>>,
    slow_start: Option<Arc<SlowStartState>>,
    persistence: Option<Arc<LoadBalancerPersistenceState>>,
    passive_health_policy: LoadBalancePassiveHealthConfig,
    slow_start_policy: LoadBalanceSlowStartConfig,
    persistence_policy: LoadBalancePersistenceConfig,
    queue_policy: LoadBalanceQueueConfig,
    queue_waiting: Arc<AtomicUsize>,
    health_check_protocol: Option<LoadBalanceHealthCheckProtocol>,
    runtime_state_file: Option<Arc<PathBuf>>,
    runtime_state_save_lock: Arc<std::sync::Mutex<()>>,
    round_robin_cursor: Arc<AtomicUsize>,
    state_prune_counter: Arc<AtomicUsize>,
    counters: Arc<BackendConnectionCounters>,
    backend_policy: BackendSelectionPolicy,
    max_iterations: usize,
    all_down_status: u16,
    retry: LoadBalancerRetryRuntimeStats,
}

const LOAD_BALANCER_RUNTIME_STATE_VERSION: u16 = 1;

#[derive(Debug)]
struct LoadBalancerQueueSlot {
    waiting: Arc<AtomicUsize>,
}

impl Drop for LoadBalancerQueueSlot {
    fn drop(&mut self) {
        self.waiting.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Debug for UpstreamLoadBalancer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UpstreamLoadBalancer")
            .field("max_iterations", &self.max_iterations)
            .finish_non_exhaustive()
    }
}

impl UpstreamLoadBalancer {
    pub fn from_proxy_config(config: &ProxyConfig) -> io::Result<Option<Self>> {
        #[cfg(test)]
        install_test_crypto_provider();

        let backend_policy = BackendSelectionPolicy::from_config(config);
        match config.load_balance.selection {
            LoadBalanceSelection::RoundRobin => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::RoundRobin(Arc::new(inner)),
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::LeastConnections => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::LeastConnections(Arc::new(inner)),
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::LeastSessions => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::LeastSessions(Arc::new(inner)),
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::LeastTime => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::LeastTime {
                        inner: Arc::new(inner),
                        latency: Arc::new(BackendLatencyState::default()),
                    },
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::PowerOfTwo => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::PowerOfTwo(Arc::new(inner)),
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::SourceHash
            | LoadBalanceSelection::UriHash
            | LoadBalanceSelection::HeaderHash
            | LoadBalanceSelection::CookieHash => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::FnvHash(Arc::new(inner)),
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::ConsistentSourceHash
            | LoadBalanceSelection::ConsistentUriHash
            | LoadBalanceSelection::ConsistentHeaderHash
            | LoadBalanceSelection::ConsistentCookieHash => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::ConsistentHash(Arc::new(inner)),
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::NginxConsistentSourceHash
            | LoadBalanceSelection::NginxConsistentUriHash
            | LoadBalanceSelection::NginxConsistentHeaderHash
            | LoadBalanceSelection::NginxConsistentCookieHash => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                let table = Arc::new(configured_nginx_ketama_table(config)?);
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::NginxConsistentHash {
                        inner: Arc::new(inner),
                        table,
                    },
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::BoundedLoadConsistentSourceHash
            | LoadBalanceSelection::BoundedLoadConsistentUriHash
            | LoadBalanceSelection::BoundedLoadConsistentHeaderHash
            | LoadBalanceSelection::BoundedLoadConsistentCookieHash => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::BoundedLoadConsistentHash {
                        inner: Arc::new(inner),
                        factor_per_mille: config.load_balance.bounded_load_factor_per_mille,
                    },
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::MaglevSourceHash
            | LoadBalanceSelection::MaglevUriHash
            | LoadBalanceSelection::MaglevHeaderHash
            | LoadBalanceSelection::MaglevCookieHash => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                let table = Arc::new(configured_maglev_table(config)?);
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::MaglevHash {
                        inner: Arc::new(inner),
                        table,
                    },
                    config,
                    backend_policy,
                )))
            }
        }
    }

    pub fn background_service_from_proxy_config(
        name: &str,
        vhost: &str,
        route: Option<&str>,
        config: &ProxyConfig,
    ) -> io::Result<Option<(Self, UpstreamLoadBalancerService)>> {
        #[cfg(test)]
        install_test_crypto_provider();

        let metric_labels = LoadBalancerMetricLabels::new(vhost, route);
        match config.load_balance.selection {
            LoadBalanceSelection::RoundRobin => background_service_for(
                name,
                metric_labels,
                config,
                UpstreamLoadBalancerInner::RoundRobin,
            ),
            LoadBalanceSelection::LeastConnections => {
                background_service_for(name, metric_labels, config, |inner| {
                    UpstreamLoadBalancerInner::LeastConnections(inner)
                })
            }
            LoadBalanceSelection::LeastSessions => {
                background_service_for(name, metric_labels, config, |inner| {
                    UpstreamLoadBalancerInner::LeastSessions(inner)
                })
            }
            LoadBalanceSelection::LeastTime => {
                background_service_for(name, metric_labels, config, |inner| {
                    UpstreamLoadBalancerInner::LeastTime {
                        inner,
                        latency: Arc::new(BackendLatencyState::default()),
                    }
                })
            }
            LoadBalanceSelection::PowerOfTwo => {
                background_service_for(name, metric_labels, config, |inner| {
                    UpstreamLoadBalancerInner::PowerOfTwo(inner)
                })
            }
            LoadBalanceSelection::SourceHash
            | LoadBalanceSelection::UriHash
            | LoadBalanceSelection::HeaderHash
            | LoadBalanceSelection::CookieHash => background_service_for(
                name,
                metric_labels,
                config,
                UpstreamLoadBalancerInner::FnvHash,
            ),
            LoadBalanceSelection::ConsistentSourceHash
            | LoadBalanceSelection::ConsistentUriHash
            | LoadBalanceSelection::ConsistentHeaderHash
            | LoadBalanceSelection::ConsistentCookieHash => background_service_for(
                name,
                metric_labels,
                config,
                UpstreamLoadBalancerInner::ConsistentHash,
            ),
            LoadBalanceSelection::NginxConsistentSourceHash
            | LoadBalanceSelection::NginxConsistentUriHash
            | LoadBalanceSelection::NginxConsistentHeaderHash
            | LoadBalanceSelection::NginxConsistentCookieHash => {
                let table = Arc::new(configured_nginx_ketama_table(config)?);
                background_service_for(name, metric_labels, config, move |inner| {
                    UpstreamLoadBalancerInner::NginxConsistentHash {
                        inner,
                        table: Arc::clone(&table),
                    }
                })
            }
            LoadBalanceSelection::BoundedLoadConsistentSourceHash
            | LoadBalanceSelection::BoundedLoadConsistentUriHash
            | LoadBalanceSelection::BoundedLoadConsistentHeaderHash
            | LoadBalanceSelection::BoundedLoadConsistentCookieHash => {
                let factor_per_mille = config.load_balance.bounded_load_factor_per_mille;
                background_service_for(name, metric_labels, config, move |inner| {
                    UpstreamLoadBalancerInner::BoundedLoadConsistentHash {
                        inner,
                        factor_per_mille,
                    }
                })
            }
            LoadBalanceSelection::MaglevSourceHash
            | LoadBalanceSelection::MaglevUriHash
            | LoadBalanceSelection::MaglevHeaderHash
            | LoadBalanceSelection::MaglevCookieHash => {
                background_maglev_service_for(name, metric_labels, config)
            }
        }
    }

    pub fn select<R>(&self, request: &R, client_ip: Option<IpAddr>) -> Option<SelectedUpstream>
    where
        R: LoadBalancerRequestView,
    {
        let persistence_key = self
            .persistence
            .as_ref()
            .and_then(|persistence| persistence.key(request, client_ip));
        if let (Some(persistence), Some(key)) = (&self.persistence, persistence_key.as_deref())
            && let Some(backend_key) = persistence.lookup(key)
        {
            let persisted = self
                .inner
                .backend_by_policy_key(backend_key)
                .and_then(|backend| {
                    self.backend_available_for_persistence(&backend)
                        .then_some(backend)
                })
                .and_then(|backend| {
                    self.prepare_selected(
                        SelectedUpstream::new(backend),
                        Some(LoadBalancerPersistenceOutcome::Hit),
                    )
                });
            if let Some(selected) = persisted {
                return Some(selected);
            }
            return self.select_fresh(
                request,
                client_ip,
                persistence_key.as_deref(),
                Some(LoadBalancerPersistenceOutcome::Fallback),
            );
        }

        self.select_fresh(
            request,
            client_ip,
            persistence_key.as_deref(),
            persistence_key
                .as_ref()
                .map(|_| LoadBalancerPersistenceOutcome::Miss),
        )
    }

    pub async fn select_or_wait<R>(
        &self,
        request: &R,
        client_ip: Option<IpAddr>,
    ) -> Option<SelectedUpstream>
    where
        R: LoadBalancerRequestView,
    {
        self.select_or_wait_result(request, client_ip)
            .await
            .selected
    }

    pub async fn select_or_wait_result<R>(
        &self,
        request: &R,
        client_ip: Option<IpAddr>,
    ) -> LoadBalancerSelectionResult
    where
        R: LoadBalancerRequestView,
    {
        if let Some(selected) = self.select(request, client_ip) {
            return LoadBalancerSelectionResult {
                selected: Some(selected),
                queue_outcome: None,
                queue_wait: None,
            };
        }
        if !self.queue_policy.enabled() {
            return LoadBalancerSelectionResult {
                selected: None,
                queue_outcome: None,
                queue_wait: None,
            };
        }
        let Some(_slot) = self.acquire_queue_slot() else {
            return LoadBalancerSelectionResult {
                selected: None,
                queue_outcome: Some(LoadBalancerQueueOutcome::Full),
                queue_wait: None,
            };
        };
        let queued_at = Instant::now();
        let deadline = queued_at + Duration::from_millis(self.queue_policy.timeout_ms);
        loop {
            if let Some(selected) = self.select(request, client_ip) {
                return LoadBalancerSelectionResult {
                    selected: Some(selected),
                    queue_outcome: Some(LoadBalancerQueueOutcome::Waited),
                    queue_wait: Some(queued_at.elapsed()),
                };
            }
            let now = Instant::now();
            if now >= deadline {
                return LoadBalancerSelectionResult {
                    selected: None,
                    queue_outcome: Some(LoadBalancerQueueOutcome::Timeout),
                    queue_wait: Some(queued_at.elapsed()),
                };
            }
            let sleep_for = deadline
                .saturating_duration_since(now)
                .min(Duration::from_millis(self.queue_policy.retry_interval_ms));
            tokio::time::sleep(sleep_for).await;
        }
    }

    fn acquire_queue_slot(&self) -> Option<LoadBalancerQueueSlot> {
        let max_waiting = self.queue_policy.max_waiting;
        let mut current = self.queue_waiting.load(Ordering::Acquire);
        loop {
            if current >= max_waiting {
                return None;
            }
            match self.queue_waiting.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(LoadBalancerQueueSlot {
                        waiting: self.queue_waiting.clone(),
                    });
                }
                Err(next) => current = next,
            }
        }
    }

    fn select_fresh<R>(
        &self,
        request: &R,
        client_ip: Option<IpAddr>,
        persistence_key: Option<&[u8]>,
        persistence_outcome: Option<LoadBalancerPersistenceOutcome>,
    ) -> Option<SelectedUpstream>
    where
        R: LoadBalancerRequestView,
    {
        self.prune_stale_backend_state_periodically();
        let key = self.key_source.request_key(request, client_ip);
        let persistence_entry_counts = self
            .persistence
            .as_ref()
            .filter(|persistence| {
                self.fresh_selection_needs_persistence_counts(persistence_key, persistence)
            })
            .map_or_else(std::collections::HashMap::new, |persistence| {
                persistence.runtime_counts().1
            });
        let selected = self.inner.select(LoadBalancerSelectInputs {
            key: key.as_deref(),
            max_iterations: self.max_iterations,
            passive_health: self.passive_health.as_deref(),
            slow_start: self.slow_start.as_deref(),
            counters: &self.counters,
            backend_policy: &self.backend_policy,
            persistence_entry_counts: &persistence_entry_counts,
            round_robin_cursor: &self.round_robin_cursor,
        })?;
        let selected = self.prepare_selected(selected, persistence_outcome)?;
        if let (Some(persistence), Some(key)) = (&self.persistence, persistence_key) {
            persistence.record(key, backend_key(&selected.backend));
            self.save_runtime_state_if_configured_in_background("persistence_record");
        } else if let Some(persistence) = &self.persistence
            && let Some((key, cookie)) = persistence.new_managed_cookie()
        {
            let mut selected = selected;
            persistence.record(&key, backend_key(&selected.backend));
            self.save_runtime_state_if_configured_in_background("managed_cookie_issue");
            selected.managed_affinity_cookie = Some(cookie);
            return Some(selected);
        }
        Some(selected)
    }

    fn fresh_selection_needs_persistence_counts(
        &self,
        persistence_key: Option<&[u8]>,
        persistence: &LoadBalancerPersistenceState,
    ) -> bool {
        self.selection == LoadBalanceSelection::LeastSessions
            && (!persistence.is_managed_cookie() || persistence_key.is_some())
    }

    fn prepare_selected(
        &self,
        mut selected: SelectedUpstream,
        persistence_outcome: Option<LoadBalancerPersistenceOutcome>,
    ) -> Option<SelectedUpstream> {
        selected.permit = Some(self.counters.permit(
            &selected.backend,
            self.backend_policy.max_in_flight(&selected.backend),
        )?);
        selected.alias = self
            .backend_aliases
            .get(&backend_key(&selected.backend))
            .cloned();
        let latency = self.inner.latency_state();
        selected.reporter = (self.passive_health.is_some() || latency.is_some()).then(|| {
            LoadBalancedUpstreamReporter::new(
                backend_key(&selected.backend),
                self.passive_health.clone(),
                self.slow_start.clone(),
                latency,
            )
        });
        selected.persistence_outcome = persistence_outcome;
        Some(selected)
    }

    fn backend_available_for_persistence(&self, backend: &Backend) -> bool {
        let key = backend_key(backend);
        self.inner.backend_ready(backend)
            && !self
                .passive_health
                .as_ref()
                .is_some_and(|health| health.key_is_currently_ejected(key))
            && self
                .slow_start
                .as_ref()
                .is_none_or(|state| state.permits_read_only(backend))
            && self.backend_policy.permits(
                backend,
                SelectionPass {
                    allow_backup: true,
                    minimum_priority_group: None,
                    ignore_slow_start: false,
                    ignore_locality: false,
                },
                &self.counters,
            )
            && !self.backend_policy.disabled(key)
            && !self.backend_policy.drained(key)
    }

    fn from_inner(
        inner: UpstreamLoadBalancerInner,
        config: &ProxyConfig,
        backend_policy: BackendSelectionPolicy,
    ) -> Self {
        let balancer =
            Self {
                inner,
                selection: config.load_balance.selection,
                key_source: LoadBalanceKeySource::from_config(config),
                backend_aliases: Arc::new(backend_aliases(config)),
                discovery_mode: LoadBalancerDiscoveryMode::from_config(config),
                passive_health: config.load_balance.passive_health.enabled.then(|| {
                    Arc::new(PassiveHealthState::from_config(
                        &config.load_balance.passive_health,
                    ))
                }),
                slow_start: config.load_balance.slow_start.enabled.then(|| {
                    Arc::new(SlowStartState::from_config(&config.load_balance.slow_start))
                }),
                persistence: config.load_balance.persistence.enabled.then(|| {
                    Arc::new(LoadBalancerPersistenceState::from_config(
                        &config.load_balance.persistence,
                    ))
                }),
                passive_health_policy: config.load_balance.passive_health.clone(),
                slow_start_policy: config.load_balance.slow_start.clone(),
                persistence_policy: config.load_balance.persistence.clone(),
                queue_policy: config.load_balance.queue.clone(),
                queue_waiting: Arc::new(AtomicUsize::new(0)),
                health_check_protocol: config
                    .load_balance
                    .health_check
                    .enabled
                    .then_some(config.load_balance.health_check.protocol),
                runtime_state_file: config.load_balance.runtime_state_file.clone().map(Arc::new),
                runtime_state_save_lock: Arc::new(std::sync::Mutex::new(())),
                round_robin_cursor: Arc::new(AtomicUsize::new(0)),
                state_prune_counter: Arc::new(AtomicUsize::new(0)),
                counters: Arc::new(BackendConnectionCounters::default()),
                backend_policy,
                max_iterations: config.load_balance.max_iterations,
                all_down_status: config.load_balance.all_down_status,
                retry: LoadBalancerRetryRuntimeStats::from_config(&config.load_balance.retry),
            };
        balancer.load_runtime_state_if_configured();
        balancer
    }

    fn prune_stale_backend_state_periodically(&self) {
        let current = self.state_prune_counter.fetch_add(1, Ordering::Relaxed);
        if !current.is_multiple_of(BACKEND_STATE_PRUNE_INTERVAL) {
            return;
        }
        self.prune_stale_backend_state();
    }

    fn prune_stale_backend_state(&self) {
        let backends = self.inner.backends();
        let live_keys = backends
            .iter()
            .map(backend_key)
            .collect::<std::collections::HashSet<_>>();
        self.counters.prune_stale(&live_keys);
        self.backend_policy.prune_stale(&live_keys);
        if let Some(persistence) = &self.persistence {
            persistence.prune_stale_for_live_backends(&live_keys);
        }
        if let Some(passive_health) = &self.passive_health {
            passive_health.prune_stale(&live_keys);
        }
        if let Some(slow_start) = &self.slow_start {
            slow_start.prune_stale(&live_keys);
        }
        if let Some(latency) = self.inner.latency_state() {
            latency.prune_stale(&live_keys);
        }
    }

    fn live_backend_keys(&self) -> std::collections::HashSet<u64> {
        self.inner.backends().iter().map(backend_key).collect()
    }

    pub fn runtime_stats(&self) -> LoadBalancerPoolRuntimeStats {
        let health_check_frequency = self.inner.health_check_frequency();
        let live_policy_keys = self.live_backend_keys();
        let (persistence_entry_count, persistence_backend_entry_counts) = self
            .persistence
            .as_ref()
            .map_or((0, std::collections::HashMap::new()), |persistence| {
                persistence.runtime_counts_for_live_backends(Some(&live_policy_keys))
            });
        let backends = self.inner.backend_stats(
            &self.backend_aliases,
            self.passive_health.as_deref(),
            self.slow_start.as_deref(),
            &self.counters,
            &self.backend_policy,
            &persistence_backend_entry_counts,
        );
        let ready_backend_count = backends.iter().filter(|backend| backend.ready).count();
        let eligible_backend_count = backends
            .iter()
            .filter(|backend| backend_runtime_status_eligible(backend))
            .count();
        let primary_available_backend_count = backends
            .iter()
            .filter(|backend| !backend.backup && backend_runtime_status_eligible(backend))
            .count();
        let backup_available_backend_count = backends
            .iter()
            .filter(|backend| backend.backup && backend_runtime_status_eligible(backend))
            .count();
        let drained_backend_count = backends.iter().filter(|backend| backend.drained).count();
        let disabled_backend_count = backends.iter().filter(|backend| backend.disabled).count();
        let runtime_overridden_backend_count = backends
            .iter()
            .filter(|backend| backend.runtime_state_override.is_some())
            .count();
        let runtime_drained_backend_count = backends
            .iter()
            .filter(|backend| {
                backend.runtime_state_override == Some(LoadBalancerRuntimeBackendState::Drained)
            })
            .count();
        let runtime_disabled_backend_count = backends
            .iter()
            .filter(|backend| {
                backend.runtime_state_override == Some(LoadBalancerRuntimeBackendState::Disabled)
            })
            .count();
        let runtime_forced_down_backend_count = backends
            .iter()
            .filter(|backend| {
                backend.runtime_state_override == Some(LoadBalancerRuntimeBackendState::ForcedDown)
            })
            .count();
        let passive_ejected_backend_count = backends
            .iter()
            .filter(|backend| backend.passive_ejected)
            .count();
        let circuit_open_backend_count = backends
            .iter()
            .filter(|backend| backend.circuit_state == LoadBalancerCircuitState::Open)
            .count();
        let saturated_backend_count = backends
            .iter()
            .filter(|backend| {
                backend
                    .max_in_flight
                    .is_some_and(|limit| backend.in_flight >= limit)
            })
            .count();
        let discovery = LoadBalancerDiscoveryRuntimeStats::from_runtime_status(
            self.discovery_mode,
            self.inner.discovery_runtime_status(),
        );
        LoadBalancerPoolRuntimeStats {
            discovery_mode: self.discovery_mode,
            discovery,
            selection: self.selection,
            backend_count: self.inner.backend_count(),
            ready_backend_count,
            available_backend_count: eligible_backend_count,
            primary_available_backend_count,
            backup_available_backend_count,
            drained_backend_count,
            disabled_backend_count,
            runtime_overridden_backend_count,
            runtime_drained_backend_count,
            runtime_disabled_backend_count,
            runtime_forced_down_backend_count,
            passive_ejected_backend_count,
            circuit_open_backend_count,
            saturated_backend_count,
            max_iterations: self.max_iterations,
            all_down_status: self.all_down_status,
            health_check_enabled: health_check_frequency.is_some(),
            health_check_protocol: self.health_check_protocol,
            health_check_frequency_secs: health_check_frequency
                .map(|frequency| frequency.as_secs()),
            parallel_health_check: self.inner.parallel_health_check(),
            passive_health_enabled: self.passive_health.is_some(),
            slow_start_enabled: self.slow_start.is_some(),
            persistence_enabled: self.persistence.is_some(),
            passive_health: self.passive_health_policy.clone(),
            slow_start: self.slow_start_policy.clone(),
            persistence: LoadBalancerPersistenceRuntimeStats::from_policy(
                self.persistence.as_deref(),
                &self.persistence_policy,
                persistence_entry_count,
            ),
            queue: LoadBalancerQueueRuntimeStats::from_policy(
                &self.queue_policy,
                &self.queue_waiting,
            ),
            retry: self.retry.clone(),
            backends,
        }
    }

    #[cfg(test)]
    fn backend_count(&self) -> usize {
        self.inner.backend_count()
    }

    #[cfg(test)]
    fn backend_weights(&self) -> Vec<usize> {
        self.inner.backend_weights()
    }

    #[cfg(test)]
    fn health_check_frequency(&self) -> Option<Duration> {
        self.inner.health_check_frequency()
    }

    pub fn runtime_state_persistent(&self) -> bool {
        self.runtime_state_file.is_some()
    }

    pub fn all_down_status(&self) -> u16 {
        self.all_down_status
    }

    #[cfg(test)]
    fn parallel_health_check(&self) -> bool {
        self.inner.parallel_health_check()
    }

    #[cfg(test)]
    async fn run_health_check(&self, parallel: bool) {
        self.inner.run_health_check(parallel).await;
    }

    pub fn set_runtime_backend_state(
        &self,
        member: &str,
        state: LoadBalancerRuntimeBackendState,
    ) -> io::Result<LoadBalancerRuntimeBackendMutation> {
        let backend = self
            .inner
            .backend_by_member(member, &self.backend_aliases)?;
        let key = backend_key(&backend);
        if !self.backend_policy.set_runtime_backend_state(key, state) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "load balancer runtime override table is full",
            ));
        }
        if state == LoadBalancerRuntimeBackendState::ManualResume {
            if let Some(passive_health) = &self.passive_health {
                passive_health.clear_key(key);
            }
            if let Some(slow_start) = &self.slow_start {
                slow_start.reset_at(key, Instant::now());
            }
        }
        self.save_runtime_state_if_configured("member_state");
        Ok(LoadBalancerRuntimeBackendMutation {
            member: member.to_owned(),
            state,
            persistent: self.runtime_state_persistent(),
            #[cfg(not(feature = "privacy-mode"))]
            address: backend.addr.to_string(),
            alias: self
                .backend_aliases
                .get(&key)
                .map(|alias| alias.to_string()),
        })
    }

    pub fn set_runtime_backend_weight(
        &self,
        member: &str,
        weight: Option<usize>,
    ) -> io::Result<LoadBalancerRuntimeBackendWeightMutation> {
        if !self.selection.supports_runtime_weight_override() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime load-balancer weight overrides are available only for round-robin, least-connections, least-sessions, and least-time selections in this release",
            ));
        }
        let backend = self
            .inner
            .backend_by_member(member, &self.backend_aliases)?;
        let key = backend_key(&backend);
        if !self.backend_policy.set_runtime_backend_weight(key, weight) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "load balancer runtime override table is full",
            ));
        }
        self.save_runtime_state_if_configured("member_weight");
        Ok(LoadBalancerRuntimeBackendWeightMutation {
            member: member.to_owned(),
            configured_weight: backend.weight,
            effective_weight: self.backend_policy.effective_weight(&backend),
            runtime_weight_override: self.backend_policy.runtime_backend_weight(key),
            persistent: self.runtime_state_persistent(),
            #[cfg(not(feature = "privacy-mode"))]
            address: backend.addr.to_string(),
            alias: self
                .backend_aliases
                .get(&key)
                .map(|alias| alias.to_string()),
        })
    }

    pub fn add_runtime_backend_member(
        &self,
        member: &str,
        weight: usize,
    ) -> io::Result<LoadBalancerRuntimeBackendSetMutation> {
        self.validate_runtime_backend_set_mutation()?;
        let backend = runtime_backend_from_member(member, weight)?;
        let key = backend_key(&backend);
        let backend_count = self.inner.add_runtime_backend(backend.clone())?;
        self.save_runtime_state_if_configured_in_background("member_add");
        Ok(LoadBalancerRuntimeBackendSetMutation {
            member: backend.addr.to_string(),
            operation: LoadBalancerRuntimeBackendSetOperation::Added,
            configured_weight: backend.weight,
            backend_count,
            persistent: false,
            #[cfg(not(feature = "privacy-mode"))]
            address: backend.addr.to_string(),
            #[cfg(not(feature = "privacy-mode"))]
            previous_address: None,
            alias: self
                .backend_aliases
                .get(&key)
                .map(|alias| alias.to_string()),
        })
    }

    pub fn remove_runtime_backend_member(
        &self,
        member: &str,
    ) -> io::Result<LoadBalancerRuntimeBackendSetMutation> {
        self.validate_runtime_backend_set_mutation()?;
        let backend = self
            .inner
            .backend_by_member(member, &self.backend_aliases)?;
        if self.counters.count(&backend) > 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "load balancer member still has in-flight connections; drain before removing",
            ));
        }
        let key = backend_key(&backend);
        let alias = self
            .backend_aliases
            .get(&key)
            .map(|alias| alias.to_string());
        let backend_count = self.inner.remove_runtime_backend(&backend)?;
        let post_remove_in_flight = self.counters.count(&backend);
        if post_remove_in_flight > 0 {
            log::warn!(
                target: "fluxheim::load_balancer",
                "load balancer member removed after zero-count gate but now has in-flight requests count={}",
                post_remove_in_flight
            );
        }
        self.clear_removed_backend_state(key);
        self.prune_stale_backend_state();
        self.save_runtime_state_if_configured_in_background("member_remove");
        Ok(LoadBalancerRuntimeBackendSetMutation {
            member: backend.addr.to_string(),
            operation: LoadBalancerRuntimeBackendSetOperation::Removed,
            configured_weight: backend.weight,
            backend_count,
            persistent: false,
            #[cfg(not(feature = "privacy-mode"))]
            address: backend.addr.to_string(),
            #[cfg(not(feature = "privacy-mode"))]
            previous_address: None,
            alias,
        })
    }

    pub fn update_runtime_backend_member(
        &self,
        member: &str,
        updated_member: Option<&str>,
        weight: Option<usize>,
    ) -> io::Result<LoadBalancerRuntimeBackendSetMutation> {
        self.validate_runtime_backend_set_mutation()?;
        let current = self
            .inner
            .backend_by_member(member, &self.backend_aliases)?;
        let updated_authority = updated_member
            .map(str::trim)
            .filter(|member| !member.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| current.addr.to_string());
        let updated_weight = weight.unwrap_or(current.weight);
        if updated_authority == current.addr.to_string() && updated_weight == current.weight {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "load balancer member update must change address or weight",
            ));
        }
        let current_key = backend_key(&current);
        let current_alias = self
            .backend_aliases
            .get(&current_key)
            .map(|alias| alias.to_string());
        if updated_authority != current.addr.to_string() && current_alias.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "load balancer aliased members cannot be retargeted without a config reload",
            ));
        }
        if updated_authority != current.addr.to_string() && self.counters.count(&current) > 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "load balancer member still has in-flight connections; drain before changing address",
            ));
        }
        let updated = runtime_backend_from_member(&updated_authority, updated_weight)?;
        let updated_key = backend_key(&updated);
        let backend_count = self
            .inner
            .update_runtime_backend(&current, updated.clone())?;
        if current_key != updated_key {
            let post_update_in_flight = self.counters.count(&current);
            if post_update_in_flight > 0 {
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member retargeted after zero-count gate but previous address now has in-flight requests count={}",
                    post_update_in_flight
                );
            }
            self.clear_removed_backend_state(current_key);
        }
        self.prune_stale_backend_state();
        self.save_runtime_state_if_configured_in_background("member_update");
        Ok(LoadBalancerRuntimeBackendSetMutation {
            member: current.addr.to_string(),
            operation: LoadBalancerRuntimeBackendSetOperation::Updated,
            configured_weight: updated.weight,
            backend_count,
            persistent: false,
            #[cfg(not(feature = "privacy-mode"))]
            address: updated.addr.to_string(),
            #[cfg(not(feature = "privacy-mode"))]
            previous_address: Some(current.addr.to_string()),
            alias: current_alias.or_else(|| {
                self.backend_aliases
                    .get(&updated_key)
                    .map(|alias| alias.to_string())
            }),
        })
    }

    pub fn clear_persistence(&self) -> usize {
        let cleared = self
            .persistence
            .as_ref()
            .map_or(0, |persistence| persistence.clear());
        if cleared > 0 {
            self.save_runtime_state_if_configured("persistence_clear");
        }
        cleared
    }

    fn clear_removed_backend_state(&self, key: u64) {
        self.backend_policy.clear_runtime_key(key);
        if let Some(passive_health) = &self.passive_health {
            passive_health.clear_key(key);
        }
    }

    pub fn runtime_state_snapshot(&self) -> LoadBalancerRuntimeStateSnapshot {
        let live_keys = self.live_backend_keys();
        LoadBalancerRuntimeStateSnapshot {
            version: LOAD_BALANCER_RUNTIME_STATE_VERSION,
            runtime_overrides: self.backend_policy.runtime_snapshot(),
            persistence: self
                .persistence
                .as_ref()
                .map(|persistence| persistence.snapshot(&live_keys)),
        }
    }

    pub fn restore_runtime_state_snapshot(
        &self,
        snapshot: &LoadBalancerRuntimeStateSnapshot,
    ) -> io::Result<LoadBalancerRuntimeStateRestore> {
        if snapshot.version != LOAD_BALANCER_RUNTIME_STATE_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported load balancer runtime state version",
            ));
        }
        let prepared_policy = self
            .backend_policy
            .prepare_runtime_snapshot(&snapshot.runtime_overrides)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let live_keys = self.live_backend_keys();
        let prepared_persistence = if let (Some(persistence), Some(snapshot)) =
            (&self.persistence, &snapshot.persistence)
        {
            Some(
                persistence
                    .prepare_snapshot(snapshot, &live_keys)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            )
        } else {
            None
        };
        let persistence_entries = prepared_persistence
            .as_ref()
            .map_or(0, |snapshot| snapshot.restored_entries());
        self.backend_policy.commit_runtime_snapshot(prepared_policy);
        if let (Some(persistence), Some(snapshot)) = (&self.persistence, prepared_persistence) {
            persistence.commit_snapshot(snapshot);
        }
        Ok(LoadBalancerRuntimeStateRestore {
            persistence_entries,
        })
    }

    fn validate_runtime_backend_set_mutation(&self) -> io::Result<()> {
        if !self.inner.supports_runtime_backend_set_mutation() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime backend-set mutation is not available for static-ring selections in this release",
            ));
        }
        if !self.inner.runtime_backend_set_mutable() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime backend-set mutation is available only for static upstream pools",
            ));
        }
        Ok(())
    }

    fn load_runtime_state_if_configured(&self) {
        let Some(path) = &self.runtime_state_file else {
            return;
        };
        match load_runtime_state_file(path) {
            Ok(Some(snapshot)) => match self.restore_runtime_state_snapshot(&snapshot) {
                Ok(restored) => log::info!(
                    target: "fluxheim::load_balancer",
                    "load balancer runtime state restored path={} persistence_entries={}",
                    path.display(),
                    restored.persistence_entries
                ),
                Err(error) => log::warn!(
                    target: "fluxheim::security",
                    "load balancer runtime state ignored path={} error={}",
                    path.display(),
                    error
                ),
            },
            Ok(None) => {}
            Err(error) => log::warn!(
                target: "fluxheim::security",
                "load balancer runtime state could not be read path={} error={}",
                path.display(),
                error
            ),
        }
    }

    fn save_runtime_state_if_configured(&self, reason: &str) {
        let Some(path) = &self.runtime_state_file else {
            return;
        };
        let _guard = self
            .runtime_state_save_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let snapshot = self.runtime_state_snapshot();
        write_runtime_state_snapshot(path, &snapshot, reason);
    }

    fn save_runtime_state_if_configured_in_background(&self, reason: &'static str) {
        if self.runtime_state_file.is_none() {
            return;
        }
        let balancer = self.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn_blocking(move || {
                balancer.save_runtime_state_if_configured(reason);
            });
        } else {
            self.save_runtime_state_if_configured(reason);
        }
    }
}

fn write_runtime_state_snapshot(
    path: &Path,
    snapshot: &LoadBalancerRuntimeStateSnapshot,
    reason: &str,
) {
    match write_runtime_state_file(path, snapshot) {
        Ok(()) => log::debug!(
            target: "fluxheim::load_balancer",
            "load balancer runtime state saved path={} reason={}",
            path.display(),
            reason
        ),
        Err(error) => log::warn!(
            target: "fluxheim::security",
            "load balancer runtime state save failed path={} reason={} error={}",
            path.display(),
            reason,
            error
        ),
    }
}

fn backend_runtime_status_eligible(backend: &LoadBalancerBackendRuntimeStats) -> bool {
    backend.ready
        && !backend.disabled
        && !backend.drained
        && !backend.passive_ejected
        && backend.slow_start_permitting
        && backend
            .max_in_flight
            .is_none_or(|limit| backend.in_flight < limit)
}

#[derive(Clone)]
enum UpstreamLoadBalancerInner {
    RoundRobin(Arc<FluxLoadBalancerRuntime>),
    LeastConnections(Arc<FluxLoadBalancerRuntime>),
    LeastSessions(Arc<FluxLoadBalancerRuntime>),
    LeastTime {
        inner: Arc<FluxLoadBalancerRuntime>,
        latency: Arc<BackendLatencyState>,
    },
    PowerOfTwo(Arc<FluxLoadBalancerRuntime>),
    FnvHash(Arc<FluxLoadBalancerRuntime>),
    ConsistentHash(Arc<FluxLoadBalancerRuntime>),
    NginxConsistentHash {
        inner: Arc<FluxLoadBalancerRuntime>,
        table: Arc<NginxKetamaTable>,
    },
    BoundedLoadConsistentHash {
        inner: Arc<FluxLoadBalancerRuntime>,
        factor_per_mille: u16,
    },
    MaglevHash {
        inner: Arc<FluxLoadBalancerRuntime>,
        table: Arc<MaglevTable>,
    },
}

impl UpstreamLoadBalancerInner {
    fn container(&self) -> &Arc<FluxLoadBalancerRuntime> {
        match self {
            Self::RoundRobin(inner)
            | Self::LeastConnections(inner)
            | Self::LeastSessions(inner)
            | Self::PowerOfTwo(inner)
            | Self::FnvHash(inner)
            | Self::ConsistentHash(inner) => inner,
            Self::LeastTime { inner, .. }
            | Self::NginxConsistentHash { inner, .. }
            | Self::BoundedLoadConsistentHash { inner, .. }
            | Self::MaglevHash { inner, .. } => inner,
        }
    }

    fn select(&self, inputs: LoadBalancerSelectInputs<'_>) -> Option<SelectedUpstream> {
        match self {
            Self::RoundRobin(inner) => select_weighted_round_robin(inner, inputs),
            Self::LeastConnections(inner) => select_least_connections(
                inner,
                inputs.counters,
                inputs.passive_health,
                inputs.slow_start,
                inputs.backend_policy,
            ),
            Self::LeastSessions(inner) => select_least_sessions(
                inner,
                inputs.counters,
                inputs.passive_health,
                inputs.slow_start,
                inputs.backend_policy,
                inputs.persistence_entry_counts,
            ),
            Self::LeastTime { inner, latency } => select_least_time(
                inner,
                inputs.counters,
                latency,
                inputs.passive_health,
                inputs.slow_start,
                inputs.backend_policy,
            ),
            Self::PowerOfTwo(inner) => select_power_of_two(
                inner,
                inputs.counters,
                inputs.max_iterations,
                inputs.passive_health,
                inputs.slow_start,
                inputs.backend_policy,
            ),
            Self::FnvHash(inner) => select_fnv_hash(inner, inputs),
            Self::ConsistentHash(inner) => select_consistent_hash(inner, inputs),
            Self::NginxConsistentHash { inner, table } => {
                select_nginx_consistent_hash(inner, table, inputs)
            }
            Self::BoundedLoadConsistentHash {
                inner,
                factor_per_mille,
            } => select_bounded_load_consistent(inner, *factor_per_mille, inputs),
            Self::MaglevHash { inner, table } => select_maglev(inner, table, inputs),
        }
    }

    fn backend_count(&self) -> usize {
        backend_container_snapshot(self.container())
            .backends()
            .len()
    }

    fn backend_stats(
        &self,
        aliases: &std::collections::HashMap<u64, Arc<str>>,
        passive_health: Option<&PassiveHealthState>,
        slow_start: Option<&SlowStartState>,
        counters: &BackendConnectionCounters,
        backend_policy: &BackendSelectionPolicy,
        persistence_entry_counts: &std::collections::HashMap<u64, usize>,
    ) -> Vec<LoadBalancerBackendRuntimeStats> {
        let inputs = BackendStatsInputs {
            aliases,
            passive_health,
            slow_start,
            counters,
            backend_policy,
            persistence_entry_counts,
            latency: None,
        };
        let snapshot = backend_container_snapshot(self.container());
        if let Self::LeastTime { latency, .. } = self {
            load_balancer_backend_stats(&snapshot, inputs.with_latency(latency))
        } else {
            load_balancer_backend_stats(&snapshot, inputs)
        }
    }

    #[cfg(test)]
    fn backend_weights(&self) -> Vec<usize> {
        backend_weights(self.container())
    }

    fn health_check_frequency(&self) -> Option<Duration> {
        self.container().health_check_frequency()
    }

    fn discovery_runtime_status(&self) -> FluxBackendDiscoveryRuntimeStatus {
        self.container().discovery_runtime_status()
    }

    fn runtime_backend_set_mutable(&self) -> bool {
        self.container().runtime_backend_set_mutable()
    }

    fn supports_runtime_backend_set_mutation(&self) -> bool {
        !matches!(
            self,
            Self::NginxConsistentHash { .. } | Self::MaglevHash { .. }
        )
    }

    fn add_runtime_backend(&self, backend: Backend) -> io::Result<usize> {
        self.container().add_runtime_backend(backend)
    }

    fn remove_runtime_backend(&self, backend: &Backend) -> io::Result<usize> {
        self.container().remove_runtime_backend(backend)
    }

    fn update_runtime_backend(&self, current: &Backend, updated: Backend) -> io::Result<usize> {
        self.container().update_runtime_backend(current, updated)
    }

    fn parallel_health_check(&self) -> bool {
        self.container().parallel_health_check()
    }

    fn latency_state(&self) -> Option<Arc<BackendLatencyState>> {
        match self {
            Self::LeastTime { latency, .. } => Some(latency.clone()),
            Self::RoundRobin(_)
            | Self::LeastConnections(_)
            | Self::LeastSessions(_)
            | Self::PowerOfTwo(_)
            | Self::FnvHash(_)
            | Self::ConsistentHash(_)
            | Self::NginxConsistentHash { .. }
            | Self::BoundedLoadConsistentHash { .. }
            | Self::MaglevHash { .. } => None,
        }
    }

    #[cfg(test)]
    async fn run_health_check(&self, parallel: bool) {
        self.container().run_health_check(parallel).await;
    }

    fn backend_by_member(
        &self,
        member: &str,
        aliases: &std::collections::HashMap<u64, Arc<str>>,
    ) -> io::Result<Backend> {
        let member = member.trim();
        if member.is_empty() || member.len() > 256 || member.chars().any(char::is_whitespace) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "load balancer member must be a configured address or alias",
            ));
        }
        let mut matched = None;
        for backend in self.backends() {
            let policy_key = backend_key(&backend);
            let alias_matches = aliases
                .get(&policy_key)
                .is_some_and(|alias| alias.eq_ignore_ascii_case(member));
            if backend.addr.to_string() == member || alias_matches {
                if matched.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "load balancer member reference is ambiguous",
                    ));
                }
                matched = Some(backend);
            }
        }
        matched.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "load balancer member is not configured in this pool",
            )
        })
    }

    fn backend_by_policy_key(&self, key: u64) -> Option<Backend> {
        self.backends()
            .into_iter()
            .find(|backend| backend_key(backend) == key)
    }

    fn backend_ready(&self, backend: &Backend) -> bool {
        backend_container_snapshot(self.container()).ready(backend)
    }

    fn backends(&self) -> Vec<Backend> {
        backend_container_snapshot(self.container())
            .backends()
            .iter()
            .cloned()
            .collect()
    }
}

#[cfg(test)]
fn backend_weights(inner: &FluxLoadBalancerRuntime) -> Vec<usize> {
    backend_container_snapshot(inner)
        .backends()
        .iter()
        .map(|backend| backend.weight())
        .collect()
}

fn runtime_backend_from_member(member: &str, weight: usize) -> io::Result<Backend> {
    let member = member.trim();
    if member.is_empty() || member.len() > 256 || member.chars().any(char::is_whitespace) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "load balancer member must be a socket address without whitespace",
        ));
    }
    if weight == 0 || weight > MAX_RUNTIME_BACKEND_WEIGHT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "load balancer member weight must be between 1 and 1000",
        ));
    }
    FluxBackend::new_with_weight(member, weight).map_err(FluxError::into_io)
}

#[cfg(test)]
mod tests {
    use std::io::{self, ErrorKind};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    use fluxheim_config::{
        LoadBalanceConfig, LoadBalanceHealthCheckConfig, LoadBalanceHealthCheckExpectedStatusRange,
        LoadBalanceHealthCheckProtocol, LoadBalanceManagedCookieSameSite,
        LoadBalancePassiveHealthConfig, LoadBalancePersistenceConfig, LoadBalancePersistenceMode,
        LoadBalanceQueueConfig, LoadBalanceSelection, LoadBalanceSlowStartConfig, ProxyConfig,
    };
    use tokio::sync::watch;

    #[cfg(not(feature = "privacy-mode"))]
    use super::LoadBalancerCircuitState;
    use super::backend::{BackendIdentity, FluxBackend};
    use super::persistence::{MAX_PERSISTENCE_KEY_BYTES, cookie_key, request_header_key};
    use super::selection::least_connections_score_is_lower;
    use super::selection_hash::fnv1a64_with_seed;
    use super::state::PassiveBackendHealth;
    use super::{
        LoadBalancedUpstreamReporter, LoadBalancerDiscoveryMode, LoadBalancerPersistenceOutcome,
        LoadBalancerQueueOutcome, LoadBalancerRequestView, LoadBalancerRuntimeBackendSetOperation,
        LoadBalancerRuntimeBackendState, PassiveHealthState, SlowStartState, UpstreamLoadBalancer,
        backend_key,
    };
    use fluxheim_common::test_support::{safe_child_path, unique_temp_path};

    fn install_test_crypto_provider() {
        #[cfg(feature = "tls-rustls-backend")]
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn runtime_weight_parser_documents_reset_keywords_and_bounds() {
        assert_eq!(
            super::parse_load_balancer_runtime_weight("configured"),
            Ok(None)
        );
        assert_eq!(
            super::parse_load_balancer_runtime_weight("default"),
            Ok(None)
        );
        assert_eq!(super::parse_load_balancer_runtime_weight("reset"), Ok(None));
        assert_eq!(super::parse_load_balancer_runtime_weight("clear"), Ok(None));
        assert_eq!(
            super::parse_load_balancer_runtime_weight(" 7 "),
            Ok(Some(7))
        );
        assert_eq!(
            super::parse_load_balancer_runtime_weight("bogus"),
            Err("load balancer weight must be a number or one of default/reset/clear/configured")
        );
        assert_eq!(
            super::parse_load_balancer_runtime_weight("0"),
            Err("load balancer weight must be between 1 and 1000")
        );
        assert_eq!(
            super::parse_load_balancer_runtime_weight("1001"),
            Err("load balancer weight must be between 1 and 1000")
        );
    }

    #[test]
    fn member_weight_parser_accepts_only_numeric_configured_weight() {
        assert_eq!(super::parse_load_balancer_member_weight(" 5 "), Ok(5));
        assert_eq!(
            super::parse_load_balancer_member_weight("reset"),
            Err("load balancer member weight must be a number")
        );
        assert_eq!(
            super::parse_load_balancer_member_weight("0"),
            Err("load balancer member weight must be between 1 and 1000")
        );
        assert_eq!(
            super::parse_load_balancer_member_weight("1001"),
            Err("load balancer member weight must be between 1 and 1000")
        );
    }

    #[derive(Clone, Debug)]
    struct TestRequest {
        uri: String,
        headers: Vec<(String, String)>,
    }

    impl TestRequest {
        fn insert_header(
            &mut self,
            name: impl Into<String>,
            value: impl ToString,
        ) -> Result<(), &'static str> {
            self.headers.push((name.into(), value.to_string()));
            Ok(())
        }
    }

    impl LoadBalancerRequestView for TestRequest {
        fn uri_key(&self) -> Vec<u8> {
            self.uri.as_bytes().to_vec()
        }

        fn header_values<'a>(&'a self, name: &str) -> Box<dyn Iterator<Item = &'a [u8]> + 'a> {
            let name = name.to_owned();
            Box::new(
                self.headers
                    .iter()
                    .filter(move |(candidate, _)| candidate.eq_ignore_ascii_case(&name))
                    .map(|(_, value)| value.as_bytes()),
            )
        }

        fn cookie_headers<'a>(&'a self) -> Box<dyn Iterator<Item = &'a str> + 'a> {
            Box::new(
                self.headers
                    .iter()
                    .filter(|(candidate, _)| candidate.eq_ignore_ascii_case("cookie"))
                    .map(|(_, value)| value.as_str()),
            )
        }
    }

    fn request() -> TestRequest {
        TestRequest {
            uri: "/app?id=42".to_owned(),
            headers: Vec::new(),
        }
    }

    fn slow_start_blocking_sample(backend: &impl BackendIdentity) -> u64 {
        let key = backend_key(backend);
        (0u64..10_000)
            .find(|sample| fnv1a64_with_seed(&sample.to_le_bytes(), key) % 1000 >= 1)
            .expect("blocking slow-start sample")
    }

    #[test]
    fn persistence_keys_reject_oversized_header_and_cookie_values() {
        let max_single_header_value = MAX_PERSISTENCE_KEY_BYTES - std::mem::size_of::<usize>();
        let mut header_request = request();
        header_request
            .insert_header("x-session", "a".repeat(max_single_header_value))
            .unwrap();
        assert_eq!(
            request_header_key(&header_request, "x-session")
                .unwrap()
                .len(),
            MAX_PERSISTENCE_KEY_BYTES
        );

        let mut oversized_header_request = request();
        oversized_header_request
            .insert_header("x-session", "a".repeat(max_single_header_value + 1))
            .unwrap();
        assert!(request_header_key(&oversized_header_request, "x-session").is_none());

        let mut cookie_request = request();
        cookie_request
            .insert_header(
                "cookie",
                format!("sid={}", "b".repeat(MAX_PERSISTENCE_KEY_BYTES)),
            )
            .unwrap();
        assert_eq!(
            cookie_key(&cookie_request, "sid").unwrap().len(),
            MAX_PERSISTENCE_KEY_BYTES
        );

        let mut oversized_cookie_request = request();
        oversized_cookie_request
            .insert_header(
                "cookie",
                format!("sid={}", "b".repeat(MAX_PERSISTENCE_KEY_BYTES + 1)),
            )
            .unwrap();
        assert!(cookie_key(&oversized_cookie_request, "sid").is_none());
    }

    #[test]
    fn managed_cookie_persistence_reuses_selected_backend() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                persistence: LoadBalancePersistenceConfig {
                    enabled: true,
                    mode: LoadBalancePersistenceMode::ManagedCookie,
                    cookie: Some("fluxheim_lb".to_owned()),
                    ttl_secs: 60,
                    table_max_entries: 16,
                    managed_cookie_path: Some("/app".to_owned()),
                    managed_cookie_same_site: LoadBalanceManagedCookieSameSite::Strict,
                    ..LoadBalancePersistenceConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let first = balancer.select(&request(), None).unwrap();
        let cookie = first
            .managed_affinity_cookie()
            .expect("fresh selection emits managed cookie")
            .header_value
            .as_str();
        assert!(cookie.starts_with("fluxheim_lb="));
        assert!(cookie.contains("; Path=/app"));
        assert!(cookie.contains("; HttpOnly"));
        assert!(cookie.contains("; Secure"));
        assert!(cookie.contains("; SameSite=Strict"));
        let first_backend = backend_key(&first.backend);
        assert_eq!(balancer.runtime_stats().persistence.entry_count, 1);

        let cookie_value = cookie
            .strip_prefix("fluxheim_lb=")
            .and_then(|value| value.split_once(';').map(|(value, _)| value))
            .unwrap();
        let mut persisted_request = request();
        persisted_request
            .insert_header("cookie", format!("fluxheim_lb={cookie_value}"))
            .unwrap();
        let second = balancer.select(&persisted_request, None).unwrap();
        assert_eq!(backend_key(&second.backend), first_backend);
        assert_eq!(
            second.persistence_outcome(),
            Some(LoadBalancerPersistenceOutcome::Hit)
        );
        assert!(second.managed_affinity_cookie().is_none());
        assert_eq!(balancer.runtime_stats().persistence.entry_count, 1);

        let third = balancer.select(&persisted_request, None).unwrap();
        assert_eq!(backend_key(&third.backend), first_backend);
        assert_eq!(
            third.persistence_outcome(),
            Some(LoadBalancerPersistenceOutcome::Hit)
        );
        assert!(third.managed_affinity_cookie().is_none());
    }

    #[test]
    fn managed_cookie_missing_cookie_respects_persistence_table_bound() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                persistence: LoadBalancePersistenceConfig {
                    enabled: true,
                    mode: LoadBalancePersistenceMode::ManagedCookie,
                    cookie: Some("fluxheim_lb".to_owned()),
                    ttl_secs: 60,
                    table_max_entries: 4,
                    ..LoadBalancePersistenceConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        for _ in 0..16 {
            let selected = balancer.select(&request(), None).unwrap();
            assert!(selected.managed_affinity_cookie.is_some());
        }

        let stats = balancer.runtime_stats();
        assert_eq!(stats.persistence.entry_count, 4);
        assert!(
            stats
                .backends
                .iter()
                .map(|backend| backend.persistence_entry_count)
                .sum::<usize>()
                <= 4
        );
    }

    #[test]
    fn builds_round_robin_from_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(balancer.backend_count(), 2);
        assert_eq!(
            balancer.runtime_stats().discovery_mode,
            LoadBalancerDiscoveryMode::Static
        );
        let stats = balancer.runtime_stats();
        assert_eq!(stats.discovery.mode, LoadBalancerDiscoveryMode::Static);
        assert!(!stats.discovery.refresh_enabled);
        assert_eq!(stats.discovery.success_count, 1);
        assert_eq!(stats.discovery.failure_count, 0);
        assert!(balancer.select(&request(), None).is_some());
    }

    #[test]
    fn builds_weighted_round_robin_from_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_weights: vec![1, 4],
            upstream_aliases: vec!["origin-a".to_owned(), "origin-b".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(balancer.backend_count(), 2);
        assert_eq!(balancer.backend_weights(), [1, 4]);
        let selected = balancer.select(&request(), None).unwrap();
        assert!(selected.has_connection_permit());
        assert_eq!(selected.address().to_string(), selected.authority());
        assert!(
            matches!(selected.alias(), Some("origin-a") | Some("origin-b")),
            "selected alias should come from configured upstream_aliases"
        );
    }

    #[test]
    fn runtime_weight_override_changes_round_robin_distribution() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_weights: vec![1, 1],
            upstream_aliases: vec!["origin-a".to_owned(), "origin-b".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let mutation = balancer
            .set_runtime_backend_weight("origin-a", Some(4))
            .unwrap();
        assert_eq!(mutation.configured_weight, 1);
        assert_eq!(mutation.effective_weight, 4);
        assert_eq!(mutation.runtime_weight_override, Some(4));
        balancer
            .set_runtime_backend_weight("origin-b", Some(1))
            .unwrap();

        let selected_aliases = (0..5)
            .map(|_| {
                balancer
                    .select(&request(), None)
                    .unwrap()
                    .alias
                    .unwrap()
                    .to_string()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            selected_aliases,
            ["origin-a", "origin-a", "origin-a", "origin-a", "origin-b"]
        );

        let stats = balancer.runtime_stats();
        let origin_a = stats
            .backends
            .iter()
            .find(|backend| backend.alias.as_deref() == Some("origin-a"))
            .unwrap();
        assert_eq!(origin_a.weight, 1);
        assert_eq!(origin_a.effective_weight, 4);
        assert_eq!(origin_a.runtime_weight_override, Some(4));
        assert!(origin_a.runtime_weight_changed_at_unix_secs.is_some());

        let reset = balancer
            .set_runtime_backend_weight("origin-a", None)
            .unwrap();
        assert_eq!(reset.effective_weight, 1);
        assert_eq!(reset.runtime_weight_override, None);
    }

    #[test]
    fn runtime_weight_override_rejects_hash_selection() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_aliases: vec!["origin-a".to_owned(), "origin-b".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::SourceHash,
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let error = balancer
            .set_runtime_backend_weight("origin-a", Some(4))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn runtime_backend_set_mutations_update_static_pool() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let added = balancer
            .add_runtime_backend_member("127.0.0.1:3002", 3)
            .unwrap();
        assert_eq!(
            added.operation,
            LoadBalancerRuntimeBackendSetOperation::Added
        );
        assert_eq!(added.configured_weight, 3);
        assert_eq!(added.backend_count, 3);
        assert_eq!(balancer.backend_count(), 3);
        assert_eq!(balancer.backend_weights(), [1, 1, 3]);

        let duplicate = balancer
            .add_runtime_backend_member("127.0.0.1:3002", 3)
            .unwrap_err();
        assert_eq!(duplicate.kind(), io::ErrorKind::AlreadyExists);

        let updated = balancer
            .update_runtime_backend_member("127.0.0.1:3002", None, Some(5))
            .unwrap();
        assert_eq!(
            updated.operation,
            LoadBalancerRuntimeBackendSetOperation::Updated
        );
        assert_eq!(updated.configured_weight, 5);
        assert_eq!(updated.backend_count, 3);
        assert_eq!(balancer.backend_weights(), [1, 1, 5]);

        let removed = balancer
            .remove_runtime_backend_member("127.0.0.1:3002")
            .unwrap();
        assert_eq!(
            removed.operation,
            LoadBalancerRuntimeBackendSetOperation::Removed
        );
        assert_eq!(removed.backend_count, 2);
        assert_eq!(balancer.backend_count(), 2);
        assert_eq!(balancer.backend_weights(), [1, 1]);
    }

    #[test]
    fn runtime_backend_set_update_rejects_aliased_address_retarget() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_aliases: vec!["origin-a".to_owned(), "origin-b".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let updated = balancer
            .update_runtime_backend_member("origin-a", None, Some(3))
            .unwrap();
        assert_eq!(updated.member, "127.0.0.1:3000");
        assert_eq!(updated.alias.as_deref(), Some("origin-a"));
        assert_eq!(updated.configured_weight, 3);

        let error = balancer
            .update_runtime_backend_member("origin-a", Some("127.0.0.1:3002"), None)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("aliased"));
    }

    #[test]
    fn runtime_backend_set_remove_reports_resolved_member_address_for_alias() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_aliases: vec!["origin-a".to_owned(), "origin-b".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let removed = balancer.remove_runtime_backend_member("origin-a").unwrap();

        assert_eq!(removed.member, "127.0.0.1:3000");
        assert_eq!(removed.alias.as_deref(), Some("origin-a"));
        assert_eq!(
            removed.operation,
            LoadBalancerRuntimeBackendSetOperation::Removed
        );
    }

    #[test]
    fn runtime_backend_set_remove_rejects_in_flight_member() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();
        let selected = balancer.select(&request(), None).unwrap();
        let member = selected.backend.addr.to_string();

        let error = balancer.remove_runtime_backend_member(&member).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        drop(selected);
        assert!(balancer.remove_runtime_backend_member(&member).is_ok());
    }

    #[test]
    fn runtime_backend_set_remove_prunes_local_persistence() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                persistence: LoadBalancePersistenceConfig {
                    enabled: true,
                    ttl_secs: 60,
                    table_max_entries: 16,
                    ..LoadBalancePersistenceConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();
        let selected = balancer
            .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))))
            .unwrap();
        let member = selected.backend.addr.to_string();
        assert_eq!(balancer.runtime_stats().persistence.entry_count, 1);

        drop(selected);
        let removed = balancer.remove_runtime_backend_member(&member).unwrap();
        assert_eq!(
            removed.operation,
            LoadBalancerRuntimeBackendSetOperation::Removed
        );
        assert_eq!(balancer.runtime_stats().persistence.entry_count, 0);
    }

    #[test]
    fn runtime_backend_set_remove_clears_runtime_override_state() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();
        balancer
            .set_runtime_backend_state(
                "127.0.0.1:3001",
                LoadBalancerRuntimeBackendState::ForcedDown,
            )
            .unwrap();
        assert_eq!(
            balancer.runtime_stats().runtime_forced_down_backend_count,
            1
        );

        balancer
            .remove_runtime_backend_member("127.0.0.1:3001")
            .unwrap();
        balancer
            .add_runtime_backend_member("127.0.0.1:3001", 1)
            .unwrap();

        let stats = balancer.runtime_stats();
        assert_eq!(stats.runtime_overridden_backend_count, 0);
        assert_eq!(stats.runtime_forced_down_backend_count, 0);
        assert_eq!(stats.primary_available_backend_count, 2);
    }

    #[test]
    fn runtime_backend_set_mutation_rejects_maglev_selection() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::MaglevUriHash,
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let error = balancer
            .add_runtime_backend_member("127.0.0.1:3002", 1)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("static-ring"));
    }

    #[test]
    fn runtime_backend_set_mutation_rejects_nginx_consistent_selection() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::NginxConsistentUriHash,
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let error = balancer
            .add_runtime_backend_member("127.0.0.1:3002", 1)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("static-ring"));
    }

    #[test]
    fn runtime_backend_set_mutation_rejects_dynamic_discovery_pools() {
        install_test_crypto_provider();
        let root = unique_temp_path("lb-runtime-mutation-dynamic-file");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("upstreams.txt");
        std::fs::write(&path, "127.0.0.1:3000\n127.0.0.1:3001\n").unwrap();
        let file_balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstream: None,
            upstreams_file: Some(path),
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let error = file_balancer
            .add_runtime_backend_member("127.0.0.1:3002", 1)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("static upstream pools"));

        let dns_balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstream: None,
            upstreams: vec!["localhost:3000".to_owned()],
            upstream_dns_refresh_secs: Some(2),
            upstream_dns_allow_private_backends: true,
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let error = dns_balancer
            .add_runtime_backend_member("127.0.0.1:3002", 1)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("static upstream pools"));
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn source_ip_persistence_reuses_selected_backend() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                persistence: LoadBalancePersistenceConfig {
                    enabled: true,
                    ttl_secs: 60,
                    table_max_entries: 16,
                    ..LoadBalancePersistenceConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let first = balancer
            .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))))
            .unwrap();
        assert_eq!(first.backend.addr.to_string(), "127.0.0.1:3000");
        assert_eq!(
            first.persistence_outcome,
            Some(LoadBalancerPersistenceOutcome::Miss)
        );
        drop(first);

        let second = balancer
            .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))))
            .unwrap();
        assert_eq!(second.backend.addr.to_string(), "127.0.0.1:3000");
        assert_eq!(
            second.persistence_outcome,
            Some(LoadBalancerPersistenceOutcome::Hit)
        );
        drop(second);

        let different_client = balancer
            .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))))
            .unwrap();
        assert_eq!(different_client.backend.addr.to_string(), "127.0.0.1:3001");
        assert_eq!(
            different_client.persistence_outcome,
            Some(LoadBalancerPersistenceOutcome::Miss)
        );

        let stats = balancer.runtime_stats();
        assert!(stats.persistence_enabled);
        assert_eq!(stats.persistence.entry_count, 2);
        assert_eq!(stats.persistence.table_max_entries, 16);
        assert_eq!(stats.persistence.ttl_secs, 60);
        assert_eq!(
            stats
                .backends
                .iter()
                .map(|backend| backend.persistence_entry_count)
                .sum::<usize>(),
            2
        );
        assert_eq!(
            stats
                .backends
                .iter()
                .find(|backend| backend.address.as_deref() == Some("127.0.0.1:3000"))
                .expect("first persisted backend")
                .persistence_entry_count,
            1
        );
        assert_eq!(
            stats
                .backends
                .iter()
                .find(|backend| backend.address.as_deref() == Some("127.0.0.1:3001"))
                .expect("second persisted backend")
                .persistence_entry_count,
            1
        );
    }

    #[test]
    fn least_sessions_uses_persistence_entry_counts() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::LeastSessions,
                max_iterations: 8,
                persistence: LoadBalancePersistenceConfig {
                    enabled: true,
                    ttl_secs: 60,
                    table_max_entries: 16,
                    ..LoadBalancePersistenceConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let first = balancer
            .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))))
            .unwrap();
        assert_eq!(first.backend.addr.to_string(), "127.0.0.1:3000");
        drop(first);

        let second = balancer
            .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))))
            .unwrap();
        assert_eq!(second.backend.addr.to_string(), "127.0.0.1:3001");

        let stats = balancer.runtime_stats();
        assert_eq!(
            stats
                .backends
                .iter()
                .map(|backend| backend.persistence_entry_count)
                .sum::<usize>(),
            2
        );
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn runtime_state_snapshot_restores_overrides_and_persistence() {
        install_test_crypto_provider();
        let config = ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                persistence: LoadBalancePersistenceConfig {
                    enabled: true,
                    ttl_secs: 60,
                    table_max_entries: 16,
                    ..LoadBalancePersistenceConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        };
        let balancer = UpstreamLoadBalancer::from_proxy_config(&config)
            .unwrap()
            .unwrap();

        let first = balancer
            .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))))
            .unwrap();
        assert_eq!(first.backend.addr.to_string(), "127.0.0.1:3000");
        drop(first);
        balancer
            .set_runtime_backend_state(
                "127.0.0.1:3001",
                LoadBalancerRuntimeBackendState::ForcedDown,
            )
            .unwrap();
        balancer
            .set_runtime_backend_weight("127.0.0.1:3000", Some(7))
            .unwrap();

        let snapshot = balancer.runtime_state_snapshot();
        let restored = UpstreamLoadBalancer::from_proxy_config(&config)
            .unwrap()
            .unwrap();
        let restore = restored.restore_runtime_state_snapshot(&snapshot).unwrap();
        assert_eq!(restore.persistence_entries, 1);

        let stats = restored.runtime_stats();
        let backend_a = stats
            .backends
            .iter()
            .find(|backend| backend.address.as_deref() == Some("127.0.0.1:3000"))
            .expect("backend a");
        assert_eq!(backend_a.runtime_weight_override, Some(7));
        assert_eq!(backend_a.persistence_entry_count, 1);
        let backend_b = stats
            .backends
            .iter()
            .find(|backend| backend.address.as_deref() == Some("127.0.0.1:3001"))
            .expect("backend b");
        assert_eq!(
            backend_b.runtime_state_override,
            Some(LoadBalancerRuntimeBackendState::ForcedDown)
        );

        let second = restored
            .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))))
            .unwrap();
        assert_eq!(second.backend.addr.to_string(), "127.0.0.1:3000");
        assert_eq!(
            second.persistence_outcome,
            Some(LoadBalancerPersistenceOutcome::Hit)
        );
    }

    #[test]
    fn runtime_state_file_restores_configured_balancer_state() {
        install_test_crypto_provider();
        let dir = unique_temp_path("lb-runtime-state-configured");
        std::fs::create_dir_all(&dir).unwrap();
        let state_file = safe_child_path(&dir, "lb-state.json");
        let config = ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                runtime_state_file: Some(state_file.clone()),
                persistence: LoadBalancePersistenceConfig {
                    enabled: true,
                    ttl_secs: 60,
                    table_max_entries: 16,
                    ..LoadBalancePersistenceConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        };
        let balancer = UpstreamLoadBalancer::from_proxy_config(&config)
            .unwrap()
            .unwrap();

        let first = balancer
            .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))))
            .unwrap();
        assert_eq!(first.backend.addr.to_string(), "127.0.0.1:3000");
        drop(first);
        balancer
            .set_runtime_backend_state("127.0.0.1:3001", LoadBalancerRuntimeBackendState::Disabled)
            .unwrap();
        assert!(state_file.exists());

        let restored = UpstreamLoadBalancer::from_proxy_config(&config)
            .unwrap()
            .unwrap();
        let stats = restored.runtime_stats();
        assert_eq!(stats.persistence.entry_count, 1);
        assert_eq!(stats.runtime_disabled_backend_count, 1);

        let second = restored
            .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))))
            .unwrap();
        assert_eq!(second.backend.addr.to_string(), "127.0.0.1:3000");
        assert_eq!(
            second.persistence_outcome,
            Some(LoadBalancerPersistenceOutcome::Hit)
        );
    }

    #[test]
    fn runtime_state_file_ignores_invalid_state_without_poisoning_pool() {
        install_test_crypto_provider();
        let dir = unique_temp_path("lb-runtime-state-invalid");
        std::fs::create_dir_all(&dir).unwrap();
        let state_file = safe_child_path(&dir, "lb-state.json");
        std::fs::write(
            &state_file,
            r#"{"version":999,"runtime_overrides":{"states":[],"weights":[]},"persistence":null}"#,
        )
        .unwrap();
        let config = ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                runtime_state_file: Some(state_file),
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        };

        let balancer = UpstreamLoadBalancer::from_proxy_config(&config)
            .unwrap()
            .unwrap();
        let selected = balancer.select(&request(), None).unwrap();
        assert_eq!(selected.backend.addr.to_string(), "127.0.0.1:3000");
    }

    #[test]
    fn runtime_state_file_restore_is_all_or_nothing() {
        install_test_crypto_provider();
        let dir = unique_temp_path("lb-runtime-state-atomic-restore");
        std::fs::create_dir_all(&dir).unwrap();
        let state_file = safe_child_path(&dir, "lb-state.json");
        let disabled_key = backend_key(&FluxBackend::new("127.0.0.1:3001").unwrap());
        std::fs::write(
            &state_file,
            format!(
                r#"{{
  "version": 1,
  "runtime_overrides": {{
    "states": [
      {{
        "key": {disabled_key},
        "state": "disabled",
        "changed_at_unix_secs": 1
      }}
    ],
    "weights": []
  }},
  "persistence": {{
    "entries": [
      {{
        "key": [],
        "backend_key": {disabled_key},
        "ttl_remaining_secs": 60
      }}
    ]
  }}
}}"#
            ),
        )
        .unwrap();
        let config = ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                runtime_state_file: Some(state_file),
                persistence: LoadBalancePersistenceConfig {
                    enabled: true,
                    ttl_secs: 60,
                    table_max_entries: 16,
                    ..LoadBalancePersistenceConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        };

        let balancer = UpstreamLoadBalancer::from_proxy_config(&config)
            .unwrap()
            .unwrap();
        let stats = balancer.runtime_stats();
        assert_eq!(stats.runtime_disabled_backend_count, 0);
        assert_eq!(stats.persistence.entry_count, 0);
    }

    #[test]
    fn header_persistence_reuses_selected_backend() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec![
                "127.0.0.1:3000".to_owned(),
                "127.0.0.1:3001".to_owned(),
                "127.0.0.1:3002".to_owned(),
            ],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                persistence: LoadBalancePersistenceConfig {
                    enabled: true,
                    mode: LoadBalancePersistenceMode::Header,
                    header: Some("x-session".to_owned()),
                    ttl_secs: 60,
                    table_max_entries: 16,
                    ..LoadBalancePersistenceConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let mut first_request = request();
        first_request.insert_header("x-session", "abc").unwrap();
        let first = balancer.select(&first_request, None).unwrap();
        assert_eq!(
            first.persistence_outcome,
            Some(LoadBalancerPersistenceOutcome::Miss)
        );

        let mut second_request = request();
        second_request.insert_header("x-session", "abc").unwrap();
        let second = balancer.select(&second_request, None).unwrap();
        assert_eq!(first.backend.addr, second.backend.addr);
        assert_eq!(
            second.persistence_outcome,
            Some(LoadBalancerPersistenceOutcome::Hit)
        );

        let missing_header = balancer.select(&request(), None).unwrap();
        assert_eq!(missing_header.persistence_outcome, None);

        let stats = balancer.runtime_stats();
        assert!(stats.persistence_enabled);
        assert_eq!(stats.persistence.mode, LoadBalancePersistenceMode::Header);
        assert_eq!(stats.persistence.header.as_deref(), Some("x-session"));
        assert_eq!(stats.persistence.entry_count, 1);
        assert_eq!(
            stats
                .backends
                .iter()
                .map(|backend| backend.persistence_entry_count)
                .sum::<usize>(),
            1
        );

        assert_eq!(balancer.clear_persistence(), 1);
        assert_eq!(balancer.runtime_stats().persistence.entry_count, 0);
    }

    #[test]
    fn cookie_persistence_reuses_selected_backend() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec![
                "127.0.0.1:3000".to_owned(),
                "127.0.0.1:3001".to_owned(),
                "127.0.0.1:3002".to_owned(),
            ],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                persistence: LoadBalancePersistenceConfig {
                    enabled: true,
                    mode: LoadBalancePersistenceMode::Cookie,
                    cookie: Some("sid".to_owned()),
                    ttl_secs: 60,
                    table_max_entries: 16,
                    ..LoadBalancePersistenceConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let mut first_request = request();
        first_request
            .insert_header("cookie", "theme=dark; sid=abc")
            .unwrap();
        let first = balancer.select(&first_request, None).unwrap();
        assert_eq!(
            first.persistence_outcome,
            Some(LoadBalancerPersistenceOutcome::Miss)
        );

        let mut second_request = request();
        second_request.insert_header("cookie", "sid=abc").unwrap();
        let second = balancer.select(&second_request, None).unwrap();
        assert_eq!(first.backend.addr, second.backend.addr);
        assert_eq!(
            second.persistence_outcome,
            Some(LoadBalancerPersistenceOutcome::Hit)
        );

        let missing_cookie = balancer.select(&request(), None).unwrap();
        assert_eq!(missing_cookie.persistence_outcome, None);

        let stats = balancer.runtime_stats();
        assert!(stats.persistence_enabled);
        assert_eq!(stats.persistence.mode, LoadBalancePersistenceMode::Cookie);
        assert_eq!(stats.persistence.cookie.as_deref(), Some("sid"));
        assert_eq!(stats.persistence.entry_count, 1);
        assert_eq!(
            stats
                .backends
                .iter()
                .map(|backend| backend.persistence_entry_count)
                .sum::<usize>(),
            1
        );
    }

    #[test]
    fn source_ip_persistence_falls_back_when_stored_backend_is_unavailable() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                passive_health: LoadBalancePassiveHealthConfig {
                    enabled: true,
                    consecutive_failure: 1,
                    ejection_secs: 60,
                    ..LoadBalancePassiveHealthConfig::default()
                },
                persistence: LoadBalancePersistenceConfig {
                    enabled: true,
                    ttl_secs: 60,
                    table_max_entries: 16,
                    ..LoadBalancePersistenceConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let first = balancer
            .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20))))
            .unwrap();
        assert_eq!(first.backend.addr.to_string(), "127.0.0.1:3000");
        first.reporter().unwrap().record_failure();
        drop(first);

        let fallback = balancer
            .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20))))
            .unwrap();
        assert_eq!(fallback.backend.addr.to_string(), "127.0.0.1:3001");
        assert_eq!(
            fallback.persistence_outcome(),
            Some(LoadBalancerPersistenceOutcome::Fallback)
        );
    }

    #[test]
    fn builds_round_robin_from_proxy_upstreams_file() {
        install_test_crypto_provider();
        let root = unique_temp_path("lb-upstreams-file");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("upstreams.txt");
        std::fs::write(
            &path,
            "# generated service-discovery output\n127.0.0.1:3000\n127.0.0.1:3001\n",
        )
        .unwrap();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstream: None,
            upstreams_file: Some(path),
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(balancer.backend_count(), 2);
        assert_eq!(
            balancer.runtime_stats().discovery_mode,
            LoadBalancerDiscoveryMode::File
        );
        let stats = balancer.runtime_stats();
        assert_eq!(stats.discovery.mode, LoadBalancerDiscoveryMode::File);
        assert!(stats.discovery.refresh_enabled);
        assert_eq!(stats.discovery.update_frequency_secs, Some(5));
        assert_eq!(stats.discovery.success_count, 1);
        assert!(balancer.select(&request(), None).is_some());
    }

    #[test]
    fn builds_round_robin_from_dns_refreshed_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstream: None,
            upstreams: vec!["localhost:3000".to_owned()],
            upstream_dns_refresh_secs: Some(2),
            upstream_dns_allow_private_backends: true,
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        assert!(balancer.backend_count() >= 1);
        assert_eq!(
            balancer.runtime_stats().discovery_mode,
            LoadBalancerDiscoveryMode::Dns
        );
        let stats = balancer.runtime_stats();
        assert_eq!(stats.discovery.mode, LoadBalancerDiscoveryMode::Dns);
        assert!(stats.discovery.refresh_enabled);
        assert_eq!(stats.discovery.update_frequency_secs, Some(2));
        assert_eq!(stats.discovery.success_count, 1);
        assert!(balancer.select(&request(), None).is_some());
    }

    #[test]
    fn builds_hash_selection_from_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::SourceHash,
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let client_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let first = balancer.select(&request(), Some(client_ip)).unwrap();
        let second = balancer.select(&request(), Some(client_ip)).unwrap();
        assert_eq!(first.backend.addr, second.backend.addr);
    }

    #[test]
    fn builds_nginx_consistent_uri_hash_selection_from_static_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_weights: vec![1, 2],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::NginxConsistentUriHash,
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let first = balancer.select(&request(), None).unwrap();
        let second = balancer.select(&request(), None).unwrap();
        assert_eq!(first.backend.addr, second.backend.addr);
        assert_eq!(
            balancer.runtime_stats().selection,
            LoadBalanceSelection::NginxConsistentUriHash
        );
    }

    #[test]
    fn rejects_nginx_consistent_hash_with_dynamic_discovery() {
        install_test_crypto_provider();
        let root = unique_temp_path("lb-nginx-consistent-dynamic-file");
        std::fs::create_dir_all(&root).unwrap();
        let path = safe_child_path(&root, "upstreams.txt");
        std::fs::write(&path, "127.0.0.1:3000\n127.0.0.1:3001\n").unwrap();
        let error = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams_file: Some(path),
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::NginxConsistentUriHash,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("nginx-compatible Ketama selections require static proxy.upstreams"),
            "{error}"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn builds_consistent_header_hash_selection_from_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::ConsistentHeaderHash,
                hash_header: Some("x-session".to_owned()),
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let mut request = request();
        request.insert_header("x-session", "abc").unwrap();
        let first = balancer.select(&request, None).unwrap();
        let second = balancer.select(&request, None).unwrap();
        assert_eq!(first.backend.addr, second.backend.addr);
    }

    #[test]
    fn builds_cookie_hash_selection_from_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::CookieHash,
                hash_cookie: Some("session".to_owned()),
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let mut request = request();
        request
            .insert_header("cookie", "other=1; session=abc; theme=dark")
            .unwrap();
        let first = balancer.select(&request, None).unwrap();
        let second = balancer.select(&request, None).unwrap();
        assert_eq!(first.backend.addr, second.backend.addr);
    }

    #[test]
    fn builds_maglev_uri_hash_selection_from_static_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec![
                "127.0.0.1:3000".to_owned(),
                "127.0.0.1:3001".to_owned(),
                "127.0.0.1:3002".to_owned(),
            ],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::MaglevUriHash,
                max_iterations: 16,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let first = balancer.select(&request(), None).unwrap();
        let second = balancer.select(&request(), None).unwrap();
        assert_eq!(first.backend.addr, second.backend.addr);
        assert_eq!(
            balancer.runtime_stats().selection,
            LoadBalanceSelection::MaglevUriHash
        );
    }

    #[test]
    fn maglev_skips_disabled_table_target() {
        install_test_crypto_provider();
        let disabled = "127.0.0.1:3000".to_owned();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec![
                disabled.clone(),
                "127.0.0.1:3001".to_owned(),
                "127.0.0.1:3002".to_owned(),
            ],
            disabled_upstreams: vec![disabled.clone()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::MaglevSourceHash,
                max_iterations: 32,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        for octet in 1..=32 {
            let selected = balancer
                .select(
                    &request(),
                    Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, octet))),
                )
                .unwrap();
            assert_ne!(selected.backend.addr.to_string(), disabled);
        }
    }

    #[test]
    fn bounded_load_consistent_hash_skips_over_bound_target() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::BoundedLoadConsistentUriHash,
                bounded_load_factor_per_mille: 1000,
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let first = balancer.select(&request(), None).unwrap();
        let second = balancer.select(&request(), None).unwrap();

        assert_ne!(first.backend.addr, second.backend.addr);
    }

    #[test]
    fn least_connections_tracks_held_permits() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::LeastConnections,
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let first = balancer.select(&request(), None).unwrap();
        let first_addr = first.backend.addr;
        let second = balancer.select(&request(), None).unwrap();
        assert_ne!(&first_addr, &second.backend.addr);
        drop(first);
        let third = balancer.select(&request(), None).unwrap();
        assert_eq!(third.backend.addr, first_addr);
    }

    #[test]
    fn least_connections_respects_backend_weights() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_weights: vec![1, 4],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::LeastConnections,
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let first = balancer.select(&request(), None).unwrap();
        assert_eq!(first.backend.addr.to_string(), "127.0.0.1:3000");

        let second = balancer.select(&request(), None).unwrap();
        assert_eq!(second.backend.addr.to_string(), "127.0.0.1:3001");

        let third = balancer.select(&request(), None).unwrap();
        assert_eq!(third.backend.addr.to_string(), "127.0.0.1:3001");
    }

    #[test]
    fn weighted_two_choice_uses_weighted_connection_pressure() {
        assert!(least_connections_score_is_lower(2, 4, 1, 1));
        assert!(!least_connections_score_is_lower(2, 1, 1, 4));
    }

    #[test]
    fn priority_groups_prefer_highest_available_group() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_priority_groups: vec![10, 100],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                passive_health: LoadBalancePassiveHealthConfig {
                    enabled: true,
                    consecutive_failure: 1,
                    ejection_secs: 60,
                    ..LoadBalancePassiveHealthConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let preferred = balancer.select(&request(), None).unwrap();
        assert_eq!(preferred.backend.addr.to_string(), "127.0.0.1:3001");
        preferred.reporter.unwrap().record_failure();

        let fallback = balancer.select(&request(), None).unwrap();
        assert_eq!(fallback.backend.addr.to_string(), "127.0.0.1:3000");
    }

    #[test]
    fn priority_groups_apply_to_least_connections() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_priority_groups: vec![10, 100],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::LeastConnections,
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let selected = balancer.select(&request(), None).unwrap();
        assert_eq!(selected.backend.addr.to_string(), "127.0.0.1:3001");
    }

    #[test]
    fn priority_group_min_active_activates_lower_group() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec![
                "127.0.0.1:3000".to_owned(),
                "127.0.0.1:3001".to_owned(),
                "127.0.0.1:3002".to_owned(),
            ],
            upstream_priority_groups: vec![100, 100, 50],
            upstream_priority_group_min_active: 2,
            upstream_max_in_flight: vec![1, 1, 1],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                passive_health: LoadBalancePassiveHealthConfig {
                    enabled: true,
                    consecutive_failure: 1,
                    ejection_secs: 60,
                    ..LoadBalancePassiveHealthConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let failed = balancer.select(&request(), None).unwrap();
        assert_eq!(failed.backend.addr.to_string(), "127.0.0.1:3000");
        failed.reporter.unwrap().record_failure();

        let activated = balancer.select(&request(), None).unwrap();
        assert_eq!(activated.backend.addr.to_string(), "127.0.0.1:3002");

        let remaining_preferred = balancer.select(&request(), None).unwrap();
        assert_eq!(
            remaining_preferred.backend.addr.to_string(),
            "127.0.0.1:3001"
        );
    }

    #[test]
    fn preferred_locality_selects_local_backend_with_fallback() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_localities: vec!["remote".to_owned(), "local".to_owned()],
            preferred_upstream_localities: vec!["local".to_owned()],
            upstream_tags: vec![
                vec!["remote".to_owned()],
                vec!["local".to_owned(), "blue".to_owned()],
            ],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let selected = balancer.select(&request(), None).unwrap();
        assert_eq!(selected.backend.addr.to_string(), "127.0.0.1:3001");

        balancer
            .set_runtime_backend_state(
                "127.0.0.1:3001",
                LoadBalancerRuntimeBackendState::ForcedDown,
            )
            .unwrap();
        let fallback = balancer.select(&request(), None).unwrap();
        assert_eq!(fallback.backend.addr.to_string(), "127.0.0.1:3000");

        let stats = balancer.runtime_stats();
        let local = stats
            .backends
            .iter()
            .find(|backend| backend.locality.as_deref() == Some("local"))
            .expect("local backend status");
        assert!(local.locality_preferred);
        assert_eq!(local.tags, ["local".to_owned(), "blue".to_owned()]);
    }

    #[test]
    fn upstream_max_in_flight_skips_capped_backend() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_max_in_flight: vec![1, 2],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let first = balancer.select(&request(), None).unwrap();
        assert_eq!(first.backend.addr.to_string(), "127.0.0.1:3000");

        let second = balancer.select(&request(), None).unwrap();
        assert_eq!(second.backend.addr.to_string(), "127.0.0.1:3001");

        let third = balancer.select(&request(), None).unwrap();
        assert_eq!(third.backend.addr.to_string(), "127.0.0.1:3001");

        assert!(balancer.select(&request(), None).is_none());
        drop(first);

        let fourth = balancer.select(&request(), None).unwrap();
        assert_eq!(fourth.backend.addr.to_string(), "127.0.0.1:3000");
    }

    #[tokio::test]
    async fn load_balancer_queue_waits_for_saturated_pool_capacity() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_max_in_flight: vec![1, 1],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                queue: LoadBalanceQueueConfig {
                    max_waiting: 1,
                    timeout_ms: 250,
                    retry_interval_ms: 5,
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let held_a = balancer.select(&request(), None).unwrap();
        let held_b = balancer.select(&request(), None).unwrap();
        assert!(balancer.select(&request(), None).is_none());
        assert!(balancer.runtime_stats().queue.enabled);

        let request = request();
        let (selected, _) = tokio::join!(
            async { balancer.select_or_wait_result(&request, None).await },
            async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                drop(held_a);
                drop(held_b);
            }
        );

        assert_eq!(
            selected.queue_outcome,
            Some(LoadBalancerQueueOutcome::Waited)
        );
        let selected = selected.selected.expect("queued selection should complete");
        assert!(
            selected.backend.addr.to_string() == "127.0.0.1:3000"
                || selected.backend.addr.to_string() == "127.0.0.1:3001"
        );
        assert_eq!(balancer.runtime_stats().queue.waiting, 0);
    }

    #[tokio::test]
    async fn load_balancer_queue_reports_full_and_timeout() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_max_in_flight: vec![1, 1],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                queue: LoadBalanceQueueConfig {
                    max_waiting: 1,
                    timeout_ms: 25,
                    retry_interval_ms: 5,
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let _held_a = balancer.select(&request(), None).unwrap();
        let _held_b = balancer.select(&request(), None).unwrap();

        let request = request();
        let (timed_out, full) = tokio::join!(
            async { balancer.select_or_wait_result(&request, None).await },
            async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                balancer.select_or_wait_result(&request, None).await
            }
        );

        assert_eq!(full.queue_outcome, Some(LoadBalancerQueueOutcome::Full));
        assert!(full.selected.is_none());
        assert_eq!(
            timed_out.queue_outcome,
            Some(LoadBalancerQueueOutcome::Timeout)
        );
        assert!(timed_out.selected.is_none());
        assert_eq!(balancer.runtime_stats().queue.waiting, 0);
    }

    #[test]
    fn least_time_learns_from_recorded_latency() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::LeastTime,
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let first = balancer.select(&request(), None).unwrap();
        let first_addr = first.backend.addr.to_string();
        first
            .reporter
            .unwrap()
            .record_status(200, Some(Duration::from_millis(200)));

        let second = balancer.select(&request(), None).unwrap();
        let second_addr = second.backend.addr.to_string();
        assert_ne!(first_addr, second_addr);
        second
            .reporter
            .unwrap()
            .record_status(200, Some(Duration::from_millis(50)));

        let selected = balancer.select(&request(), None).unwrap();
        assert_eq!(selected.backend.addr.to_string(), second_addr);
    }

    #[test]
    fn builds_power_of_two_selection_from_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::PowerOfTwo,
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let selected = balancer.select(&request(), None).unwrap();
        assert!(selected.permit.is_some());
    }

    #[test]
    fn slow_start_gates_new_backends_until_warmed() {
        let state = SlowStartState::from_config(&LoadBalanceSlowStartConfig {
            enabled: true,
            duration_secs: 60,
        });
        let backend = FluxBackend::new("127.0.0.1:3000").unwrap();
        state
            .sample_counter
            .store(slow_start_blocking_sample(&backend), Ordering::Relaxed);

        assert!(!state.permits(&backend));
        state.backends.lock().unwrap().insert(
            backend_key(&backend),
            Instant::now() - Duration::from_secs(61),
        );
        assert!(state.permits(&backend));
    }

    #[test]
    fn slow_start_read_only_reports_majority_warm() {
        let state = SlowStartState::from_config(&LoadBalanceSlowStartConfig {
            enabled: true,
            duration_secs: 60,
        });
        let backend = FluxBackend::new("127.0.0.1:3000").unwrap();
        state
            .backends
            .lock()
            .unwrap()
            .insert(backend_key(&backend), Instant::now());
        assert!(!state.permits_read_only(&backend));

        state.backends.lock().unwrap().insert(
            backend_key(&backend),
            Instant::now() - Duration::from_secs(31),
        );
        assert!(state.permits_read_only(&backend));
    }

    #[test]
    fn slow_start_does_not_outage_all_warming_backends() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                slow_start: LoadBalanceSlowStartConfig {
                    enabled: true,
                    duration_secs: 60,
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        assert!(balancer.select(&request(), None).is_some());
    }

    #[test]
    fn passive_recovery_restarts_slow_start_window() {
        let slow_start = Arc::new(SlowStartState::from_config(&LoadBalanceSlowStartConfig {
            enabled: true,
            duration_secs: 60,
        }));
        let backend = FluxBackend::new("127.0.0.1:3000").unwrap();
        let key = backend_key(&backend);
        slow_start
            .backends
            .lock()
            .unwrap()
            .insert(key, Instant::now() - Duration::from_secs(61));
        assert!(slow_start.permits(&backend));

        let reporter = LoadBalancedUpstreamReporter::new(
            key,
            Some(Arc::new(PassiveHealthState::from_config(
                &LoadBalancePassiveHealthConfig {
                    enabled: true,
                    consecutive_failure: 1,
                    ejection_secs: 1,
                    ..LoadBalancePassiveHealthConfig::default()
                },
            ))),
            Some(slow_start.clone()),
            None,
        );
        let outcome = reporter.record_failure();
        assert!(outcome.failed);
        assert!(outcome.ejected);

        slow_start
            .sample_counter
            .store(slow_start_blocking_sample(&backend), Ordering::Relaxed);
        assert!(!slow_start.permits(&backend));
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn passive_health_ejects_failed_backend() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                passive_health: LoadBalancePassiveHealthConfig {
                    enabled: true,
                    consecutive_failure: 1,
                    ejection_secs: 60,
                    ..LoadBalancePassiveHealthConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let failed = balancer.select(&request(), None).unwrap();
        let failed_addr = failed.backend.addr;
        let outcome = failed.reporter.unwrap().record_status(503, None);
        assert!(outcome.failed);
        assert!(outcome.ejected);
        let stats = balancer.runtime_stats();
        let failed_addr_text = failed_addr.to_string();
        let failed_stats = stats
            .backends
            .iter()
            .find(|backend| backend.address.as_deref() == Some(failed_addr_text.as_str()))
            .expect("failed backend stats");
        assert!(failed_stats.passive_ejected);
        assert_eq!(failed_stats.circuit_state, LoadBalancerCircuitState::Open);
        assert!(failed_stats.passive_ejection_remaining_secs.is_some());
        assert_eq!(stats.circuit_open_backend_count, 1);
        let next = balancer.select(&request(), None).unwrap();
        assert_ne!(failed_addr, next.backend.addr);
    }

    #[test]
    fn passive_health_floor_prevents_full_pool_outage() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                passive_health: LoadBalancePassiveHealthConfig {
                    enabled: true,
                    consecutive_failure: 1,
                    ejection_secs: 60,
                    ..LoadBalancePassiveHealthConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let first = balancer.select(&request(), None).unwrap();
        let first_addr = first.backend.addr;
        assert!(first.reporter.unwrap().record_failure().ejected);
        let second = balancer.select(&request(), None).unwrap();
        let second_addr = second.backend.addr;
        assert_ne!(first_addr, second_addr);
        assert!(second.reporter.unwrap().record_failure().ejected);

        let stats = balancer.runtime_stats();
        assert_eq!(stats.passive_ejected_backend_count, 2);
        assert_eq!(stats.available_backend_count, 0);
        let selected = balancer
            .select(&request(), None)
            .expect("passive health floor keeps a backend selectable");
        assert!(selected.backend.addr == first_addr || selected.backend.addr == second_addr);
    }

    #[test]
    fn passive_health_floor_can_be_disabled_for_strict_fail_closed() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                passive_health: LoadBalancePassiveHealthConfig {
                    enabled: true,
                    consecutive_failure: 1,
                    ejection_secs: 60,
                    min_healthy_backends: 0,
                    ..LoadBalancePassiveHealthConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let first = balancer.select(&request(), None).unwrap();
        first.reporter.unwrap().record_failure();
        let second = balancer.select(&request(), None).unwrap();
        second.reporter.unwrap().record_failure();

        assert!(balancer.select(&request(), None).is_none());
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn runtime_status_reports_passive_failure_count_before_ejection() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                passive_health: LoadBalancePassiveHealthConfig {
                    enabled: true,
                    consecutive_failure: 2,
                    ejection_secs: 60,
                    ..LoadBalancePassiveHealthConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let failed = balancer.select(&request(), None).unwrap();
        let failed_addr_text = failed.backend.addr.to_string();
        let outcome = failed.reporter.unwrap().record_status(503, None);
        assert!(outcome.failed);
        assert!(!outcome.ejected);
        let stats = balancer.runtime_stats();
        let failed_stats = stats
            .backends
            .iter()
            .find(|backend| backend.address.as_deref() == Some(failed_addr_text.as_str()))
            .expect("failed backend stats");
        assert_eq!(failed_stats.passive_consecutive_failures, Some(1));
        assert!(!failed_stats.passive_ejected);
        assert_eq!(failed_stats.circuit_state, LoadBalancerCircuitState::Closed);
        assert_eq!(stats.circuit_open_backend_count, 0);
    }

    #[test]
    fn passive_health_accepts_failure_status_ranges() {
        let health = PassiveHealthState::from_config(&LoadBalancePassiveHealthConfig {
            enabled: true,
            failure_status_ranges: vec![LoadBalanceHealthCheckExpectedStatusRange {
                start: 520,
                end: 529,
            }],
            ..LoadBalancePassiveHealthConfig::default()
        });

        assert!(health.failure_status(520));
        assert!(health.failure_status(529));
        assert!(!health.failure_status(503));
    }

    #[test]
    fn passive_health_prune_keeps_live_and_active_ejections() {
        let health = PassiveHealthState::from_config(&LoadBalancePassiveHealthConfig {
            enabled: true,
            ..LoadBalancePassiveHealthConfig::default()
        });
        let now = Instant::now();
        health.backends.lock().unwrap().extend([
            (
                1,
                PassiveBackendHealth {
                    consecutive_failures: 1,
                    ejected_until: None,
                },
            ),
            (
                2,
                PassiveBackendHealth {
                    consecutive_failures: 1,
                    ejected_until: None,
                },
            ),
            (
                3,
                PassiveBackendHealth {
                    consecutive_failures: 0,
                    ejected_until: Some(now + Duration::from_secs(60)),
                },
            ),
            (
                4,
                PassiveBackendHealth {
                    consecutive_failures: 0,
                    ejected_until: Some(now - Duration::from_secs(1)),
                },
            ),
        ]);
        health.prune_stale(&[1].into_iter().collect());
        let backends = health.backends.lock().unwrap();

        assert!(backends.contains_key(&1));
        assert!(!backends.contains_key(&2));
        assert!(backends.contains_key(&3));
        assert!(!backends.contains_key(&4));
    }

    #[test]
    fn passive_health_ejects_slow_backend() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                passive_health: LoadBalancePassiveHealthConfig {
                    enabled: true,
                    consecutive_failure: 1,
                    ejection_secs: 60,
                    max_latency_ms: 100,
                    ..LoadBalancePassiveHealthConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let failed = balancer.select(&request(), None).unwrap();
        let failed_addr = failed.backend.addr;
        let outcome = failed
            .reporter
            .unwrap()
            .record_status(200, Some(Duration::from_millis(150)));
        assert!(outcome.failed);
        assert!(outcome.ejected);
        let next = balancer.select(&request(), None).unwrap();
        assert_ne!(failed_addr, next.backend.addr);
    }

    #[test]
    fn backup_upstreams_are_used_after_primary_ejection() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            backup_upstreams: vec!["127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                passive_health: LoadBalancePassiveHealthConfig {
                    enabled: true,
                    consecutive_failure: 1,
                    ejection_secs: 60,
                    ..LoadBalancePassiveHealthConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let primary = balancer.select(&request(), None).unwrap();
        assert_eq!(primary.backend.addr.to_string(), "127.0.0.1:3000");
        primary.reporter.unwrap().record_failure();
        let stats = balancer.runtime_stats();
        assert_eq!(stats.primary_available_backend_count, 0);
        assert_eq!(stats.backup_available_backend_count, 1);
        assert_eq!(stats.passive_ejected_backend_count, 1);
        let backup = balancer.select(&request(), None).unwrap();
        assert_eq!(backup.backend.addr.to_string(), "127.0.0.1:3001");
    }

    #[test]
    fn drained_upstreams_do_not_receive_new_selections() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            drain_upstreams: vec!["127.0.0.1:3000".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        for _ in 0..4 {
            let selected = balancer.select(&request(), None).unwrap();
            assert_eq!(selected.backend.addr.to_string(), "127.0.0.1:3001");
        }
        let stats = balancer.runtime_stats();
        assert_eq!(stats.drained_backend_count, 1);
        assert_eq!(stats.primary_available_backend_count, 1);
    }

    #[test]
    fn disabled_upstreams_do_not_receive_new_selections() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            disabled_upstreams: vec!["127.0.0.1:3000".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        for _ in 0..4 {
            let selected = balancer.select(&request(), None).unwrap();
            assert_eq!(selected.backend.addr.to_string(), "127.0.0.1:3001");
        }
        let stats = balancer.runtime_stats();
        assert_eq!(stats.disabled_backend_count, 1);
        assert_eq!(stats.primary_available_backend_count, 1);
        let disabled = stats
            .backends
            .iter()
            .find(|backend| backend.disabled)
            .expect("disabled backend status");
        assert!(!disabled.ready);
    }

    #[test]
    fn runtime_backend_state_overrides_selection_by_alias() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_aliases: vec!["primary-a".to_owned(), "primary-b".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let mutation = balancer
            .set_runtime_backend_state("primary-a", LoadBalancerRuntimeBackendState::Drained)
            .unwrap();
        #[cfg(not(feature = "privacy-mode"))]
        assert_eq!(mutation.address, "127.0.0.1:3000");
        assert_eq!(mutation.alias.as_deref(), Some("primary-a"));
        let stats = balancer.runtime_stats();
        assert_eq!(stats.drained_backend_count, 1);
        assert_eq!(stats.runtime_overridden_backend_count, 1);
        assert_eq!(stats.runtime_drained_backend_count, 1);
        assert_eq!(stats.runtime_disabled_backend_count, 0);
        assert_eq!(stats.runtime_forced_down_backend_count, 0);
        assert_eq!(stats.primary_available_backend_count, 1);
        let runtime_drained = stats
            .backends
            .iter()
            .find(|backend| backend.alias.as_deref() == Some("primary-a"))
            .expect("runtime drained backend status");
        assert_eq!(
            runtime_drained.runtime_state_override,
            Some(LoadBalancerRuntimeBackendState::Drained)
        );
        assert!(runtime_drained.runtime_state_changed_at_unix_secs.is_some());
        for _ in 0..4 {
            let selected = balancer.select(&request(), None).unwrap();
            assert_eq!(selected.backend.addr.to_string(), "127.0.0.1:3001");
        }

        balancer
            .set_runtime_backend_state("primary-b", LoadBalancerRuntimeBackendState::Disabled)
            .unwrap();
        let stats = balancer.runtime_stats();
        assert_eq!(stats.drained_backend_count, 1);
        assert_eq!(stats.disabled_backend_count, 1);
        assert_eq!(stats.runtime_overridden_backend_count, 2);
        assert_eq!(stats.runtime_drained_backend_count, 1);
        assert_eq!(stats.runtime_disabled_backend_count, 1);
        assert_eq!(stats.runtime_forced_down_backend_count, 0);
        assert_eq!(stats.primary_available_backend_count, 0);
        let runtime_disabled = stats
            .backends
            .iter()
            .find(|backend| backend.alias.as_deref() == Some("primary-b"))
            .expect("runtime disabled backend status");
        assert!(
            runtime_disabled
                .runtime_state_changed_at_unix_secs
                .is_some()
        );
        assert!(balancer.select(&request(), None).is_none());

        balancer
            .set_runtime_backend_state("primary-a", LoadBalancerRuntimeBackendState::Normal)
            .unwrap();
        let stats = balancer.runtime_stats();
        assert_eq!(stats.runtime_overridden_backend_count, 1);
        assert_eq!(stats.runtime_drained_backend_count, 0);
        assert_eq!(stats.runtime_disabled_backend_count, 1);
        assert_eq!(stats.runtime_forced_down_backend_count, 0);
        let normal = stats
            .backends
            .iter()
            .find(|backend| backend.alias.as_deref() == Some("primary-a"))
            .expect("normal backend status");
        assert_eq!(normal.runtime_state_changed_at_unix_secs, None);
        let selected = balancer.select(&request(), None).unwrap();
        assert_eq!(selected.backend.addr.to_string(), "127.0.0.1:3000");
    }

    #[test]
    fn runtime_backend_state_supports_forced_down() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_aliases: vec!["primary-a".to_owned(), "primary-b".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let mutation = balancer
            .set_runtime_backend_state("primary-a", LoadBalancerRuntimeBackendState::ForcedDown)
            .unwrap();
        assert_eq!(mutation.state, LoadBalancerRuntimeBackendState::ForcedDown);
        assert_eq!(mutation.state.as_str(), "forced_down");

        let stats = balancer.runtime_stats();
        assert_eq!(stats.disabled_backend_count, 1);
        assert_eq!(stats.runtime_overridden_backend_count, 1);
        assert_eq!(stats.runtime_disabled_backend_count, 0);
        assert_eq!(stats.runtime_forced_down_backend_count, 1);
        assert_eq!(stats.primary_available_backend_count, 1);
        let forced_down = stats
            .backends
            .iter()
            .find(|backend| backend.alias.as_deref() == Some("primary-a"))
            .expect("forced down backend status");
        assert!(forced_down.disabled);
        assert_eq!(
            forced_down.runtime_state_override,
            Some(LoadBalancerRuntimeBackendState::ForcedDown)
        );

        for _ in 0..4 {
            let selected = balancer.select(&request(), None).unwrap();
            assert_eq!(selected.backend.addr.to_string(), "127.0.0.1:3001");
        }

        balancer
            .set_runtime_backend_state("primary-a", LoadBalancerRuntimeBackendState::Normal)
            .unwrap();
        let stats = balancer.runtime_stats();
        assert_eq!(stats.disabled_backend_count, 0);
        assert_eq!(stats.runtime_overridden_backend_count, 0);
        assert_eq!(stats.runtime_forced_down_backend_count, 0);
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn manual_resume_clears_passive_ejection() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_aliases: vec!["primary-a".to_owned(), "primary-b".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                passive_health: LoadBalancePassiveHealthConfig {
                    enabled: true,
                    consecutive_failure: 1,
                    ejection_secs: 60,
                    ..LoadBalancePassiveHealthConfig::default()
                },
                slow_start: LoadBalanceSlowStartConfig {
                    enabled: true,
                    duration_secs: 30,
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let failed = balancer.select(&request(), None).unwrap();
        let failed_addr = failed.backend.addr.to_string();
        failed.reporter.unwrap().record_failure();
        let stats = balancer.runtime_stats();
        let ejected = stats
            .backends
            .iter()
            .find(|backend| backend.address.as_deref() == Some(failed_addr.as_str()))
            .expect("ejected backend status");
        assert!(ejected.passive_ejected);
        assert_eq!(ejected.circuit_state, LoadBalancerCircuitState::Open);

        let mutation = balancer
            .set_runtime_backend_state(&failed_addr, LoadBalancerRuntimeBackendState::ManualResume)
            .unwrap();
        assert_eq!(mutation.state.as_str(), "manual_resume");

        let stats = balancer.runtime_stats();
        let resumed = stats
            .backends
            .iter()
            .find(|backend| backend.address.as_deref() == Some(failed_addr.as_str()))
            .expect("resumed backend status");
        assert!(!resumed.passive_ejected);
        assert_eq!(resumed.circuit_state, LoadBalancerCircuitState::Closed);
        assert_eq!(resumed.passive_consecutive_failures, None);
        assert_eq!(stats.circuit_open_backend_count, 0);
    }

    #[test]
    fn configures_tcp_health_check() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                health_check: LoadBalanceHealthCheckConfig {
                    enabled: true,
                    interval_secs: 3,
                    consecutive_success: 2,
                    consecutive_failure: 4,
                    parallel: true,
                    ..LoadBalanceHealthCheckConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(
            balancer.health_check_frequency(),
            Some(Duration::from_secs(3))
        );
        assert!(balancer.parallel_health_check());
    }

    #[tokio::test]
    async fn tcp_health_check_transitions_backend_readiness() {
        install_test_crypto_provider();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream = listener.local_addr().unwrap().to_string();
        drop(listener);

        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec![upstream.clone(), "127.0.0.1:1".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                health_check: LoadBalanceHealthCheckConfig {
                    enabled: true,
                    protocol: LoadBalanceHealthCheckProtocol::Tcp,
                    consecutive_success: 2,
                    consecutive_failure: 2,
                    interval_secs: 1,
                    connect_timeout_secs: Some(1),
                    ..LoadBalanceHealthCheckConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(balancer.runtime_stats().ready_backend_count, 2);

        balancer.run_health_check(false).await;
        assert_eq!(balancer.runtime_stats().ready_backend_count, 2);
        balancer.run_health_check(false).await;
        assert_eq!(balancer.runtime_stats().ready_backend_count, 0);

        let listener = std::net::TcpListener::bind(&upstream).unwrap();
        balancer.run_health_check(false).await;
        assert_eq!(balancer.runtime_stats().ready_backend_count, 0);
        balancer.run_health_check(false).await;
        assert_eq!(balancer.runtime_stats().ready_backend_count, 1);
        drop(listener);
    }

    #[test]
    fn builds_background_service_and_shared_selector() {
        install_test_crypto_provider();
        let (balancer, _service) = UpstreamLoadBalancer::background_service_from_proxy_config(
            "test",
            "test",
            None,
            &ProxyConfig {
                upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
                ..ProxyConfig::default()
            },
        )
        .unwrap()
        .unwrap();

        assert_eq!(balancer.backend_count(), 2);
        assert!(balancer.select(&request(), None).is_some());
    }

    #[tokio::test]
    async fn load_balancer_background_service_notifies_ready_after_initial_update() {
        install_test_crypto_provider();
        let (_balancer, service) = UpstreamLoadBalancer::background_service_from_proxy_config(
            "test",
            "test",
            None,
            &ProxyConfig {
                upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
                ..ProxyConfig::default()
            },
        )
        .unwrap()
        .unwrap();

        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let (ready_sender, mut ready_receiver) = watch::channel(false);
        let service_task = tokio::spawn(async move {
            service
                .start(
                    crate::background::FluxShutdown::new(shutdown_receiver),
                    crate::background::FluxBackgroundReady::new(move || {
                        ready_sender.send_replace(true);
                    }),
                )
                .await;
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while !*ready_receiver.borrow_and_update() {
                ready_receiver.changed().await.unwrap();
            }
        })
        .await
        .unwrap();

        shutdown_sender.send(true).unwrap();
        service_task.await.unwrap();
    }

    #[tokio::test]
    async fn load_balancer_background_service_runs_under_native_supervisor() {
        install_test_crypto_provider();
        let (_balancer, service) = UpstreamLoadBalancer::background_service_from_proxy_config(
            "test",
            "test",
            None,
            &ProxyConfig {
                upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
                ..ProxyConfig::default()
            },
        )
        .unwrap()
        .unwrap();

        let supervisor = fluxheim_runtime::NativeBackgroundSupervisor::new();
        let (ready_sender, mut ready_receiver) = watch::channel(false);
        let handle =
            supervisor.spawn_service_with_ready(service.into_native_service(), move || {
                ready_sender.send_replace(true);
            });

        tokio::time::timeout(Duration::from_secs(1), async {
            while !*ready_receiver.borrow_and_update() {
                ready_receiver.changed().await.unwrap();
            }
        })
        .await
        .unwrap();

        assert_eq!(
            handle.kind(),
            Some(fluxheim_runtime::BackgroundTaskKind::LoadBalancerRefresh)
        );
        assert!(supervisor.shutdown());
        handle.join().await.unwrap();
    }

    #[test]
    fn stays_disabled_without_load_balanced_upstreams() {
        let without_upstreams =
            UpstreamLoadBalancer::from_proxy_config(&ProxyConfig::default()).unwrap();
        let single_upstream = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["missing-container.test:3000".to_owned()],
            ..ProxyConfig::default()
        })
        .unwrap();

        assert!(without_upstreams.is_none());
        assert!(single_upstream.is_none());
    }
}
