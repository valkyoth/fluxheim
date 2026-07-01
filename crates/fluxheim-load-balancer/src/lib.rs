#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::fmt::{Debug, Formatter};
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fluxheim_config::{
    LoadBalanceHealthCheckProtocol, LoadBalancePassiveHealthConfig, LoadBalancePersistenceConfig,
    LoadBalanceQueueConfig, LoadBalanceSelection, LoadBalanceSlowStartConfig, ProxyConfig,
};

mod api;
mod api_selection;
mod backend;
mod backend_model;
mod background;
mod crypto;
mod discovery;
mod discovery_dns;
mod discovery_http;
#[cfg(test)]
mod discovery_tests;
mod health;
mod inner;
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
mod runtime_mutation;
mod runtime_state;
mod selection;
mod selection_candidate;
mod selection_consistent;
mod selection_fnv;
mod selection_hash;
mod selection_ketama;
mod selection_maglev;
mod selection_power;
mod selection_weight;
mod service;
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
use self::backend::RuntimeBackend as Backend;
use self::discovery::{
    background_maglev_service_for, background_service_for, configured_load_balancer,
    configured_maglev_table, configured_nginx_ketama_table,
};
use self::inner::UpstreamLoadBalancerInner;
pub(crate) use self::key::backend_key;
use self::persistence::{LoadBalanceKeySource, LoadBalancerPersistenceState};
use self::policy::BackendSelectionPolicy;
use self::policy_config::backend_aliases;
use self::selection::{LoadBalancerSelectInputs, SelectionPass};
use self::state::{
    BackendConnectionCounters, BackendLatencyState, PassiveHealthState, SlowStartState,
};
pub use self::state::{LoadBalancedConnectionPermit, LoadBalancedUpstreamReporter};

pub use self::background::{FluxBackgroundReady, FluxShutdown};
pub use self::crypto::set_admin_hmac_sha256;
#[cfg(feature = "metrics")]
pub use self::metrics::set_load_balancer_event_recorder;
pub use self::persistence::LoadBalancerRequestView;
pub use self::service::UpstreamLoadBalancerService;

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

#[cfg(test)]
mod tests_backend_state;
#[cfg(test)]
mod tests_background;
#[cfg(test)]
mod tests_discovery;
#[cfg(test)]
mod tests_health_policy;
#[cfg(test)]
mod tests_parse;
#[cfg(test)]
mod tests_persistence;
#[cfg(test)]
mod tests_queue;
#[cfg(test)]
mod tests_runtime_mutation;
#[cfg(test)]
mod tests_runtime_state_file;
#[cfg(test)]
mod tests_selection;
#[cfg(test)]
mod tests_selection_policy;
#[cfg(test)]
mod tests_support;
