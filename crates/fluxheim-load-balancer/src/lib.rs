#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::fmt::{Debug, Formatter};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fluxheim_config::{
    LoadBalanceHealthCheckProtocol, LoadBalancePassiveHealthConfig, LoadBalancePersistenceConfig,
    LoadBalanceQueueConfig, LoadBalanceSelection, LoadBalanceSlowStartConfig, ProxyConfig,
};

mod api;
mod api_selection;
mod backend;
mod backend_model;
mod background;
mod construction;
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
mod queue;
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
mod stats;

#[cfg(test)]
fn install_test_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub(crate) use self::api::LoadBalancerMetricLabels;
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
use self::inner::UpstreamLoadBalancerInner;
pub(crate) use self::key::backend_key;
use self::persistence::{LoadBalanceKeySource, LoadBalancerPersistenceState};
use self::policy::BackendSelectionPolicy;
use self::policy_config::backend_aliases;
use self::selection::{LoadBalancerSelectInputs, SelectionPass};
use self::state::{BackendConnectionCounters, PassiveHealthState, SlowStartState};
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

impl Debug for UpstreamLoadBalancer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UpstreamLoadBalancer")
            .field("max_iterations", &self.max_iterations)
            .finish_non_exhaustive()
    }
}

impl UpstreamLoadBalancer {
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

    #[cfg(test)]
    fn backend_count(&self) -> usize {
        self.inner.backend_count()
    }

    #[cfg(test)]
    fn backend_weights(&self) -> Vec<usize> {
        self.inner.backend_weights()
    }

    #[cfg(test)]
    fn health_check_frequency(&self) -> Option<std::time::Duration> {
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
