use std::fmt::{Debug, Formatter};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use pingora::http::RequestHeader;
use pingora::lb::Backend;
use pingora::lb::prelude::LoadBalancer;
use pingora::lb::selection::{Consistent, FNVHash, Random, RoundRobin};
use pingora::services::ServiceWithDependents;
use serde::Serialize;

use crate::config::{
    LoadBalanceHealthCheckExpectedStatusRange, LoadBalancePassiveHealthConfig,
    LoadBalancePersistenceConfig, LoadBalancePersistenceMode, LoadBalanceQueueConfig,
    LoadBalanceRetryConfig, LoadBalanceSelection, LoadBalanceSlowStartConfig, ProxyConfig,
};

mod discovery;
mod health;
mod persistence;
mod policy;
mod selection;
mod state;

use self::discovery::{
    background_maglev_service_for, background_service_for, configured_load_balancer,
    configured_maglev_table,
};
use self::persistence::{LoadBalanceKeySource, LoadBalancerPersistenceState};
use self::policy::{
    BackendSelectionPolicy, BackendStatsInputs, backend_aliases, backend_policy_key,
    load_balancer_backend_stats,
};
use self::selection::{
    LoadBalancerSelectInputs, MaglevTable, SelectionPass, select_bounded_load_consistent,
    select_least_connections, select_least_sessions, select_least_time, select_maglev,
    select_pingora, select_power_of_two,
};
use self::state::{
    BackendConnectionCounters, BackendLatencyState, PassiveHealthState, SlowStartState,
    backend_connection_key,
};
pub use self::state::{LoadBalancedConnectionPermit, LoadBalancedUpstreamReporter};

pub type UpstreamLoadBalancerService = Box<dyn ServiceWithDependents>;
const BACKEND_STATE_PRUNE_INTERVAL: usize = 1024;

#[derive(Clone)]
pub struct UpstreamLoadBalancer {
    inner: UpstreamLoadBalancerInner,
    selection: LoadBalanceSelection,
    key_source: LoadBalanceKeySource,
    backend_aliases: Arc<std::collections::HashMap<u64, Arc<str>>>,
    passive_health: Option<Arc<PassiveHealthState>>,
    slow_start: Option<Arc<SlowStartState>>,
    persistence: Option<Arc<LoadBalancerPersistenceState>>,
    passive_health_policy: LoadBalancePassiveHealthConfig,
    slow_start_policy: LoadBalanceSlowStartConfig,
    persistence_policy: LoadBalancePersistenceConfig,
    queue_policy: LoadBalanceQueueConfig,
    queue_waiting: Arc<AtomicUsize>,
    state_prune_counter: Arc<AtomicUsize>,
    counters: Arc<BackendConnectionCounters>,
    backend_policy: BackendSelectionPolicy,
    max_iterations: usize,
    all_down_status: u16,
    retry: LoadBalancerRetryRuntimeStats,
}

pub struct SelectedUpstream {
    pub backend: Backend,
    pub alias: Option<Arc<str>>,
    pub permit: Option<LoadBalancedConnectionPermit>,
    pub reporter: Option<LoadBalancedUpstreamReporter>,
    pub persistence_outcome: Option<LoadBalancerPersistenceOutcome>,
}

pub struct LoadBalancerSelectionResult {
    pub selected: Option<SelectedUpstream>,
    pub queue_outcome: Option<LoadBalancerQueueOutcome>,
    pub queue_wait: Option<Duration>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadBalancerPersistenceOutcome {
    Hit,
    Miss,
    Fallback,
}

impl LoadBalancerPersistenceOutcome {
    pub fn event(self) -> &'static str {
        match self {
            Self::Hit => "persistence_hit",
            Self::Miss => "persistence_miss",
            Self::Fallback => "persistence_fallback",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadBalancerQueueOutcome {
    Waited,
    Full,
    Timeout,
}

impl LoadBalancerQueueOutcome {
    pub fn event(self) -> &'static str {
        match self {
            Self::Waited => "queue_waited",
            Self::Full => "queue_full",
            Self::Timeout => "queue_timeout",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadBalancedUpstreamOutcome {
    pub failed: bool,
    pub ejected: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancerRuntimeBackendState {
    Normal,
    Drained,
    Disabled,
    ForcedDown,
    ManualResume,
}

impl LoadBalancerRuntimeBackendState {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "normal" | "enable" | "enabled" => Some(Self::Normal),
            "drain" | "drained" => Some(Self::Drained),
            "disable" | "disabled" => Some(Self::Disabled),
            "down" | "force-down" | "force_down" | "forced-down" | "forced_down" => {
                Some(Self::ForcedDown)
            }
            "resume" | "resumed" | "manual-resume" | "manual_resume" => Some(Self::ManualResume),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Drained => "drained",
            Self::Disabled => "disabled",
            Self::ForcedDown => "forced_down",
            Self::ManualResume => "manual_resume",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LoadBalancerRuntimeBackendMutation {
    pub member: String,
    pub state: LoadBalancerRuntimeBackendState,
    pub address: String,
    pub alias: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancerCircuitState {
    Closed,
    Open,
}

#[derive(Clone, Debug, Serialize)]
pub struct LoadBalancerPoolRuntimeStats {
    pub selection: LoadBalanceSelection,
    pub backend_count: usize,
    pub ready_backend_count: usize,
    pub available_backend_count: usize,
    pub primary_available_backend_count: usize,
    pub backup_available_backend_count: usize,
    pub drained_backend_count: usize,
    pub disabled_backend_count: usize,
    pub runtime_overridden_backend_count: usize,
    pub runtime_drained_backend_count: usize,
    pub runtime_disabled_backend_count: usize,
    pub runtime_forced_down_backend_count: usize,
    pub passive_ejected_backend_count: usize,
    pub circuit_open_backend_count: usize,
    pub saturated_backend_count: usize,
    pub max_iterations: usize,
    pub all_down_status: u16,
    pub health_check_enabled: bool,
    pub health_check_frequency_secs: Option<u64>,
    pub parallel_health_check: bool,
    pub passive_health_enabled: bool,
    pub slow_start_enabled: bool,
    pub persistence_enabled: bool,
    pub passive_health: LoadBalancePassiveHealthConfig,
    pub slow_start: LoadBalanceSlowStartConfig,
    pub persistence: LoadBalancerPersistenceRuntimeStats,
    pub queue: LoadBalancerQueueRuntimeStats,
    pub retry: LoadBalancerRetryRuntimeStats,
    pub backends: Vec<LoadBalancerBackendRuntimeStats>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LoadBalancerRetryRuntimeStats {
    pub enabled: bool,
    pub max_retries: u8,
    pub methods: Vec<String>,
    pub statuses: Vec<u16>,
    pub status_ranges: Vec<LoadBalanceHealthCheckExpectedStatusRange>,
    pub budget_per_window: u32,
    pub budget_window_secs: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct LoadBalancerPersistenceRuntimeStats {
    pub enabled: bool,
    pub mode: LoadBalancePersistenceMode,
    pub header: Option<String>,
    pub cookie: Option<String>,
    pub ttl_secs: u64,
    pub table_max_entries: usize,
    pub entry_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct LoadBalancerQueueRuntimeStats {
    pub enabled: bool,
    pub max_waiting: usize,
    pub timeout_ms: u64,
    pub retry_interval_ms: u64,
    pub waiting: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct LoadBalancerBackendRuntimeStats {
    pub address: Option<String>,
    pub alias: Option<String>,
    pub tags: Vec<String>,
    pub weight: usize,
    pub locality: Option<String>,
    pub locality_preferred: bool,
    pub ready: bool,
    pub backup: bool,
    pub drained: bool,
    pub disabled: bool,
    pub runtime_state_override: Option<LoadBalancerRuntimeBackendState>,
    pub runtime_state_changed_at_unix_secs: Option<u64>,
    pub persistence_entry_count: usize,
    pub priority_group: Option<u16>,
    pub max_in_flight: Option<usize>,
    pub in_flight: usize,
    pub passive_ejected: bool,
    pub circuit_state: LoadBalancerCircuitState,
    pub passive_consecutive_failures: Option<usize>,
    pub passive_ejection_remaining_secs: Option<u64>,
    pub slow_start_permitting: bool,
    pub latency_micros: Option<u64>,
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
        match config.load_balance.selection {
            LoadBalanceSelection::RoundRobin => {
                let Some(inner) = configured_load_balancer::<RoundRobin>(config)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::RoundRobin(Arc::new(inner)),
                    config,
                )))
            }
            LoadBalanceSelection::LeastConnections => {
                let Some(inner) = configured_load_balancer::<RoundRobin>(config)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::LeastConnections(Arc::new(inner)),
                    config,
                )))
            }
            LoadBalanceSelection::LeastSessions => {
                let Some(inner) = configured_load_balancer::<RoundRobin>(config)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::LeastSessions(Arc::new(inner)),
                    config,
                )))
            }
            LoadBalanceSelection::LeastTime => {
                let Some(inner) = configured_load_balancer::<RoundRobin>(config)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::LeastTime {
                        inner: Arc::new(inner),
                        latency: Arc::new(BackendLatencyState::default()),
                    },
                    config,
                )))
            }
            LoadBalanceSelection::PowerOfTwo => {
                let Some(inner) = configured_load_balancer::<Random>(config)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::PowerOfTwo(Arc::new(inner)),
                    config,
                )))
            }
            LoadBalanceSelection::SourceHash
            | LoadBalanceSelection::UriHash
            | LoadBalanceSelection::HeaderHash
            | LoadBalanceSelection::CookieHash => {
                let Some(inner) = configured_load_balancer::<FNVHash>(config)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::FnvHash(Arc::new(inner)),
                    config,
                )))
            }
            LoadBalanceSelection::ConsistentSourceHash
            | LoadBalanceSelection::ConsistentUriHash
            | LoadBalanceSelection::ConsistentHeaderHash
            | LoadBalanceSelection::ConsistentCookieHash => {
                let Some(inner) = configured_load_balancer::<Consistent>(config)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::ConsistentHash(Arc::new(inner)),
                    config,
                )))
            }
            LoadBalanceSelection::BoundedLoadConsistentSourceHash
            | LoadBalanceSelection::BoundedLoadConsistentUriHash
            | LoadBalanceSelection::BoundedLoadConsistentHeaderHash
            | LoadBalanceSelection::BoundedLoadConsistentCookieHash => {
                let Some(inner) = configured_load_balancer::<Consistent>(config)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::BoundedLoadConsistentHash {
                        inner: Arc::new(inner),
                        factor_per_mille: config.load_balance.bounded_load_factor_per_mille,
                    },
                    config,
                )))
            }
            LoadBalanceSelection::MaglevSourceHash
            | LoadBalanceSelection::MaglevUriHash
            | LoadBalanceSelection::MaglevHeaderHash
            | LoadBalanceSelection::MaglevCookieHash => {
                let Some(inner) = configured_load_balancer::<RoundRobin>(config)? else {
                    return Ok(None);
                };
                let table = Arc::new(configured_maglev_table(config)?);
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::MaglevHash {
                        inner: Arc::new(inner),
                        table,
                    },
                    config,
                )))
            }
        }
    }

    pub fn background_service_from_proxy_config(
        name: &str,
        config: &ProxyConfig,
    ) -> io::Result<Option<(Self, UpstreamLoadBalancerService)>> {
        match config.load_balance.selection {
            LoadBalanceSelection::RoundRobin => background_service_for::<RoundRobin, _>(
                name,
                config,
                UpstreamLoadBalancerInner::RoundRobin,
            ),
            LoadBalanceSelection::LeastConnections => {
                background_service_for::<RoundRobin, _>(name, config, |inner| {
                    UpstreamLoadBalancerInner::LeastConnections(inner)
                })
            }
            LoadBalanceSelection::LeastSessions => {
                background_service_for::<RoundRobin, _>(name, config, |inner| {
                    UpstreamLoadBalancerInner::LeastSessions(inner)
                })
            }
            LoadBalanceSelection::LeastTime => {
                background_service_for::<RoundRobin, _>(name, config, |inner| {
                    UpstreamLoadBalancerInner::LeastTime {
                        inner,
                        latency: Arc::new(BackendLatencyState::default()),
                    }
                })
            }
            LoadBalanceSelection::PowerOfTwo => {
                background_service_for::<Random, _>(name, config, |inner| {
                    UpstreamLoadBalancerInner::PowerOfTwo(inner)
                })
            }
            LoadBalanceSelection::SourceHash
            | LoadBalanceSelection::UriHash
            | LoadBalanceSelection::HeaderHash
            | LoadBalanceSelection::CookieHash => background_service_for::<FNVHash, _>(
                name,
                config,
                UpstreamLoadBalancerInner::FnvHash,
            ),
            LoadBalanceSelection::ConsistentSourceHash
            | LoadBalanceSelection::ConsistentUriHash
            | LoadBalanceSelection::ConsistentHeaderHash
            | LoadBalanceSelection::ConsistentCookieHash => {
                background_service_for::<Consistent, _>(
                    name,
                    config,
                    UpstreamLoadBalancerInner::ConsistentHash,
                )
            }
            LoadBalanceSelection::BoundedLoadConsistentSourceHash
            | LoadBalanceSelection::BoundedLoadConsistentUriHash
            | LoadBalanceSelection::BoundedLoadConsistentHeaderHash
            | LoadBalanceSelection::BoundedLoadConsistentCookieHash => {
                let factor_per_mille = config.load_balance.bounded_load_factor_per_mille;
                background_service_for::<Consistent, _>(name, config, move |inner| {
                    UpstreamLoadBalancerInner::BoundedLoadConsistentHash {
                        inner,
                        factor_per_mille,
                    }
                })
            }
            LoadBalanceSelection::MaglevSourceHash
            | LoadBalanceSelection::MaglevUriHash
            | LoadBalanceSelection::MaglevHeaderHash
            | LoadBalanceSelection::MaglevCookieHash => background_maglev_service_for(name, config),
        }
    }

    pub fn select(
        &self,
        request: &RequestHeader,
        client_ip: Option<IpAddr>,
    ) -> Option<SelectedUpstream> {
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

    pub async fn select_or_wait(
        &self,
        request: &RequestHeader,
        client_ip: Option<IpAddr>,
    ) -> Option<SelectedUpstream> {
        self.select_or_wait_result(request, client_ip)
            .await
            .selected
    }

    pub async fn select_or_wait_result(
        &self,
        request: &RequestHeader,
        client_ip: Option<IpAddr>,
    ) -> LoadBalancerSelectionResult {
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

    fn select_fresh(
        &self,
        request: &RequestHeader,
        client_ip: Option<IpAddr>,
        persistence_key: Option<&[u8]>,
        persistence_outcome: Option<LoadBalancerPersistenceOutcome>,
    ) -> Option<SelectedUpstream> {
        self.prune_stale_backend_state_periodically();
        let key = self.key_source.request_key(request, client_ip);
        let persistence_entry_counts = self
            .persistence
            .as_ref()
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
        })?;
        let selected = self.prepare_selected(selected, persistence_outcome)?;
        if let (Some(persistence), Some(key)) = (&self.persistence, persistence_key) {
            persistence.record(key, backend_policy_key(&selected.backend));
        }
        Some(selected)
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
            .get(&backend_policy_key(&selected.backend))
            .cloned();
        let latency = self.inner.latency_state();
        selected.reporter = (self.passive_health.is_some() || latency.is_some()).then(|| {
            LoadBalancedUpstreamReporter::new(
                backend_connection_key(&selected.backend),
                self.passive_health.clone(),
                self.slow_start.clone(),
                latency,
            )
        });
        selected.persistence_outcome = persistence_outcome;
        Some(selected)
    }

    fn backend_available_for_persistence(&self, backend: &Backend) -> bool {
        let policy_key = backend_policy_key(backend);
        let connection_key = backend_connection_key(backend);
        self.inner.backend_ready(backend)
            && !self
                .passive_health
                .as_ref()
                .is_some_and(|health| health.key_is_currently_ejected(connection_key))
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
            && !self.backend_policy.disabled(policy_key)
            && !self.backend_policy.drained(policy_key)
    }

    fn from_inner(inner: UpstreamLoadBalancerInner, config: &ProxyConfig) -> Self {
        Self {
            inner,
            selection: config.load_balance.selection,
            key_source: LoadBalanceKeySource::from_config(config),
            backend_aliases: Arc::new(backend_aliases(config)),
            passive_health: config.load_balance.passive_health.enabled.then(|| {
                Arc::new(PassiveHealthState::from_config(
                    &config.load_balance.passive_health,
                ))
            }),
            slow_start: config
                .load_balance
                .slow_start
                .enabled
                .then(|| Arc::new(SlowStartState::from_config(&config.load_balance.slow_start))),
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
            state_prune_counter: Arc::new(AtomicUsize::new(0)),
            counters: Arc::new(BackendConnectionCounters::default()),
            backend_policy: BackendSelectionPolicy::from_config(config),
            max_iterations: config.load_balance.max_iterations,
            all_down_status: config.load_balance.all_down_status,
            retry: LoadBalancerRetryRuntimeStats::from_config(&config.load_balance.retry),
        }
    }

    fn prune_stale_backend_state_periodically(&self) {
        let current = self.state_prune_counter.fetch_add(1, Ordering::Relaxed);
        if !current.is_multiple_of(BACKEND_STATE_PRUNE_INTERVAL) {
            return;
        }
        let live_keys = self
            .inner
            .backends()
            .into_iter()
            .map(|backend| backend_connection_key(&backend))
            .collect::<std::collections::HashSet<_>>();
        self.counters.prune_stale(&live_keys);
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

    pub fn runtime_stats(&self) -> LoadBalancerPoolRuntimeStats {
        let health_check_frequency = self.inner.health_check_frequency();
        let (persistence_entry_count, persistence_backend_entry_counts) = self
            .persistence
            .as_ref()
            .map_or((0, std::collections::HashMap::new()), |persistence| {
                persistence.runtime_counts()
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
        LoadBalancerPoolRuntimeStats {
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
            health_check_frequency_secs: health_check_frequency
                .map(|frequency| frequency.as_secs()),
            parallel_health_check: self.inner.parallel_health_check(),
            passive_health_enabled: self.passive_health.is_some(),
            slow_start_enabled: self.slow_start.is_some(),
            persistence_enabled: self.persistence.is_some(),
            passive_health: self.passive_health_policy.clone(),
            slow_start: self.slow_start_policy.clone(),
            persistence: LoadBalancerPersistenceRuntimeStats {
                enabled: self.persistence.is_some(),
                mode: self.persistence_policy.mode,
                header: self.persistence_policy.header.clone(),
                cookie: self.persistence_policy.cookie.clone(),
                ttl_secs: self.persistence_policy.ttl_secs,
                table_max_entries: self.persistence_policy.table_max_entries,
                entry_count: persistence_entry_count,
            },
            queue: LoadBalancerQueueRuntimeStats {
                enabled: self.queue_policy.enabled(),
                max_waiting: self.queue_policy.max_waiting,
                timeout_ms: self.queue_policy.timeout_ms,
                retry_interval_ms: self.queue_policy.retry_interval_ms,
                waiting: self.queue_waiting.load(Ordering::Acquire),
            },
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
        let policy_key = backend_policy_key(&backend);
        let connection_key = backend_connection_key(&backend);
        self.backend_policy
            .set_runtime_backend_state(policy_key, state);
        if state == LoadBalancerRuntimeBackendState::ManualResume {
            if let Some(passive_health) = &self.passive_health {
                passive_health.clear_key(connection_key);
            }
            if let Some(slow_start) = &self.slow_start {
                slow_start.reset_at(connection_key, Instant::now());
            }
        }
        Ok(LoadBalancerRuntimeBackendMutation {
            member: member.to_owned(),
            state,
            address: backend.addr.to_string(),
            alias: self
                .backend_aliases
                .get(&policy_key)
                .map(|alias| alias.to_string()),
        })
    }

    pub fn clear_persistence(&self) -> usize {
        self.persistence
            .as_ref()
            .map_or(0, |persistence| persistence.clear())
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

impl LoadBalancerRetryRuntimeStats {
    fn from_config(config: &LoadBalanceRetryConfig) -> Self {
        Self {
            enabled: config.enabled,
            max_retries: config.max_retries,
            methods: config.methods.clone(),
            statuses: config.statuses.clone(),
            status_ranges: config.status_ranges.clone(),
            budget_per_window: config.budget_per_window,
            budget_window_secs: config.budget_window_secs,
        }
    }
}

#[derive(Clone)]
enum UpstreamLoadBalancerInner {
    RoundRobin(Arc<LoadBalancer<RoundRobin>>),
    LeastConnections(Arc<LoadBalancer<RoundRobin>>),
    LeastSessions(Arc<LoadBalancer<RoundRobin>>),
    LeastTime {
        inner: Arc<LoadBalancer<RoundRobin>>,
        latency: Arc<BackendLatencyState>,
    },
    PowerOfTwo(Arc<LoadBalancer<Random>>),
    FnvHash(Arc<LoadBalancer<FNVHash>>),
    ConsistentHash(Arc<LoadBalancer<Consistent>>),
    BoundedLoadConsistentHash {
        inner: Arc<LoadBalancer<Consistent>>,
        factor_per_mille: u16,
    },
    MaglevHash {
        inner: Arc<LoadBalancer<RoundRobin>>,
        table: Arc<MaglevTable>,
    },
}

impl UpstreamLoadBalancerInner {
    fn select(&self, inputs: LoadBalancerSelectInputs<'_>) -> Option<SelectedUpstream> {
        match self {
            Self::RoundRobin(inner) => select_pingora(
                inner,
                b"",
                inputs.max_iterations,
                inputs.passive_health,
                inputs.slow_start,
                inputs.counters,
                inputs.backend_policy,
            )
            .map(SelectedUpstream::new),
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
            Self::FnvHash(inner) => select_pingora(
                inner,
                inputs.key.unwrap_or_default(),
                inputs.max_iterations,
                inputs.passive_health,
                inputs.slow_start,
                inputs.counters,
                inputs.backend_policy,
            )
            .map(SelectedUpstream::new),
            Self::ConsistentHash(inner) => select_pingora(
                inner,
                inputs.key.unwrap_or_default(),
                inputs.max_iterations,
                inputs.passive_health,
                inputs.slow_start,
                inputs.counters,
                inputs.backend_policy,
            )
            .map(SelectedUpstream::new),
            Self::BoundedLoadConsistentHash {
                inner,
                factor_per_mille,
            } => select_bounded_load_consistent(inner, *factor_per_mille, inputs),
            Self::MaglevHash { inner, table } => select_maglev(inner, table, inputs),
        }
    }

    fn backend_count(&self) -> usize {
        match self {
            Self::RoundRobin(inner) => inner.backends().get_backend().len(),
            Self::LeastConnections(inner) => inner.backends().get_backend().len(),
            Self::LeastSessions(inner) => inner.backends().get_backend().len(),
            Self::LeastTime { inner, .. } => inner.backends().get_backend().len(),
            Self::PowerOfTwo(inner) => inner.backends().get_backend().len(),
            Self::FnvHash(inner) => inner.backends().get_backend().len(),
            Self::ConsistentHash(inner) => inner.backends().get_backend().len(),
            Self::BoundedLoadConsistentHash { inner, .. } => inner.backends().get_backend().len(),
            Self::MaglevHash { inner, .. } => inner.backends().get_backend().len(),
        }
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
        match self {
            Self::RoundRobin(inner) => load_balancer_backend_stats(inner, inputs),
            Self::LeastConnections(inner) => load_balancer_backend_stats(inner, inputs),
            Self::LeastSessions(inner) => load_balancer_backend_stats(inner, inputs),
            Self::LeastTime { inner, latency } => {
                load_balancer_backend_stats(inner, inputs.with_latency(latency))
            }
            Self::PowerOfTwo(inner) => load_balancer_backend_stats(inner, inputs),
            Self::FnvHash(inner) => load_balancer_backend_stats(inner, inputs),
            Self::ConsistentHash(inner) => load_balancer_backend_stats(inner, inputs),
            Self::BoundedLoadConsistentHash { inner, .. } => {
                load_balancer_backend_stats(inner, inputs)
            }
            Self::MaglevHash { inner, .. } => load_balancer_backend_stats(inner, inputs),
        }
    }

    #[cfg(test)]
    fn backend_weights(&self) -> Vec<usize> {
        match self {
            Self::RoundRobin(inner) => backend_weights(inner),
            Self::LeastConnections(inner) => backend_weights(inner),
            Self::LeastSessions(inner) => backend_weights(inner),
            Self::LeastTime { inner, .. } => backend_weights(inner),
            Self::PowerOfTwo(inner) => backend_weights(inner),
            Self::FnvHash(inner) => backend_weights(inner),
            Self::ConsistentHash(inner) => backend_weights(inner),
            Self::BoundedLoadConsistentHash { inner, .. } => backend_weights(inner),
            Self::MaglevHash { inner, .. } => backend_weights(inner),
        }
    }

    fn health_check_frequency(&self) -> Option<Duration> {
        match self {
            Self::RoundRobin(inner) => inner.health_check_frequency,
            Self::LeastConnections(inner) => inner.health_check_frequency,
            Self::LeastSessions(inner) => inner.health_check_frequency,
            Self::LeastTime { inner, .. } => inner.health_check_frequency,
            Self::PowerOfTwo(inner) => inner.health_check_frequency,
            Self::FnvHash(inner) => inner.health_check_frequency,
            Self::ConsistentHash(inner) => inner.health_check_frequency,
            Self::BoundedLoadConsistentHash { inner, .. } => inner.health_check_frequency,
            Self::MaglevHash { inner, .. } => inner.health_check_frequency,
        }
    }

    fn parallel_health_check(&self) -> bool {
        match self {
            Self::RoundRobin(inner) => inner.parallel_health_check,
            Self::LeastConnections(inner) => inner.parallel_health_check,
            Self::LeastSessions(inner) => inner.parallel_health_check,
            Self::LeastTime { inner, .. } => inner.parallel_health_check,
            Self::PowerOfTwo(inner) => inner.parallel_health_check,
            Self::FnvHash(inner) => inner.parallel_health_check,
            Self::ConsistentHash(inner) => inner.parallel_health_check,
            Self::BoundedLoadConsistentHash { inner, .. } => inner.parallel_health_check,
            Self::MaglevHash { inner, .. } => inner.parallel_health_check,
        }
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
            | Self::BoundedLoadConsistentHash { .. }
            | Self::MaglevHash { .. } => None,
        }
    }

    #[cfg(test)]
    async fn run_health_check(&self, parallel: bool) {
        match self {
            Self::RoundRobin(inner) => inner.backends().run_health_check(parallel).await,
            Self::LeastConnections(inner) => inner.backends().run_health_check(parallel).await,
            Self::LeastSessions(inner) => inner.backends().run_health_check(parallel).await,
            Self::LeastTime { inner, .. } => inner.backends().run_health_check(parallel).await,
            Self::PowerOfTwo(inner) => inner.backends().run_health_check(parallel).await,
            Self::FnvHash(inner) => inner.backends().run_health_check(parallel).await,
            Self::ConsistentHash(inner) => inner.backends().run_health_check(parallel).await,
            Self::BoundedLoadConsistentHash { inner, .. } => {
                inner.backends().run_health_check(parallel).await
            }
            Self::MaglevHash { inner, .. } => inner.backends().run_health_check(parallel).await,
        }
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
            let policy_key = backend_policy_key(&backend);
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
            .find(|backend| backend_policy_key(backend) == key)
    }

    fn backend_ready(&self, backend: &Backend) -> bool {
        match self {
            Self::RoundRobin(inner) => inner.backends().ready(backend),
            Self::LeastConnections(inner) => inner.backends().ready(backend),
            Self::LeastSessions(inner) => inner.backends().ready(backend),
            Self::LeastTime { inner, .. } => inner.backends().ready(backend),
            Self::PowerOfTwo(inner) => inner.backends().ready(backend),
            Self::FnvHash(inner) => inner.backends().ready(backend),
            Self::ConsistentHash(inner) => inner.backends().ready(backend),
            Self::BoundedLoadConsistentHash { inner, .. } => inner.backends().ready(backend),
            Self::MaglevHash { inner, .. } => inner.backends().ready(backend),
        }
    }

    fn backends(&self) -> Vec<Backend> {
        match self {
            Self::RoundRobin(inner) => inner.backends().get_backend().iter().cloned().collect(),
            Self::LeastConnections(inner) => {
                inner.backends().get_backend().iter().cloned().collect()
            }
            Self::LeastSessions(inner) => inner.backends().get_backend().iter().cloned().collect(),
            Self::LeastTime { inner, .. } => {
                inner.backends().get_backend().iter().cloned().collect()
            }
            Self::PowerOfTwo(inner) => inner.backends().get_backend().iter().cloned().collect(),
            Self::FnvHash(inner) => inner.backends().get_backend().iter().cloned().collect(),
            Self::ConsistentHash(inner) => inner.backends().get_backend().iter().cloned().collect(),
            Self::BoundedLoadConsistentHash { inner, .. } => {
                inner.backends().get_backend().iter().cloned().collect()
            }
            Self::MaglevHash { inner, .. } => {
                inner.backends().get_backend().iter().cloned().collect()
            }
        }
    }
}

impl SelectedUpstream {
    pub(super) fn new(backend: Backend) -> Self {
        Self {
            backend,
            alias: None,
            permit: None,
            reporter: None,
            persistence_outcome: None,
        }
    }
}

#[cfg(test)]
fn backend_weights<S>(inner: &LoadBalancer<S>) -> Vec<usize>
where
    S: pingora::lb::selection::BackendSelection + 'static,
    S::Iter: pingora::lb::selection::BackendIter,
{
    inner
        .backends()
        .get_backend()
        .iter()
        .map(|backend| backend.weight)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    use pingora::http::RequestHeader;
    use pingora::lb::Backend;

    use crate::config::{
        LoadBalanceConfig, LoadBalanceHealthCheckConfig, LoadBalanceHealthCheckExpectedStatusRange,
        LoadBalanceHealthCheckProtocol, LoadBalancePassiveHealthConfig,
        LoadBalancePersistenceConfig, LoadBalancePersistenceMode, LoadBalanceQueueConfig,
        LoadBalanceSelection, LoadBalanceSlowStartConfig, ProxyConfig,
    };

    use super::persistence::{MAX_PERSISTENCE_KEY_BYTES, cookie_key, request_header_key};
    use super::selection::{fnv1a64_with_seed, least_connections_score_is_lower};
    use super::state::PassiveBackendHealth;
    use super::{
        LoadBalancedUpstreamReporter, LoadBalancerCircuitState, LoadBalancerPersistenceOutcome,
        LoadBalancerQueueOutcome, LoadBalancerRuntimeBackendState, PassiveHealthState,
        SlowStartState, UpstreamLoadBalancer, backend_connection_key,
    };
    use crate::test_support::unique_temp_path;

    fn install_test_crypto_provider() {
        #[cfg(feature = "tls-rustls-backend")]
        let _ = crate::tls::install_rustls_crypto_provider();
    }

    fn request() -> RequestHeader {
        RequestHeader::build("GET", b"/app?id=42", None).unwrap()
    }

    fn slow_start_blocking_sample(backend: &Backend) -> u64 {
        let key = backend_connection_key(backend);
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
        assert!(
            matches!(
                selected.alias.as_deref(),
                Some("origin-a") | Some("origin-b")
            ),
            "selected alias should come from configured upstream_aliases"
        );
    }

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
        first.reporter.as_ref().unwrap().record_failure();
        drop(first);

        let fallback = balancer
            .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20))))
            .unwrap();
        assert_eq!(fallback.backend.addr.to_string(), "127.0.0.1:3001");
        assert_eq!(
            fallback.persistence_outcome,
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
        assert!(balancer.select(&request(), None).is_some());
    }

    #[test]
    fn builds_round_robin_from_dns_refreshed_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstream: None,
            upstreams: vec!["localhost:3000".to_owned()],
            upstream_dns_refresh_secs: Some(2),
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        assert!(balancer.backend_count() >= 1);
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
        let first_addr = first.backend.addr.clone();
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

        let preferred = balancer.select(&request(), None).unwrap();
        assert_eq!(preferred.backend.addr.to_string(), "127.0.0.1:3001");

        let activated = balancer.select(&request(), None).unwrap();
        assert_eq!(activated.backend.addr.to_string(), "127.0.0.1:3002");
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
        let backend = Backend::new("127.0.0.1:3000").unwrap();
        state
            .sample_counter
            .store(slow_start_blocking_sample(&backend), Ordering::Relaxed);

        assert!(!state.permits(&backend));
        state.backends.lock().unwrap().insert(
            backend_connection_key(&backend),
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
        let backend = Backend::new("127.0.0.1:3000").unwrap();
        state
            .backends
            .lock()
            .unwrap()
            .insert(backend_connection_key(&backend), Instant::now());
        assert!(!state.permits_read_only(&backend));

        state.backends.lock().unwrap().insert(
            backend_connection_key(&backend),
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
        let backend = Backend::new("127.0.0.1:3000").unwrap();
        let key = backend_connection_key(&backend);
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
        let failed_addr = failed.backend.addr.clone();
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
        let failed_addr = failed.backend.addr.clone();
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
    fn configures_pingora_tcp_health_check() {
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
