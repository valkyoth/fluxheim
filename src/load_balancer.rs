use std::collections::hash_map::DefaultHasher;
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures::FutureExt;
use pingora::http::RequestHeader;
use pingora::http::ResponseHeader;
use pingora::lb::Backend;
use pingora::lb::Backends;
use pingora::lb::discovery::{ServiceDiscovery, Static};
use pingora::lb::health_check::{HttpHealthCheck, TcpHealthCheck};
use pingora::lb::prelude::LoadBalancer;
use pingora::lb::selection::{
    BackendIter, BackendSelection, Consistent, FNVHash, Random, RoundRobin,
};
use pingora::services::ServiceWithDependents;
use pingora::services::background::{BackgroundService, GenBackgroundService};
use pingora::{Error, ErrorType};
use serde::Serialize;

use crate::config::{
    LoadBalanceHealthCheckExpectedHeader, LoadBalanceHealthCheckExpectedStatusRange,
    LoadBalanceHealthCheckProtocol, LoadBalancePassiveHealthConfig, LoadBalancePersistenceConfig,
    LoadBalancePersistenceMode, LoadBalanceRetryConfig, LoadBalanceSelection,
    LoadBalanceSlowStartConfig, ProxyConfig,
};

pub type UpstreamLoadBalancerService = Box<dyn ServiceWithDependents>;

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
pub struct LoadBalancerBackendRuntimeStats {
    pub address: Option<String>,
    pub alias: Option<String>,
    pub weight: usize,
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
pub struct LoadBalancedConnectionPermit {
    counter: Arc<AtomicUsize>,
}

#[derive(Clone)]
pub struct LoadBalancedUpstreamReporter {
    backend_key: u64,
    passive_health: Option<Arc<PassiveHealthState>>,
    slow_start: Option<Arc<SlowStartState>>,
    latency: Option<Arc<BackendLatencyState>>,
}

impl Debug for LoadBalancedUpstreamReporter {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoadBalancedUpstreamReporter")
            .field("backend_key", &self.backend_key)
            .finish_non_exhaustive()
    }
}

impl Drop for LoadBalancedConnectionPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
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
        }
    }

    pub fn background_service_from_proxy_config(
        name: &str,
        config: &ProxyConfig,
    ) -> io::Result<Option<(Self, UpstreamLoadBalancerService)>> {
        match config.load_balance.selection {
            LoadBalanceSelection::RoundRobin => background_service_for::<RoundRobin>(
                name,
                config,
                UpstreamLoadBalancerInner::RoundRobin,
            ),
            LoadBalanceSelection::LeastConnections => {
                background_service_for::<RoundRobin>(name, config, |inner| {
                    UpstreamLoadBalancerInner::LeastConnections(inner)
                })
            }
            LoadBalanceSelection::LeastSessions => {
                background_service_for::<RoundRobin>(name, config, |inner| {
                    UpstreamLoadBalancerInner::LeastSessions(inner)
                })
            }
            LoadBalanceSelection::LeastTime => {
                background_service_for::<RoundRobin>(name, config, |inner| {
                    UpstreamLoadBalancerInner::LeastTime {
                        inner,
                        latency: Arc::new(BackendLatencyState::default()),
                    }
                })
            }
            LoadBalanceSelection::PowerOfTwo => {
                background_service_for::<Random>(name, config, |inner| {
                    UpstreamLoadBalancerInner::PowerOfTwo(inner)
                })
            }
            LoadBalanceSelection::SourceHash
            | LoadBalanceSelection::UriHash
            | LoadBalanceSelection::HeaderHash
            | LoadBalanceSelection::CookieHash => {
                background_service_for::<FNVHash>(name, config, UpstreamLoadBalancerInner::FnvHash)
            }
            LoadBalanceSelection::ConsistentSourceHash
            | LoadBalanceSelection::ConsistentUriHash
            | LoadBalanceSelection::ConsistentHeaderHash
            | LoadBalanceSelection::ConsistentCookieHash => background_service_for::<Consistent>(
                name,
                config,
                UpstreamLoadBalancerInner::ConsistentHash,
            ),
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

    fn select_fresh(
        &self,
        request: &RequestHeader,
        client_ip: Option<IpAddr>,
        persistence_key: Option<&[u8]>,
        persistence_outcome: Option<LoadBalancerPersistenceOutcome>,
    ) -> Option<SelectedUpstream> {
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
            LoadBalancedUpstreamReporter {
                backend_key: backend_connection_key(&selected.backend),
                passive_health: self.passive_health.clone(),
                slow_start: self.slow_start.clone(),
                latency,
            }
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
                .is_none_or(|state| state.permits(backend))
            && self.backend_policy.permits(
                backend,
                SelectionPass {
                    allow_backup: true,
                    minimum_priority_group: None,
                    ignore_slow_start: false,
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
            counters: Arc::new(BackendConnectionCounters::default()),
            backend_policy: BackendSelectionPolicy::from_config(config),
            max_iterations: config.load_balance.max_iterations,
            all_down_status: config.load_balance.all_down_status,
            retry: LoadBalancerRetryRuntimeStats::from_config(&config.load_balance.retry),
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
}

#[derive(Clone, Copy)]
struct LoadBalancerSelectInputs<'a> {
    key: Option<&'a [u8]>,
    max_iterations: usize,
    passive_health: Option<&'a PassiveHealthState>,
    slow_start: Option<&'a SlowStartState>,
    counters: &'a BackendConnectionCounters,
    backend_policy: &'a BackendSelectionPolicy,
    persistence_entry_counts: &'a std::collections::HashMap<u64, usize>,
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
            | Self::ConsistentHash(_) => None,
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
        }
    }
}

impl SelectedUpstream {
    fn new(backend: Backend) -> Self {
        Self {
            backend,
            alias: None,
            permit: None,
            reporter: None,
            persistence_outcome: None,
        }
    }
}

impl LoadBalancedUpstreamReporter {
    pub fn record_status(
        &self,
        status: u16,
        latency: Option<Duration>,
    ) -> LoadBalancedUpstreamOutcome {
        if let (Some(latency_state), Some(latency)) = (&self.latency, latency) {
            latency_state.record_latency(self.backend_key, latency);
        }
        let Some(passive_health) = &self.passive_health else {
            return LoadBalancedUpstreamOutcome {
                failed: false,
                ejected: false,
            };
        };
        let failed = passive_health.status_is_failure(status, latency);
        let ejected_at = passive_health.record_status(self.backend_key, status, latency);
        if let Some(restart_at) = ejected_at {
            self.reset_slow_start(restart_at);
        }
        LoadBalancedUpstreamOutcome {
            failed,
            ejected: ejected_at.is_some(),
        }
    }

    pub fn record_failure(&self) -> LoadBalancedUpstreamOutcome {
        let Some(passive_health) = &self.passive_health else {
            return LoadBalancedUpstreamOutcome {
                failed: true,
                ejected: false,
            };
        };
        let ejected_at = passive_health.record_failure(self.backend_key);
        if let Some(restart_at) = ejected_at {
            self.reset_slow_start(restart_at);
        }
        LoadBalancedUpstreamOutcome {
            failed: true,
            ejected: ejected_at.is_some(),
        }
    }

    fn reset_slow_start(&self, restart_at: Instant) {
        if let Some(slow_start) = &self.slow_start {
            slow_start.reset_at(self.backend_key, restart_at);
        }
    }
}

struct PassiveHealthState {
    consecutive_failure: usize,
    ejection: Duration,
    max_latency: Option<Duration>,
    failure_statuses: Arc<[u16]>,
    failure_status_ranges: Arc<[LoadBalanceHealthCheckExpectedStatusRange]>,
    backends: Arc<Mutex<std::collections::HashMap<u64, PassiveBackendHealth>>>,
}

#[derive(Clone, Copy, Debug, Default)]
struct PassiveBackendHealth {
    consecutive_failures: usize,
    ejected_until: Option<Instant>,
}

impl PassiveHealthState {
    fn from_config(config: &LoadBalancePassiveHealthConfig) -> Self {
        Self {
            consecutive_failure: config.consecutive_failure,
            ejection: Duration::from_secs(config.ejection_secs),
            max_latency: (config.max_latency_ms > 0)
                .then(|| Duration::from_millis(config.max_latency_ms)),
            failure_statuses: config.failure_statuses.clone().into(),
            failure_status_ranges: config.failure_status_ranges.clone().into(),
            backends: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    fn is_ejected(&self, backend: &Backend) -> bool {
        let key = backend_connection_key(backend);
        self.key_is_ejected(key)
    }

    fn key_is_ejected(&self, key: u64) -> bool {
        let mut backends = self
            .backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(state) = backends.get_mut(&key) else {
            return false;
        };
        if state
            .ejected_until
            .is_some_and(|until| Instant::now() < until)
        {
            return true;
        }
        state.ejected_until = None;
        false
    }

    fn key_is_currently_ejected(&self, key: u64) -> bool {
        self.backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .and_then(|state| state.ejected_until)
            .is_some_and(|until| Instant::now() < until)
    }

    fn key_consecutive_failures(&self, key: u64) -> Option<usize> {
        self.backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .map(|state| state.consecutive_failures)
    }

    fn key_ejection_remaining_secs(&self, key: u64) -> Option<u64> {
        self.backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .and_then(|state| state.ejected_until)
            .and_then(|until| {
                until
                    .checked_duration_since(Instant::now())
                    .map(|remaining| remaining.as_secs().saturating_add(1))
            })
    }

    fn record_status(&self, key: u64, status: u16, latency: Option<Duration>) -> Option<Instant> {
        if self.status_is_failure(status, latency) {
            self.record_failure(key)
        } else {
            self.record_success(key);
            None
        }
    }

    fn record_failure(&self, key: u64) -> Option<Instant> {
        let mut backends = self
            .backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = backends.entry(key).or_default();
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= self.consecutive_failure {
            state.consecutive_failures = 0;
            let ejected_until = Instant::now() + self.ejection;
            state.ejected_until = Some(ejected_until);
            return Some(ejected_until);
        }
        None
    }

    fn record_success(&self, key: u64) {
        let mut backends = self
            .backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(state) = backends.get_mut(&key) {
            state.consecutive_failures = 0;
            state.ejected_until = None;
        }
    }

    fn clear_key(&self, key: u64) {
        self.backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key);
    }

    fn failure_status(&self, status: u16) -> bool {
        if self.failure_statuses.is_empty() && self.failure_status_ranges.is_empty() {
            return (500..=599).contains(&status);
        }
        self.failure_statuses.contains(&status)
            || self
                .failure_status_ranges
                .iter()
                .any(|range| (range.start..=range.end).contains(&status))
    }

    fn status_is_failure(&self, status: u16, latency: Option<Duration>) -> bool {
        self.failure_status(status)
            || latency.is_some_and(|latency| {
                self.max_latency
                    .is_some_and(|max_latency| latency >= max_latency)
            })
    }
}

#[derive(Debug)]
struct SlowStartState {
    duration: Duration,
    backends: Mutex<std::collections::HashMap<u64, Instant>>,
}

impl SlowStartState {
    fn from_config(config: &LoadBalanceSlowStartConfig) -> Self {
        Self {
            duration: Duration::from_secs(config.duration_secs),
            backends: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn permits(&self, backend: &Backend) -> bool {
        let now = Instant::now();
        let key = backend_connection_key(backend);
        let mut backends = self
            .backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let started_at = *backends.entry(key).or_insert(now);
        let elapsed = now.saturating_duration_since(started_at);
        if elapsed >= self.duration {
            return true;
        }

        let progress_per_mille =
            ((elapsed.as_millis() * 1000) / self.duration.as_millis()).clamp(1, 1000) as u64;
        (key % 1000) < progress_per_mille
    }

    fn reset_at(&self, key: u64, restart_at: Instant) {
        self.backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key, restart_at);
    }

    fn permits_read_only(&self, backend: &Backend) -> bool {
        let now = Instant::now();
        let key = backend_connection_key(backend);
        let Some(started_at) = self
            .backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .copied()
        else {
            return true;
        };
        let elapsed = now.saturating_duration_since(started_at);
        if elapsed >= self.duration {
            return true;
        }

        let progress_per_mille =
            ((elapsed.as_millis() * 1000) / self.duration.as_millis()).clamp(1, 1000) as u64;
        (key % 1000) < progress_per_mille
    }
}

#[derive(Default)]
struct BackendConnectionCounters {
    counters: Mutex<std::collections::HashMap<u64, Arc<AtomicUsize>>>,
}

impl BackendConnectionCounters {
    fn count(&self, backend: &Backend) -> usize {
        self.counter(backend).load(Ordering::Acquire)
    }

    fn count_existing(&self, backend: &Backend) -> usize {
        self.counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&backend_connection_key(backend))
            .map(|counter| counter.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    fn permit(
        &self,
        backend: &Backend,
        max_in_flight: Option<usize>,
    ) -> Option<LoadBalancedConnectionPermit> {
        let counter = self.counter(backend);
        let mut current = counter.load(Ordering::Acquire);
        loop {
            if max_in_flight.is_some_and(|limit| current >= limit) {
                return None;
            }
            let next = current.checked_add(1)?;
            match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Some(LoadBalancedConnectionPermit { counter }),
                Err(observed) => current = observed,
            }
        }
    }

    fn counter(&self, backend: &Backend) -> Arc<AtomicUsize> {
        let mut counters = self
            .counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        counters
            .entry(backend_connection_key(backend))
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone()
    }
}

#[derive(Default)]
struct BackendLatencyState {
    latency_micros: Mutex<std::collections::HashMap<u64, u64>>,
}

impl BackendLatencyState {
    fn record_latency(&self, key: u64, latency: Duration) {
        let sample = latency.as_micros().clamp(1, u128::from(u64::MAX)) as u64;
        let mut latency_micros = self
            .latency_micros
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        latency_micros
            .entry(key)
            .and_modify(|stored| {
                *stored = stored.saturating_mul(3).saturating_add(sample) / 4;
            })
            .or_insert(sample);
    }

    fn score(&self, backend: &Backend) -> Option<u64> {
        self.score_key(backend_connection_key(backend))
    }

    fn score_key(&self, key: u64) -> Option<u64> {
        self.latency_micros
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .copied()
    }
}

#[derive(Debug)]
struct LoadBalancerPersistenceState {
    mode: LoadBalancePersistenceMode,
    header: Option<String>,
    cookie: Option<String>,
    ttl: Duration,
    table_max_entries: usize,
    table: Mutex<std::collections::HashMap<Vec<u8>, LoadBalancerPersistenceEntry>>,
}

#[derive(Clone, Copy, Debug)]
struct LoadBalancerPersistenceEntry {
    backend_key: u64,
    expires_at: Instant,
}

impl LoadBalancerPersistenceState {
    fn from_config(config: &LoadBalancePersistenceConfig) -> Self {
        Self {
            mode: config.mode,
            header: config.header.clone(),
            cookie: config.cookie.clone(),
            ttl: Duration::from_secs(config.ttl_secs),
            table_max_entries: config.table_max_entries,
            table: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn key(&self, request: &RequestHeader, client_ip: Option<IpAddr>) -> Option<Vec<u8>> {
        match self.mode {
            LoadBalancePersistenceMode::SourceIp => client_ip.map(|ip| ip.to_string().into_bytes()),
            LoadBalancePersistenceMode::Header => self
                .header
                .as_deref()
                .and_then(|header| request_header_key(request, header)),
            LoadBalancePersistenceMode::Cookie => self
                .cookie
                .as_deref()
                .and_then(|cookie| cookie_key(request, cookie)),
        }
    }

    fn lookup(&self, key: &[u8]) -> Option<u64> {
        let now = Instant::now();
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = table.get(key).copied()?;
        if entry.expires_at <= now {
            table.remove(key);
            return None;
        }
        Some(entry.backend_key)
    }

    fn record(&self, key: &[u8], backend_key: u64) {
        let now = Instant::now();
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if table.len() >= self.table_max_entries && !table.contains_key(key) {
            table.retain(|_, entry| entry.expires_at > now);
            if table.len() >= self.table_max_entries
                && let Some(stale_key) = table
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires_at)
                    .map(|(key, _)| key.clone())
            {
                table.remove(&stale_key);
            }
        }
        if table.len() < self.table_max_entries || table.contains_key(key) {
            table.insert(
                key.to_vec(),
                LoadBalancerPersistenceEntry {
                    backend_key,
                    expires_at: now + self.ttl,
                },
            );
        }
    }

    fn clear(&self) -> usize {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = table.len();
        table.clear();
        removed
    }

    fn runtime_counts(&self) -> (usize, std::collections::HashMap<u64, usize>) {
        let now = Instant::now();
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        table.retain(|_, entry| entry.expires_at > now);
        let mut backend_counts = std::collections::HashMap::new();
        for entry in table.values() {
            *backend_counts.entry(entry.backend_key).or_insert(0) += 1;
        }
        (table.len(), backend_counts)
    }
}

fn backend_connection_key(backend: &Backend) -> u64 {
    let mut hasher = DefaultHasher::new();
    backend.hash(&mut hasher);
    hasher.finish()
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[derive(Clone, Debug, Default)]
struct BackendSelectionPolicy {
    backup: Arc<std::collections::HashSet<u64>>,
    drain: Arc<std::collections::HashSet<u64>>,
    disabled: Arc<std::collections::HashSet<u64>>,
    runtime: Arc<RuntimeBackendPolicyOverrides>,
    priority: Arc<std::collections::HashMap<u64, u16>>,
    max_in_flight: Arc<std::collections::HashMap<u64, usize>>,
    priority_groups: Arc<[u16]>,
    priority_group_min_active: usize,
}

#[derive(Debug, Default)]
struct RuntimeBackendPolicyOverrides {
    drain: Mutex<std::collections::HashSet<u64>>,
    disabled: Mutex<std::collections::HashSet<u64>>,
    forced_down: Mutex<std::collections::HashSet<u64>>,
    changed_at_unix_secs: Mutex<std::collections::HashMap<u64, u64>>,
}

impl BackendSelectionPolicy {
    fn from_config(config: &ProxyConfig) -> Self {
        let priority = backend_priority_groups(config);
        let priority_groups = sorted_priority_groups(&priority);
        Self {
            backup: backend_policy_keys(&config.backup_upstreams).into(),
            drain: backend_policy_keys(&config.drain_upstreams).into(),
            disabled: backend_policy_keys(&config.disabled_upstreams).into(),
            runtime: Arc::new(RuntimeBackendPolicyOverrides::default()),
            priority: priority.into(),
            max_in_flight: backend_max_in_flight(config).into(),
            priority_groups: priority_groups.into(),
            priority_group_min_active: config.upstream_priority_group_min_active,
        }
    }

    fn permits(
        &self,
        backend: &Backend,
        pass: SelectionPass,
        counters: &BackendConnectionCounters,
    ) -> bool {
        let key = backend_policy_key(backend);
        !self.disabled(key)
            && !self.drained(key)
            && (pass.allow_backup || !self.backup.contains(&key))
            && pass
                .minimum_priority_group
                .is_none_or(|group| self.priority.get(&key).copied().unwrap_or(0) >= group)
            && self
                .max_in_flight
                .get(&key)
                .is_none_or(|limit| counters.count(backend) < *limit)
    }

    fn priority_groups(&self) -> &[u16] {
        &self.priority_groups
    }

    fn priority_group_min_active(&self) -> usize {
        self.priority_group_min_active
    }

    fn is_lowest_priority_group(&self, group: u16) -> bool {
        self.priority_groups
            .last()
            .is_some_and(|lowest| *lowest == group)
    }

    fn max_in_flight(&self, backend: &Backend) -> Option<usize> {
        self.max_in_flight
            .get(&backend_policy_key(backend))
            .copied()
    }

    fn backup(&self, key: u64) -> bool {
        self.backup.contains(&key)
    }

    fn drained(&self, key: u64) -> bool {
        self.drain.contains(&key) || self.runtime.drained(key)
    }

    fn disabled(&self, key: u64) -> bool {
        self.disabled.contains(&key) || self.runtime.disabled(key)
    }

    fn priority_group(&self, key: u64) -> Option<u16> {
        self.priority.get(&key).copied()
    }

    fn max_in_flight_key(&self, key: u64) -> Option<usize> {
        self.max_in_flight.get(&key).copied()
    }

    fn set_runtime_backend_state(&self, key: u64, state: LoadBalancerRuntimeBackendState) {
        self.runtime.set_state(key, state);
    }

    fn runtime_backend_state(&self, key: u64) -> Option<LoadBalancerRuntimeBackendState> {
        self.runtime.state(key)
    }

    fn runtime_backend_state_changed_at_unix_secs(&self, key: u64) -> Option<u64> {
        self.runtime.changed_at_unix_secs(key)
    }
}

impl RuntimeBackendPolicyOverrides {
    fn drained(&self, key: u64) -> bool {
        self.drain
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&key)
    }

    fn disabled(&self, key: u64) -> bool {
        self.disabled
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&key)
            || self.forced_down(key)
    }

    fn forced_down(&self, key: u64) -> bool {
        self.forced_down
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&key)
    }

    fn set_state(&self, key: u64, state: LoadBalancerRuntimeBackendState) {
        let mut drain = self
            .drain
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut disabled = self
            .disabled
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut forced_down = self
            .forced_down
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut changed_at = self
            .changed_at_unix_secs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        drain.remove(&key);
        disabled.remove(&key);
        forced_down.remove(&key);
        match state {
            LoadBalancerRuntimeBackendState::Normal
            | LoadBalancerRuntimeBackendState::ManualResume => {
                changed_at.remove(&key);
            }
            LoadBalancerRuntimeBackendState::Drained => {
                drain.insert(key);
                changed_at.insert(key, unix_secs());
            }
            LoadBalancerRuntimeBackendState::Disabled => {
                disabled.insert(key);
                changed_at.insert(key, unix_secs());
            }
            LoadBalancerRuntimeBackendState::ForcedDown => {
                forced_down.insert(key);
                changed_at.insert(key, unix_secs());
            }
        }
    }

    fn state(&self, key: u64) -> Option<LoadBalancerRuntimeBackendState> {
        let drain = self
            .drain
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let disabled = self
            .disabled
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let forced_down = self
            .forced_down
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if forced_down.contains(&key) {
            return Some(LoadBalancerRuntimeBackendState::ForcedDown);
        }
        if disabled.contains(&key) {
            return Some(LoadBalancerRuntimeBackendState::Disabled);
        }
        if drain.contains(&key) {
            return Some(LoadBalancerRuntimeBackendState::Drained);
        }
        None
    }

    fn changed_at_unix_secs(&self, key: u64) -> Option<u64> {
        self.changed_at_unix_secs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .copied()
    }
}

fn backend_policy_keys(upstreams: &[String]) -> std::collections::HashSet<u64> {
    upstreams
        .iter()
        .filter_map(|upstream| Backend::new(upstream).ok())
        .map(|backend| backend_policy_key(&backend))
        .collect()
}

fn backend_policy_key(backend: &Backend) -> u64 {
    let mut hasher = DefaultHasher::new();
    backend.addr.hash(&mut hasher);
    hasher.finish()
}

fn backend_priority_groups(config: &ProxyConfig) -> std::collections::HashMap<u64, u16> {
    config
        .upstreams
        .iter()
        .zip(&config.upstream_priority_groups)
        .filter_map(|(upstream, priority)| {
            let backend = Backend::new(upstream).ok()?;
            Some((backend_policy_key(&backend), *priority))
        })
        .collect()
}

fn backend_max_in_flight(config: &ProxyConfig) -> std::collections::HashMap<u64, usize> {
    config
        .upstreams
        .iter()
        .zip(&config.upstream_max_in_flight)
        .filter_map(|(upstream, max_in_flight)| {
            let backend = Backend::new(upstream).ok()?;
            Some((backend_policy_key(&backend), *max_in_flight))
        })
        .collect()
}

fn sorted_priority_groups(priority: &std::collections::HashMap<u64, u16>) -> Vec<u16> {
    let mut groups = priority
        .values()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    groups.reverse();
    groups
}

fn backend_aliases(config: &ProxyConfig) -> std::collections::HashMap<u64, Arc<str>> {
    config
        .upstreams
        .iter()
        .zip(&config.upstream_aliases)
        .filter_map(|(upstream, alias)| {
            let backend = Backend::new(upstream).ok()?;
            Some((
                backend_policy_key(&backend),
                Arc::<str>::from(alias.as_str()),
            ))
        })
        .collect()
}

#[derive(Clone, Copy)]
struct BackendStatsInputs<'a> {
    aliases: &'a std::collections::HashMap<u64, Arc<str>>,
    passive_health: Option<&'a PassiveHealthState>,
    slow_start: Option<&'a SlowStartState>,
    counters: &'a BackendConnectionCounters,
    backend_policy: &'a BackendSelectionPolicy,
    persistence_entry_counts: &'a std::collections::HashMap<u64, usize>,
    latency: Option<&'a Arc<BackendLatencyState>>,
}

impl<'a> BackendStatsInputs<'a> {
    fn with_latency(self, latency: &'a Arc<BackendLatencyState>) -> Self {
        Self {
            latency: Some(latency),
            ..self
        }
    }
}

fn load_balancer_backend_stats<S>(
    inner: &LoadBalancer<S>,
    inputs: BackendStatsInputs<'_>,
) -> Vec<LoadBalancerBackendRuntimeStats>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    inner
        .backends()
        .get_backend()
        .iter()
        .map(|backend| {
            let policy_key = backend_policy_key(backend);
            let connection_key = backend_connection_key(backend);
            let passive_ejected = inputs
                .passive_health
                .is_some_and(|health| health.key_is_currently_ejected(connection_key));
            LoadBalancerBackendRuntimeStats {
                #[cfg(not(feature = "privacy-mode"))]
                address: Some(backend.addr.to_string()),
                #[cfg(feature = "privacy-mode")]
                address: None,
                alias: inputs
                    .aliases
                    .get(&policy_key)
                    .map(|alias| alias.to_string()),
                weight: backend.weight,
                ready: inner.backends().ready(backend),
                backup: inputs.backend_policy.backup(policy_key),
                drained: inputs.backend_policy.drained(policy_key),
                disabled: inputs.backend_policy.disabled(policy_key),
                runtime_state_override: inputs.backend_policy.runtime_backend_state(policy_key),
                runtime_state_changed_at_unix_secs: inputs
                    .backend_policy
                    .runtime_backend_state_changed_at_unix_secs(policy_key),
                persistence_entry_count: inputs
                    .persistence_entry_counts
                    .get(&policy_key)
                    .copied()
                    .unwrap_or(0),
                priority_group: inputs.backend_policy.priority_group(policy_key),
                max_in_flight: inputs.backend_policy.max_in_flight_key(policy_key),
                in_flight: inputs.counters.count_existing(backend),
                passive_ejected,
                circuit_state: if passive_ejected {
                    LoadBalancerCircuitState::Open
                } else {
                    LoadBalancerCircuitState::Closed
                },
                passive_consecutive_failures: inputs
                    .passive_health
                    .and_then(|health| health.key_consecutive_failures(connection_key)),
                passive_ejection_remaining_secs: inputs
                    .passive_health
                    .and_then(|health| health.key_ejection_remaining_secs(connection_key)),
                slow_start_permitting: inputs
                    .slow_start
                    .is_none_or(|state| state.permits_read_only(backend)),
                latency_micros: inputs
                    .latency
                    .and_then(|state| state.score_key(connection_key)),
            }
        })
        .collect()
}

fn select_pingora<S>(
    inner: &LoadBalancer<S>,
    key: &[u8],
    max_iterations: usize,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    counters: &BackendConnectionCounters,
    backend_policy: &BackendSelectionPolicy,
) -> Option<Backend>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    let context = SelectionContext {
        passive_health,
        slow_start,
        counters,
        backend_policy,
    };
    for priority_group in selection_priority_groups(backend_policy) {
        let pass = SelectionPass {
            minimum_priority_group: priority_group,
            allow_backup: false,
            ignore_slow_start: false,
        };
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(backend) =
            select_pingora_with_backup_policy(inner, key, max_iterations, context, pass)
        {
            return Some(backend);
        }
    }
    for priority_group in selection_priority_groups(backend_policy) {
        let pass = SelectionPass {
            minimum_priority_group: priority_group,
            allow_backup: true,
            ignore_slow_start: false,
        };
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(backend) =
            select_pingora_with_backup_policy(inner, key, max_iterations, context, pass)
        {
            return Some(backend);
        }
    }
    for priority_group in selection_priority_groups(backend_policy) {
        let pass = SelectionPass {
            minimum_priority_group: priority_group,
            allow_backup: false,
            ignore_slow_start: true,
        };
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(backend) =
            select_pingora_with_backup_policy(inner, key, max_iterations, context, pass)
        {
            return Some(backend);
        }
    }
    None
}

#[derive(Clone, Copy)]
struct SelectionPass {
    minimum_priority_group: Option<u16>,
    allow_backup: bool,
    ignore_slow_start: bool,
}

#[derive(Clone, Copy)]
struct SelectionContext<'a> {
    passive_health: Option<&'a PassiveHealthState>,
    slow_start: Option<&'a SlowStartState>,
    counters: &'a BackendConnectionCounters,
    backend_policy: &'a BackendSelectionPolicy,
}

fn selection_priority_groups(backend_policy: &BackendSelectionPolicy) -> Vec<Option<u16>> {
    if backend_policy.priority_groups().is_empty() {
        return vec![None];
    }
    backend_policy
        .priority_groups()
        .iter()
        .copied()
        .map(Some)
        .collect()
}

fn priority_activation_satisfied<S>(
    inner: &LoadBalancer<S>,
    context: SelectionContext<'_>,
    pass: SelectionPass,
) -> bool
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    if pass.minimum_priority_group.is_none()
        || context.backend_policy.priority_group_min_active() <= 1
        || pass
            .minimum_priority_group
            .is_some_and(|group| context.backend_policy.is_lowest_priority_group(group))
    {
        return true;
    }

    inner
        .backends()
        .get_backend()
        .iter()
        .filter(|backend| {
            inner.backends().ready(backend)
                && context
                    .backend_policy
                    .permits(backend, pass, context.counters)
                && context
                    .passive_health
                    .is_none_or(|health| !health.is_ejected(backend))
                && (pass.ignore_slow_start
                    || context
                        .slow_start
                        .is_none_or(|state| state.permits(backend)))
        })
        .take(context.backend_policy.priority_group_min_active())
        .count()
        >= context.backend_policy.priority_group_min_active()
}

fn select_pingora_with_backup_policy<S>(
    inner: &LoadBalancer<S>,
    key: &[u8],
    max_iterations: usize,
    context: SelectionContext<'_>,
    pass: SelectionPass,
) -> Option<Backend>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    inner.select_with(key, max_iterations, |backend, ready| {
        ready
            && context
                .backend_policy
                .permits(backend, pass, context.counters)
            && context
                .passive_health
                .is_none_or(|health| !health.is_ejected(backend))
            && (pass.ignore_slow_start
                || context
                    .slow_start
                    .is_none_or(|state| state.permits(backend)))
    })
}

fn select_least_connections(
    inner: &LoadBalancer<RoundRobin>,
    counters: &BackendConnectionCounters,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
) -> Option<SelectedUpstream> {
    let context = SelectionContext {
        passive_health,
        slow_start,
        counters,
        backend_policy,
    };
    for priority_group in selection_priority_groups(backend_policy) {
        let pass = SelectionPass {
            minimum_priority_group: priority_group,
            allow_backup: false,
            ignore_slow_start: false,
        };
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(selected) = select_least_connections_with_backup_policy(
            inner,
            counters,
            passive_health,
            slow_start,
            backend_policy,
            pass,
        ) {
            return Some(selected);
        }
    }
    for priority_group in selection_priority_groups(backend_policy) {
        let pass = SelectionPass {
            minimum_priority_group: priority_group,
            allow_backup: true,
            ignore_slow_start: false,
        };
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(selected) = select_least_connections_with_backup_policy(
            inner,
            counters,
            passive_health,
            slow_start,
            backend_policy,
            pass,
        ) {
            return Some(selected);
        }
    }
    for priority_group in selection_priority_groups(backend_policy) {
        let pass = SelectionPass {
            minimum_priority_group: priority_group,
            allow_backup: false,
            ignore_slow_start: true,
        };
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(selected) = select_least_connections_with_backup_policy(
            inner,
            counters,
            passive_health,
            slow_start,
            backend_policy,
            pass,
        ) {
            return Some(selected);
        }
    }
    None
}

fn select_least_connections_with_backup_policy(
    inner: &LoadBalancer<RoundRobin>,
    counters: &BackendConnectionCounters,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
    pass: SelectionPass,
) -> Option<SelectedUpstream> {
    let mut selected = None;
    for backend in inner.backends().get_backend().iter() {
        if !inner.backends().ready(backend)
            || !backend_policy.permits(backend, pass, counters)
            || passive_health.is_some_and(|health| health.is_ejected(backend))
            || (!pass.ignore_slow_start && slow_start.is_some_and(|state| !state.permits(backend)))
        {
            continue;
        }
        let connections = counters.count(backend);
        let weight = backend.weight.max(1);
        if selected.as_ref().is_none_or(
            |(_, selected_connections, selected_weight): &(Backend, usize, usize)| {
                least_connections_score_is_lower(
                    connections,
                    weight,
                    *selected_connections,
                    *selected_weight,
                )
            },
        ) {
            selected = Some((backend.clone(), connections, weight));
        }
    }
    let backend = selected.map(|(backend, _, _)| backend)?;
    Some(SelectedUpstream {
        permit: None,
        alias: None,
        backend,
        reporter: None,
        persistence_outcome: None,
    })
}

fn select_least_sessions(
    inner: &LoadBalancer<RoundRobin>,
    counters: &BackendConnectionCounters,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
    persistence_entry_counts: &std::collections::HashMap<u64, usize>,
) -> Option<SelectedUpstream> {
    let context = SelectionContext {
        passive_health,
        slow_start,
        counters,
        backend_policy,
    };
    for priority_group in selection_priority_groups(backend_policy) {
        let pass = SelectionPass {
            minimum_priority_group: priority_group,
            allow_backup: false,
            ignore_slow_start: false,
        };
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(selected) = select_least_sessions_with_backup_policy(
            inner,
            counters,
            passive_health,
            slow_start,
            backend_policy,
            persistence_entry_counts,
            pass,
        ) {
            return Some(selected);
        }
    }
    for priority_group in selection_priority_groups(backend_policy) {
        let pass = SelectionPass {
            minimum_priority_group: priority_group,
            allow_backup: true,
            ignore_slow_start: false,
        };
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(selected) = select_least_sessions_with_backup_policy(
            inner,
            counters,
            passive_health,
            slow_start,
            backend_policy,
            persistence_entry_counts,
            pass,
        ) {
            return Some(selected);
        }
    }
    for priority_group in selection_priority_groups(backend_policy) {
        let pass = SelectionPass {
            minimum_priority_group: priority_group,
            allow_backup: false,
            ignore_slow_start: true,
        };
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(selected) = select_least_sessions_with_backup_policy(
            inner,
            counters,
            passive_health,
            slow_start,
            backend_policy,
            persistence_entry_counts,
            pass,
        ) {
            return Some(selected);
        }
    }
    None
}

fn select_least_sessions_with_backup_policy(
    inner: &LoadBalancer<RoundRobin>,
    counters: &BackendConnectionCounters,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
    persistence_entry_counts: &std::collections::HashMap<u64, usize>,
    pass: SelectionPass,
) -> Option<SelectedUpstream> {
    let mut selected = None;
    for backend in inner.backends().get_backend().iter() {
        if !inner.backends().ready(backend)
            || !backend_policy.permits(backend, pass, counters)
            || passive_health.is_some_and(|health| health.is_ejected(backend))
            || (!pass.ignore_slow_start && slow_start.is_some_and(|state| !state.permits(backend)))
        {
            continue;
        }
        let sessions = persistence_entry_counts
            .get(&backend_policy_key(backend))
            .copied()
            .unwrap_or(0);
        let weight = backend.weight.max(1);
        if selected.as_ref().is_none_or(
            |(_, selected_sessions, selected_weight): &(Backend, usize, usize)| {
                least_connections_score_is_lower(
                    sessions,
                    weight,
                    *selected_sessions,
                    *selected_weight,
                )
            },
        ) {
            selected = Some((backend.clone(), sessions, weight));
        }
    }
    let backend = selected.map(|(backend, _, _)| backend)?;
    Some(SelectedUpstream {
        permit: None,
        alias: None,
        backend,
        reporter: None,
        persistence_outcome: None,
    })
}

fn least_connections_score_is_lower(
    candidate_connections: usize,
    candidate_weight: usize,
    selected_connections: usize,
    selected_weight: usize,
) -> bool {
    candidate_connections.saturating_mul(selected_weight)
        < selected_connections.saturating_mul(candidate_weight)
}

fn select_least_time(
    inner: &LoadBalancer<RoundRobin>,
    counters: &BackendConnectionCounters,
    latency: &BackendLatencyState,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
) -> Option<SelectedUpstream> {
    let context = SelectionContext {
        passive_health,
        slow_start,
        counters,
        backend_policy,
    };
    for priority_group in selection_priority_groups(backend_policy) {
        let pass = SelectionPass {
            minimum_priority_group: priority_group,
            allow_backup: false,
            ignore_slow_start: false,
        };
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(selected) = select_least_time_with_backup_policy(
            inner,
            counters,
            latency,
            passive_health,
            slow_start,
            backend_policy,
            pass,
        ) {
            return Some(selected);
        }
    }
    for priority_group in selection_priority_groups(backend_policy) {
        let pass = SelectionPass {
            minimum_priority_group: priority_group,
            allow_backup: true,
            ignore_slow_start: false,
        };
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(selected) = select_least_time_with_backup_policy(
            inner,
            counters,
            latency,
            passive_health,
            slow_start,
            backend_policy,
            pass,
        ) {
            return Some(selected);
        }
    }
    for priority_group in selection_priority_groups(backend_policy) {
        let pass = SelectionPass {
            minimum_priority_group: priority_group,
            allow_backup: false,
            ignore_slow_start: true,
        };
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(selected) = select_least_time_with_backup_policy(
            inner,
            counters,
            latency,
            passive_health,
            slow_start,
            backend_policy,
            pass,
        ) {
            return Some(selected);
        }
    }
    None
}

fn select_least_time_with_backup_policy(
    inner: &LoadBalancer<RoundRobin>,
    counters: &BackendConnectionCounters,
    latency: &BackendLatencyState,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
    pass: SelectionPass,
) -> Option<SelectedUpstream> {
    let mut selected = None;
    for backend in inner.backends().get_backend().iter() {
        if !inner.backends().ready(backend)
            || !backend_policy.permits(backend, pass, counters)
            || passive_health.is_some_and(|health| health.is_ejected(backend))
            || (!pass.ignore_slow_start && slow_start.is_some_and(|state| !state.permits(backend)))
        {
            continue;
        }
        let latency_score = latency.score(backend).unwrap_or(0);
        let connections = counters.count(backend);
        let weight = backend.weight.max(1);
        if selected.as_ref().is_none_or(
            |(_, selected_latency, selected_connections, selected_weight): &(
                Backend,
                u64,
                usize,
                usize,
            )| {
                least_time_score_is_lower(
                    latency_score,
                    connections,
                    weight,
                    *selected_latency,
                    *selected_connections,
                    *selected_weight,
                )
            },
        ) {
            selected = Some((backend.clone(), latency_score, connections, weight));
        }
    }
    let backend = selected.map(|(backend, _, _, _)| backend)?;
    Some(SelectedUpstream {
        permit: None,
        alias: None,
        backend,
        reporter: None,
        persistence_outcome: None,
    })
}

fn least_time_score_is_lower(
    candidate_latency: u64,
    candidate_connections: usize,
    candidate_weight: usize,
    selected_latency: u64,
    selected_connections: usize,
    selected_weight: usize,
) -> bool {
    let candidate = candidate_latency.saturating_mul(selected_weight as u64);
    let selected = selected_latency.saturating_mul(candidate_weight as u64);
    candidate < selected
        || (candidate == selected
            && least_connections_score_is_lower(
                candidate_connections,
                candidate_weight,
                selected_connections,
                selected_weight,
            ))
}

fn select_power_of_two(
    inner: &LoadBalancer<Random>,
    counters: &BackendConnectionCounters,
    max_iterations: usize,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
) -> Option<SelectedUpstream> {
    let first = select_pingora(
        inner,
        b"",
        max_iterations,
        passive_health,
        slow_start,
        counters,
        backend_policy,
    )?;
    let first_key = backend_connection_key(&first);
    let second = (0..max_iterations)
        .filter_map(|_| {
            select_pingora(
                inner,
                b"",
                max_iterations,
                passive_health,
                slow_start,
                counters,
                backend_policy,
            )
        })
        .find(|backend| backend_connection_key(backend) != first_key)
        .unwrap_or_else(|| first.clone());
    let selected = if counters.count(&second) < counters.count(&first) {
        second
    } else {
        first
    };
    Some(SelectedUpstream {
        permit: None,
        alias: None,
        backend: selected,
        reporter: None,
        persistence_outcome: None,
    })
}

#[derive(Clone, Debug)]
enum LoadBalanceKeySource {
    None,
    SourceIp,
    Uri,
    Header(String),
    Cookie(String),
}

impl LoadBalanceKeySource {
    fn from_config(config: &ProxyConfig) -> Self {
        match config.load_balance.selection {
            LoadBalanceSelection::RoundRobin => Self::None,
            LoadBalanceSelection::LeastConnections => Self::None,
            LoadBalanceSelection::LeastSessions => Self::None,
            LoadBalanceSelection::LeastTime => Self::None,
            LoadBalanceSelection::PowerOfTwo => Self::None,
            LoadBalanceSelection::SourceHash | LoadBalanceSelection::ConsistentSourceHash => {
                Self::SourceIp
            }
            LoadBalanceSelection::UriHash | LoadBalanceSelection::ConsistentUriHash => Self::Uri,
            LoadBalanceSelection::HeaderHash | LoadBalanceSelection::ConsistentHeaderHash => config
                .load_balance
                .hash_header
                .clone()
                .map(Self::Header)
                .unwrap_or(Self::None),
            LoadBalanceSelection::CookieHash | LoadBalanceSelection::ConsistentCookieHash => config
                .load_balance
                .hash_cookie
                .clone()
                .map(Self::Cookie)
                .unwrap_or(Self::None),
        }
    }

    fn request_key(&self, request: &RequestHeader, client_ip: Option<IpAddr>) -> Option<Vec<u8>> {
        match self {
            Self::None => None,
            Self::SourceIp => client_ip.map(|ip| ip.to_string().into_bytes()),
            Self::Uri => Some(request.uri.to_string().into_bytes()),
            Self::Header(name) => request_header_key(request, name),
            Self::Cookie(name) => cookie_key(request, name),
        }
    }
}

fn request_header_key(request: &RequestHeader, name: &str) -> Option<Vec<u8>> {
    let mut key = Vec::new();
    for value in request.headers.get_all(name) {
        let bytes = value.as_bytes();
        key.extend_from_slice(&bytes.len().to_le_bytes());
        key.extend_from_slice(bytes);
    }
    (!key.is_empty()).then_some(key)
}

fn cookie_key(request: &RequestHeader, name: &str) -> Option<Vec<u8>> {
    for header in request.headers.get_all("cookie") {
        let Ok(header) = header.to_str() else {
            continue;
        };
        for part in header.split(';') {
            let Some((candidate, value)) = part.trim().split_once('=') else {
                continue;
            };
            if candidate.trim() == name {
                return Some(value.trim().as_bytes().to_vec());
            }
        }
    }
    None
}

fn configured_load_balancer<S>(config: &ProxyConfig) -> io::Result<Option<LoadBalancer<S>>>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    if config.upstreams.len() < 2
        && config.upstreams_file.is_none()
        && config.upstream_dns_refresh_secs.is_none()
    {
        return Ok(None);
    }

    let mut load_balancer = LoadBalancer::from_backends(configured_backend_discovery(config)?);
    if config.upstreams_file.is_some() {
        load_balancer.update_frequency = Some(Duration::from_secs(
            config.upstreams_file_refresh_secs.clamp(1, 300),
        ));
    } else if let Some(refresh_secs) = config.upstream_dns_refresh_secs {
        load_balancer.update_frequency = Some(Duration::from_secs(refresh_secs.clamp(1, 300)));
    }
    load_balancer
        .update()
        .now_or_never()
        .ok_or_else(|| io::Error::other("static load balancer update blocked unexpectedly"))?
        .map_err(|error| io::Error::other(error.to_string()))?;
    apply_disabled_backend_enablement(&load_balancer, config);
    if config.load_balance.health_check.enabled {
        let health_check = configured_health_check(config)?;
        load_balancer.set_health_check(health_check);
        load_balancer.health_check_frequency = Some(Duration::from_secs(
            config.load_balance.health_check.interval_secs,
        ));
        load_balancer.parallel_health_check = config.load_balance.health_check.parallel;
    }

    Ok(Some(load_balancer))
}

fn apply_disabled_backend_enablement<S>(load_balancer: &LoadBalancer<S>, config: &ProxyConfig)
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    for upstream in &config.disabled_upstreams {
        if let Ok(backend) = Backend::new(upstream) {
            load_balancer.backends().set_enable(&backend, false);
        }
    }
}

struct FileUpstreamDiscovery {
    path: PathBuf,
}

#[async_trait]
impl ServiceDiscovery for FileUpstreamDiscovery {
    async fn discover(
        &self,
    ) -> pingora::Result<(
        std::collections::BTreeSet<Backend>,
        std::collections::HashMap<u64, bool>,
    )> {
        let upstreams = read_proxy_upstreams_file_for_discovery(self.path.clone()).await?;
        let mut backends = std::collections::BTreeSet::new();
        for upstream in upstreams {
            let backend = Backend::new(&upstream).map_err(|error| {
                Error::because(
                    ErrorType::InvalidHTTPHeader,
                    "proxy upstreams file contains an invalid backend",
                    io::Error::other(error.to_string()),
                )
            })?;
            backends.insert(backend);
        }
        Ok((backends, std::collections::HashMap::new()))
    }
}

async fn read_proxy_upstreams_file_for_discovery(path: PathBuf) -> pingora::Result<Vec<String>> {
    let result = if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::spawn_blocking(move || crate::config::read_proxy_upstreams_file(&path))
            .await
            .map_err(|error| {
                Error::because(
                    ErrorType::InternalError,
                    "proxy upstreams file discovery task failed",
                    io::Error::other(error.to_string()),
                )
            })?
    } else {
        // Pingora performs the initial load-balancer update synchronously during
        // construction. There is no Tokio reactor yet in that path, so this
        // bootstrap read must stay immediately ready for now_or_never().
        crate::config::read_proxy_upstreams_file(&path)
    };

    result.map_err(|error| {
        Error::because(
            ErrorType::ReadError,
            "failed to read proxy upstreams file",
            error,
        )
    })
}

struct DnsUpstreamDiscovery {
    upstreams: Arc<[String]>,
}

#[async_trait]
impl ServiceDiscovery for DnsUpstreamDiscovery {
    async fn discover(
        &self,
    ) -> pingora::Result<(
        std::collections::BTreeSet<Backend>,
        std::collections::HashMap<u64, bool>,
    )> {
        let mut backends = std::collections::BTreeSet::new();
        for upstream in self.upstreams.iter() {
            let resolved = resolve_proxy_upstream_for_discovery(upstream).await?;
            for address in resolved {
                let backend = Backend::new(&address.to_string()).map_err(|error| {
                    Error::because(
                        ErrorType::InternalError,
                        "resolved proxy upstream is not usable as a backend",
                        io::Error::other(error.to_string()),
                    )
                })?;
                backends.insert(backend);
            }
        }
        if backends.is_empty() {
            return Error::e_explain(
                ErrorType::ConnectError,
                "DNS discovery resolved no proxy upstreams",
            );
        }
        Ok((backends, std::collections::HashMap::new()))
    }
}

async fn resolve_proxy_upstream_for_discovery(upstream: &str) -> pingora::Result<Vec<SocketAddr>> {
    let result = if tokio::runtime::Handle::try_current().is_ok() {
        tokio::net::lookup_host(upstream)
            .await
            .map(|resolved| resolved.collect())
    } else {
        // See read_proxy_upstreams_file_for_discovery(): construction-time
        // update is polled synchronously before a reactor is available. Later
        // refreshes run under Tokio and use lookup_host().
        upstream
            .to_socket_addrs()
            .map(|resolved| resolved.collect::<Vec<_>>())
    };

    result.map_err(|error| {
        Error::because(
            ErrorType::ConnectError,
            "failed to resolve proxy upstream",
            error,
        )
    })
}

fn configured_health_check(
    config: &ProxyConfig,
) -> io::Result<Box<dyn pingora::lb::health_check::HealthCheck + Send + Sync + 'static>> {
    match config.load_balance.health_check.protocol {
        LoadBalanceHealthCheckProtocol::Tcp => {
            let mut health_check = if config.upstream_tls {
                TcpHealthCheck::new_tls(&config.upstream_sni())
            } else {
                TcpHealthCheck::new()
            };
            health_check.consecutive_success = config.load_balance.health_check.consecutive_success;
            health_check.consecutive_failure = config.load_balance.health_check.consecutive_failure;
            apply_health_check_peer_timeouts(
                &mut health_check.peer_template.options.connection_timeout,
                None,
                config,
            );
            Ok(health_check)
        }
        LoadBalanceHealthCheckProtocol::Http => configured_http_health_check(config).map(|check| {
            check as Box<dyn pingora::lb::health_check::HealthCheck + Send + Sync + 'static>
        }),
    }
}

fn configured_http_health_check(config: &ProxyConfig) -> io::Result<Box<HttpHealthCheck>> {
    let host = config
        .load_balance
        .health_check
        .host
        .clone()
        .unwrap_or_else(|| config.upstream_sni());
    let mut request = RequestHeader::build(
        config.load_balance.health_check.method.as_str(),
        config.load_balance.health_check.path.as_bytes(),
        None,
    )
    .map_err(|error| io::Error::other(error.to_string()))?;
    request
        .append_header("Host", &host)
        .map_err(|error| io::Error::other(error.to_string()))?;

    let mut health_check = HttpHealthCheck::new(&host, config.upstream_tls);
    health_check.req = request;
    health_check.consecutive_success = config.load_balance.health_check.consecutive_success;
    health_check.consecutive_failure = config.load_balance.health_check.consecutive_failure;
    health_check.reuse_connection = config.load_balance.health_check.reuse_connection;
    health_check.port_override = config.load_balance.health_check.port_override;
    apply_health_check_peer_timeouts(
        &mut health_check.peer_template.options.connection_timeout,
        Some(&mut health_check.peer_template.options.read_timeout),
        config,
    );
    if !config
        .load_balance
        .health_check
        .expected_statuses
        .is_empty()
        || !config
            .load_balance
            .health_check
            .expected_status_ranges
            .is_empty()
        || !config.load_balance.health_check.expected_headers.is_empty()
    {
        let expected_statuses: Arc<[u16]> = config
            .load_balance
            .health_check
            .expected_statuses
            .clone()
            .into();
        let expected_status_ranges: Arc<[LoadBalanceHealthCheckExpectedStatusRange]> = config
            .load_balance
            .health_check
            .expected_status_ranges
            .clone()
            .into();
        let expected_headers: Arc<[LoadBalanceHealthCheckExpectedHeader]> = config
            .load_balance
            .health_check
            .expected_headers
            .clone()
            .into();
        health_check.validator = Some(Box::new(move |response| {
            validate_http_health_response(
                response,
                &expected_statuses,
                &expected_status_ranges,
                &expected_headers,
            )
        }));
    }
    Ok(Box::new(health_check))
}

fn apply_health_check_peer_timeouts(
    connection_timeout: &mut Option<Duration>,
    read_timeout: Option<&mut Option<Duration>>,
    config: &ProxyConfig,
) {
    if let Some(timeout) = config
        .load_balance
        .health_check
        .connect_timeout_secs
        .or(config.connect_timeout_secs)
    {
        *connection_timeout = Some(Duration::from_secs(timeout));
    }
    if let Some(read_timeout) = read_timeout
        && let Some(timeout) = config
            .load_balance
            .health_check
            .read_timeout_secs
            .or(config.read_timeout_secs)
    {
        *read_timeout = Some(Duration::from_secs(timeout));
    }
}

fn validate_http_health_response(
    response: &ResponseHeader,
    expected_statuses: &[u16],
    expected_status_ranges: &[LoadBalanceHealthCheckExpectedStatusRange],
    expected_headers: &[LoadBalanceHealthCheckExpectedHeader],
) -> pingora::Result<()> {
    let status = response.status.as_u16();
    if expected_statuses.is_empty() && expected_status_ranges.is_empty() {
        if status != 200 {
            return Error::e_explain(
                ErrorType::HTTPStatus(status),
                "unexpected HTTP health check status",
            );
        }
    } else if !expected_statuses.contains(&status)
        && !expected_status_ranges
            .iter()
            .any(|range| (range.start..=range.end).contains(&status))
    {
        return Error::e_explain(
            ErrorType::HTTPStatus(status),
            "unexpected HTTP health check status",
        );
    }

    for expected in expected_headers {
        let mut matched = false;
        for value in response.headers.get_all(expected.name.as_str()) {
            if value.as_bytes() == expected.value.as_bytes() {
                matched = true;
                break;
            }
        }
        if !matched {
            return Error::e_explain(
                ErrorType::InvalidHTTPHeader,
                "missing expected HTTP health check header",
            );
        }
    }
    Ok(())
}

fn background_service_for<S>(
    name: &str,
    config: &ProxyConfig,
    wrap: fn(Arc<LoadBalancer<S>>) -> UpstreamLoadBalancerInner,
) -> io::Result<Option<(UpstreamLoadBalancer, UpstreamLoadBalancerService)>>
where
    S: BackendSelection + Send + Sync + 'static,
    S::Iter: BackendIter,
    LoadBalancer<S>: BackgroundService,
{
    let Some(inner) = configured_load_balancer::<S>(config)? else {
        return Ok(None);
    };

    let service = GenBackgroundService::new(format!("LB {name}"), Arc::new(inner));
    let load_balancer = UpstreamLoadBalancer::from_inner(wrap(service.task()), config);
    Ok(Some((load_balancer, Box::new(service))))
}

fn configured_backends(config: &ProxyConfig) -> io::Result<std::collections::BTreeSet<Backend>> {
    let mut backends = std::collections::BTreeSet::new();
    for (index, upstream) in config.upstreams.iter().enumerate() {
        let weight = config.upstream_weights.get(index).copied().unwrap_or(1);
        let backend = Backend::new_with_weight(upstream, weight)
            .map_err(|error| io::Error::other(error.to_string()))?;
        backends.insert(backend);
    }
    Ok(backends)
}

fn configured_backend_discovery(config: &ProxyConfig) -> io::Result<Backends> {
    if let Some(path) = &config.upstreams_file {
        return Ok(Backends::new(Box::new(FileUpstreamDiscovery {
            path: path.clone(),
        })));
    }
    if config.upstream_dns_refresh_secs.is_some() {
        return Ok(Backends::new(Box::new(DnsUpstreamDiscovery {
            upstreams: config.upstreams.clone().into(),
        })));
    }

    Ok(Backends::new(Static::new(configured_backends(config)?)))
}

#[cfg(test)]
fn backend_weights<S>(inner: &LoadBalancer<S>) -> Vec<usize>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
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
    use std::time::{Duration, Instant};

    use pingora::http::{RequestHeader, ResponseHeader};
    use pingora::lb::Backend;

    use crate::config::{
        LoadBalanceConfig, LoadBalanceHealthCheckConfig, LoadBalanceHealthCheckExpectedHeader,
        LoadBalanceHealthCheckExpectedStatusRange, LoadBalanceHealthCheckProtocol,
        LoadBalancePassiveHealthConfig, LoadBalancePersistenceConfig, LoadBalancePersistenceMode,
        LoadBalanceSelection, LoadBalanceSlowStartConfig, ProxyConfig,
    };

    use super::{
        LoadBalancedUpstreamReporter, LoadBalancerCircuitState, LoadBalancerPersistenceOutcome,
        LoadBalancerRuntimeBackendState, PassiveHealthState, SlowStartState, UpstreamLoadBalancer,
        backend_connection_key, configured_http_health_check, validate_http_health_response,
    };
    use crate::test_support::unique_temp_path;

    fn install_test_crypto_provider() {
        #[cfg(feature = "tls-rustls-backend")]
        let _ = crate::tls::install_rustls_crypto_provider();
    }

    fn request() -> RequestHeader {
        RequestHeader::build("GET", b"/app?id=42", None).unwrap()
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
        let backend = (3000..4000)
            .filter_map(|port| Backend::new(&format!("127.0.0.1:{port}")).ok())
            .find(|backend| backend_connection_key(backend) % 1000 > 900)
            .expect("test backend with high slow-start gate");

        assert!(!state.permits(&backend));
        state.backends.lock().unwrap().insert(
            backend_connection_key(&backend),
            Instant::now() - Duration::from_secs(61),
        );
        assert!(state.permits(&backend));
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
        let backend = (3000..4000)
            .filter_map(|port| Backend::new(&format!("127.0.0.1:{port}")).ok())
            .find(|backend| backend_connection_key(backend) % 1000 > 900)
            .expect("test backend with high slow-start gate");
        let key = backend_connection_key(&backend);
        slow_start
            .backends
            .lock()
            .unwrap()
            .insert(key, Instant::now() - Duration::from_secs(61));
        assert!(slow_start.permits(&backend));

        let reporter = LoadBalancedUpstreamReporter {
            backend_key: key,
            passive_health: Some(Arc::new(PassiveHealthState::from_config(
                &LoadBalancePassiveHealthConfig {
                    enabled: true,
                    consecutive_failure: 1,
                    ejection_secs: 1,
                    ..LoadBalancePassiveHealthConfig::default()
                },
            ))),
            slow_start: Some(slow_start.clone()),
            latency: None,
        };
        let outcome = reporter.record_failure();
        assert!(outcome.failed);
        assert!(outcome.ejected);

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
    fn configures_pingora_http_health_check() {
        let health_check = configured_http_health_check(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            connect_timeout_secs: Some(2),
            read_timeout_secs: Some(4),
            load_balance: LoadBalanceConfig {
                health_check: LoadBalanceHealthCheckConfig {
                    enabled: true,
                    protocol: LoadBalanceHealthCheckProtocol::Http,
                    consecutive_success: 2,
                    consecutive_failure: 3,
                    method: "HEAD".to_owned(),
                    path: "/healthz".to_owned(),
                    host: Some("origin.example.test".to_owned()),
                    expected_statuses: vec![200, 204],
                    expected_status_ranges: vec![LoadBalanceHealthCheckExpectedStatusRange {
                        start: 300,
                        end: 399,
                    }],
                    expected_headers: vec![LoadBalanceHealthCheckExpectedHeader {
                        name: "x-fluxheim-health".to_owned(),
                        value: "ready".to_owned(),
                    }],
                    reuse_connection: true,
                    port_override: Some(8081),
                    connect_timeout_secs: Some(5),
                    read_timeout_secs: Some(6),
                    ..LoadBalanceHealthCheckConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap();

        assert_eq!(health_check.consecutive_success, 2);
        assert_eq!(health_check.consecutive_failure, 3);
        assert_eq!(health_check.req.method.as_str(), "HEAD");
        assert!(health_check.reuse_connection);
        assert_eq!(health_check.port_override, Some(8081));
        assert_eq!(
            health_check.peer_template.options.connection_timeout,
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            health_check.peer_template.options.read_timeout,
            Some(Duration::from_secs(6))
        );
        assert!(health_check.validator.is_some());
    }

    #[test]
    fn validates_http_health_check_expected_headers() {
        let expected_statuses = [204];
        let expected_status_ranges = [LoadBalanceHealthCheckExpectedStatusRange {
            start: 300,
            end: 399,
        }];
        let expected_headers = [LoadBalanceHealthCheckExpectedHeader {
            name: "x-fluxheim-health".to_owned(),
            value: "ready".to_owned(),
        }];
        let mut response = ResponseHeader::build(204, None).unwrap();
        response
            .append_header("x-fluxheim-health", "ready")
            .unwrap();
        assert!(
            validate_http_health_response(
                &response,
                &expected_statuses,
                &expected_status_ranges,
                &expected_headers
            )
            .is_ok()
        );

        let missing = ResponseHeader::build(204, None).unwrap();
        assert!(
            validate_http_health_response(
                &missing,
                &expected_statuses,
                &expected_status_ranges,
                &expected_headers
            )
            .is_err()
        );

        let ranged = ResponseHeader::build(302, None).unwrap();
        assert!(validate_http_health_response(&ranged, &[], &expected_status_ranges, &[]).is_ok());
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
