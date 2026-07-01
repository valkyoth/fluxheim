use std::io;
use std::sync::Arc;
use std::time::Duration;

use fluxheim_common::FluxError;

use super::MAX_RUNTIME_BACKEND_WEIGHT;
use super::api::LoadBalancerBackendRuntimeStats;
#[cfg(test)]
use super::backend::BackendIdentity;
use super::backend::{
    FluxBackend, FluxBackendDiscoveryRuntimeStatus, FluxLoadBalancerRuntime,
    RuntimeBackend as Backend, backend_container_snapshot,
};
use super::key::backend_key;
use super::policy::BackendSelectionPolicy;
use super::policy_stats::{BackendStatsInputs, load_balancer_backend_stats};
use super::selection::{
    LoadBalancerSelectInputs, select_least_connections, select_least_sessions, select_least_time,
    select_maglev, select_weighted_round_robin,
};
use super::selection_consistent::{
    select_bounded_load_consistent, select_consistent_hash, select_nginx_consistent_hash,
};
use super::selection_fnv::select_fnv_hash;
use super::selection_ketama::NginxKetamaTable;
use super::selection_maglev::MaglevTable;
use super::selection_power::select_power_of_two;
use super::state::{
    BackendConnectionCounters, BackendLatencyState, PassiveHealthState, SlowStartState,
};

#[derive(Clone)]
pub(super) enum UpstreamLoadBalancerInner {
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

    pub(super) fn select(
        &self,
        inputs: LoadBalancerSelectInputs<'_>,
    ) -> Option<super::SelectedUpstream> {
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

    pub(super) fn backend_count(&self) -> usize {
        backend_container_snapshot(self.container())
            .backends()
            .len()
    }

    pub(super) fn backend_stats(
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
    pub(super) fn backend_weights(&self) -> Vec<usize> {
        backend_weights(self.container())
    }

    pub(super) fn health_check_frequency(&self) -> Option<Duration> {
        self.container().health_check_frequency()
    }

    pub(super) fn discovery_runtime_status(&self) -> FluxBackendDiscoveryRuntimeStatus {
        self.container().discovery_runtime_status()
    }

    pub(super) fn runtime_backend_set_mutable(&self) -> bool {
        self.container().runtime_backend_set_mutable()
    }

    pub(super) fn supports_runtime_backend_set_mutation(&self) -> bool {
        !matches!(
            self,
            Self::NginxConsistentHash { .. } | Self::MaglevHash { .. }
        )
    }

    pub(super) fn add_runtime_backend(&self, backend: Backend) -> io::Result<usize> {
        self.container().add_runtime_backend(backend)
    }

    pub(super) fn remove_runtime_backend(&self, backend: &Backend) -> io::Result<usize> {
        self.container().remove_runtime_backend(backend)
    }

    pub(super) fn update_runtime_backend(
        &self,
        current: &Backend,
        updated: Backend,
    ) -> io::Result<usize> {
        self.container().update_runtime_backend(current, updated)
    }

    pub(super) fn parallel_health_check(&self) -> bool {
        self.container().parallel_health_check()
    }

    pub(super) fn latency_state(&self) -> Option<Arc<BackendLatencyState>> {
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
    pub(super) async fn run_health_check(&self, parallel: bool) {
        self.container().run_health_check(parallel).await;
    }

    pub(super) fn backend_by_member(
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

    pub(super) fn backend_by_policy_key(&self, key: u64) -> Option<Backend> {
        self.backends()
            .into_iter()
            .find(|backend| backend_key(backend) == key)
    }

    pub(super) fn backend_ready(&self, backend: &Backend) -> bool {
        backend_container_snapshot(self.container()).ready(backend)
    }

    pub(super) fn backends(&self) -> Vec<Backend> {
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

pub(super) fn runtime_backend_from_member(member: &str, weight: usize) -> io::Result<Backend> {
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
