use std::sync::{Arc, Mutex};

use fluxheim_config::ProxyConfig;

use super::LoadBalancerRuntimeBackendState;
use super::backend::{BackendIdentity, FluxBackend};
use super::key::backend_key;
use super::policy_config::{
    backend_localities, backend_max_in_flight, backend_priority_groups, backend_tags,
    sorted_priority_groups,
};
pub(crate) use super::policy_runtime::RuntimeBackendPolicySnapshot;
#[cfg(test)]
pub(crate) use super::policy_runtime::{
    MAX_RUNTIME_BACKEND_POLICY_OVERRIDE_ENTRIES, RuntimeBackendPolicyStateSnapshot,
};
use super::policy_runtime::{PreparedRuntimeBackendPolicySnapshot, RuntimeBackendPolicyOverrides};
use super::selection::SelectionPass;
use super::state::BackendConnectionCounters;

const MAX_HEALTH_DERIVED_WEIGHT_ENTRIES: usize = 4096;

#[derive(Clone, Debug, Default)]
pub(super) struct BackendSelectionPolicy {
    backup: Arc<std::collections::HashSet<u64>>,
    drain: Arc<std::collections::HashSet<u64>>,
    disabled: Arc<std::collections::HashSet<u64>>,
    runtime: Arc<RuntimeBackendPolicyOverrides>,
    priority: Arc<std::collections::HashMap<u64, u16>>,
    localities: Arc<std::collections::HashMap<u64, Arc<str>>>,
    preferred_localities: Arc<std::collections::HashSet<Arc<str>>>,
    tags: Arc<std::collections::HashMap<u64, Arc<[String]>>>,
    max_in_flight: Arc<std::collections::HashMap<u64, usize>>,
    priority_groups: Arc<[u16]>,
    priority_group_min_active: usize,
    health_weights: Arc<HealthDerivedWeights>,
}

#[derive(Debug, Default)]
pub(super) struct HealthDerivedWeights {
    weights: Mutex<std::collections::HashMap<u64, u8>>,
}

impl BackendSelectionPolicy {
    pub(super) fn from_config(config: &ProxyConfig) -> Self {
        let priority = backend_priority_groups(config);
        let priority_groups = sorted_priority_groups(&priority);
        Self {
            backup: backend_keys(&config.backup_upstreams).into(),
            drain: backend_keys(&config.drain_upstreams).into(),
            disabled: backend_keys(&config.disabled_upstreams).into(),
            runtime: Arc::new(RuntimeBackendPolicyOverrides::default()),
            priority: priority.into(),
            localities: backend_localities(config).into(),
            preferred_localities: config
                .preferred_upstream_localities
                .iter()
                .map(|locality| Arc::<str>::from(locality.to_ascii_lowercase()))
                .collect::<std::collections::HashSet<_>>()
                .into(),
            tags: backend_tags(config).into(),
            max_in_flight: backend_max_in_flight(config).into(),
            priority_groups: priority_groups.into(),
            priority_group_min_active: config.upstream_priority_group_min_active,
            health_weights: Arc::new(HealthDerivedWeights::default()),
        }
    }

    pub(super) fn health_weights(&self) -> Arc<HealthDerivedWeights> {
        self.health_weights.clone()
    }

    pub(super) fn permits(
        &self,
        backend: &impl BackendIdentity,
        pass: SelectionPass,
        counters: &BackendConnectionCounters,
    ) -> bool {
        let key = backend_key(backend);
        !self.disabled(key)
            && !self.drained(key)
            && (pass.allow_backup || !self.backup.contains(&key))
            && pass
                .minimum_priority_group
                .is_none_or(|group| self.priority.get(&key).copied().unwrap_or(0) >= group)
            && self.locality_permits(key, pass)
            && self
                .max_in_flight
                .get(&key)
                .is_none_or(|limit| counters.count(backend) < *limit)
    }

    pub(super) fn priority_groups(&self) -> &[u16] {
        &self.priority_groups
    }

    pub(super) fn priority_group_min_active(&self) -> usize {
        self.priority_group_min_active
    }

    pub(super) fn is_lowest_priority_group(&self, group: u16) -> bool {
        self.priority_groups
            .last()
            .is_some_and(|lowest| *lowest == group)
    }

    pub(super) fn max_in_flight(&self, backend: &impl BackendIdentity) -> Option<usize> {
        self.max_in_flight.get(&backend_key(backend)).copied()
    }

    pub(super) fn preferred_localities(&self) -> &std::collections::HashSet<Arc<str>> {
        &self.preferred_localities
    }

    fn locality_permits(&self, key: u64, pass: SelectionPass) -> bool {
        if pass.ignore_locality || self.preferred_localities.is_empty() {
            return true;
        }
        self.localities
            .get(&key)
            .is_some_and(|locality| self.preferred_localities.contains(locality))
    }

    pub(super) fn backup(&self, key: u64) -> bool {
        self.backup.contains(&key)
    }

    pub(super) fn drained(&self, key: u64) -> bool {
        self.drain.contains(&key) || self.runtime.drained(key)
    }

    pub(super) fn disabled(&self, key: u64) -> bool {
        self.disabled.contains(&key) || self.runtime.disabled(key)
    }

    pub(super) fn priority_group(&self, key: u64) -> Option<u16> {
        self.priority.get(&key).copied()
    }

    pub(super) fn max_in_flight_key(&self, key: u64) -> Option<usize> {
        self.max_in_flight.get(&key).copied()
    }

    pub(super) fn locality_key(&self, key: u64) -> Option<Arc<str>> {
        self.localities.get(&key).cloned()
    }

    pub(super) fn tags(&self, key: u64) -> Vec<String> {
        self.tags
            .get(&key)
            .map(|tags| tags.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub(super) fn set_runtime_backend_state(
        &self,
        key: u64,
        state: LoadBalancerRuntimeBackendState,
    ) -> bool {
        self.runtime.set_state(key, state)
    }

    pub(super) fn set_runtime_backend_weight(&self, key: u64, weight: Option<usize>) -> bool {
        self.runtime.set_weight(key, weight)
    }

    pub(super) fn effective_weight(&self, backend: &impl BackendIdentity) -> usize {
        let key = backend_key(backend);
        let base = self
            .runtime
            .weight(key)
            .unwrap_or_else(|| backend.weight())
            .max(1);
        self.health_weights
            .weight_percent(key)
            .map_or(base, |percent| {
                base.saturating_mul(usize::from(percent)).saturating_add(99) / 100
            })
            .max(1)
    }

    pub(super) fn health_weight_percent(&self, key: u64) -> Option<u8> {
        self.health_weights.weight_percent(key)
    }

    pub(super) fn prune_stale(&self, live_keys: &std::collections::HashSet<u64>) {
        self.runtime.prune_stale(live_keys);
        self.health_weights.prune_stale(live_keys);
    }

    pub(super) fn clear_runtime_key(&self, key: u64) {
        self.runtime.clear_key(key);
        self.health_weights.clear_key(key);
    }

    pub(crate) fn runtime_snapshot(&self) -> RuntimeBackendPolicySnapshot {
        self.runtime.snapshot()
    }

    #[cfg(test)]
    pub(crate) fn restore_runtime_snapshot(
        &self,
        snapshot: &RuntimeBackendPolicySnapshot,
    ) -> Result<(), &'static str> {
        self.runtime.restore_snapshot(snapshot)
    }

    pub(super) fn prepare_runtime_snapshot(
        &self,
        snapshot: &RuntimeBackendPolicySnapshot,
    ) -> Result<PreparedRuntimeBackendPolicySnapshot, &'static str> {
        self.runtime.prepare_snapshot(snapshot)
    }

    pub(super) fn commit_runtime_snapshot(&self, prepared: PreparedRuntimeBackendPolicySnapshot) {
        self.runtime.commit_snapshot(prepared);
    }

    pub(super) fn runtime_backend_state(
        &self,
        key: u64,
    ) -> Option<LoadBalancerRuntimeBackendState> {
        self.runtime.state(key)
    }

    pub(super) fn runtime_backend_state_changed_at_unix_secs(&self, key: u64) -> Option<u64> {
        self.runtime.changed_at_unix_secs(key)
    }

    pub(super) fn runtime_backend_weight(&self, key: u64) -> Option<usize> {
        self.runtime.weight(key)
    }

    pub(super) fn runtime_backend_weight_changed_at_unix_secs(&self, key: u64) -> Option<u64> {
        self.runtime.weight_changed_at_unix_secs(key)
    }
}

impl HealthDerivedWeights {
    pub(super) fn set_percent(&self, key: u64, percent: Option<u8>) {
        let mut weights = self
            .weights
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(percent) = percent.filter(|percent| (1..100).contains(percent)) {
            if weights.len() >= MAX_HEALTH_DERIVED_WEIGHT_ENTRIES && !weights.contains_key(&key) {
                log::warn!(
                    target: "fluxheim::security",
                    "health-weight map at capacity ({MAX_HEALTH_DERIVED_WEIGHT_ENTRIES}); degradation signal dropped for backend key {key:#x}"
                );
                return;
            }
            weights.insert(key, percent);
        } else {
            weights.remove(&key);
        }
    }

    pub(super) fn weight_percent(&self, key: u64) -> Option<u8> {
        self.weights
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .copied()
    }

    fn prune_stale(&self, live_keys: &std::collections::HashSet<u64>) {
        self.weights
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|key, _| live_keys.contains(key));
    }

    fn clear_key(&self, key: u64) {
        self.weights
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key);
    }
}

fn backend_keys(upstreams: &[String]) -> std::collections::HashSet<u64> {
    upstreams
        .iter()
        .filter_map(|upstream| FluxBackend::new(upstream).ok())
        .map(|backend| backend_key(&backend))
        .collect()
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod policy_tests;
