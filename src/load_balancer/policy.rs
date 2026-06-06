use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::ProxyConfig;

use super::backend::{BackendContainer, backend_container_ready, backend_container_set};
use super::backend::{BackendIdentity, FluxBackend};
use super::key::backend_key;
use super::selection::SelectionPass;
use super::state::{
    BackendConnectionCounters, BackendLatencyState, PassiveHealthState, SlowStartState,
};
use super::{
    LoadBalancerBackendRuntimeStats, LoadBalancerCircuitState, LoadBalancerRuntimeBackendState,
};

const MAX_RUNTIME_BACKEND_POLICY_OVERRIDE_ENTRIES: usize = 4096;

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

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
}

#[derive(Debug, Default)]
struct RuntimeBackendPolicyOverrides {
    state: Mutex<RuntimeBackendPolicyOverrideState>,
}

#[derive(Debug, Default)]
struct RuntimeBackendPolicyOverrideState {
    drain: std::collections::HashSet<u64>,
    disabled: std::collections::HashSet<u64>,
    forced_down: std::collections::HashSet<u64>,
    weights: std::collections::HashMap<u64, usize>,
    weight_changed_at_unix_secs: std::collections::HashMap<u64, u64>,
    changed_at_unix_secs: std::collections::HashMap<u64, u64>,
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
        }
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

    fn backup(&self, key: u64) -> bool {
        self.backup.contains(&key)
    }

    pub(super) fn drained(&self, key: u64) -> bool {
        self.drain.contains(&key) || self.runtime.drained(key)
    }

    pub(super) fn disabled(&self, key: u64) -> bool {
        self.disabled.contains(&key) || self.runtime.disabled(key)
    }

    fn priority_group(&self, key: u64) -> Option<u16> {
        self.priority.get(&key).copied()
    }

    fn max_in_flight_key(&self, key: u64) -> Option<usize> {
        self.max_in_flight.get(&key).copied()
    }

    fn locality_key(&self, key: u64) -> Option<Arc<str>> {
        self.localities.get(&key).cloned()
    }

    fn tags(&self, key: u64) -> Vec<String> {
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
        self.runtime
            .weight(backend_key(backend))
            .unwrap_or_else(|| backend.weight())
            .max(1)
    }

    pub(super) fn prune_stale(&self, live_keys: &std::collections::HashSet<u64>) {
        self.runtime.prune_stale(live_keys);
    }

    fn runtime_backend_state(&self, key: u64) -> Option<LoadBalancerRuntimeBackendState> {
        self.runtime.state(key)
    }

    fn runtime_backend_state_changed_at_unix_secs(&self, key: u64) -> Option<u64> {
        self.runtime.changed_at_unix_secs(key)
    }

    pub(super) fn runtime_backend_weight(&self, key: u64) -> Option<usize> {
        self.runtime.weight(key)
    }

    fn runtime_backend_weight_changed_at_unix_secs(&self, key: u64) -> Option<u64> {
        self.runtime.weight_changed_at_unix_secs(key)
    }
}

impl RuntimeBackendPolicyOverrides {
    fn drained(&self, key: u64) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain
            .contains(&key)
    }

    fn disabled(&self, key: u64) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.disabled.contains(&key) || state.forced_down.contains(&key)
    }

    fn set_state(&self, key: u64, state: LoadBalancerRuntimeBackendState) -> bool {
        let mut overrides = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        overrides.drain.remove(&key);
        overrides.disabled.remove(&key);
        overrides.forced_down.remove(&key);
        match state {
            LoadBalancerRuntimeBackendState::Normal
            | LoadBalancerRuntimeBackendState::ManualResume => {
                overrides.changed_at_unix_secs.remove(&key);
                true
            }
            LoadBalancerRuntimeBackendState::Drained => {
                if !runtime_override_key_has_capacity(&overrides.drain, key) {
                    return false;
                }
                overrides.drain.insert(key);
                overrides.changed_at_unix_secs.insert(key, unix_secs());
                true
            }
            LoadBalancerRuntimeBackendState::Disabled => {
                if !runtime_override_key_has_capacity(&overrides.disabled, key) {
                    return false;
                }
                overrides.disabled.insert(key);
                overrides.changed_at_unix_secs.insert(key, unix_secs());
                true
            }
            LoadBalancerRuntimeBackendState::ForcedDown => {
                if !runtime_override_key_has_capacity(&overrides.forced_down, key) {
                    return false;
                }
                overrides.forced_down.insert(key);
                overrides.changed_at_unix_secs.insert(key, unix_secs());
                true
            }
        }
    }

    fn set_weight(&self, key: u64, weight: Option<usize>) -> bool {
        let mut overrides = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(weight) = weight {
            if !overrides.weights.contains_key(&key)
                && overrides.weights.len() >= MAX_RUNTIME_BACKEND_POLICY_OVERRIDE_ENTRIES
            {
                return false;
            }
            overrides.weights.insert(key, weight);
            overrides
                .weight_changed_at_unix_secs
                .insert(key, unix_secs());
        } else {
            overrides.weights.remove(&key);
            overrides.weight_changed_at_unix_secs.remove(&key);
        }
        true
    }

    fn state(&self, key: u64) -> Option<LoadBalancerRuntimeBackendState> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.forced_down.contains(&key) {
            return Some(LoadBalancerRuntimeBackendState::ForcedDown);
        }
        if state.disabled.contains(&key) {
            return Some(LoadBalancerRuntimeBackendState::Disabled);
        }
        if state.drain.contains(&key) {
            return Some(LoadBalancerRuntimeBackendState::Drained);
        }
        None
    }

    fn changed_at_unix_secs(&self, key: u64) -> Option<u64> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .changed_at_unix_secs
            .get(&key)
            .copied()
    }

    fn weight(&self, key: u64) -> Option<usize> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .weights
            .get(&key)
            .copied()
    }

    fn weight_changed_at_unix_secs(&self, key: u64) -> Option<u64> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .weight_changed_at_unix_secs
            .get(&key)
            .copied()
    }

    fn prune_stale(&self, live_keys: &std::collections::HashSet<u64>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.drain.retain(|key| live_keys.contains(key));
        let retained_override_keys = state
            .disabled
            .union(&state.forced_down)
            .copied()
            .collect::<std::collections::HashSet<_>>();
        state
            .changed_at_unix_secs
            .retain(|key, _| live_keys.contains(key) || retained_override_keys.contains(key));
        state
            .weights
            .retain(|key, _| live_keys.contains(key) || retained_override_keys.contains(key));
        state
            .weight_changed_at_unix_secs
            .retain(|key, _| live_keys.contains(key) || retained_override_keys.contains(key));
    }
}

fn runtime_override_key_has_capacity(keys: &std::collections::HashSet<u64>, key: u64) -> bool {
    keys.contains(&key) || keys.len() < MAX_RUNTIME_BACKEND_POLICY_OVERRIDE_ENTRIES
}

fn backend_keys(upstreams: &[String]) -> std::collections::HashSet<u64> {
    upstreams
        .iter()
        .filter_map(|upstream| FluxBackend::new(upstream).ok())
        .map(|backend| backend_key(&backend))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_backend_policy_overrides_prune_only_transient_drain_keys() {
        let policy = BackendSelectionPolicy::default();
        policy.set_runtime_backend_state(1, LoadBalancerRuntimeBackendState::Drained);
        policy.set_runtime_backend_state(2, LoadBalancerRuntimeBackendState::Disabled);
        policy.set_runtime_backend_state(3, LoadBalancerRuntimeBackendState::ForcedDown);

        assert_eq!(
            policy.runtime_backend_state(1),
            Some(LoadBalancerRuntimeBackendState::Drained)
        );
        assert_eq!(
            policy.runtime_backend_state(2),
            Some(LoadBalancerRuntimeBackendState::Disabled)
        );
        assert_eq!(
            policy.runtime_backend_state(3),
            Some(LoadBalancerRuntimeBackendState::ForcedDown)
        );
        assert!(
            policy
                .runtime_backend_state_changed_at_unix_secs(1)
                .is_some()
        );

        policy.prune_stale(&[2].into_iter().collect());

        assert_eq!(policy.runtime_backend_state(1), None);
        assert_eq!(
            policy.runtime_backend_state(2),
            Some(LoadBalancerRuntimeBackendState::Disabled)
        );
        assert_eq!(
            policy.runtime_backend_state(3),
            Some(LoadBalancerRuntimeBackendState::ForcedDown)
        );
        assert_eq!(policy.runtime_backend_state_changed_at_unix_secs(1), None);
        assert!(
            policy
                .runtime_backend_state_changed_at_unix_secs(2)
                .is_some()
        );
        assert!(
            policy
                .runtime_backend_state_changed_at_unix_secs(3)
                .is_some()
        );
    }

    #[test]
    fn runtime_backend_policy_prune_stale_runtime_weight_keys() {
        let policy = BackendSelectionPolicy::default();
        policy.set_runtime_backend_weight(1, Some(4));
        policy.set_runtime_backend_weight(2, Some(8));

        assert_eq!(policy.runtime_backend_weight(1), Some(4));
        assert_eq!(policy.runtime_backend_weight(2), Some(8));

        policy.prune_stale(&[2].into_iter().collect());

        assert_eq!(policy.runtime_backend_weight(1), None);
        assert_eq!(policy.runtime_backend_weight(2), Some(8));
        assert_eq!(policy.runtime_backend_weight_changed_at_unix_secs(1), None);
        assert!(
            policy
                .runtime_backend_weight_changed_at_unix_secs(2)
                .is_some()
        );
    }

    #[test]
    fn runtime_backend_policy_keeps_weight_for_disabled_churned_backend() {
        let policy = BackendSelectionPolicy::default();
        assert!(policy.set_runtime_backend_state(1, LoadBalancerRuntimeBackendState::Disabled));
        assert!(policy.set_runtime_backend_weight(1, Some(4)));

        policy.prune_stale(&std::collections::HashSet::new());

        assert_eq!(
            policy.runtime_backend_state(1),
            Some(LoadBalancerRuntimeBackendState::Disabled)
        );
        assert_eq!(policy.runtime_backend_weight(1), Some(4));
        assert!(
            policy
                .runtime_backend_weight_changed_at_unix_secs(1)
                .is_some()
        );

        assert!(policy.set_runtime_backend_state(1, LoadBalancerRuntimeBackendState::Normal));
        policy.prune_stale(&std::collections::HashSet::new());

        assert_eq!(policy.runtime_backend_state(1), None);
        assert_eq!(policy.runtime_backend_weight(1), None);
        assert_eq!(policy.runtime_backend_weight_changed_at_unix_secs(1), None);
    }

    #[test]
    fn runtime_backend_policy_rejects_oversized_persistent_override_table() {
        let policy = BackendSelectionPolicy::default();
        for key in 0..MAX_RUNTIME_BACKEND_POLICY_OVERRIDE_ENTRIES as u64 {
            assert!(
                policy.set_runtime_backend_state(key, LoadBalancerRuntimeBackendState::Disabled)
            );
        }

        assert!(!policy.set_runtime_backend_state(
            MAX_RUNTIME_BACKEND_POLICY_OVERRIDE_ENTRIES as u64,
            LoadBalancerRuntimeBackendState::Disabled
        ));
        assert!(policy.set_runtime_backend_state(0, LoadBalancerRuntimeBackendState::ForcedDown));
        assert!(policy.set_runtime_backend_state(0, LoadBalancerRuntimeBackendState::Normal));
        assert!(policy.set_runtime_backend_state(
            MAX_RUNTIME_BACKEND_POLICY_OVERRIDE_ENTRIES as u64,
            LoadBalancerRuntimeBackendState::Disabled
        ));
    }
}

fn backend_priority_groups(config: &ProxyConfig) -> std::collections::HashMap<u64, u16> {
    config
        .upstreams
        .iter()
        .zip(&config.upstream_priority_groups)
        .filter_map(|(upstream, priority)| {
            let backend = FluxBackend::new(upstream).ok()?;
            Some((backend_key(&backend), *priority))
        })
        .collect()
}

fn backend_max_in_flight(config: &ProxyConfig) -> std::collections::HashMap<u64, usize> {
    config
        .upstreams
        .iter()
        .zip(&config.upstream_max_in_flight)
        .filter_map(|(upstream, max_in_flight)| {
            let backend = FluxBackend::new(upstream).ok()?;
            Some((backend_key(&backend), *max_in_flight))
        })
        .collect()
}

fn backend_localities(config: &ProxyConfig) -> std::collections::HashMap<u64, Arc<str>> {
    config
        .upstreams
        .iter()
        .zip(&config.upstream_localities)
        .filter_map(|(upstream, locality)| {
            let backend = FluxBackend::new(upstream).ok()?;
            Some((
                backend_key(&backend),
                Arc::<str>::from(locality.to_ascii_lowercase()),
            ))
        })
        .collect()
}

fn backend_tags(config: &ProxyConfig) -> std::collections::HashMap<u64, Arc<[String]>> {
    config
        .upstreams
        .iter()
        .zip(&config.upstream_tags)
        .filter_map(|(upstream, tags)| {
            let backend = FluxBackend::new(upstream).ok()?;
            Some((backend_key(&backend), Arc::<[String]>::from(tags.clone())))
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

pub(super) fn backend_aliases(config: &ProxyConfig) -> std::collections::HashMap<u64, Arc<str>> {
    config
        .upstreams
        .iter()
        .zip(&config.upstream_aliases)
        .filter_map(|(upstream, alias)| {
            let backend = FluxBackend::new(upstream).ok()?;
            Some((backend_key(&backend), Arc::<str>::from(alias.as_str())))
        })
        .collect()
}

#[derive(Clone, Copy)]
pub(super) struct BackendStatsInputs<'a> {
    pub(super) aliases: &'a std::collections::HashMap<u64, Arc<str>>,
    pub(super) passive_health: Option<&'a PassiveHealthState>,
    pub(super) slow_start: Option<&'a SlowStartState>,
    pub(super) counters: &'a BackendConnectionCounters,
    pub(super) backend_policy: &'a BackendSelectionPolicy,
    pub(super) persistence_entry_counts: &'a std::collections::HashMap<u64, usize>,
    pub(super) latency: Option<&'a Arc<BackendLatencyState>>,
}

impl<'a> BackendStatsInputs<'a> {
    pub(super) fn with_latency(self, latency: &'a Arc<BackendLatencyState>) -> Self {
        Self {
            latency: Some(latency),
            ..self
        }
    }
}

pub(super) fn load_balancer_backend_stats(
    inner: &impl BackendContainer,
    inputs: BackendStatsInputs<'_>,
) -> Vec<LoadBalancerBackendRuntimeStats> {
    backend_container_set(inner)
        .iter()
        .map(|backend| {
            let key = backend_key(backend);
            let passive_ejected = inputs
                .passive_health
                .is_some_and(|health| health.key_is_currently_ejected(key));
            LoadBalancerBackendRuntimeStats {
                #[cfg(not(feature = "privacy-mode"))]
                address: Some(backend.authority()),
                #[cfg(feature = "privacy-mode")]
                address: None,
                alias: inputs.aliases.get(&key).map(|alias| alias.to_string()),
                tags: inputs.backend_policy.tags(key),
                weight: backend.weight(),
                effective_weight: inputs.backend_policy.effective_weight(backend),
                runtime_weight_override: inputs.backend_policy.runtime_backend_weight(key),
                runtime_weight_changed_at_unix_secs: inputs
                    .backend_policy
                    .runtime_backend_weight_changed_at_unix_secs(key),
                locality: inputs
                    .backend_policy
                    .locality_key(key)
                    .map(|locality| locality.to_string()),
                locality_preferred: inputs.backend_policy.locality_key(key).is_some_and(
                    |locality| {
                        inputs
                            .backend_policy
                            .preferred_localities()
                            .contains(&locality)
                    },
                ),
                ready: backend_container_ready(inner, backend),
                backup: inputs.backend_policy.backup(key),
                drained: inputs.backend_policy.drained(key),
                disabled: inputs.backend_policy.disabled(key),
                runtime_state_override: inputs.backend_policy.runtime_backend_state(key),
                runtime_state_changed_at_unix_secs: inputs
                    .backend_policy
                    .runtime_backend_state_changed_at_unix_secs(key),
                persistence_entry_count: inputs
                    .persistence_entry_counts
                    .get(&key)
                    .copied()
                    .unwrap_or(0),
                priority_group: inputs.backend_policy.priority_group(key),
                max_in_flight: inputs.backend_policy.max_in_flight_key(key),
                in_flight: inputs.counters.count_existing(backend),
                passive_ejected,
                circuit_state: if passive_ejected {
                    LoadBalancerCircuitState::Open
                } else {
                    LoadBalancerCircuitState::Closed
                },
                passive_consecutive_failures: inputs
                    .passive_health
                    .and_then(|health| health.key_consecutive_failures(key)),
                passive_ejection_remaining_secs: inputs
                    .passive_health
                    .and_then(|health| health.key_ejection_remaining_secs(key)),
                slow_start_permitting: inputs
                    .slow_start
                    .is_none_or(|state| state.permits_read_only(backend)),
                latency_micros: inputs.latency.and_then(|state| state.score_key(key)),
            }
        })
        .collect()
}
