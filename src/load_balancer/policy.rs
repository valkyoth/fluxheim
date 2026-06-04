use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use pingora::lb::Backend;
use pingora::lb::prelude::LoadBalancer;
use pingora::lb::selection::{BackendIter, BackendSelection};

use crate::config::ProxyConfig;

use super::selection::SelectionPass;
use super::selection::fnv1a64;
use super::state::{
    BackendConnectionCounters, BackendLatencyState, PassiveHealthState, SlowStartState,
    backend_connection_key,
};
use super::{
    LoadBalancerBackendRuntimeStats, LoadBalancerCircuitState, LoadBalancerRuntimeBackendState,
};

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
            backup: backend_policy_keys(&config.backup_upstreams).into(),
            drain: backend_policy_keys(&config.drain_upstreams).into(),
            disabled: backend_policy_keys(&config.disabled_upstreams).into(),
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

    pub(super) fn max_in_flight(&self, backend: &Backend) -> Option<usize> {
        self.max_in_flight
            .get(&backend_policy_key(backend))
            .copied()
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
    ) {
        self.runtime.set_state(key, state);
    }

    pub(super) fn set_runtime_backend_weight(&self, key: u64, weight: Option<usize>) {
        self.runtime.set_weight(key, weight);
    }

    pub(super) fn effective_weight(&self, backend: &Backend) -> usize {
        self.runtime
            .weight(backend_policy_key(backend))
            .unwrap_or(backend.weight)
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

    fn set_state(&self, key: u64, state: LoadBalancerRuntimeBackendState) {
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
            }
            LoadBalancerRuntimeBackendState::Drained => {
                overrides.drain.insert(key);
                overrides.changed_at_unix_secs.insert(key, unix_secs());
            }
            LoadBalancerRuntimeBackendState::Disabled => {
                overrides.disabled.insert(key);
                overrides.changed_at_unix_secs.insert(key, unix_secs());
            }
            LoadBalancerRuntimeBackendState::ForcedDown => {
                overrides.forced_down.insert(key);
                overrides.changed_at_unix_secs.insert(key, unix_secs());
            }
        }
    }

    fn set_weight(&self, key: u64, weight: Option<usize>) {
        let mut overrides = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(weight) = weight {
            overrides.weights.insert(key, weight);
            overrides
                .weight_changed_at_unix_secs
                .insert(key, unix_secs());
        } else {
            overrides.weights.remove(&key);
            overrides.weight_changed_at_unix_secs.remove(&key);
        }
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
        state.weights.retain(|key, _| live_keys.contains(key));
        state
            .weight_changed_at_unix_secs
            .retain(|key, _| live_keys.contains(key));
    }
}

fn backend_policy_keys(upstreams: &[String]) -> std::collections::HashSet<u64> {
    upstreams
        .iter()
        .filter_map(|upstream| Backend::new(upstream).ok())
        .map(|backend| backend_policy_key(&backend))
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
}

pub(super) fn backend_policy_key(backend: &Backend) -> u64 {
    fnv1a64(backend.addr.to_string().as_bytes())
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

fn backend_localities(config: &ProxyConfig) -> std::collections::HashMap<u64, Arc<str>> {
    config
        .upstreams
        .iter()
        .zip(&config.upstream_localities)
        .filter_map(|(upstream, locality)| {
            let backend = Backend::new(upstream).ok()?;
            Some((
                backend_policy_key(&backend),
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
            let backend = Backend::new(upstream).ok()?;
            Some((
                backend_policy_key(&backend),
                Arc::<[String]>::from(tags.clone()),
            ))
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
            let backend = Backend::new(upstream).ok()?;
            Some((
                backend_policy_key(&backend),
                Arc::<str>::from(alias.as_str()),
            ))
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

pub(super) fn load_balancer_backend_stats<S>(
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
                tags: inputs.backend_policy.tags(policy_key),
                weight: backend.weight,
                effective_weight: inputs.backend_policy.effective_weight(backend),
                runtime_weight_override: inputs.backend_policy.runtime_backend_weight(policy_key),
                runtime_weight_changed_at_unix_secs: inputs
                    .backend_policy
                    .runtime_backend_weight_changed_at_unix_secs(policy_key),
                locality: inputs
                    .backend_policy
                    .locality_key(policy_key)
                    .map(|locality| locality.to_string()),
                locality_preferred: inputs.backend_policy.locality_key(policy_key).is_some_and(
                    |locality| {
                        inputs
                            .backend_policy
                            .preferred_localities()
                            .contains(&locality)
                    },
                ),
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
