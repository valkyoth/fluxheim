use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{LoadBalancerRuntimeBackendState, MAX_RUNTIME_BACKEND_WEIGHT};

pub(crate) const MAX_RUNTIME_BACKEND_POLICY_OVERRIDE_ENTRIES: usize = 4096;

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[derive(Debug, Default)]
pub(crate) struct RuntimeBackendPolicyOverrides {
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

#[derive(Debug)]
pub(crate) struct PreparedRuntimeBackendPolicySnapshot {
    state: RuntimeBackendPolicyOverrideState,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct RuntimeBackendPolicySnapshot {
    pub(crate) states: Vec<RuntimeBackendPolicyStateSnapshot>,
    pub(crate) weights: Vec<RuntimeBackendPolicyWeightSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct RuntimeBackendPolicyStateSnapshot {
    pub(crate) key: u64,
    pub(crate) state: LoadBalancerRuntimeBackendState,
    pub(crate) changed_at_unix_secs: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct RuntimeBackendPolicyWeightSnapshot {
    pub(crate) key: u64,
    pub(crate) weight: usize,
    pub(crate) changed_at_unix_secs: u64,
}

impl RuntimeBackendPolicyOverrides {
    pub(crate) fn drained(&self, key: u64) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain
            .contains(&key)
    }

    pub(crate) fn disabled(&self, key: u64) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.disabled.contains(&key) || state.forced_down.contains(&key)
    }

    pub(crate) fn set_state(&self, key: u64, state: LoadBalancerRuntimeBackendState) -> bool {
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

    pub(crate) fn set_weight(&self, key: u64, weight: Option<usize>) -> bool {
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

    pub(crate) fn state(&self, key: u64) -> Option<LoadBalancerRuntimeBackendState> {
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

    pub(crate) fn changed_at_unix_secs(&self, key: u64) -> Option<u64> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .changed_at_unix_secs
            .get(&key)
            .copied()
    }

    pub(crate) fn weight(&self, key: u64) -> Option<usize> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .weights
            .get(&key)
            .copied()
    }

    pub(crate) fn weight_changed_at_unix_secs(&self, key: u64) -> Option<u64> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .weight_changed_at_unix_secs
            .get(&key)
            .copied()
    }

    pub(crate) fn prune_stale(&self, live_keys: &std::collections::HashSet<u64>) {
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

    pub(crate) fn clear_key(&self, key: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.drain.remove(&key);
        state.disabled.remove(&key);
        state.forced_down.remove(&key);
        state.weights.remove(&key);
        state.weight_changed_at_unix_secs.remove(&key);
        state.changed_at_unix_secs.remove(&key);
    }

    pub(crate) fn snapshot(&self) -> RuntimeBackendPolicySnapshot {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut states = Vec::with_capacity(
            state
                .drain
                .len()
                .saturating_add(state.disabled.len())
                .saturating_add(state.forced_down.len()),
        );
        states.extend(
            state
                .drain
                .iter()
                .copied()
                .map(|key| RuntimeBackendPolicyStateSnapshot {
                    key,
                    state: LoadBalancerRuntimeBackendState::Drained,
                    changed_at_unix_secs: state
                        .changed_at_unix_secs
                        .get(&key)
                        .copied()
                        .unwrap_or(0),
                }),
        );
        states.extend(state.disabled.iter().copied().map(|key| {
            RuntimeBackendPolicyStateSnapshot {
                key,
                state: LoadBalancerRuntimeBackendState::Disabled,
                changed_at_unix_secs: state.changed_at_unix_secs.get(&key).copied().unwrap_or(0),
            }
        }));
        states.extend(state.forced_down.iter().copied().map(|key| {
            RuntimeBackendPolicyStateSnapshot {
                key,
                state: LoadBalancerRuntimeBackendState::ForcedDown,
                changed_at_unix_secs: state.changed_at_unix_secs.get(&key).copied().unwrap_or(0),
            }
        }));
        states.sort_by_key(|entry| (entry.key, entry.state.as_str()));

        let mut weights = state
            .weights
            .iter()
            .map(|(key, weight)| RuntimeBackendPolicyWeightSnapshot {
                key: *key,
                weight: *weight,
                changed_at_unix_secs: state
                    .weight_changed_at_unix_secs
                    .get(key)
                    .copied()
                    .unwrap_or(0),
            })
            .collect::<Vec<_>>();
        weights.sort_by_key(|entry| entry.key);
        RuntimeBackendPolicySnapshot { states, weights }
    }

    #[cfg(test)]
    pub(crate) fn restore_snapshot(
        &self,
        snapshot: &RuntimeBackendPolicySnapshot,
    ) -> Result<(), &'static str> {
        let prepared = self.prepare_snapshot(snapshot)?;
        self.commit_snapshot(prepared);
        Ok(())
    }

    pub(crate) fn prepare_snapshot(
        &self,
        snapshot: &RuntimeBackendPolicySnapshot,
    ) -> Result<PreparedRuntimeBackendPolicySnapshot, &'static str> {
        if snapshot.states.len() > MAX_RUNTIME_BACKEND_POLICY_OVERRIDE_ENTRIES
            || snapshot.weights.len() > MAX_RUNTIME_BACKEND_POLICY_OVERRIDE_ENTRIES
        {
            return Err("load balancer runtime override snapshot exceeds entry limit");
        }

        let mut seen_states = std::collections::HashSet::with_capacity(snapshot.states.len());
        let mut next = RuntimeBackendPolicyOverrideState::default();
        for entry in &snapshot.states {
            if !seen_states.insert(entry.key) {
                return Err("load balancer runtime override snapshot has duplicate state keys");
            }
            match entry.state {
                LoadBalancerRuntimeBackendState::Drained => {
                    next.drain.insert(entry.key);
                }
                LoadBalancerRuntimeBackendState::Disabled => {
                    next.disabled.insert(entry.key);
                }
                LoadBalancerRuntimeBackendState::ForcedDown => {
                    next.forced_down.insert(entry.key);
                }
                LoadBalancerRuntimeBackendState::Normal
                | LoadBalancerRuntimeBackendState::ManualResume => {
                    return Err("load balancer runtime override snapshot has non-persistent state");
                }
            }
            next.changed_at_unix_secs
                .insert(entry.key, entry.changed_at_unix_secs);
        }

        let mut seen_weights = std::collections::HashSet::with_capacity(snapshot.weights.len());
        for entry in &snapshot.weights {
            if !seen_weights.insert(entry.key) {
                return Err("load balancer runtime override snapshot has duplicate weight keys");
            }
            if entry.weight == 0 || entry.weight > MAX_RUNTIME_BACKEND_WEIGHT {
                return Err("load balancer runtime override snapshot has invalid weight");
            }
            next.weights.insert(entry.key, entry.weight);
            next.weight_changed_at_unix_secs
                .insert(entry.key, entry.changed_at_unix_secs);
        }

        Ok(PreparedRuntimeBackendPolicySnapshot { state: next })
    }

    pub(crate) fn commit_snapshot(&self, prepared: PreparedRuntimeBackendPolicySnapshot) {
        *self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = prepared.state;
    }
}

fn runtime_override_key_has_capacity(keys: &std::collections::HashSet<u64>, key: u64) -> bool {
    keys.contains(&key) || keys.len() < MAX_RUNTIME_BACKEND_POLICY_OVERRIDE_ENTRIES
}
