use std::sync::Arc;

use super::backend::{BackendContainerSnapshot, BackendIdentity};
use super::key::backend_key;
use super::policy::BackendSelectionPolicy;
use super::state::{
    BackendConnectionCounters, BackendLatencyState, PassiveHealthState, SlowStartState,
};
use super::{LoadBalancerBackendRuntimeStats, LoadBalancerCircuitState};

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
    snapshot: &BackendContainerSnapshot,
    inputs: BackendStatsInputs<'_>,
) -> Vec<LoadBalancerBackendRuntimeStats> {
    snapshot
        .backends()
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
                health_weight_percent: inputs.backend_policy.health_weight_percent(key),
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
                ready: snapshot.ready(backend),
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
