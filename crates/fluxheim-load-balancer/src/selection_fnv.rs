use super::SelectedUpstream;
use super::backend::backend_container_snapshot;
use super::backend::{BackendContainer, BackendContainerSnapshot, RuntimeBackend as Backend};
use super::key::backend_key;
use super::selection::{
    LoadBalancerSelectInputs, SelectionPass, priority_activation_satisfied, selection_passes,
};
use super::selection_candidate::{SelectionContext, backend_candidate_allowed};
use super::selection_hash::{fnv_route_secret, fnv1a64_with_seed};
use super::selection_weight::weighted_backend_indices;

pub(super) fn select_fnv_hash(
    inner: &impl BackendContainer,
    inputs: LoadBalancerSelectInputs<'_>,
) -> Option<SelectedUpstream> {
    let snapshot = backend_container_snapshot(inner);
    let context = SelectionContext {
        passive_health: inputs.passive_health,
        slow_start: inputs.slow_start,
        counters: inputs.counters,
        backend_policy: inputs.backend_policy,
    };
    for pass in selection_passes(inputs.backend_policy) {
        if !priority_activation_satisfied(&snapshot, context, pass) {
            continue;
        }
        if let Some(backend) = select_fnv_hash_with_backup_policy(
            &snapshot,
            inputs.key.unwrap_or_default(),
            inputs.max_iterations,
            context,
            pass,
        ) {
            return Some(SelectedUpstream::new(backend));
        }
    }
    None
}

fn select_fnv_hash_with_backup_policy(
    snapshot: &BackendContainerSnapshot,
    key: &[u8],
    max_iterations: usize,
    context: SelectionContext<'_>,
    pass: SelectionPass,
) -> Option<Backend> {
    let backends: Vec<Backend> = snapshot.backends().iter().cloned().collect();
    if backends.is_empty() {
        return None;
    }
    let weighted = weighted_backend_indices(&backends);
    if weighted.is_empty() {
        return None;
    }

    let mut seen = std::collections::HashSet::new();
    let mut index = fnv1a64_with_seed(key, fnv_route_secret());
    for step in 0..max_iterations.max(1) {
        let candidate_index = if step == 0 {
            weighted[index as usize % weighted.len()]
        } else {
            index = fnv1a64_with_seed(&index.to_le_bytes(), fnv_route_secret());
            index as usize % backends.len()
        };
        let candidate = &backends[candidate_index];
        if !seen.insert(backend_key(candidate)) {
            continue;
        }
        if backend_candidate_allowed(snapshot, candidate, context, pass) {
            return Some(candidate.clone());
        }
    }
    None
}
