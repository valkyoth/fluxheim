use super::SelectedUpstream;
use super::backend::backend_container_snapshot;
use super::backend::{BackendContainer, BackendContainerSnapshot, RuntimeBackend as Backend};
use super::key::backend_key;
use super::policy::BackendSelectionPolicy;
use super::selection::{
    SelectionPass, least_connections_score_is_lower, priority_activation_satisfied,
    selection_passes,
};
use super::selection_candidate::{SelectionContext, backend_candidate_allowed};
use super::selection_hash::random_u64;
use super::selection_weight::weighted_backend_indices;
use super::state::{BackendConnectionCounters, PassiveHealthState, SlowStartState};

pub(super) fn select_power_of_two(
    inner: &impl BackendContainer,
    counters: &BackendConnectionCounters,
    max_iterations: usize,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
) -> Option<SelectedUpstream> {
    let snapshot = backend_container_snapshot(inner);
    let context = SelectionContext {
        passive_health,
        slow_start,
        counters,
        backend_policy,
    };
    for pass in selection_passes(backend_policy) {
        if !priority_activation_satisfied(&snapshot, context, pass) {
            continue;
        }
        if let Some(selected) =
            select_power_of_two_with_backup_policy(&snapshot, max_iterations, context, pass)
        {
            return Some(selected);
        }
    }
    None
}

fn select_power_of_two_with_backup_policy(
    snapshot: &BackendContainerSnapshot,
    max_iterations: usize,
    context: SelectionContext<'_>,
    pass: SelectionPass,
) -> Option<SelectedUpstream> {
    let first = select_weighted_random_candidate(snapshot, max_iterations, context, pass, None)?;
    let first_key = backend_key(&first);
    let second =
        select_weighted_random_candidate(snapshot, max_iterations, context, pass, Some(first_key))
            .unwrap_or_else(|| first.clone());
    let selected = if least_connections_score_is_lower(
        context.counters.count(&second),
        context.backend_policy.effective_weight(&second),
        context.counters.count(&first),
        context.backend_policy.effective_weight(&first),
    ) {
        second
    } else {
        first
    };
    Some(SelectedUpstream::new(selected))
}

fn select_weighted_random_candidate(
    snapshot: &BackendContainerSnapshot,
    max_iterations: usize,
    context: SelectionContext<'_>,
    pass: SelectionPass,
    excluded_key: Option<u64>,
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

    let weighted_candidate = &backends[weighted[random_u64() as usize % weighted.len()]];
    if random_candidate_allowed(
        snapshot,
        weighted_candidate,
        context,
        pass,
        excluded_key,
        &mut seen,
    ) {
        return Some(weighted_candidate.clone());
    }

    let start = random_u64() as usize % backends.len();
    for offset in 0..max_iterations.max(1).min(backends.len()) {
        let candidate = &backends[(start + offset) % backends.len()];
        if random_candidate_allowed(snapshot, candidate, context, pass, excluded_key, &mut seen) {
            return Some(candidate.clone());
        }
    }
    None
}

fn random_candidate_allowed(
    snapshot: &BackendContainerSnapshot,
    candidate: &Backend,
    context: SelectionContext<'_>,
    pass: SelectionPass,
    excluded_key: Option<u64>,
    seen: &mut std::collections::HashSet<u64>,
) -> bool {
    let candidate_key = backend_key(candidate);
    if excluded_key == Some(candidate_key) || !seen.insert(candidate_key) {
        return false;
    }
    backend_candidate_allowed(snapshot, candidate, context, pass)
}
