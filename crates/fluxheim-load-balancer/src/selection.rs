use std::sync::atomic::{AtomicUsize, Ordering};

use super::SelectedUpstream;
use super::backend::{BackendContainer, BackendContainerSnapshot, backend_container_snapshot};
use super::backend::{BackendIdentity, RuntimeBackend as Backend};
use super::key::backend_key;
use super::policy::BackendSelectionPolicy;
use super::selection_candidate::{
    SelectionContext, backend_candidate_allowed, backend_candidate_allowed_read_only,
};
use super::selection_hash::{fnv_route_secret, fnv1a64_with_seed};
#[cfg(test)]
use super::selection_ketama::NginxKetamaPoint;
#[cfg(test)]
use super::selection_ketama::NginxKetamaTable;
use super::selection_maglev::MaglevTable;
#[cfg(test)]
use super::selection_maglev::{maglev_candidate, maglev_table_size};
use super::state::{
    BackendConnectionCounters, BackendLatencyState, PassiveHealthState, SlowStartState,
};

#[derive(Clone, Copy)]
pub(super) struct LoadBalancerSelectInputs<'a> {
    pub(super) key: Option<&'a [u8]>,
    pub(super) max_iterations: usize,
    pub(super) passive_health: Option<&'a PassiveHealthState>,
    pub(super) slow_start: Option<&'a SlowStartState>,
    pub(super) counters: &'a BackendConnectionCounters,
    pub(super) backend_policy: &'a BackendSelectionPolicy,
    pub(super) persistence_entry_counts: &'a std::collections::HashMap<u64, usize>,
    pub(super) round_robin_cursor: &'a AtomicUsize,
}

#[derive(Clone, Copy)]
pub(super) struct SelectionPass {
    pub(super) minimum_priority_group: Option<u16>,
    pub(super) allow_backup: bool,
    pub(super) ignore_slow_start: bool,
    pub(super) ignore_locality: bool,
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

pub(super) fn selection_passes(backend_policy: &BackendSelectionPolicy) -> Vec<SelectionPass> {
    let mut passes = Vec::new();
    for ignore_locality in [false, true] {
        if ignore_locality && backend_policy.preferred_localities().is_empty() {
            continue;
        }
        for (allow_backup, ignore_slow_start) in [(false, false), (true, false), (false, true)] {
            for priority_group in selection_priority_groups(backend_policy) {
                passes.push(SelectionPass {
                    minimum_priority_group: priority_group,
                    allow_backup,
                    ignore_slow_start,
                    ignore_locality,
                });
            }
        }
    }
    passes
}

pub(super) fn priority_activation_satisfied(
    snapshot: &BackendContainerSnapshot,
    context: SelectionContext<'_>,
    pass: SelectionPass,
) -> bool {
    if pass.minimum_priority_group.is_none()
        || context.backend_policy.priority_group_min_active() <= 1
        || pass
            .minimum_priority_group
            .is_some_and(|group| context.backend_policy.is_lowest_priority_group(group))
    {
        return true;
    }

    snapshot
        .backends()
        .iter()
        .filter(|backend| backend_candidate_allowed_read_only(snapshot, backend, context, pass))
        .take(context.backend_policy.priority_group_min_active())
        .count()
        >= context.backend_policy.priority_group_min_active()
}

pub(super) fn select_weighted_round_robin(
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
        if let Some(selected) = select_weighted_round_robin_with_backup_policy(
            &snapshot,
            inputs.round_robin_cursor,
            context,
            pass,
        ) {
            return Some(selected);
        }
    }
    None
}

fn select_weighted_round_robin_with_backup_policy(
    snapshot: &BackendContainerSnapshot,
    cursor: &AtomicUsize,
    context: SelectionContext<'_>,
    pass: SelectionPass,
) -> Option<SelectedUpstream> {
    let mut candidates = Vec::new();
    let mut total_weight = 0usize;
    for backend in snapshot.backends().iter() {
        if !backend_candidate_allowed(snapshot, backend, context, pass) {
            continue;
        }
        let weight = context.backend_policy.effective_weight(backend);
        total_weight = total_weight.saturating_add(weight);
        candidates.push((backend.clone(), weight));
    }
    if total_weight == 0 {
        return None;
    }
    let mut target = cursor.fetch_add(1, Ordering::Relaxed) % total_weight;
    for (backend, weight) in candidates {
        if target < weight {
            return Some(SelectedUpstream::new(backend));
        }
        target = target.saturating_sub(weight);
    }
    None
}

pub(super) fn select_least_connections(
    inner: &impl BackendContainer,
    counters: &BackendConnectionCounters,
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
        if let Some(selected) = select_least_connections_with_backup_policy(
            &snapshot,
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
    snapshot: &BackendContainerSnapshot,
    counters: &BackendConnectionCounters,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
    pass: SelectionPass,
) -> Option<SelectedUpstream> {
    let mut selected = None;
    for backend in snapshot.backends().iter() {
        let context = SelectionContext {
            passive_health,
            slow_start,
            counters,
            backend_policy,
        };
        if !backend_candidate_allowed(snapshot, backend, context, pass) {
            continue;
        }
        let connections = counters.count(backend);
        let weight = backend_policy.effective_weight(backend);
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
    Some(SelectedUpstream::new(backend))
}

pub(super) fn select_least_sessions(
    inner: &impl BackendContainer,
    counters: &BackendConnectionCounters,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
    persistence_entry_counts: &std::collections::HashMap<u64, usize>,
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
        if let Some(selected) = select_least_sessions_with_backup_policy(
            &snapshot,
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
    snapshot: &BackendContainerSnapshot,
    counters: &BackendConnectionCounters,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
    persistence_entry_counts: &std::collections::HashMap<u64, usize>,
    pass: SelectionPass,
) -> Option<SelectedUpstream> {
    let mut selected = None;
    for backend in snapshot.backends().iter() {
        let context = SelectionContext {
            passive_health,
            slow_start,
            counters,
            backend_policy,
        };
        if !backend_candidate_allowed(snapshot, backend, context, pass) {
            continue;
        }
        let sessions = persistence_entry_counts
            .get(&backend_key(backend))
            .copied()
            .unwrap_or(0);
        let weight = backend_policy.effective_weight(backend);
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
    Some(SelectedUpstream::new(backend))
}

pub(super) fn least_connections_score_is_lower(
    candidate_connections: usize,
    candidate_weight: usize,
    selected_connections: usize,
    selected_weight: usize,
) -> bool {
    candidate_connections.saturating_mul(selected_weight)
        < selected_connections.saturating_mul(candidate_weight)
}

pub(super) fn select_least_time(
    inner: &impl BackendContainer,
    counters: &BackendConnectionCounters,
    latency: &BackendLatencyState,
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
        if let Some(selected) = select_least_time_with_backup_policy(
            &snapshot,
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
    snapshot: &BackendContainerSnapshot,
    counters: &BackendConnectionCounters,
    latency: &BackendLatencyState,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
    pass: SelectionPass,
) -> Option<SelectedUpstream> {
    let mut selected = None;
    for backend in snapshot.backends().iter() {
        let context = SelectionContext {
            passive_health,
            slow_start,
            counters,
            backend_policy,
        };
        if !backend_candidate_allowed(snapshot, backend, context, pass) {
            continue;
        }
        let latency_score = latency.score(backend).unwrap_or(0);
        let connections = counters.count(backend);
        let weight = backend_policy.effective_weight(backend);
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
    Some(SelectedUpstream::new(backend))
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

pub(super) fn weighted_backend_indices(backends: &[Backend]) -> Vec<usize> {
    let mut weighted = Vec::new();
    for (index, backend) in backends.iter().enumerate() {
        weighted.extend(std::iter::repeat_n(index, backend.weight().max(1)));
    }
    weighted
}

pub(super) fn select_maglev(
    inner: &impl BackendContainer,
    table: &MaglevTable,
    inputs: LoadBalancerSelectInputs<'_>,
) -> Option<SelectedUpstream> {
    let snapshot = backend_container_snapshot(inner);
    let backend_by_key: std::collections::HashMap<u64, Backend> = snapshot
        .backends()
        .iter()
        .cloned()
        .map(|backend| (backend_key(&backend), backend))
        .collect();
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
        for key in table.candidate_keys(inputs.key.unwrap_or_default(), inputs.max_iterations) {
            let Some(backend) = backend_by_key.get(&key) else {
                continue;
            };
            if backend_candidate_allowed(&snapshot, backend, context, pass) {
                return Some(SelectedUpstream::new(backend.clone()));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maglev_candidate_uses_exact_wide_modular_arithmetic() {
        let offset = 0;
        let table_size = maglev_table_size();
        let next = table_size - 1;
        let skip = table_size - 1;
        let expected =
            ((offset as u128 + (next as u128 * skip as u128)) % table_size as u128) as usize;

        assert_eq!(maglev_candidate(offset, next, skip), expected);
        assert_eq!(expected, 1);
        assert_eq!(u32::MAX as usize % table_size, 0);
    }

    #[test]
    fn nginx_ketama_backend_keys_suppresses_duplicate_points() {
        let table = NginxKetamaTable {
            points: vec![
                NginxKetamaPoint {
                    hash: 0,
                    backend_key: 10,
                },
                NginxKetamaPoint {
                    hash: 1,
                    backend_key: 10,
                },
                NginxKetamaPoint {
                    hash: 2,
                    backend_key: 20,
                },
                NginxKetamaPoint {
                    hash: u32::MAX,
                    backend_key: 20,
                },
            ],
        };

        assert_eq!(table.backend_keys(b"", 4), vec![10, 20]);
    }
}
