use std::net::SocketAddr;
use std::process;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::SelectedUpstream;
use super::backend::{BackendContainer, BackendContainerSnapshot, backend_container_snapshot};
use super::backend::{BackendIdentity, RuntimeBackend as Backend};
use super::key::backend_key;
use super::policy::BackendSelectionPolicy;
use super::state::{
    BackendConnectionCounters, BackendLatencyState, PassiveHealthState, SlowStartState,
};
use crc32fast::Hasher as Crc32Hasher;
use fluxheim_common::{FluxError, FluxResult};

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const MAGLEV_TABLE_SIZE: usize = 65_537;
const NGINX_KETAMA_POINT_MULTIPLE: usize = 160;

pub(super) fn fnv1a64(bytes: &[u8]) -> u64 {
    fnv1a64_with_seed(bytes, FNV_OFFSET_BASIS)
}

pub(super) fn fnv1a64_with_seed(bytes: &[u8], seed: u64) -> u64 {
    let mut hash = seed;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

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

fn selection_passes(backend_policy: &BackendSelectionPolicy) -> Vec<SelectionPass> {
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

fn priority_activation_satisfied(
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

fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    if let Err(error) = getrandom::fill(&mut bytes) {
        log::error!(
            target: "fluxheim::security",
            "failed to generate load-balancer random candidate seed: {error}"
        );
        process::abort();
    }
    u64::from_le_bytes(bytes)
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

fn weighted_backend_indices(backends: &[Backend]) -> Vec<usize> {
    let mut weighted = Vec::new();
    for (index, backend) in backends.iter().enumerate() {
        weighted.extend(std::iter::repeat_n(index, backend.weight().max(1)));
    }
    weighted
}

fn backend_candidate_allowed(
    snapshot: &BackendContainerSnapshot,
    backend: &Backend,
    context: SelectionContext<'_>,
    pass: SelectionPass,
) -> bool {
    backend_candidate_base_allowed(snapshot, backend, context, pass, false)
        && passive_health_candidate_allowed(snapshot, backend, context)
}

fn backend_candidate_allowed_read_only(
    snapshot: &BackendContainerSnapshot,
    backend: &Backend,
    context: SelectionContext<'_>,
    pass: SelectionPass,
) -> bool {
    backend_candidate_base_allowed(snapshot, backend, context, pass, true)
        && passive_health_candidate_allowed(snapshot, backend, context)
}

fn backend_candidate_base_allowed(
    snapshot: &BackendContainerSnapshot,
    backend: &Backend,
    context: SelectionContext<'_>,
    pass: SelectionPass,
    slow_start_read_only: bool,
) -> bool {
    snapshot.ready(backend)
        && context
            .backend_policy
            .permits(backend, pass, context.counters)
        && (pass.ignore_slow_start
            || context.slow_start.is_none_or(|state| {
                if slow_start_read_only {
                    state.permits_read_only(backend)
                } else {
                    state.permits(backend)
                }
            }))
}

fn passive_health_candidate_allowed(
    snapshot: &BackendContainerSnapshot,
    backend: &Backend,
    context: SelectionContext<'_>,
) -> bool {
    let Some(health) = context.passive_health else {
        return true;
    };
    if !health.is_ejected(backend) {
        return true;
    }
    let floor = health.min_healthy_backends();
    floor > 0 && non_ejected_candidate_count(snapshot, context, floor) < floor
}

fn non_ejected_candidate_count(
    snapshot: &BackendContainerSnapshot,
    context: SelectionContext<'_>,
    limit: usize,
) -> usize {
    let Some(health) = context.passive_health else {
        return limit;
    };
    let floor_pass = SelectionPass {
        minimum_priority_group: None,
        allow_backup: true,
        ignore_slow_start: true,
        ignore_locality: true,
    };
    snapshot
        .backends()
        .iter()
        .filter(|backend| {
            backend_candidate_base_allowed(snapshot, backend, context, floor_pass, true)
                && !health.is_ejected(backend)
        })
        .take(limit)
        .count()
}

pub(super) fn select_consistent_hash(
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
        if let Some(backend) = select_consistent_hash_with_backup_policy(
            &snapshot,
            inputs.key.unwrap_or_default(),
            inputs.max_iterations,
            context,
            pass,
            None,
        ) {
            return Some(SelectedUpstream::new(backend));
        }
    }
    None
}

pub(super) fn select_nginx_consistent_hash(
    inner: &impl BackendContainer,
    table: &NginxKetamaTable,
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
        for selected_key in
            table.backend_keys(inputs.key.unwrap_or_default(), inputs.max_iterations)
        {
            let Some(backend) = snapshot
                .backends()
                .iter()
                .find(|backend| backend_key(backend) == selected_key)
            else {
                continue;
            };
            if backend_candidate_allowed(&snapshot, backend, context, pass) {
                return Some(SelectedUpstream::new(backend.clone()));
            }
        }
    }
    None
}

pub(super) fn select_bounded_load_consistent(
    inner: &impl BackendContainer,
    factor_per_mille: u16,
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
        if let Some(backend) = select_bounded_load_consistent_with_backup_policy(
            &snapshot,
            inputs.key.unwrap_or_default(),
            inputs.max_iterations,
            context,
            pass,
            factor_per_mille,
        ) {
            return Some(SelectedUpstream::new(backend));
        }
    }
    None
}

fn select_bounded_load_consistent_with_backup_policy(
    snapshot: &BackendContainerSnapshot,
    key: &[u8],
    max_iterations: usize,
    context: SelectionContext<'_>,
    pass: SelectionPass,
    factor_per_mille: u16,
) -> Option<Backend> {
    let Some(bound) = bounded_load_snapshot(snapshot, context, pass, factor_per_mille) else {
        return select_consistent_hash_with_backup_policy(
            snapshot,
            key,
            max_iterations,
            context,
            pass,
            None,
        );
    };
    select_consistent_hash_with_backup_policy(
        snapshot,
        key,
        max_iterations,
        context,
        pass,
        Some(&bound),
    )
    .or_else(|| {
        select_consistent_hash_with_backup_policy(
            snapshot,
            key,
            max_iterations,
            context,
            pass,
            None,
        )
    })
}

#[derive(Clone, Copy, Debug)]
struct BoundedLoadSnapshot {
    total_connections: usize,
    total_weight: usize,
    factor_per_mille: u16,
}

fn bounded_load_snapshot(
    snapshot: &BackendContainerSnapshot,
    context: SelectionContext<'_>,
    pass: SelectionPass,
    factor_per_mille: u16,
) -> Option<BoundedLoadSnapshot> {
    let mut total_connections = 0usize;
    let mut total_weight = 0usize;
    for backend in snapshot.backends().iter() {
        if !backend_candidate_allowed_read_only(snapshot, backend, context, pass) {
            continue;
        }
        total_connections = total_connections.saturating_add(context.counters.count(backend));
        total_weight =
            total_weight.saturating_add(context.backend_policy.effective_weight(backend));
    }
    (total_weight > 0 && total_connections > 0).then_some(BoundedLoadSnapshot {
        total_connections,
        total_weight,
        factor_per_mille,
    })
}

fn bounded_load_permits(
    backend: &Backend,
    counters: &BackendConnectionCounters,
    backend_policy: &BackendSelectionPolicy,
    bound: &BoundedLoadSnapshot,
) -> bool {
    let candidate_connections = counters.count(backend) as u128;
    let candidate_weight = backend_policy.effective_weight(backend) as u128;
    let left = candidate_connections
        .saturating_mul(bound.total_weight as u128)
        .saturating_mul(1000);
    let right = (bound.total_connections as u128)
        .saturating_mul(candidate_weight)
        .saturating_mul(u128::from(bound.factor_per_mille));
    left <= right
}

fn select_consistent_hash_with_backup_policy(
    snapshot: &BackendContainerSnapshot,
    key: &[u8],
    max_iterations: usize,
    context: SelectionContext<'_>,
    pass: SelectionPass,
    bound: Option<&BoundedLoadSnapshot>,
) -> Option<Backend> {
    let candidates = consistent_hash_candidates(snapshot, key, context.backend_policy);
    let limit = max_iterations.max(1).min(candidates.len());
    candidates
        .into_iter()
        .take(limit)
        .map(|(_, _, backend)| backend)
        .find(|backend| {
            backend_candidate_allowed(snapshot, backend, context, pass)
                && bound.is_none_or(|bound| {
                    bounded_load_permits(backend, context.counters, context.backend_policy, bound)
                })
        })
}

fn consistent_hash_candidates(
    snapshot: &BackendContainerSnapshot,
    key: &[u8],
    backend_policy: &BackendSelectionPolicy,
) -> Vec<(u64, u64, Backend)> {
    let mut candidates: Vec<_> = snapshot
        .backends()
        .iter()
        .cloned()
        .map(|backend| {
            let key_id = backend_key(&backend);
            (
                consistent_backend_score(key, key_id, backend_policy.effective_weight(&backend)),
                key_id,
                backend,
            )
        })
        .collect();
    candidates.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    candidates
}

fn consistent_backend_score(key: &[u8], backend_key: u64, weight: usize) -> u64 {
    let mut best = 0u64;
    for replica in 0..weight.max(1) {
        let mut hash = fnv1a64_with_seed(key, consistent_route_secret());
        hash = fnv1a64_with_seed(&backend_key.to_le_bytes(), hash);
        hash = fnv1a64_with_seed(&(replica as u64).to_le_bytes(), hash);
        best = best.max(hash);
    }
    best
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NginxKetamaPoint {
    hash: u32,
    backend_key: u64,
}

#[derive(Clone, Debug)]
pub(super) struct NginxKetamaTable {
    points: Vec<NginxKetamaPoint>,
}

impl NginxKetamaTable {
    pub(super) fn from_backend_identities<'a, I, B>(backends: I) -> FluxResult<Self>
    where
        I: IntoIterator<Item = &'a B>,
        B: BackendIdentity + 'a,
    {
        let mut points = Vec::new();
        for backend in backends {
            let authority = backend.authority();
            let address = authority.parse::<SocketAddr>().map_err(|error| {
                FluxError::io(
                    "nginx-compatible consistent hash backend is not a socket address",
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, error),
                )
            })?;
            push_nginx_ketama_points(&mut points, address, backend.key(), backend.weight());
        }
        if points.is_empty() {
            return Err(FluxError::InvalidInput(
                "nginx-compatible consistent hash requires at least one backend",
            ));
        }
        points.sort_unstable_by_key(|point| point.hash);
        points.dedup_by(|left, right| left.hash == right.hash);
        Ok(Self { points })
    }

    fn backend_keys(&self, key: &[u8], max_iterations: usize) -> Vec<u64> {
        if self.points.is_empty() {
            return Vec::new();
        }
        let hash = crc32fast::hash(key);
        let start = match self.points.binary_search_by(|point| point.hash.cmp(&hash)) {
            Ok(index) => index,
            Err(index) if index == self.points.len() => 0,
            Err(index) => index,
        };
        let limit = max_iterations.max(1).min(self.points.len());
        let mut keys = Vec::new();
        for offset in 0..self.points.len() {
            if keys.len() >= limit {
                break;
            }
            let key = self.points[(start + offset) % self.points.len()].backend_key;
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        keys
    }
}

fn push_nginx_ketama_points(
    points: &mut Vec<NginxKetamaPoint>,
    address: SocketAddr,
    backend_key: u64,
    weight: usize,
) {
    let mut base = Vec::new();
    base.extend_from_slice(address.ip().to_string().as_bytes());
    base.push(0);
    base.extend_from_slice(address.port().to_string().as_bytes());

    let mut previous_hash = 0u32;
    let point_count = weight.max(1).saturating_mul(NGINX_KETAMA_POINT_MULTIPLE);
    for _ in 0..point_count {
        let mut hasher = Crc32Hasher::new();
        hasher.update(&base);
        hasher.update(&previous_hash.to_le_bytes());
        let hash = hasher.finalize();
        points.push(NginxKetamaPoint { hash, backend_key });
        previous_hash = hash;
    }
}

#[derive(Clone, Debug)]
pub(super) struct MaglevTable {
    slots: Vec<u64>,
}

impl MaglevTable {
    pub(super) fn from_backend_identities<'a, I, B>(backends: I) -> FluxResult<Self>
    where
        I: IntoIterator<Item = &'a B>,
        B: BackendIdentity + 'a,
    {
        let keys: Vec<u64> = backends.into_iter().map(backend_key).collect();
        Self::from_backend_keys(&keys)
    }

    fn from_backend_keys(keys: &[u64]) -> FluxResult<Self> {
        if keys.is_empty() {
            return Err(FluxError::InvalidInput(
                "maglev requires at least one backend",
            ));
        }

        let mut slots = vec![u64::MAX; MAGLEV_TABLE_SIZE];
        let mut next = vec![0usize; keys.len()];
        let permutations: Vec<(usize, usize)> = keys
            .iter()
            .map(|backend_key| {
                let key = backend_key.to_le_bytes();
                let offset = fnv1a64_with_seed(&key, FNV_OFFSET_BASIS) as usize % MAGLEV_TABLE_SIZE;
                let skip = (fnv1a64_with_seed(&key, 0x8422_2325_cbf2_9ce4) as usize
                    % (MAGLEV_TABLE_SIZE - 1))
                    + 1;
                (offset, skip)
            })
            .collect();

        let mut filled = 0usize;
        while filled < MAGLEV_TABLE_SIZE {
            for (index, backend_key) in keys.iter().enumerate() {
                loop {
                    let (offset, skip) = permutations[index];
                    let candidate = maglev_candidate(offset, next[index], skip);
                    next[index] = next[index].saturating_add(1);
                    if slots[candidate] == u64::MAX {
                        slots[candidate] = *backend_key;
                        filled = filled.saturating_add(1);
                        break;
                    }
                }
                if filled == MAGLEV_TABLE_SIZE {
                    break;
                }
            }
        }

        Ok(Self { slots })
    }

    fn candidate_keys<'a>(
        &'a self,
        key: &'a [u8],
        max_iterations: usize,
    ) -> impl Iterator<Item = u64> + 'a {
        let start = fnv1a64_with_seed(key, maglev_route_secret()) as usize % self.slots.len();
        let limit = max_iterations.max(1).min(self.slots.len());
        (0..limit).map(move |offset| self.slots[(start + offset) % self.slots.len()])
    }
}

fn maglev_candidate(offset: usize, next: usize, skip: usize) -> usize {
    ((offset as u128 + (next as u128 * skip as u128)) % MAGLEV_TABLE_SIZE as u128) as usize
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

fn maglev_route_secret() -> u64 {
    route_secret(&MAGLEV_ROUTE_SECRET, "Maglev routing hash")
}

fn consistent_route_secret() -> u64 {
    route_secret(&CONSISTENT_ROUTE_SECRET, "consistent-hash routing")
}

fn fnv_route_secret() -> u64 {
    route_secret(&FNV_ROUTE_SECRET, "FNV routing hash")
}

static MAGLEV_ROUTE_SECRET: OnceLock<u64> = OnceLock::new();
static CONSISTENT_ROUTE_SECRET: OnceLock<u64> = OnceLock::new();
static FNV_ROUTE_SECRET: OnceLock<u64> = OnceLock::new();

fn route_secret(secret: &'static OnceLock<u64>, label: &'static str) -> u64 {
    *secret.get_or_init(|| {
        let mut bytes = [0u8; 8];
        if let Err(error) = getrandom::fill(&mut bytes) {
            log::error!(
                target: "fluxheim::security",
                "failed to seed {label} secret: {error}"
            );
            process::abort();
        }
        u64::from_le_bytes(bytes)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maglev_candidate_uses_exact_wide_modular_arithmetic() {
        let offset = 0;
        let next = MAGLEV_TABLE_SIZE - 1;
        let skip = MAGLEV_TABLE_SIZE - 1;
        let expected =
            ((offset as u128 + (next as u128 * skip as u128)) % MAGLEV_TABLE_SIZE as u128) as usize;

        assert_eq!(maglev_candidate(offset, next, skip), expected);
        assert_eq!(expected, 1);
        assert_eq!(u32::MAX as usize % MAGLEV_TABLE_SIZE, 0);
    }
}
