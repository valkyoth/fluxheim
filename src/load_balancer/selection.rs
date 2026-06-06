use std::process;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use pingora::lb::Backend;
use pingora::lb::prelude::LoadBalancer;
use pingora::lb::selection::{BackendIter, BackendSelection, Consistent, Random, RoundRobin};

use super::SelectedUpstream;
use super::backend::BackendIdentity;
use super::key::backend_key;
use super::policy::BackendSelectionPolicy;
use super::state::{
    BackendConnectionCounters, BackendLatencyState, PassiveHealthState, SlowStartState,
};
use crate::flux_error::{FluxError, FluxResult};

const MAGLEV_TABLE_SIZE: usize = 65_537;

pub(super) fn fnv1a64(bytes: &[u8]) -> u64 {
    fnv1a64_with_seed(bytes, 0xcbf2_9ce4_8422_2325)
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

pub(super) fn select_pingora<S>(
    inner: &LoadBalancer<S>,
    key: &[u8],
    max_iterations: usize,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    counters: &BackendConnectionCounters,
    backend_policy: &BackendSelectionPolicy,
) -> Option<Backend>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    let context = SelectionContext {
        passive_health,
        slow_start,
        counters,
        backend_policy,
    };
    for pass in selection_passes(backend_policy) {
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(backend) =
            select_pingora_with_backup_policy(inner, key, max_iterations, context, pass)
        {
            return Some(backend);
        }
    }
    None
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

fn priority_activation_satisfied<S>(
    inner: &LoadBalancer<S>,
    context: SelectionContext<'_>,
    pass: SelectionPass,
) -> bool
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    if pass.minimum_priority_group.is_none()
        || context.backend_policy.priority_group_min_active() <= 1
        || pass
            .minimum_priority_group
            .is_some_and(|group| context.backend_policy.is_lowest_priority_group(group))
    {
        return true;
    }

    inner
        .backends()
        .get_backend()
        .iter()
        .filter(|backend| {
            inner.backends().ready(backend)
                && context
                    .backend_policy
                    .permits(backend, pass, context.counters)
                && context
                    .passive_health
                    .is_none_or(|health| !health.is_ejected(backend))
                && (pass.ignore_slow_start
                    || context
                        .slow_start
                        .is_none_or(|state| state.permits_read_only(backend)))
        })
        .take(context.backend_policy.priority_group_min_active())
        .count()
        >= context.backend_policy.priority_group_min_active()
}

fn select_pingora_with_backup_policy<S>(
    inner: &LoadBalancer<S>,
    key: &[u8],
    max_iterations: usize,
    context: SelectionContext<'_>,
    pass: SelectionPass,
) -> Option<Backend>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    inner.select_with(key, max_iterations, |backend, ready| {
        ready
            && context
                .backend_policy
                .permits(backend, pass, context.counters)
            && context
                .passive_health
                .is_none_or(|health| !health.is_ejected(backend))
            && (pass.ignore_slow_start
                || context
                    .slow_start
                    .is_none_or(|state| state.permits(backend)))
    })
}

pub(super) fn select_weighted_round_robin(
    inner: &LoadBalancer<RoundRobin>,
    inputs: LoadBalancerSelectInputs<'_>,
) -> Option<SelectedUpstream> {
    let context = SelectionContext {
        passive_health: inputs.passive_health,
        slow_start: inputs.slow_start,
        counters: inputs.counters,
        backend_policy: inputs.backend_policy,
    };
    for pass in selection_passes(inputs.backend_policy) {
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(selected) = select_weighted_round_robin_with_backup_policy(
            inner,
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
    inner: &LoadBalancer<RoundRobin>,
    cursor: &AtomicUsize,
    context: SelectionContext<'_>,
    pass: SelectionPass,
) -> Option<SelectedUpstream> {
    let mut candidates = Vec::new();
    let mut total_weight = 0usize;
    for backend in inner.backends().get_backend().iter() {
        if !inner.backends().ready(backend)
            || !context
                .backend_policy
                .permits(backend, pass, context.counters)
            || context
                .passive_health
                .is_some_and(|health| health.is_ejected(backend))
            || (!pass.ignore_slow_start
                && context
                    .slow_start
                    .is_some_and(|state| !state.permits(backend)))
        {
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
    inner: &LoadBalancer<RoundRobin>,
    counters: &BackendConnectionCounters,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
) -> Option<SelectedUpstream> {
    let context = SelectionContext {
        passive_health,
        slow_start,
        counters,
        backend_policy,
    };
    for pass in selection_passes(backend_policy) {
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(selected) = select_least_connections_with_backup_policy(
            inner,
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
    inner: &LoadBalancer<RoundRobin>,
    counters: &BackendConnectionCounters,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
    pass: SelectionPass,
) -> Option<SelectedUpstream> {
    let mut selected = None;
    for backend in inner.backends().get_backend().iter() {
        if !inner.backends().ready(backend)
            || !backend_policy.permits(backend, pass, counters)
            || passive_health.is_some_and(|health| health.is_ejected(backend))
            || (!pass.ignore_slow_start && slow_start.is_some_and(|state| !state.permits(backend)))
        {
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
    inner: &LoadBalancer<RoundRobin>,
    counters: &BackendConnectionCounters,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
    persistence_entry_counts: &std::collections::HashMap<u64, usize>,
) -> Option<SelectedUpstream> {
    let context = SelectionContext {
        passive_health,
        slow_start,
        counters,
        backend_policy,
    };
    for pass in selection_passes(backend_policy) {
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(selected) = select_least_sessions_with_backup_policy(
            inner,
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
    inner: &LoadBalancer<RoundRobin>,
    counters: &BackendConnectionCounters,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
    persistence_entry_counts: &std::collections::HashMap<u64, usize>,
    pass: SelectionPass,
) -> Option<SelectedUpstream> {
    let mut selected = None;
    for backend in inner.backends().get_backend().iter() {
        if !inner.backends().ready(backend)
            || !backend_policy.permits(backend, pass, counters)
            || passive_health.is_some_and(|health| health.is_ejected(backend))
            || (!pass.ignore_slow_start && slow_start.is_some_and(|state| !state.permits(backend)))
        {
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
    inner: &LoadBalancer<RoundRobin>,
    counters: &BackendConnectionCounters,
    latency: &BackendLatencyState,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
) -> Option<SelectedUpstream> {
    let context = SelectionContext {
        passive_health,
        slow_start,
        counters,
        backend_policy,
    };
    for pass in selection_passes(backend_policy) {
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(selected) = select_least_time_with_backup_policy(
            inner,
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
    inner: &LoadBalancer<RoundRobin>,
    counters: &BackendConnectionCounters,
    latency: &BackendLatencyState,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
    pass: SelectionPass,
) -> Option<SelectedUpstream> {
    let mut selected = None;
    for backend in inner.backends().get_backend().iter() {
        if !inner.backends().ready(backend)
            || !backend_policy.permits(backend, pass, counters)
            || passive_health.is_some_and(|health| health.is_ejected(backend))
            || (!pass.ignore_slow_start && slow_start.is_some_and(|state| !state.permits(backend)))
        {
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
    inner: &LoadBalancer<Random>,
    counters: &BackendConnectionCounters,
    max_iterations: usize,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
) -> Option<SelectedUpstream> {
    let first = select_pingora(
        inner,
        b"",
        max_iterations,
        passive_health,
        slow_start,
        counters,
        backend_policy,
    )?;
    let first_key = backend_key(&first);
    let second = (0..max_iterations)
        .filter_map(|_| {
            select_pingora(
                inner,
                b"",
                max_iterations,
                passive_health,
                slow_start,
                counters,
                backend_policy,
            )
        })
        .find(|backend| backend_key(backend) != first_key)
        .unwrap_or_else(|| first.clone());
    let selected = if least_connections_score_is_lower(
        counters.count(&second),
        backend_policy.effective_weight(&second),
        counters.count(&first),
        backend_policy.effective_weight(&first),
    ) {
        second
    } else {
        first
    };
    Some(SelectedUpstream::new(selected))
}

pub(super) fn select_bounded_load_consistent(
    inner: &LoadBalancer<Consistent>,
    factor_per_mille: u16,
    inputs: LoadBalancerSelectInputs<'_>,
) -> Option<SelectedUpstream> {
    let context = SelectionContext {
        passive_health: inputs.passive_health,
        slow_start: inputs.slow_start,
        counters: inputs.counters,
        backend_policy: inputs.backend_policy,
    };
    for pass in selection_passes(inputs.backend_policy) {
        if !priority_activation_satisfied(inner, context, pass) {
            continue;
        }
        if let Some(backend) = select_bounded_load_consistent_with_backup_policy(
            inner,
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
    inner: &LoadBalancer<Consistent>,
    key: &[u8],
    max_iterations: usize,
    context: SelectionContext<'_>,
    pass: SelectionPass,
    factor_per_mille: u16,
) -> Option<Backend> {
    let Some(bound) = bounded_load_snapshot(inner, context, pass, factor_per_mille) else {
        return select_pingora_with_backup_policy(inner, key, max_iterations, context, pass);
    };
    let bounded = inner.select_with(key, max_iterations, |backend, ready| {
        ready
            && context
                .backend_policy
                .permits(backend, pass, context.counters)
            && context
                .passive_health
                .is_none_or(|health| !health.is_ejected(backend))
            && (pass.ignore_slow_start
                || context
                    .slow_start
                    .is_none_or(|state| state.permits(backend)))
            && bounded_load_permits(backend, context.counters, &bound)
    });
    bounded.or_else(|| select_pingora_with_backup_policy(inner, key, max_iterations, context, pass))
}

#[derive(Clone, Copy, Debug)]
struct BoundedLoadSnapshot {
    total_connections: usize,
    total_weight: usize,
    factor_per_mille: u16,
}

fn bounded_load_snapshot(
    inner: &LoadBalancer<Consistent>,
    context: SelectionContext<'_>,
    pass: SelectionPass,
    factor_per_mille: u16,
) -> Option<BoundedLoadSnapshot> {
    let mut total_connections = 0usize;
    let mut total_weight = 0usize;
    for backend in inner.backends().get_backend().iter() {
        if !inner.backends().ready(backend)
            || !context
                .backend_policy
                .permits(backend, pass, context.counters)
            || context
                .passive_health
                .is_some_and(|health| health.is_ejected(backend))
            || (!pass.ignore_slow_start
                && context
                    .slow_start
                    .is_some_and(|state| !state.permits_read_only(backend)))
        {
            continue;
        }
        total_connections = total_connections.saturating_add(context.counters.count(backend));
        total_weight = total_weight.saturating_add(backend.weight.max(1));
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
    bound: &BoundedLoadSnapshot,
) -> bool {
    let candidate_connections = counters.count(backend) as u128;
    let candidate_weight = backend.weight.max(1) as u128;
    let left = candidate_connections
        .saturating_mul(bound.total_weight as u128)
        .saturating_mul(1000);
    let right = (bound.total_connections as u128)
        .saturating_mul(candidate_weight)
        .saturating_mul(u128::from(bound.factor_per_mille));
    left <= right
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
                let offset =
                    fnv1a64_with_seed(&key, 0xcbf2_9ce4_8422_2325) as usize % MAGLEV_TABLE_SIZE;
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
    inner: &LoadBalancer<RoundRobin>,
    table: &MaglevTable,
    inputs: LoadBalancerSelectInputs<'_>,
) -> Option<SelectedUpstream> {
    let backend_by_key: std::collections::HashMap<u64, Backend> = inner
        .backends()
        .get_backend()
        .iter()
        .cloned()
        .map(|backend| (backend_key(&backend), backend))
        .collect();
    for pass in selection_passes(inputs.backend_policy) {
        if !priority_activation_satisfied(
            inner,
            SelectionContext {
                passive_health: inputs.passive_health,
                slow_start: inputs.slow_start,
                counters: inputs.counters,
                backend_policy: inputs.backend_policy,
            },
            pass,
        ) {
            continue;
        }
        for key in table.candidate_keys(inputs.key.unwrap_or_default(), inputs.max_iterations) {
            let Some(backend) = backend_by_key.get(&key) else {
                continue;
            };
            if inner.backends().ready(backend)
                && inputs
                    .backend_policy
                    .permits(backend, pass, inputs.counters)
                && inputs
                    .passive_health
                    .is_none_or(|health| !health.is_ejected(backend))
                && (pass.ignore_slow_start
                    || inputs.slow_start.is_none_or(|state| state.permits(backend)))
            {
                return Some(SelectedUpstream::new(backend.clone()));
            }
        }
    }
    None
}

fn maglev_route_secret() -> u64 {
    static SECRET: OnceLock<u64> = OnceLock::new();
    *SECRET.get_or_init(|| {
        let mut bytes = [0u8; 8];
        if let Err(error) = getrandom::fill(&mut bytes) {
            log::error!(
                target: "fluxheim::security",
                "failed to seed Maglev routing hash secret: {error}"
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
