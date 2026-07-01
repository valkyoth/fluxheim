use super::SelectedUpstream;
use super::backend::backend_container_snapshot;
use super::backend::{BackendContainer, BackendContainerSnapshot, RuntimeBackend as Backend};
use super::key::backend_key;
use super::policy::BackendSelectionPolicy;
use super::selection::{
    LoadBalancerSelectInputs, SelectionPass, priority_activation_satisfied, selection_passes,
};
use super::selection_candidate::{
    SelectionContext, backend_candidate_allowed, backend_candidate_allowed_read_only,
};
use super::selection_hash::{consistent_route_secret, fnv1a64_with_seed};
use super::selection_ketama::NginxKetamaTable;
use super::state::BackendConnectionCounters;

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
