use super::backend::{BackendContainerSnapshot, RuntimeBackend as Backend};
use super::policy::BackendSelectionPolicy;
use super::selection::SelectionPass;
use super::state::{BackendConnectionCounters, PassiveHealthState, SlowStartState};

#[derive(Clone, Copy)]
pub(super) struct SelectionContext<'a> {
    pub(super) passive_health: Option<&'a PassiveHealthState>,
    pub(super) slow_start: Option<&'a SlowStartState>,
    pub(super) counters: &'a BackendConnectionCounters,
    pub(super) backend_policy: &'a BackendSelectionPolicy,
}

pub(super) fn backend_candidate_allowed(
    snapshot: &BackendContainerSnapshot,
    backend: &Backend,
    context: SelectionContext<'_>,
    pass: SelectionPass,
) -> bool {
    backend_candidate_base_allowed(snapshot, backend, context, pass, false)
        && passive_health_candidate_allowed(snapshot, backend, context)
}

pub(super) fn backend_candidate_allowed_read_only(
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
