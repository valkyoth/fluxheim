//! Finite operational events. Production producers never encode or perform sink I/O.
use std::sync::OnceLock;

use crate::event::{
    ActorClass, AuditOperation, AuditOutcome, EventData, FailureReason, SecurityReason,
};

#[path = "operational_dispatch.rs"]
mod dispatch;
pub use dispatch::{
    AuditPermit, AuditUnavailable, Dispatcher, DispatcherStatus, EventFilter, LaneStatus,
    QUEUE_CAPACITY,
};

static DISPATCHER: OnceLock<Dispatcher> = OnceLock::new();

tokio::task_local! {
    static REQUEST: (dispatch::PendingCorrelation, crate::event::CapturePolicy);
}

/// Request-local values, not thread-local state. Detached background tasks start
/// without this context. Audit admission and identity never use request context.
pub async fn scope<T>(
    correlation: crate::event::CorrelationInput<'_>,
    policy: crate::event::CapturePolicy,
    future: impl std::future::Future<Output = T>,
) -> T {
    REQUEST
        .scope(
            (
                dispatch::PendingCorrelation::capture(correlation, policy),
                policy,
            ),
            future,
        )
        .await
}

pub fn reserve_audit(
    operation: AuditOperation,
    actor: ActorClass,
) -> Result<AuditPermit, AuditUnavailable> {
    DISPATCHER
        .get()
        .ok_or(AuditUnavailable)?
        .try_reserve_audit(operation, actor)
}

pub fn install(dispatcher: Dispatcher) -> Result<(), &'static str> {
    DISPATCHER
        .set(dispatcher)
        .map_err(|_| "operational dispatcher already installed")
}

pub fn status() -> Option<DispatcherStatus> {
    DISPATCHER.get().map(Dispatcher::status)
}

pub fn shutdown(timeout: std::time::Duration) {
    if let Some(dispatcher) = DISPATCHER.get() {
        dispatcher.shutdown(timeout);
    }
}

/// No synchronous fallback: an uninitialized dispatcher must not block serving.
pub fn emit(data: EventData) {
    #[cfg(feature = "test-support")]
    if crate::event_test_support::capture(data) {
        return;
    }
    if let Some(dispatcher) = DISPATCHER.get() {
        if !matches!(data, EventData::Audit { .. })
            && REQUEST
                .try_with(|(correlation, policy)| {
                    dispatcher.try_emit_correlated(data, correlation.input(), *policy)
                })
                .is_ok()
        {
            return;
        }
        dispatcher.try_emit(data);
    }
}

/// The producer must establish local generation or configured peer trust first.
/// Candidates are validated and copied into fixed-size queue fields after admission.
pub fn emit_correlated(
    data: EventData,
    correlation: crate::event::CorrelationInput<'_>,
    policy: crate::event::CapturePolicy,
) {
    if let Some(dispatcher) = DISPATCHER.get() {
        dispatcher.try_emit_correlated(data, correlation, policy);
    }
}

pub fn failure(reason: FailureReason) {
    emit(EventData::Error {
        reason,
        attempt: None,
    });
}

pub fn security(reason: SecurityReason) {
    emit(EventData::Security { reason });
}

pub fn audit(operation: AuditOperation, outcome: AuditOutcome, actor: ActorClass) {
    emit(EventData::Audit {
        operation,
        outcome,
        actor,
        revision: None,
    });
}

/// Bounds shutdown waiting even if the OS cannot cancel a blocked sink write.
pub struct ShutdownGuard;
impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        shutdown(std::time::Duration::from_millis(500));
    }
}
