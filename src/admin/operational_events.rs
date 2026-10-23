use super::{AdminApp, AdminResponse, StatusCode, json_response};
use fluxheim_observability::event::{ActorClass, AuditOperation, AuditOutcome};
use fluxheim_observability::operational::{AuditPermit, AuditUnavailable};

pub(super) fn operation(method: &str, path: &str) -> Option<AuditOperation> {
    if method != "POST" {
        return None;
    }
    Some(match path {
        "/_fluxheim/reload" => AuditOperation::Reload,
        "/_fluxheim/snapshot" => AuditOperation::Snapshot,
        "/_fluxheim/rollback" => AuditOperation::Rollback,
        "/_fluxheim/self-heal/confirm"
        | "/_fluxheim/self-heal/fail"
        | "/_fluxheim/self-heal/report" => AuditOperation::SelfHeal,
        "/_fluxheim/cache/activity/reset" => AuditOperation::CacheActivityReset,
        "/_fluxheim/load-balancer/member-state"
        | "/_fluxheim/load-balancer/member-weight"
        | "/_fluxheim/load-balancer/member-add"
        | "/_fluxheim/load-balancer/member-remove"
        | "/_fluxheim/load-balancer/member-update" => AuditOperation::LoadBalancerUpdate,
        "/_fluxheim/load-balancer/persistence/clear" => AuditOperation::PersistenceClear,
        "/_fluxheim/cache/purge"
        | "/_fluxheim/cache/purge-bulk"
        | "/_fluxheim/cache/purge-index"
        | "/_fluxheim/cache/purge-prefix"
        | "/_fluxheim/cache/purge-tag"
        | "/_fluxheim/cache/purge-stale"
        | "/_fluxheim/cache/purge-wildcard" => AuditOperation::CachePurge,
        _ => return None,
    })
}

impl AdminApp {
    pub(super) fn reserve_audit(
        &self,
        operation: AuditOperation,
        actor: ActorClass,
    ) -> Result<AuditPermit, AuditUnavailable> {
        #[cfg(test)]
        if let Some(dispatcher) = &self.audit_dispatcher {
            return dispatcher.try_reserve_audit(operation, actor);
        }
        fluxheim_observability::operational::reserve_audit(operation, actor)
    }
}

pub(super) fn unavailable() -> AdminResponse {
    json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        br#"{"error":"audit_unavailable"}"#,
    )
}

pub(super) fn complete(
    permit: Option<AuditPermit>,
    outcome: AuditOutcome,
    response: AdminResponse,
) -> AdminResponse {
    if let Some(permit) = permit
        && permit.commit(outcome).is_err()
    {
        // The operation may already have executed. Do not report a false success
        // or imply that retrying is safe; this differs from pre-mutation rejection.
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            br#"{"error":"audit_delivery_failed","operation_may_have_completed":true}"#,
        );
    }
    response
}

pub(super) fn authenticated_outcome(
    permit: Option<AuditPermit>,
    response: AdminResponse,
) -> AdminResponse {
    complete(permit, outcome(response.status), response)
}

pub(super) fn outcome(status: http::StatusCode) -> AuditOutcome {
    if status.is_success() {
        AuditOutcome::Succeeded
    } else if status.is_client_error() {
        AuditOutcome::Rejected
    } else {
        AuditOutcome::Failed
    }
}
