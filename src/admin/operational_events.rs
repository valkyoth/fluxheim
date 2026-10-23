use fluxheim_observability::event::{ActorClass, AuditOperation, AuditOutcome};

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

// Call only after token and client-certificate policy have both succeeded.
pub(super) fn authenticated_outcome(operation: Option<AuditOperation>, status: http::StatusCode) {
    if let Some(operation) = operation {
        fluxheim_observability::operational::audit(
            operation,
            outcome(status),
            ActorClass::AdminToken,
        );
    }
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
