use super::*;
use crate::admin::AdminResponse;
use fluxheim_observability::event::{ActorClass, AuditOperation, AuditOutcome, EventFormat};
use fluxheim_observability::operational::Dispatcher;

fn disabled(app: &mut AdminApp) {
    app.audit_dispatcher = Some(Arc::new(
        Dispatcher::new(
            EventFormat::Json,
            Arc::new(|_| false),
            std::array::from_fn(|_| Box::new(std::io::sink()) as Box<dyn std::io::Write + Send>),
        )
        .unwrap(),
    ));
}

fn assert_unavailable(response: AdminResponse) {
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.body, br#"{"error":"audit_unavailable"}"#);
}

#[test]
fn disabled_audit_rejects_every_mutation_before_dispatch_but_not_reads_or_auth() {
    let mut app = app();
    disabled(&mut app);
    for path in [
        "reload",
        "snapshot",
        "rollback",
        "self-heal/confirm",
        "self-heal/fail",
        "self-heal/report",
        "cache/activity/reset",
        "load-balancer/member-state",
        "load-balancer/member-weight",
        "load-balancer/member-add",
        "load-balancer/member-remove",
        "load-balancer/member-update",
        "load-balancer/persistence/clear",
        "cache/purge",
        "cache/purge-bulk",
        "cache/purge-index",
        "cache/purge-prefix",
        "cache/purge-tag",
        "cache/purge-stale",
        "cache/purge-wildcard",
    ] {
        assert_unavailable(app.handle(
            "POST",
            &format!("/_fluxheim/{path}"),
            None,
            &auth_headers(),
        ));
    }
    assert!(app.store.list().unwrap().is_empty());
    assert_eq!(app.store.current_id().unwrap(), None);
    assert_eq!(app.runtime_state().runtime_snapshot, None);
    assert_eq!(
        app.handle("GET", "/_fluxheim/status", None, &auth_headers())
            .status,
        StatusCode::OK
    );
    assert_eq!(
        app.handle("POST", "/_fluxheim/snapshot", None, &HeaderMap::new())
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.handle("POST", "/_fluxheim/unknown", None, &auth_headers())
            .status,
        StatusCode::NOT_FOUND
    );
}

#[test]
fn missing_or_shutdown_dispatcher_blocks_snapshot_without_writing_files() {
    let mut app = app();
    app.audit_dispatcher
        .as_ref()
        .unwrap()
        .shutdown(std::time::Duration::from_millis(500));
    assert_unavailable(app.handle("POST", "/_fluxheim/snapshot", None, &auth_headers()));
    app.audit_dispatcher = None;
    assert_unavailable(app.handle("POST", "/_fluxheim/snapshot", None, &auth_headers()));
    assert!(app.store.list().unwrap().is_empty());
}

#[test]
fn full_audit_reservations_block_mutation_until_capacity_returns() {
    let app = app();
    let dispatcher = app.audit_dispatcher.as_ref().unwrap();
    let mut permits = Vec::new();
    // Fill across admission windows so denial is by capacity, not timing.
    for count in [100, 28] {
        for _ in 0..count {
            permits.push(
                dispatcher
                    .try_reserve_audit(AuditOperation::Snapshot, ActorClass::AdminToken)
                    .unwrap(),
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(1100));
    }
    assert_eq!(dispatcher.status().audit.reserved, 128);
    assert_unavailable(app.handle("POST", "/_fluxheim/snapshot", None, &auth_headers()));
    assert_eq!(dispatcher.status().audit.queue_full, 1);
    assert!(app.store.list().unwrap().is_empty());
    drop(permits);
    assert_eq!(
        app.handle("POST", "/_fluxheim/snapshot", None, &auth_headers())
            .status,
        StatusCode::CREATED
    );
    assert_eq!(app.store.list().unwrap().len(), 1);
}

#[test]
fn automatic_recovery_keeps_pending_state_when_audit_is_unavailable() {
    let mut app = app_with_config_and_self_healing(Config::default(), true);
    let previous = app
        .store
        .snapshot_config(&Config::default(), Some("previous"))
        .unwrap();
    let candidate = app
        .store
        .snapshot_config(&Config::default(), Some("candidate"))
        .unwrap();
    set_test_runtime_state(
        &app,
        Some(candidate.id.clone()),
        Some(previous.id.clone()),
        Some(PendingValidation {
            target_snapshot: candidate.id.clone(),
            previous_snapshot: Some(previous.id),
            impact: "snapshot".to_owned(),
            expires_unix_secs: 0,
            successful_checks: 0,
            failed_checks: 0,
            rollback_attempts: 0,
            last_rollback_failure: None,
        }),
    );
    disabled(&mut app);
    // Both watchdog enforcement and authenticated reads must reserve before rollback.
    assert_unavailable(app.enforce_self_healing_deadline().unwrap());
    assert_unavailable(app.handle("GET", "/_fluxheim/status", None, &auth_headers()));
    assert_unavailable(app.handle(
        "POST",
        "/_fluxheim/self-heal/confirm",
        None,
        &auth_headers(),
    ));
    assert_eq!(app.store.current_id().unwrap(), Some(candidate.id.clone()));
    let state = app.runtime_state();
    assert_eq!(state.runtime_snapshot, Some(candidate.id));
    let pending = state.pending_validation.unwrap();
    assert_eq!(pending.rollback_attempts, 0);
    assert_eq!(pending.successful_checks, 0);
}

#[test]
fn completion_failure_never_claims_success_or_safe_retry() {
    let app = app();
    let dispatcher = app.audit_dispatcher.as_ref().unwrap();
    let permit = dispatcher
        .try_reserve_audit(AuditOperation::Snapshot, ActorClass::AdminToken)
        .unwrap();
    dispatcher.shutdown(std::time::Duration::from_millis(500));
    let response = super::super::operational_events::complete(
        Some(permit),
        AuditOutcome::Succeeded,
        json_response(StatusCode::CREATED, b"{}"),
    );
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["error"], "audit_delivery_failed");
    assert_eq!(body["operation_may_have_completed"], true);
    assert_eq!(dispatcher.status().audit.reserved, 0);
}
