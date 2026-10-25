use super::*;
use fluxheim_observability::event::{
    ActorClass, AuditOperation, AuditOutcome, FailureReason, HttpStatus, Method, SecurityReason,
};
use std::time::Duration;

#[test]
fn logical_completion_is_separate_from_attempts_and_failed_bytes() {
    let metrics = Operational::new().unwrap();
    for (outcome, status, bytes) in [
        (AccessOutcome::Completed, Some(200), 19),
        (AccessOutcome::Cancelled, None, 999),
        (AccessOutcome::Failed, Some(502), 999),
    ] {
        metrics.record(Measurement::RequestStarted);
        for failed in [true, false] {
            metrics.record(Measurement::AttemptStarted);
            metrics.record(Measurement::AttemptFinished {
                failed,
                cancelled: false,
                duration: Duration::from_millis(10),
            });
        }
        metrics.record(Measurement::Event(EventData::Access {
            outcome,
            method: Method::GET,
            status: status.and_then(HttpStatus::new),
            bytes_sent: bytes,
            duration_micros: 25_000,
            attempts: 2,
        }));
    }
    assert_eq!(metrics.active.get(), 0);
    assert_eq!(metrics.active_attempts.get(), 0);
    assert_eq!(metrics.bytes.get(), 19);
    assert_eq!(
        metrics
            .requests
            .with_label_values(&["GET", "2xx", "completed"])
            .get(),
        1
    );
    assert_eq!(metrics.attempts.with_label_values(&["failed"]).get(), 3);
    assert_eq!(metrics.attempts.with_label_values(&["completed"]).get(), 3);
    let samples = metrics.duration.collect();
    let h = samples[0].get_metric()[0].get_histogram();
    assert_eq!(h.sample_count(), 1);
    assert_eq!(h.sample_sum(), 0.025);
    assert_eq!(h.get_bucket()[3].cumulative_count(), 1);
}

#[test]
fn failure_security_and_audit_measurement_do_not_require_a_dispatcher() {
    let metrics = Operational::new().unwrap();
    metrics.record(Measurement::Event(EventData::Error {
        reason: FailureReason::TlsVerification,
        attempt: None,
    }));
    metrics.record(Measurement::Event(EventData::Security {
        reason: SecurityReason::AdmissionRejected,
    }));
    metrics.record(Measurement::Event(EventData::Audit {
        operation: AuditOperation::Rollback,
        outcome: AuditOutcome::Failed,
        actor: ActorClass::Automatic,
        revision: None,
    }));
    assert_eq!(
        metrics
            .failures
            .with_label_values(&["tls_verification"])
            .get(),
        1
    );
    assert_eq!(
        metrics
            .security
            .with_label_values(&["admission_rejected"])
            .get(),
        1
    );
    assert_eq!(
        metrics
            .audit
            .with_label_values(&["rollback", "failed"])
            .get(),
        1
    );
    for outcome in [
        HandshakeOutcome::Succeeded,
        HandshakeOutcome::Failed,
        HandshakeOutcome::Timeout,
    ] {
        metrics.record(Measurement::TlsHandshake(outcome));
    }
    assert_eq!(metrics.tls.collect()[0].get_metric().len(), 3);
}

#[test]
fn concurrent_lifetimes_balance_and_cardinality_is_independent_of_host_path_ids() {
    let metrics = Operational::new().unwrap();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let metrics = &metrics;
            scope.spawn(move || {
                for i in 0..1000 {
                    metrics.record(Measurement::ConnectionStarted);
                    metrics.record(Measurement::RequestStarted);
                    metrics.record(Measurement::AttemptStarted);
                    metrics.record(Measurement::AttemptFinished {
                        failed: true,
                        cancelled: true,
                        duration: Duration::ZERO,
                    });
                    metrics.record(Measurement::Event(EventData::Access {
                        outcome: AccessOutcome::Cancelled,
                        method: Method::from_request(&format!("host/path/secret-{i}")),
                        status: None,
                        duration_micros: 0,
                        bytes_sent: 0,
                        attempts: 1,
                    }));
                    metrics.record(Measurement::ConnectionFinished);
                }
            });
        }
    });
    assert_eq!(metrics.active.get(), 0);
    assert_eq!(metrics.active_attempts.get(), 0);
    assert_eq!(metrics.active_connections.get(), 0);
    assert_eq!(metrics.requests.collect()[0].get_metric().len(), 1);
    assert_eq!(
        metrics
            .requests
            .with_label_values(&["OTHER", "unknown", "cancelled"])
            .get(),
        8000
    );
}

#[test]
fn fixed_domains_fit_reserved_budget_including_histogram_buckets() {
    // 10 methods * 7 status classes * 3 outcomes, two 3-outcome histograms,
    // 22 failures, 9 security reasons, 10*3 admin outcomes, 2 connections,
    // 3 TLS results and 4 scalar measurements. Dispatch health < 100, old scalars <100.
    let maximum =
        10 * 7 * 3 + 2 * 3 * (BUCKETS.len() + 3) + 22 + 9 + 10 * 3 + 2 + 3 + 4 + 100 + 100;
    assert!(maximum < 1000);
    let registry = prometheus::Registry::new();
    registry
        .register(Box::new(Operational::new().unwrap()))
        .unwrap();
    registry
        .register(Box::new(crate::metrics::health::Health::new().unwrap()))
        .unwrap();
    assert!(!registry.gather().is_empty());
}
