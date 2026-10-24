use super::*;
use crate::event::{ActorClass, AuditOperation, AuditOutcome, FailureReason, SecurityReason};
use std::sync::{Condvar, Mutex};

#[path = "operational_audit_tests.rs"]
mod audit_reservation;

fn security() -> EventData {
    EventData::Security {
        reason: SecurityReason::HostRejected,
    }
}
fn audit() -> EventData {
    EventData::Audit {
        operation: AuditOperation::Snapshot,
        outcome: AuditOutcome::Succeeded,
        actor: ActorClass::AdminToken,
        revision: None,
    }
}
fn error() -> EventData {
    EventData::Error {
        reason: FailureReason::Dns,
        attempt: None,
    }
}

#[derive(Clone, Default)]
struct Output(Arc<Mutex<Vec<u8>>>);
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Default)]
struct Gate(Arc<(Mutex<(bool, bool)>, Condvar)>);
impl Gate {
    fn wait_started(&self) {
        let (lock, cv) = &*self.0;
        let (state, timeout) = cv
            .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(5), |s| !s.0)
            .unwrap();
        assert!(!timeout.timed_out() && state.0);
    }
    fn release(&self) {
        let (lock, cv) = &*self.0;
        lock.lock().unwrap().1 = true;
        cv.notify_all();
    }
}
struct Blocked(Gate);
impl Write for Blocked {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let (lock, cv) = &*self.0.0;
        let mut state = lock.lock().unwrap();
        state.0 = true;
        cv.notify_all();
        while !state.1 {
            state = cv.wait(state).unwrap();
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn wait_until(mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !check() {
        assert!(Instant::now() < deadline, "worker did not make progress");
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
#[cfg(not(feature = "privacy-mode"))]
fn correlated_events_reach_the_worker_with_bounded_validated_ids() {
    let output = Output::default();
    let dispatcher = Dispatcher::new(
        EventFormat::Json,
        Arc::new(|_| true),
        [
            Box::new(output.clone()),
            Box::new(io::sink()),
            Box::new(io::sink()),
        ],
    )
    .unwrap();
    let data = EventData::Access {
        outcome: crate::event::AccessOutcome::Completed,
        method: crate::event::Method::GET,
        status: crate::event::HttpStatus::new(200),
        duration_micros: 1,
        bytes_sent: 2,
        attempts: 1,
    };
    let policy = CapturePolicy {
        access_enabled: true,
        include_request_id: true,
        include_trace_ids: true,
        ..Default::default()
    };
    dispatcher.try_emit_correlated(
        data,
        CorrelationInput {
            trusted: true,
            request_id: Some("a".repeat(128).as_str()),
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736"),
            span_id: Some("00f067aa0ba902b7"),
        },
        policy,
    );
    dispatcher.try_emit_correlated(
        data,
        CorrelationInput {
            trusted: false,
            request_id: Some("secret"),
            ..Default::default()
        },
        policy,
    );
    dispatcher.try_emit_correlated(
        data,
        CorrelationInput {
            trusted: true,
            request_id: Some("x".repeat(129).as_str()),
            ..Default::default()
        },
        policy,
    );
    wait_until(|| dispatcher.status().ordinary.written == 3);
    dispatcher.shutdown(Duration::from_secs(1));
    let bytes = output.0.lock().unwrap();
    let lines: Vec<serde_json::Value> = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines[0]["correlation"]["request_id"], "a".repeat(128));
    assert_eq!(
        lines[0]["correlation"]["trace_id"],
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    assert_eq!(lines[1]["correlation"], serde_json::json!({}));
    assert_eq!(lines[2]["correlation"], serde_json::json!({}));
}

#[test]
fn public_flood_is_rejected_before_encoding_and_cannot_spend_audit_capacity() {
    let gate = Gate::default();
    let output = Output::default();
    let dispatcher = Dispatcher::new(
        EventFormat::Json,
        Arc::new(|_| true),
        [
            Box::new(io::sink()),
            Box::new(Blocked(gate.clone())),
            Box::new(output.clone()),
        ],
    )
    .unwrap();
    let now = Instant::now();
    dispatcher.try_emit_at(security(), now);
    gate.wait_started();
    let start = Instant::now();
    for _ in 0..999 {
        dispatcher.try_emit_at(security(), now);
    }
    assert!(start.elapsed() < Duration::from_secs(2));
    let status = dispatcher.status();
    assert_eq!(status.security.accepted, 100);
    assert_eq!(status.security.rate_limited, 900);
    assert_eq!(
        status.security.encoded, 1,
        "rejected records must not encode or flush"
    );
    assert_eq!(status.security.written, 0);
    // Even a contended security budget cannot contend with an authenticated audit.
    let held = dispatcher.lanes[1].budget.lock().unwrap();
    dispatcher.try_emit_at(security(), now);
    dispatcher.try_emit_at(audit(), now);
    wait_until(|| dispatcher.status().audit.written == 1);
    drop(held);
    let event: serde_json::Value = serde_json::from_slice(&output.0.lock().unwrap()).unwrap();
    assert_eq!(event["data"]["actor"], "admin_token");
    assert_eq!(event["data"]["operation"], "snapshot");
    assert_eq!(dispatcher.status().audit.rate_limited, 0);
    gate.release();
    dispatcher.shutdown(Duration::from_millis(500));
    assert_eq!(dispatcher.status().security.written, 100);
}

#[test]
fn stalled_queue_has_fixed_capacity_and_shutdown_deadline() {
    let gate = Gate::default();
    let dispatcher = Dispatcher::new(
        EventFormat::Text,
        Arc::new(|_| true),
        [
            Box::new(Blocked(gate.clone())),
            Box::new(io::sink()),
            Box::new(io::sink()),
        ],
    )
    .unwrap();
    let now = Instant::now();
    dispatcher.try_emit_at(error(), now);
    gate.wait_started();
    // Advance admission windows without sleeping; queue capacity must remain fixed.
    for second in 1..10 {
        for _ in 0..100 {
            dispatcher.try_emit_at(error(), now + Duration::from_secs(second));
        }
    }
    let status = dispatcher.status();
    assert_eq!(status.ordinary.accepted, QUEUE_CAPACITY as u64 + 1);
    assert_eq!(status.ordinary.encoded, 1);
    assert_eq!(status.ordinary.queue_full, 900 - QUEUE_CAPACITY as u64);
    assert_eq!(
        status.queue_payload_bytes_per_lane,
        QUEUE_CAPACITY * std::mem::size_of::<Pending>()
    );
    let start = Instant::now();
    dispatcher.shutdown(Duration::from_millis(20));
    assert!(start.elapsed() < Duration::from_secs(1));
    dispatcher.try_emit(error());
    assert_eq!(dispatcher.status().ordinary.unavailable, 1);
    gate.release();
    wait_until(|| !dispatcher.status().ordinary.worker_alive);
}

#[test]
fn filtering_precedes_admission_and_only_selected_format_is_written() {
    for (format, prefix) in [
        (EventFormat::Json, "{"),
        (EventFormat::Text, "ERROR error {"),
    ] {
        let output = Output::default();
        let dispatcher = Dispatcher::new(
            format,
            Arc::new(|data| matches!(data, EventData::Error { .. })),
            [
                Box::new(output.clone()),
                Box::new(io::sink()),
                Box::new(io::sink()),
            ],
        )
        .unwrap();
        dispatcher.try_emit(security());
        assert_eq!(dispatcher.status().security.filtered, 1);
        assert!(dispatcher.lanes[1].budget.lock().unwrap().is_none());
        dispatcher.try_emit(error());
        dispatcher.shutdown(Duration::from_millis(500));
        assert_eq!(dispatcher.status().ordinary.encoded, 1);
        let bytes = output.0.lock().unwrap();
        assert!(std::str::from_utf8(&bytes).unwrap().starts_with(prefix));
        assert!(bytes.len() <= crate::event::MAX_EVENT_BYTES);
    }
}

#[test]
fn sink_failure_is_visible_without_retry_or_recursive_logging() {
    struct Failed;
    impl Write for Failed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("must not flush after failed write")
        }
    }
    let dispatcher = Dispatcher::new(
        EventFormat::Json,
        Arc::new(|_| true),
        [Box::new(Failed), Box::new(io::sink()), Box::new(io::sink())],
    )
    .unwrap();
    dispatcher.try_emit(error());
    wait_until(|| !dispatcher.status().ordinary.worker_alive);
    dispatcher.try_emit(error());
    let status = dispatcher.status();
    assert_eq!(status.ordinary.sink_errors, 1);
    assert_eq!(status.ordinary.encoded, 1);
    assert_eq!(status.ordinary.unavailable, 1);
    assert_eq!(status.ordinary.written, 0);
    dispatcher.try_emit(audit());
    dispatcher.shutdown(Duration::from_millis(500));
    assert_eq!(dispatcher.status().audit.written, 1);
}

#[test]
fn failed_flush_is_not_reported_as_delivered_and_queued_losses_are_counted() {
    struct FailedFlush(Gate);
    impl Write for FailedFlush {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Blocked(self.0.clone()).write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }
    let gate = Gate::default();
    let dispatcher = Dispatcher::new(
        EventFormat::Json,
        Arc::new(|_| true),
        [
            Box::new(FailedFlush(gate.clone())),
            Box::new(io::sink()),
            Box::new(io::sink()),
        ],
    )
    .unwrap();
    let now = Instant::now();
    dispatcher.try_emit_at(error(), now);
    gate.wait_started();
    for _ in 0..4 {
        dispatcher.try_emit_at(error(), now);
    }
    gate.release();
    wait_until(|| dispatcher.status().ordinary.discarded == 4);
    let status = dispatcher.status();
    assert_eq!(status.ordinary.sink_errors, 1);
    assert_eq!(status.ordinary.written, 0);
    assert_eq!(status.ordinary.pending, 0);
    assert_eq!(status.ordinary.encoded, 1);
}

#[test]
fn rate_budget_recovers_and_counters_saturate() {
    let dispatcher = Dispatcher::new(
        EventFormat::Json,
        Arc::new(|_| true),
        [
            Box::new(io::sink()),
            Box::new(io::sink()),
            Box::new(io::sink()),
        ],
    )
    .unwrap();
    let now = Instant::now();
    for lane in &dispatcher.lanes {
        for _ in 0..100 {
            assert!(lane.admit(now));
        }
        assert!(!lane.admit(now));
        assert!(lane.admit(now + Duration::from_secs(1)));
        lane.counters
            .rate_limited
            .store(u64::MAX, Ordering::Relaxed);
        increment(&lane.counters.rate_limited);
        assert_eq!(lane.status().rate_limited, u64::MAX);
    }
}
