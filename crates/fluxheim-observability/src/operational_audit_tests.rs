use super::*;

fn reserve(dispatcher: &Dispatcher, now: Instant) -> Result<AuditPermit, AuditUnavailable> {
    dispatcher.try_reserve_audit_at(AuditOperation::Snapshot, ActorClass::AdminToken, now)
}

fn dispatcher(filter: EventFilter, writer: Writer) -> Dispatcher {
    Dispatcher::new(
        EventFormat::Json,
        filter,
        [Box::new(io::sink()), Box::new(io::sink()), writer],
    )
    .unwrap()
}

#[test]
fn reserved_completion_is_not_rate_limited_again() {
    let output = Output::default();
    let dispatcher = dispatcher(Arc::new(|_| true), Box::new(output.clone()));
    let now = Instant::now();
    let permits: Vec<_> = (0..100)
        .map(|_| reserve(&dispatcher, now).unwrap())
        .collect();
    assert!(reserve(&dispatcher, now).is_err());
    assert_eq!(dispatcher.status().audit.reserved, 100);
    for permit in permits {
        permit.commit(AuditOutcome::Succeeded).unwrap();
    }
    dispatcher.shutdown(Duration::from_millis(500));
    let status = dispatcher.status().audit;
    assert_eq!(status.reserved, 0);
    assert_eq!(status.rate_limited, 1);
    assert_eq!(status.accepted, 100);
    assert_eq!(status.written, 100);
    assert_eq!(output.0.lock().unwrap().split(|b| *b == b'\n').count(), 101);
}

#[test]
fn reserved_queued_and_inflight_audits_share_a_hard_capacity_bound() {
    let gate = Gate::default();
    let dispatcher = dispatcher(Arc::new(|_| true), Box::new(Blocked(gate.clone())));
    let now = Instant::now();
    let permit = reserve(&dispatcher, now).unwrap();
    dispatcher.try_emit_at(audit(), now);
    gate.wait_started();
    for i in 0..300 {
        dispatcher.try_emit_at(audit(), now + Duration::from_secs(1 + i / 100));
    }
    assert_eq!(dispatcher.status().audit.accepted, 127);
    assert_eq!(dispatcher.status().audit.reserved, 1);
    assert!(reserve(&dispatcher, now + Duration::from_secs(5)).is_err());
    permit.commit(AuditOutcome::Succeeded).unwrap();
    assert_eq!(dispatcher.status().audit.accepted, 128);
    assert_eq!(dispatcher.status().audit.pending, 128);
    gate.release();
    wait_until(|| dispatcher.status().audit.written == 128);
    drop(reserve(&dispatcher, now + Duration::from_secs(6)).unwrap());
    assert_eq!(
        dispatcher.lanes[2]
            .counters
            .audit_slots
            .load(Ordering::Acquire),
        128
    );
}

#[test]
fn unused_permit_returns_capacity_but_not_rate_budget() {
    let dispatcher = dispatcher(Arc::new(|_| true), Box::new(io::sink()));
    let now = Instant::now();
    for _ in 0..100 {
        drop(reserve(&dispatcher, now).unwrap());
    }
    assert!(reserve(&dispatcher, now).is_err());
    assert_eq!(dispatcher.status().audit.reserved, 0);
    assert_eq!(dispatcher.status().audit.accepted, 0);
    assert_eq!(
        dispatcher.lanes[2]
            .counters
            .audit_slots
            .load(Ordering::Acquire),
        128
    );
    assert!(reserve(&dispatcher, now + Duration::from_secs(1)).is_ok());
}

#[test]
fn each_possible_outcome_must_be_enabled_before_reservation() {
    for disabled in [
        AuditOutcome::Succeeded,
        AuditOutcome::Rejected,
        AuditOutcome::Failed,
    ] {
        let dispatcher = dispatcher(
            Arc::new(move |data| {
                !matches!(data, EventData::Audit { outcome, .. }
                    if std::mem::discriminant(&outcome) == std::mem::discriminant(&disabled))
            }),
            Box::new(io::sink()),
        );
        assert!(reserve(&dispatcher, Instant::now()).is_err());
        assert_eq!(dispatcher.status().audit.filtered, 1);
        assert!(dispatcher.lanes[2].budget.lock().unwrap().is_none());
        assert_eq!(dispatcher.status().audit.reserved, 0);
    }
}

#[test]
fn shutdown_rejects_reservation_and_completion_without_leaking_credit() {
    let dispatcher = dispatcher(Arc::new(|_| true), Box::new(io::sink()));
    let now = Instant::now();
    let permit = reserve(&dispatcher, now).unwrap();
    dispatcher.shutdown(Duration::from_millis(500));
    assert!(reserve(&dispatcher, now).is_err());
    assert!(permit.commit(AuditOutcome::Failed).is_err());
    assert_eq!(dispatcher.status().audit.reserved, 0);
    assert_eq!(dispatcher.status().audit.accepted, 0);
    assert_eq!(
        dispatcher.lanes[2]
            .counters
            .audit_slots
            .load(Ordering::Acquire),
        128
    );
}

#[test]
fn failed_audit_sink_rejects_new_and_previously_reserved_work() {
    struct Failed;
    impl Write for Failed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("failed write must not flush")
        }
    }
    let dispatcher = dispatcher(Arc::new(|_| true), Box::new(Failed));
    let now = Instant::now();
    let held = reserve(&dispatcher, now).unwrap();
    reserve(&dispatcher, now)
        .unwrap()
        .commit(AuditOutcome::Succeeded)
        .unwrap();
    wait_until(|| !dispatcher.status().audit.worker_alive);
    assert!(reserve(&dispatcher, now).is_err());
    assert!(held.commit(AuditOutcome::Failed).is_err());
    assert_eq!(dispatcher.status().audit.sink_errors, 1);
    assert_eq!(dispatcher.status().audit.written, 0);
    assert_eq!(dispatcher.status().audit.reserved, 0);
    assert_eq!(
        dispatcher.lanes[2]
            .counters
            .audit_slots
            .load(Ordering::Acquire),
        128
    );
}

#[test]
fn concurrent_reservations_and_background_audits_cannot_steal_a_held_credit() {
    let gate = Gate::default();
    let dispatcher = dispatcher(Arc::new(|_| true), Box::new(Blocked(gate.clone())));
    let now = Instant::now();
    let held = reserve(&dispatcher, now).unwrap();
    dispatcher.try_emit_at(audit(), now);
    gate.wait_started();
    std::thread::scope(|scope| {
        for thread in 0..8 {
            let dispatcher = &dispatcher;
            scope.spawn(move || {
                for second in 1..100 {
                    let time = now + Duration::from_secs(second);
                    if thread % 2 == 0 {
                        if let Ok(permit) = reserve(dispatcher, time) {
                            permit.commit(AuditOutcome::Rejected).unwrap();
                        }
                    } else {
                        dispatcher.try_emit_at(audit(), time);
                    }
                }
            });
        }
    });
    assert!(dispatcher.status().audit.accepted <= 127);
    held.commit(AuditOutcome::Succeeded).unwrap();
    let accepted = dispatcher.status().audit.accepted;
    gate.release();
    wait_until(|| dispatcher.status().audit.written == accepted);
    assert_eq!(dispatcher.status().audit.reserved, 0);
    assert_eq!(
        dispatcher.lanes[2]
            .counters
            .audit_slots
            .load(Ordering::Acquire),
        128
    );
}
