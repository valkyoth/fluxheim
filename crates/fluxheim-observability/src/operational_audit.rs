use super::*;
use crate::event::{ActorClass, AuditOperation, AuditOutcome};

#[derive(Debug, Clone, Copy)]
pub struct AuditUnavailable;

pub(super) fn take_slot(c: &Counters) -> bool {
    if c.audit_slots
        .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
        .is_ok()
    {
        true
    } else {
        increment(&c.queue_full);
        false
    }
}

fn data(operation: AuditOperation, outcome: AuditOutcome, actor: ActorClass) -> EventData {
    EventData::Audit {
        operation,
        outcome,
        actor,
        revision: None,
    }
}

impl Dispatcher {
    /// Reserve rate admission AND capacity, including queued/in-flight audits.
    /// All result severities must be enabled before a mutation can begin.
    pub fn try_reserve_audit(
        &self,
        operation: AuditOperation,
        actor: ActorClass,
    ) -> Result<AuditPermit, AuditUnavailable> {
        self.try_reserve_audit_at(operation, actor, Instant::now())
    }

    pub(super) fn try_reserve_audit_at(
        &self,
        operation: AuditOperation,
        actor: ActorClass,
        now: Instant,
    ) -> Result<AuditPermit, AuditUnavailable> {
        let lane = &self.lanes[2];
        let c = &lane.counters;
        for outcome in [
            AuditOutcome::Succeeded,
            AuditOutcome::Rejected,
            AuditOutcome::Failed,
        ] {
            if !(self.filter)(data(operation, outcome, actor)) {
                increment(&c.filtered);
                return Err(AuditUnavailable);
            }
        }
        if c.closing.load(Ordering::Acquire) || !c.alive.load(Ordering::Acquire) {
            increment(&c.unavailable);
            return Err(AuditUnavailable);
        }
        if !lane.admit(now) || !take_slot(c) {
            return Err(AuditUnavailable);
        }
        increment(&c.reserved);
        Ok(AuditPermit {
            sender: lane.sender.clone(),
            counters: c.clone(),
            operation,
            actor,
            held: true,
        })
    }
}

/// Single-use credit. Queue fullness and subsequent rate-limit exhaustion cannot
/// steal it. This is memory reservation, not durable intent or delivery acknowledgment.
#[must_use = "hold the permit across the operation and commit its outcome"]
pub struct AuditPermit {
    sender: SyncSender<Pending>,
    counters: Arc<Counters>,
    operation: AuditOperation,
    actor: ActorClass,
    held: bool,
}

impl AuditPermit {
    pub fn commit(mut self, outcome: AuditOutcome) -> Result<(), AuditUnavailable> {
        let c = &self.counters;
        if !c.alive.load(Ordering::Acquire) || c.closing.load(Ordering::Acquire) {
            increment(&c.unavailable);
            return Err(AuditUnavailable);
        }
        let data = data(self.operation, outcome, self.actor);
        let pending = Pending {
            data,
            timestamp: u64::try_from(crate::unix_time_nanos()).unwrap_or(u64::MAX),
            correlation: Default::default(),
            policy: Default::default(),
        };
        match self.sender.try_send(pending) {
            Ok(()) => {
                self.held = false;
                c.reserved.fetch_sub(1, Ordering::Relaxed);
                increment(&c.accepted);
                #[cfg(feature = "test-support")]
                crate::event_test_support::capture(data);
                Ok(())
            }
            Err(error) => {
                match error {
                    TrySendError::Full(_) => increment(&c.queue_full),
                    TrySendError::Disconnected(_) => increment(&c.unavailable),
                }
                Err(AuditUnavailable)
            }
        }
    }
}

impl Drop for AuditPermit {
    fn drop(&mut self) {
        if self.held {
            self.counters.reserved.fetch_sub(1, Ordering::Relaxed);
            self.counters.audit_slots.fetch_add(1, Ordering::Release);
        }
    }
}
