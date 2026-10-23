//! Operational producers accept only finite codes, never request fields or raw errors.
//! Delivery remains synchronous until the bounded-dispatch checkpoint.
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::event::{
    ActorClass, AdmissionClass, AuditOperation, AuditOutcome, CapturePolicy, CorrelationInput,
    EventData, EventFormat, FailureReason, SecurityReason, StructuredEvent,
};

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

/// There is deliberately no correlation, resource, policy or actor inference from HTTP.
pub fn emit(data: EventData) {
    if !log::log_enabled!(target: data.target(), data.level()) {
        return;
    }
    let Some(event) = StructuredEvent::capture(
        u64::try_from(crate::unix_time_nanos()).unwrap_or(u64::MAX),
        data,
        None,
        CorrelationInput::default(),
        CapturePolicy::default(),
        true,
    ) else {
        return;
    };
    let (Ok(json), Ok(text)) = (
        event.encode(EventFormat::Json),
        event.encode(EventFormat::Text),
    ) else {
        return;
    };
    let (Ok(json), Ok(text)) = (
        std::str::from_utf8(json.as_bytes()),
        std::str::from_utf8(text.as_bytes()),
    ) else {
        return;
    };
    // The fixed message preserves env_logger's regex filter semantics. Payloads
    // travel separately, so they are not reparsed from arbitrary legacy messages.
    log::log!(target: data.target(), data.level(),
        fluxheim_event_json = json, fluxheim_event_text = text; "{}", data.message());
}

/// Fixed-state, nonblocking per-class admission. Each class gets 100 records per
/// one-second window; ordinary errors cannot consume the security/audit budget.
pub struct EventBudget {
    ordinary: Mutex<Option<(Instant, u32)>>,
    protected: Mutex<Option<(Instant, u32)>>,
    dropped: AtomicU64,
}

impl Default for EventBudget {
    fn default() -> Self {
        Self {
            ordinary: Mutex::new(None),
            protected: Mutex::new(None),
            dropped: AtomicU64::new(0),
        }
    }
}

impl EventBudget {
    pub fn admit(&self, class: AdmissionClass, now: Instant) -> bool {
        let bucket = match class {
            AdmissionClass::Ordinary => &self.ordinary,
            AdmissionClass::Protected => &self.protected,
        };
        if let Ok(mut state) = bucket.try_lock() {
            let (start, count) = state.get_or_insert((now, 0));
            if now.saturating_duration_since(*start) >= Duration::from_secs(1) {
                *start = now;
                *count = 0;
            }
            if *count < 100 {
                *count += 1;
                return true;
            }
        }
        let _ = self
            .dropped
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
        false
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Read only the reserved bounded payload on a known operational target.
pub fn record_payload<'a>(
    record: &'a log::Record<'a>,
    format: EventFormat,
) -> Option<(&'a str, AdmissionClass)> {
    let class = match record.target() {
        "fluxheim::event::error" => AdmissionClass::Ordinary,
        "fluxheim::event::security" | "fluxheim::event::audit" => AdmissionClass::Protected,
        _ => return None,
    };
    let key = match format {
        EventFormat::Json => "fluxheim_event_json",
        EventFormat::Text => "fluxheim_event_text",
    };
    let value = record.key_values().get(key.into())?.to_borrowed_str()?;
    (value.len() <= crate::event::MAX_EVENT_BYTES).then_some((value, class))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_admission_is_separate_nonblocking_and_recovers() {
        let budget = EventBudget::default();
        let now = Instant::now();
        for _ in 0..100 {
            assert!(budget.admit(AdmissionClass::Ordinary, now));
        }
        assert!(!budget.admit(AdmissionClass::Ordinary, now));
        assert!(budget.admit(AdmissionClass::Protected, now));
        let held = budget.protected.lock().unwrap();
        assert!(!budget.admit(AdmissionClass::Protected, now));
        drop(held);
        assert!(budget.admit(AdmissionClass::Ordinary, now + Duration::from_secs(1)));
        assert_eq!(budget.dropped(), 2);
    }
}
