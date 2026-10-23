//! Opt-in producer capture, not a production delivery path. Use current-thread async tests.
use crate::event::{CapturePolicy, CorrelationInput, EventData, EventFormat, StructuredEvent};
use std::cell::RefCell;

thread_local! {
    static EVENTS: RefCell<Option<Vec<serde_json::Value>>> = const { RefCell::new(None) };
}

pub(crate) fn capture(data: EventData) -> bool {
    EVENTS.with(|events| {
        let mut events = events.borrow_mut();
        let Some(events) = events.as_mut() else {
            return false;
        };
        if events.len() < 1024
            && let Some(event) = StructuredEvent::capture(
                0,
                data,
                None,
                CorrelationInput::default(),
                CapturePolicy::default(),
                true,
            )
            && let Ok(encoded) = event.encode(EventFormat::Json)
            && let Ok(event) = serde_json::from_slice(encoded.as_bytes())
        {
            events.push(event);
        }
        true
    })
}

pub struct Capture;
impl Capture {
    pub fn start() -> Self {
        EVENTS.with(|events| assert!(events.replace(Some(Vec::new())).is_none(), "nested capture"));
        Self
    }

    pub fn events(&self) -> Vec<serde_json::Value> {
        EVENTS.with(|events| events.borrow().clone().unwrap_or_default())
    }

    pub fn assert_reason(&self, reason: &str, count: usize) {
        let events = self.events();
        assert_eq!(
            events
                .iter()
                .filter(|event| event["data"]["reason"] == reason)
                .count(),
            count,
            "events: {events:?}"
        );
        for event in events {
            assert_eq!(event["correlation"], serde_json::json!({}));
            assert!(event.get("resource").is_none());
        }
    }

    pub fn assert_audit(&self, operation: &str, outcome: &str, actor: &str) {
        let events = self.events();
        assert_eq!(
            events
                .iter()
                .filter(|event| event["data"]["operation"] == operation
                    && event["data"]["outcome"] == outcome
                    && event["data"]["actor"] == actor)
                .count(),
            1,
            "events: {events:?}"
        );
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        EVENTS.with(|events| {
            events.replace(None);
        });
    }
}
