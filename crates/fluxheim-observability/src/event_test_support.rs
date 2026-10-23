//! Opt-in test logger. Capture is thread-local: use current-thread async tests.
use std::cell::RefCell;
use std::sync::Once;

thread_local! {
    static EVENTS: RefCell<Option<Vec<serde_json::Value>>> = const { RefCell::new(None) };
}

struct Logger;
impl log::Log for Logger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        if let Some((payload, _)) =
            crate::operational::record_payload(record, crate::event::EventFormat::Json)
        {
            EVENTS.with(|events| {
                if let Some(events) = events.borrow_mut().as_mut()
                    && events.len() < 1024
                    && let Ok(event) = serde_json::from_str(payload)
                {
                    events.push(event);
                }
            });
        }
    }
    fn flush(&self) {}
}

pub struct Capture;
impl Capture {
    pub fn start() -> Self {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            assert!(
                log::set_logger(&Logger).is_ok(),
                "test logger already installed"
            );
            log::set_max_level(log::LevelFilter::Trace);
        });
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
