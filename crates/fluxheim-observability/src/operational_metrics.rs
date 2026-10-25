//! Optional process-local measurement hook; carries no request-controlled strings.
use crate::event::EventData;
use std::sync::OnceLock;
use std::time::Duration;

#[derive(Clone, Copy)]
pub enum Measurement {
    Event(EventData),
    RequestStarted,
    AttemptStarted,
    AttemptFinished {
        failed: bool,
        cancelled: bool,
        duration: Duration,
    },
    ConnectionStarted,
    ConnectionFinished,
    ConnectionRejected,
    TlsHandshake(HandshakeOutcome),
}

#[derive(Clone, Copy)]
pub enum HandshakeOutcome {
    Succeeded,
    Failed,
    Timeout,
}

static RECORDER: OnceLock<fn(Measurement)> = OnceLock::new();

pub fn install(recorder: fn(Measurement)) -> bool {
    RECORDER.set(recorder).is_ok()
}

pub fn record(measurement: Measurement) {
    if let Some(recorder) = RECORDER.get() {
        recorder(measurement);
    }
}

/// Move into the connection task so cancellation and shutdown release the gauge.
pub struct Connection {
    recorder: Option<fn(Measurement)>,
}
impl Default for Connection {
    fn default() -> Self {
        let recorder = RECORDER.get().copied();
        if let Some(recorder) = recorder {
            recorder(Measurement::ConnectionStarted);
        }
        Self { recorder }
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(recorder) = self.recorder {
            recorder(Measurement::ConnectionFinished);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn connection_ownership_balances_unpolled_cancellation_and_late_install() {
        static STARTED: AtomicUsize = AtomicUsize::new(0);
        static FINISHED: AtomicUsize = AtomicUsize::new(0);
        let unmeasured = Connection::default();
        assert!(install(|measurement| match measurement {
            Measurement::ConnectionStarted => {
                STARTED.fetch_add(1, Ordering::Relaxed);
            }
            Measurement::ConnectionFinished => {
                FINISHED.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }));
        drop(unmeasured);
        assert_eq!(FINISHED.load(Ordering::Relaxed), 0);

        let connection = Connection::default();
        let unpolled_task = async move {
            let _connection = connection;
            std::future::pending::<()>().await;
        };
        assert_eq!(STARTED.load(Ordering::Relaxed), 1);
        drop(unpolled_task);
        assert_eq!(FINISHED.load(Ordering::Relaxed), 1);
    }
}
