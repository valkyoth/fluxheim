use super::record::Record;
use std::cell::Cell;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

pub(super) const CAPACITY: u64 = 128;
pub(super) const PRODUCERS: u64 = 8;
thread_local! { static ENTERED: Cell<bool> = const { Cell::new(false) }; }

struct Enter;
impl Enter {
    fn new() -> Option<Self> {
        ENTERED.with(|entered| {
            if entered.replace(true) {
                None
            } else {
                Some(Self)
            }
        })
    }
}
impl Drop for Enter {
    fn drop(&mut self) {
        ENTERED.with(|entered| entered.set(false));
    }
}
fn inc(value: &AtomicU64) {
    let _ = value.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
}
fn take(value: &AtomicU64, max: u64) -> bool {
    value
        .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < max).then(|| n + 1)
        })
        .is_ok()
}

#[derive(Default)]
struct Counters {
    accepted: AtomicU64,
    filtered: AtomicU64,
    oversized: AtomicU64,
    queue_full: AtomicU64,
    producer_busy: AtomicU64,
    recursive: AtomicU64,
    unavailable: AtomicU64,
    written: AtomicU64,
    discarded: AtomicU64,
    sink_errors: AtomicU64,
    worker_panics: AtomicU64,
    capture_panics: AtomicU64,
    completed: AtomicU64,
    credits: AtomicU64,
    producers: AtomicU64,
    alive: AtomicBool,
    closing: AtomicBool,
}

#[derive(serde::Serialize)]
pub(crate) struct Status {
    pub(super) file_sink: Option<super::file::Status>,
    capacity: u64,
    max_producers: u64,
    queue_payload_bytes: usize,
    max_encoded_bytes: usize,
    accepted: u64,
    filtered: u64,
    oversized: u64,
    queue_full: u64,
    producer_busy: u64,
    recursive: u64,
    unavailable: u64,
    written: u64,
    discarded: u64,
    sink_errors: u64,
    worker_panics: u64,
    capture_panics: u64,
    pending: u64,
    active_producers: u64,
    worker_alive: bool,
}

struct Producer(Arc<Counters>);
impl Drop for Producer {
    fn drop(&mut self) {
        if std::thread::panicking() {
            inc(&self.0.capture_panics);
        }
        self.0.producers.fetch_sub(1, Ordering::Release);
    }
}
struct Credit(Arc<Counters>);
impl Drop for Credit {
    fn drop(&mut self) {
        self.0.credits.fetch_sub(1, Ordering::Release);
    }
}
struct Queued {
    record: Record,
    credit: Credit,
    tracked: bool,
    delivered: bool,
}
impl Drop for Queued {
    fn drop(&mut self) {
        if self.tracked {
            inc(&self.credit.0.completed);
            if !self.delivered {
                inc(&self.credit.0.discarded);
            }
        }
    }
}

pub(super) struct Logger {
    matcher: env_logger::Logger,
    sender: mpsc::SyncSender<Queued>,
    counters: Arc<Counters>,
}

impl Logger {
    pub(super) fn max_level(&self) -> log::LevelFilter {
        self.matcher.filter()
    }

    pub(super) fn new(
        matcher: env_logger::Logger,
        format: crate::config::LoggingFormat,
        writer: Box<dyn Write + Send>,
    ) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(CAPACITY as usize);
        let counters = Arc::new(Counters::default());
        counters.alive.store(true, Ordering::Release);
        let c = counters.clone();
        std::thread::Builder::new()
            .name("fluxheim-legacy-log".into())
            .spawn(move || {
                let _entered = Enter::new();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    worker(&receiver, writer, format, &c)
                }));
                if result.is_err() {
                    inc(&c.worker_panics);
                }
                c.alive.store(false, Ordering::Release);
                // Dropping the receiver accounts for every remaining record via Queued::drop.
                drop(receiver);
            })?;
        Ok(Self {
            matcher,
            sender,
            counters,
        })
    }

    pub(super) fn status(&self) -> Status {
        let c = &self.counters;
        let read = |v: &AtomicU64| v.load(Ordering::Relaxed);
        Status {
            file_sink: None,
            capacity: CAPACITY,
            max_producers: PRODUCERS,
            queue_payload_bytes: CAPACITY as usize * std::mem::size_of::<Queued>(),
            max_encoded_bytes: super::record::MAX_ENCODED,
            accepted: read(&c.accepted),
            filtered: read(&c.filtered),
            oversized: read(&c.oversized),
            queue_full: read(&c.queue_full),
            producer_busy: read(&c.producer_busy),
            recursive: read(&c.recursive),
            unavailable: read(&c.unavailable),
            written: read(&c.written),
            discarded: read(&c.discarded),
            sink_errors: read(&c.sink_errors),
            worker_panics: read(&c.worker_panics),
            capture_panics: read(&c.capture_panics),
            pending: read(&c.accepted).saturating_sub(read(&c.completed)),
            active_producers: read(&c.producers),
            worker_alive: c.alive.load(Ordering::Acquire),
        }
    }

    pub(super) fn shutdown(&self, timeout: Duration) {
        self.counters.closing.store(true, Ordering::Release);
        let start = Instant::now();
        while self.counters.alive.load(Ordering::Acquire)
            && start.elapsed() < timeout.min(Duration::from_millis(500))
        {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        self.matcher.enabled(metadata)
    }
    fn log(&self, record: &log::Record<'_>) {
        let c = &self.counters;
        let Some(_entered) = Enter::new() else {
            inc(&c.recursive);
            return;
        };
        if c.closing.load(Ordering::Acquire) || !c.alive.load(Ordering::Acquire) {
            inc(&c.unavailable);
            return;
        }
        if !self.enabled(record.metadata()) {
            inc(&c.filtered);
            return;
        }
        if !take(&c.producers, PRODUCERS) {
            inc(&c.producer_busy);
            return;
        }
        let _producer = Producer(c.clone());
        if !take(&c.credits, CAPACITY) {
            inc(&c.queue_full);
            return;
        }
        let credit = Credit(c.clone());
        let Ok(captured) = Record::capture(record) else {
            inc(&c.oversized);
            return;
        };
        // Match regex on the bounded copy, never arbitrary Display a second time.
        if !self.matcher.matches(
            &log::Record::builder()
                .level(captured.level)
                .target(captured.target.as_str())
                .args(format_args!("{}", captured.message.as_str()))
                .build(),
        ) {
            inc(&c.filtered);
            return;
        }
        let queued = Queued {
            record: captured,
            credit,
            tracked: true,
            delivered: false,
        };
        match self.sender.try_send(queued) {
            Ok(()) => inc(&c.accepted),
            Err(error) => {
                let mut queued = match error {
                    mpsc::TrySendError::Full(q) => {
                        inc(&c.queue_full);
                        q
                    }
                    mpsc::TrySendError::Disconnected(q) => {
                        inc(&c.unavailable);
                        q
                    }
                };
                queued.tracked = false;
            }
        }
    }
    // log::Log::flush has no timeout contract. Never turn it into a producer I/O wait.
    fn flush(&self) {}
}

impl Drop for Logger {
    fn drop(&mut self) {
        self.counters.closing.store(true, Ordering::Release);
    }
}

fn worker(
    receiver: &mpsc::Receiver<Queued>,
    mut writer: Box<dyn Write + Send>,
    format: crate::config::LoggingFormat,
    c: &Counters,
) {
    loop {
        let mut queued = match receiver.recv_timeout(Duration::from_millis(10)) {
            Ok(q) => q,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if c.closing.load(Ordering::Acquire) {
                    break;
                }
                continue;
            }
        };
        let encoded = match queued.record.encode(format) {
            Ok(encoded) => encoded,
            Err(_) => {
                inc(&c.oversized);
                continue;
            }
        };
        if writer
            .write_all(encoded.as_str().as_bytes())
            .and_then(|()| writer.flush())
            .is_err()
        {
            inc(&c.sink_errors);
            break;
        }
        queued.delivered = true;
        inc(&c.written);
    }
}

#[cfg(test)]
#[path = "runtime_log_dispatch_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "runtime_log_fatal_tests.rs"]
mod fatal_tests;
