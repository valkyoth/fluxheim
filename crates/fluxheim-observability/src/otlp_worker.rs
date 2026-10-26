//! Best-effort export, bounded independently of request handling and local scraping.
use std::collections::VecDeque;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

use crate::otlp_delivery::{Delivery, ExportOutcome, ExportSignal, MAX_EXPORT_BYTES};

#[cfg(test)]
#[path = "otlp_worker_tests.rs"]
mod tests;

const MAX_QUEUE_BYTES: usize = 8 * 1024 * 1024;
const DRAIN: Duration = Duration::from_secs(2);
const ATTEMPTS: usize = 3;
static WORKERS: Mutex<Vec<Weak<State>>> = Mutex::new(Vec::new());

#[derive(Default)]
struct Health {
    accepted: AtomicU64,
    dropped: AtomicU64,
    success: AtomicU64,
    partial: AtomicU64,
    failed: AtomicU64,
    retries: AtomicU64,
    queued_bytes: AtomicU64,
    active: AtomicU64,
}
static TRACE: Health = Health::new();
static METRICS: Health = Health::new();
impl Health {
    const fn new() -> Self {
        Self {
            accepted: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            success: AtomicU64::new(0),
            partial: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            retries: AtomicU64::new(0),
            queued_bytes: AtomicU64::new(0),
            active: AtomicU64::new(0),
        }
    }
}
fn add(counter: &AtomicU64, value: u64) {
    let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_add(value))
    });
}
fn sub(counter: &AtomicU64, value: u64) {
    let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(value))
    });
}

/// Fixed labels only; these diagnostics are not gathered into OTLP payloads.
pub fn export_health_text() -> String {
    use std::fmt::Write;
    let mut text = String::new();
    for (signal, health) in [("traces", &TRACE), ("metrics", &METRICS)] {
        for (name, counter) in [
            ("accepted_total", &health.accepted),
            ("dropped_total", &health.dropped),
            ("success_total", &health.success),
            ("partial_total", &health.partial),
            ("failed_total", &health.failed),
            ("retries_total", &health.retries),
            ("queued_bytes", &health.queued_bytes),
            ("active_requests", &health.active),
        ] {
            let _ = writeln!(
                text,
                "fluxheim_otlp_{name}{{signal=\"{signal}\"}} {}",
                counter.load(Ordering::Relaxed)
            );
        }
    }
    text
}

#[derive(Default)]
struct Queue {
    items: VecDeque<Job>,
    bytes: usize,
    stop: Option<Instant>,
    finished: bool,
}
struct Job {
    payload: String,
    deadline: Instant,
}
struct State {
    queue: Mutex<Queue>,
    wake: Condvar,
    limit: usize,
    timeout: Duration,
    health: &'static Health,
}
struct Owner(Arc<State>);
impl Drop for Owner {
    fn drop(&mut self) {
        self.0.stop();
    }
}
impl State {
    fn stop(&self) {
        let mut queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        queue.stop.get_or_insert_with(|| Instant::now() + DRAIN);
        self.wake.notify_all();
    }
}

#[derive(Clone)]
pub struct ExportWorker(Arc<Owner>);
impl std::fmt::Debug for ExportWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExportWorker")
    }
}
pub struct ExportOptions<'a> {
    pub endpoint: &'a str,
    pub ca: Option<&'a Path>,
    pub token: Option<&'a Path>,
    pub signal: ExportSignal,
    pub queue_size: usize,
    pub timeout: Duration,
    pub on_complete: Option<fn(ExportOutcome)>,
}
impl ExportWorker {
    pub fn new(options: ExportOptions<'_>) -> io::Result<Self> {
        if !(1..=1_000_000).contains(&options.queue_size)
            || !(Duration::from_secs(1)..=Duration::from_secs(60)).contains(&options.timeout)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid OTLP worker limits",
            ));
        }
        let delivery = Delivery::new(options.endpoint, options.ca, options.token, options.signal)?;
        let mut workers = WORKERS.lock().unwrap_or_else(|e| e.into_inner());
        workers.retain(|worker| worker.strong_count() > 0);
        if workers.len() >= 32 {
            return Err(io::Error::other("OTLP worker limit reached"));
        }
        let state = Arc::new(State {
            queue: Mutex::new(Queue::default()),
            wake: Condvar::new(),
            limit: options.queue_size,
            timeout: options.timeout,
            health: match options.signal {
                ExportSignal::Traces => &TRACE,
                ExportSignal::Metrics => &METRICS,
            },
        });
        let worker_state = state.clone();
        std::thread::Builder::new()
            .name("Fluxheim OTLP".into())
            .spawn(move || run(worker_state, delivery, options.on_complete))?;
        workers.push(Arc::downgrade(&state));
        Ok(Self(Arc::new(Owner(state))))
    }

    /// Never waits for collector I/O or queue capacity. Rejects new work after shutdown.
    /// The short queue lock covers bookkeeping only, never delivery or retry waits.
    pub fn try_export(&self, payload: String) -> bool {
        let state = &self.0.0;
        if payload.is_empty() || payload.capacity() > MAX_EXPORT_BYTES {
            self.record_drop();
            return false;
        }
        let mut queue = state.queue.lock().unwrap_or_else(|e| e.into_inner());
        if queue.stop.is_some()
            || queue.items.len() >= state.limit
            || payload.capacity() > MAX_QUEUE_BYTES.saturating_sub(queue.bytes)
        {
            self.record_drop();
            return false;
        }
        queue.bytes += payload.capacity();
        add(&state.health.queued_bytes, payload.capacity() as u64);
        queue.items.push_back(Job {
            payload,
            deadline: Instant::now() + state.timeout,
        });
        add(&state.health.accepted, 1);
        state.wake.notify_one();
        true
    }
    pub fn record_drop(&self) {
        add(&self.0.0.health.dropped, 1);
    }
    /// Initiates an asynchronous two-second best-effort drain, not durable delivery.
    pub fn shutdown(&self) {
        self.0.0.stop();
    }
}

/// Process-wide final drain. Call after request tasks stop, on a blocking thread.
/// One shared deadline bounds all workers rather than waiting two seconds per worker.
pub fn shutdown_exports() {
    let end = Instant::now() + DRAIN;
    let workers: Vec<_> = WORKERS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter_map(Weak::upgrade)
        .collect();
    for state in &workers {
        state.stop();
    }
    for state in workers {
        let mut queue = state.queue.lock().unwrap_or_else(|e| e.into_inner());
        while !queue.finished {
            let wait = end.saturating_duration_since(Instant::now());
            if wait.is_zero() {
                return;
            }
            queue = state
                .wake
                .wait_timeout(queue, wait)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

fn run(state: Arc<State>, delivery: Delivery, on_complete: Option<fn(ExportOutcome)>) {
    loop {
        let payload = {
            let mut queue = state.queue.lock().unwrap_or_else(|e| e.into_inner());
            while queue.items.is_empty() && queue.stop.is_none() {
                queue = state.wake.wait(queue).unwrap_or_else(|e| e.into_inner());
            }
            if queue.stop.is_some_and(|end| Instant::now() >= end)
                || (queue.items.is_empty() && queue.stop.is_some())
            {
                add(&state.health.dropped, queue.items.len() as u64);
                sub(&state.health.queued_bytes, queue.bytes as u64);
                let discarded = std::mem::take(&mut queue.items);
                queue.bytes = 0;
                queue.finished = true;
                state.wake.notify_all();
                drop(queue);
                drop(discarded);
                return;
            }
            let Some(payload) = queue.items.pop_front() else {
                continue;
            };
            queue.bytes = queue.bytes.saturating_sub(payload.payload.capacity());
            sub(
                &state.health.queued_bytes,
                payload.payload.capacity() as u64,
            );
            payload
        };
        let outcome = deliver(&state, &delivery, &payload.payload, payload.deadline);
        match outcome {
            ExportOutcome::Success => add(&state.health.success, 1),
            ExportOutcome::Partial => add(&state.health.partial, 1),
            _ => {
                add(&state.health.failed, 1);
                add(&state.health.dropped, 1);
            }
        }
        if let Some(callback) = on_complete {
            callback(outcome);
        }
    }
}

fn deliver(state: &State, delivery: &Delivery, payload: &str, end: Instant) -> ExportOutcome {
    let mut outcome = ExportOutcome::Transport;
    for attempt in 0..ATTEMPTS {
        let deadline = state
            .queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stop
            .map_or(end, |stop| stop.min(end));
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        add(&state.health.active, 1);
        outcome = delivery.post(payload, remaining.min(DRAIN));
        sub(&state.health.active, 1);
        let retry_after = match outcome {
            ExportOutcome::Retry(delay) => delay,
            ExportOutcome::Transport => Duration::ZERO,
            _ => break,
        };
        if attempt + 1 == ATTEMPTS {
            break;
        }
        let mut jitter = [0u8; 1];
        let _ = getrandom::fill(&mut jitter);
        let delay = retry_after.max(Duration::from_millis(
            (100 << attempt) + u64::from(jitter[0] % 51),
        ));
        let ready = Instant::now() + delay;
        let mut queue = state.queue.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            let deadline = queue.stop.map_or(end, |stop| stop.min(end));
            if ready >= deadline {
                return outcome;
            }
            let wait = ready.saturating_duration_since(Instant::now());
            if wait.is_zero() {
                break;
            }
            queue = state
                .wake
                .wait_timeout(queue, wait)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        add(&state.health.retries, 1);
    }
    outcome
}
