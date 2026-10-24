use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::event::{
    AdmissionClass, CapturePolicy, CorrelationInput, EventData, EventFormat, StructuredEvent,
};

pub const QUEUE_CAPACITY: usize = 128;
#[path = "operational_audit.rs"]
mod audit;
pub use audit::{AuditPermit, AuditUnavailable};
pub type EventFilter = Arc<dyn Fn(EventData) -> bool + Send + Sync>;
type Writer = Box<dyn Write + Send>;

// No strings or arbitrary heap-backed payloads can enter a queue.
#[derive(Clone, Copy)]
struct Pending {
    data: EventData,
    timestamp: u64,
    correlation: PendingCorrelation,
    policy: CapturePolicy,
}

#[derive(Clone, Copy)]
pub(super) struct PendingCorrelation {
    request: [u8; 128],
    request_len: u8,
    trace: [u8; 32],
    span: [u8; 16],
}

impl Default for PendingCorrelation {
    fn default() -> Self {
        Self {
            request: [0; 128],
            request_len: 0,
            trace: [0; 32],
            span: [0; 16],
        }
    }
}

impl PendingCorrelation {
    pub(super) fn capture(input: CorrelationInput<'_>, policy: CapturePolicy) -> Self {
        let mut value = Self::default();
        if !input.trusted || policy.privacy_mode || cfg!(feature = "privacy-mode") {
            return value;
        }
        if policy.include_request_id
            && let Some(id) = input
                .request_id
                .filter(|id| crate::access_log_request_id_valid(id))
        {
            value.request[..id.len()].copy_from_slice(id.as_bytes());
            value.request_len = id.len() as u8;
        }
        if policy.include_trace_ids
            && let (Some(trace), Some(span)) = (input.trace_id, input.span_id)
            && trace.len() == 32
            && span.len() == 16
            && trace.bytes().all(|b| b.is_ascii_hexdigit())
            && span.bytes().all(|b| b.is_ascii_hexdigit())
        {
            value.trace.copy_from_slice(trace.as_bytes());
            value.span.copy_from_slice(span.as_bytes());
        }
        value
    }

    pub(super) fn input(&self) -> CorrelationInput<'_> {
        CorrelationInput {
            trusted: true,
            request_id: (self.request_len > 0)
                .then(|| std::str::from_utf8(&self.request[..usize::from(self.request_len)]).ok())
                .flatten(),
            trace_id: (self.trace[0] != 0)
                .then(|| std::str::from_utf8(&self.trace).ok())
                .flatten(),
            span_id: (self.span[0] != 0)
                .then(|| std::str::from_utf8(&self.span).ok())
                .flatten(),
        }
    }
}

#[derive(Default)]
struct Counters {
    accepted: AtomicU64,
    filtered: AtomicU64,
    rate_limited: AtomicU64,
    queue_full: AtomicU64,
    unavailable: AtomicU64,
    encoded: AtomicU64,
    written: AtomicU64,
    sink_errors: AtomicU64,
    discarded: AtomicU64,
    completed: AtomicU64,
    alive: AtomicBool,
    closing: AtomicBool,
    audit_slots: AtomicU64,
    reserved: AtomicU64,
}

fn increment(value: &AtomicU64) {
    let _ = value.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
}

#[derive(serde::Serialize)]
pub struct LaneStatus {
    pub reserved: u64,
    pub accepted: u64,
    pub filtered: u64,
    pub rate_limited: u64,
    pub queue_full: u64,
    pub unavailable: u64,
    pub encoded: u64,
    pub written: u64,
    pub sink_errors: u64,
    pub discarded: u64,
    pub pending: u64,
    pub worker_alive: bool,
}

#[derive(serde::Serialize)]
pub struct DispatcherStatus {
    pub queue_capacity_per_lane: usize,
    pub queue_payload_bytes_per_lane: usize,
    pub ordinary: LaneStatus,
    pub security: LaneStatus,
    pub audit: LaneStatus,
}

struct Lane {
    sender: SyncSender<Pending>,
    budget: Mutex<Option<(Instant, u32)>>,
    counters: Arc<Counters>,
}

impl Lane {
    fn admit(&self, now: Instant) -> bool {
        if let Ok(mut budget) = self.budget.try_lock() {
            let (start, count) = budget.get_or_insert((now, 0));
            if now.saturating_duration_since(*start) >= Duration::from_secs(1) {
                *start = now;
                *count = 0;
            }
            if *count < 100 {
                *count += 1;
                return true;
            }
        }
        increment(&self.counters.rate_limited);
        false
    }

    fn status(&self) -> LaneStatus {
        let c = &self.counters;
        let read = |v: &AtomicU64| v.load(Ordering::Relaxed);
        LaneStatus {
            reserved: read(&c.reserved),
            accepted: read(&c.accepted),
            filtered: read(&c.filtered),
            rate_limited: read(&c.rate_limited),
            queue_full: read(&c.queue_full),
            unavailable: read(&c.unavailable),
            encoded: read(&c.encoded),
            written: read(&c.written),
            sink_errors: read(&c.sink_errors),
            discarded: read(&c.discarded),
            pending: read(&c.accepted).saturating_sub(read(&c.completed)),
            worker_alive: c.alive.load(Ordering::Acquire),
        }
    }
}

pub struct Dispatcher {
    lanes: [Lane; 3],
    filter: EventFilter,
}

impl Dispatcher {
    /// Fixed three workers and three separately bounded queues. Filter must only
    /// inspect the fixed event metadata/message; it must not perform I/O.
    pub fn new(format: EventFormat, filter: EventFilter, writers: [Writer; 3]) -> io::Result<Self> {
        let mut lanes = Vec::with_capacity(3);
        for (index, writer) in writers.into_iter().enumerate() {
            let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
            let counters = Arc::new(Counters::default());
            counters
                .audit_slots
                .store(QUEUE_CAPACITY as u64, Ordering::Relaxed);
            counters.alive.store(true, Ordering::Release);
            let worker_counters = counters.clone();
            std::thread::Builder::new()
                .name(format!("fluxheim-events-{index}"))
                .spawn(move || writer_loop(receiver, writer, format, worker_counters))?;
            lanes.push(Lane {
                sender,
                counters,
                budget: Mutex::new(None),
            });
        }
        let lanes = lanes
            .try_into()
            .map_err(|_| io::Error::other("invalid dispatcher lanes"))?;
        Ok(Self { lanes, filter })
    }

    pub fn try_emit(&self, data: EventData) {
        self.try_emit_at(data, Instant::now());
    }

    fn try_emit_at(&self, data: EventData, now: Instant) {
        self.emit_at(
            data,
            CorrelationInput::default(),
            CapturePolicy::default(),
            now,
        );
    }

    pub fn try_emit_correlated(
        &self,
        data: EventData,
        correlation: CorrelationInput<'_>,
        policy: CapturePolicy,
    ) {
        self.emit_at(data, correlation, policy, Instant::now());
    }

    fn emit_at(
        &self,
        data: EventData,
        correlation: CorrelationInput<'_>,
        policy: CapturePolicy,
        now: Instant,
    ) {
        let index = match data.admission_class() {
            AdmissionClass::Ordinary => 0,
            AdmissionClass::Security => 1,
            AdmissionClass::Audit => 2,
        };
        let lane = &self.lanes[index];
        let c = &lane.counters;
        if !policy.allows(data, (self.filter)(data)) {
            increment(&c.filtered);
            return;
        }
        if c.closing.load(Ordering::Acquire) || !c.alive.load(Ordering::Acquire) {
            increment(&c.unavailable);
            return;
        }
        if !lane.admit(now) {
            return;
        }
        let audit = matches!(data, EventData::Audit { .. });
        if audit && !audit::take_slot(c) {
            return;
        }
        let pending = Pending {
            data,
            timestamp: u64::try_from(crate::unix_time_nanos()).unwrap_or(u64::MAX),
            correlation: PendingCorrelation::capture(correlation, policy),
            policy,
        };
        match lane.sender.try_send(pending) {
            Ok(()) => increment(&c.accepted),
            Err(error) => {
                if audit {
                    c.audit_slots.fetch_add(1, Ordering::Relaxed);
                }
                match error {
                    TrySendError::Full(_) => increment(&c.queue_full),
                    TrySendError::Disconnected(_) => increment(&c.unavailable),
                }
            }
        }
    }

    pub fn status(&self) -> DispatcherStatus {
        DispatcherStatus {
            queue_capacity_per_lane: QUEUE_CAPACITY,
            queue_payload_bytes_per_lane: QUEUE_CAPACITY * std::mem::size_of::<Pending>(),
            ordinary: self.lanes[0].status(),
            security: self.lanes[1].status(),
            audit: self.lanes[2].status(),
        }
    }

    pub fn shutdown(&self, timeout: Duration) {
        for lane in &self.lanes {
            lane.counters.closing.store(true, Ordering::Release);
        }
        let start = Instant::now();
        while self
            .lanes
            .iter()
            .any(|lane| lane.counters.alive.load(Ordering::Acquire))
            && start.elapsed() < timeout.min(Duration::from_millis(500))
        {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for Dispatcher {
    fn drop(&mut self) {
        for lane in &self.lanes {
            lane.counters.closing.store(true, Ordering::Release);
        }
    }
}

fn writer_loop(
    receiver: Receiver<Pending>,
    mut writer: Writer,
    format: EventFormat,
    c: Arc<Counters>,
) {
    struct Alive(Arc<Counters>);
    impl Drop for Alive {
        fn drop(&mut self) {
            self.0.alive.store(false, Ordering::Release);
        }
    }
    let _alive = Alive(c.clone());
    loop {
        let pending = match receiver.recv_timeout(Duration::from_millis(10)) {
            Ok(pending) => pending,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if c.closing.load(Ordering::Acquire) {
                    break;
                }
                continue;
            }
        };
        let encoded = StructuredEvent::capture(
            pending.timestamp,
            pending.data,
            None,
            pending.correlation.input(),
            pending.policy,
            true,
        )
        .and_then(|event| event.encode(format).ok());
        let result = if let Some(encoded) = encoded {
            increment(&c.encoded);
            writer
                .write_all(encoded.as_bytes())
                .and_then(|()| writer.flush())
        } else {
            Err(io::Error::other("operational event encoding failed"))
        };
        increment(&c.completed);
        if matches!(pending.data, EventData::Audit { .. }) {
            c.audit_slots.fetch_add(1, Ordering::Release);
        }
        if result.is_err() {
            increment(&c.sink_errors);
            c.alive.store(false, Ordering::Release);
            // Never recursively log or retry a failed sink; account for queued losses.
            for pending in receiver.try_iter() {
                if matches!(pending.data, EventData::Audit { .. }) {
                    c.audit_slots.fetch_add(1, Ordering::Release);
                }
                increment(&c.discarded);
                increment(&c.completed);
            }
            break;
        }
        increment(&c.written);
    }
}

#[cfg(test)]
#[path = "operational_dispatch_tests.rs"]
mod tests;
