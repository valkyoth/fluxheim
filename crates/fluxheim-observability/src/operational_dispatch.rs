use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::event::{
    AdmissionClass, CapturePolicy, CorrelationInput, EventData, EventFormat, StructuredEvent,
};

pub const QUEUE_CAPACITY: usize = 128;
pub type EventFilter = Arc<dyn Fn(EventData) -> bool + Send + Sync>;
type Writer = Box<dyn Write + Send>;

// No strings or arbitrary heap-backed payloads can enter a queue.
#[derive(Clone, Copy)]
struct Pending {
    data: EventData,
    timestamp: u64,
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
}

fn increment(value: &AtomicU64) {
    let _ = value.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
}

#[derive(serde::Serialize)]
pub struct LaneStatus {
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
        let index = match data.admission_class() {
            AdmissionClass::Ordinary => 0,
            AdmissionClass::Security => 1,
            AdmissionClass::Audit => 2,
        };
        let lane = &self.lanes[index];
        let c = &lane.counters;
        if !CapturePolicy::default().allows(data, (self.filter)(data)) {
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
        let pending = Pending {
            data,
            timestamp: u64::try_from(crate::unix_time_nanos()).unwrap_or(u64::MAX),
        };
        match lane.sender.try_send(pending) {
            Ok(()) => increment(&c.accepted),
            Err(TrySendError::Full(_)) => increment(&c.queue_full),
            Err(TrySendError::Disconnected(_)) => increment(&c.unavailable),
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
            CorrelationInput::default(),
            CapturePolicy::default(),
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
        if result.is_err() {
            increment(&c.sink_errors);
            c.alive.store(false, Ordering::Release);
            // Never recursively log or retry a failed sink; account for queued losses.
            for _ in receiver.try_iter() {
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
