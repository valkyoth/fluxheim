use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug)]
pub(crate) struct NativeConcurrencyPermit {
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for NativeConcurrencyPermit {
    fn drop(&mut self) {
        let _ = self.permit.take();
    }
}

#[derive(Debug)]
struct NativeQueuedConcurrencyWaiter {
    queued: Arc<AtomicUsize>,
}

impl Drop for NativeQueuedConcurrencyWaiter {
    fn drop(&mut self) {
        self.queued.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NativeConcurrencyLimit {
    enabled: bool,
    max_in_flight: usize,
    max_queue: usize,
    status: u16,
    queue_timeout: Duration,
    semaphore: Arc<Semaphore>,
    queued: Arc<AtomicUsize>,
}

impl PartialEq for NativeConcurrencyLimit {
    fn eq(&self, other: &Self) -> bool {
        self.enabled == other.enabled
            && self.max_in_flight == other.max_in_flight
            && self.max_queue == other.max_queue
            && self.status == other.status
            && self.queue_timeout == other.queue_timeout
    }
}

impl Eq for NativeConcurrencyLimit {}

impl Default for NativeConcurrencyLimit {
    fn default() -> Self {
        Self {
            enabled: false,
            max_in_flight: 0,
            max_queue: 0,
            status: 503,
            queue_timeout: Duration::ZERO,
            semaphore: Arc::new(Semaphore::new(0)),
            queued: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl NativeConcurrencyLimit {
    pub(crate) fn from_config(config: &fluxheim_config::ConcurrencyLimitConfig) -> Self {
        let max_queue = if config.max_queue == 0 {
            config
                .max_in_flight
                .saturating_mul(4)
                .max(config.max_in_flight)
                .min(1_000_000)
        } else {
            config.max_queue
        };
        Self {
            enabled: config.enabled,
            max_in_flight: config.max_in_flight,
            max_queue,
            status: config.status,
            queue_timeout: Duration::from_millis(config.queue_timeout_ms),
            semaphore: Arc::new(Semaphore::new(config.max_in_flight)),
            queued: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) async fn acquire(&self) -> Result<Option<NativeConcurrencyPermit>, u16> {
        if !self.enabled {
            return Ok(None);
        }

        match Arc::clone(&self.semaphore).try_acquire_owned() {
            Ok(permit) => {
                return Ok(Some(NativeConcurrencyPermit {
                    permit: Some(permit),
                }));
            }
            Err(_) if self.queue_timeout.is_zero() => return Err(self.status),
            Err(_) => {}
        }

        if !self.try_enter_queue() {
            return Err(self.status);
        }
        let queued = NativeQueuedConcurrencyWaiter {
            queued: Arc::clone(&self.queued),
        };
        let result = tokio::time::timeout(
            self.queue_timeout,
            Arc::clone(&self.semaphore).acquire_owned(),
        )
        .await;
        drop(queued);

        match result {
            Ok(Ok(permit)) => Ok(Some(NativeConcurrencyPermit {
                permit: Some(permit),
            })),
            Ok(Err(_)) | Err(_) => Err(self.status),
        }
    }

    fn try_enter_queue(&self) -> bool {
        let mut current = self.queued.load(Ordering::Acquire);
        loop {
            if current >= self.max_queue {
                return false;
            }
            let Some(next) = current.checked_add(1) else {
                return false;
            };
            match self.queued.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }
}
