use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::sync::futures::OwnedNotified;

use crate::native_http1_cache::{NativeMemoryCacheState, lock_native_memory_cache};

const NATIVE_ORIGIN_FILL_CONCURRENCY_MAX_KEYS: usize = 4096;
const NATIVE_PEER_FILL_CONCURRENCY_MAX_KEYS: usize = 4096;

static NATIVE_ORIGIN_FILL_CONCURRENCY: OnceLock<Mutex<HashMap<String, Arc<AtomicUsize>>>> =
    OnceLock::new();
static NATIVE_PEER_FILL_CONCURRENCY: OnceLock<Mutex<HashMap<String, Arc<AtomicUsize>>>> =
    OnceLock::new();

#[derive(Debug)]
pub(crate) struct NativeOriginFillPermit {
    counter: Arc<AtomicUsize>,
}

#[derive(Debug)]
pub(crate) struct NativePeerFillPermit {
    counter: Arc<AtomicUsize>,
}

#[derive(Debug)]
pub(crate) enum NativeCacheFillGate {
    Disabled,
    Writer(NativeCacheFillPermit),
    Waiter(NativeCacheFillWaiter),
}

#[derive(Debug)]
pub(crate) struct NativeCacheFillWaiter {
    notified: Pin<Box<OwnedNotified>>,
    timeout: Duration,
}

#[derive(Debug, Default)]
pub(crate) struct NativeCacheFillWaitBudget {
    deadline: Option<tokio::time::Instant>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeCacheFillWaitTimeout;

#[derive(Debug)]
pub(crate) struct NativeCacheFillPermit {
    state: Arc<Mutex<NativeMemoryCacheState>>,
    key: String,
    notify: Arc<Notify>,
}

impl NativeCacheFillPermit {
    pub(crate) fn new(
        state: Arc<Mutex<NativeMemoryCacheState>>,
        key: String,
        notify: Arc<Notify>,
    ) -> Self {
        Self { state, key, notify }
    }
}

impl NativeCacheFillWaiter {
    pub(crate) fn new(notify: Arc<Notify>, timeout: Duration) -> Self {
        let mut notified = Box::pin(notify.notified_owned());
        notified.as_mut().enable();
        Self { notified, timeout }
    }
}

impl NativeCacheFillWaitBudget {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) async fn wait(&mut self, waiter: NativeCacheFillWaiter) -> bool {
        let deadline = match self.deadline {
            Some(deadline) => deadline,
            None => {
                let now = tokio::time::Instant::now();
                let deadline = now.checked_add(waiter.timeout).unwrap_or(now);
                self.deadline = Some(deadline);
                deadline
            }
        };
        tokio::time::timeout_at(deadline, waiter.notified)
            .await
            .is_ok()
    }
}

impl Drop for NativeOriginFillPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for NativePeerFillPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for NativeCacheFillPermit {
    fn drop(&mut self) {
        let mut state = lock_native_memory_cache(&self.state, "proxy");
        if state
            .filling
            .get(&self.key)
            .is_some_and(|fill| Arc::ptr_eq(&fill.notify, &self.notify))
        {
            state.filling.remove(&self.key);
        }
        self.notify.notify_waiters();
    }
}

pub(crate) fn acquire_native_origin_fill_permit(
    key: String,
    max_concurrent: usize,
) -> Option<NativeOriginFillPermit> {
    acquire_cache_fill_concurrency_permit(
        &NATIVE_ORIGIN_FILL_CONCURRENCY,
        NATIVE_ORIGIN_FILL_CONCURRENCY_MAX_KEYS,
        key,
        max_concurrent,
        "origin-fill",
        "native origin-fill concurrency lock poisoned; aborting to avoid inconsistent cache-fill limits",
    )
    .map(|counter| NativeOriginFillPermit { counter })
}

pub(crate) fn acquire_native_peer_fill_permit(
    key: String,
    max_concurrent: usize,
) -> Option<NativePeerFillPermit> {
    acquire_cache_fill_concurrency_permit(
        &NATIVE_PEER_FILL_CONCURRENCY,
        NATIVE_PEER_FILL_CONCURRENCY_MAX_KEYS,
        key,
        max_concurrent,
        "peer-fill",
        "native peer-fill concurrency lock poisoned; aborting to avoid inconsistent cache-fill limits",
    )
    .map(|counter| NativePeerFillPermit { counter })
}

fn acquire_cache_fill_concurrency_permit(
    registry: &'static OnceLock<Mutex<HashMap<String, Arc<AtomicUsize>>>>,
    max_keys: usize,
    key: String,
    max_concurrent: usize,
    label: &'static str,
    poison_message: &'static str,
) -> Option<Arc<AtomicUsize>> {
    let counter = {
        let mut counters = match registry.get_or_init(|| Mutex::new(HashMap::new())).lock() {
            Ok(guard) => guard,
            Err(_) => {
                log::error!(target: "fluxheim::security", "{poison_message}");
                std::process::abort();
            }
        };
        prune_inactive_cache_fill_counters(&mut counters, max_keys);
        if counters.len() >= max_keys && !counters.contains_key(&key) {
            return None;
        }
        counters
            .entry(key.clone())
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone()
    };

    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= max_concurrent {
            return None;
        }
        let Some(next) = current.checked_add(1) else {
            log::error!(
                target: "fluxheim::security",
                "native {label} concurrency counter saturated for {key}; refusing permit"
            );
            return None;
        };
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(counter),
            Err(observed) => current = observed,
        }
    }
}

fn prune_inactive_cache_fill_counters(
    counters: &mut HashMap<String, Arc<AtomicUsize>>,
    max_keys: usize,
) {
    if counters.len() < max_keys {
        return;
    }
    counters.retain(|_, counter| counter.load(Ordering::Acquire) > 0);
}

#[cfg(test)]
mod tests {
    use super::{NativeCacheFillWaitBudget, NativeCacheFillWaiter};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Notify;

    #[tokio::test]
    async fn owned_waiter_observes_notify_waiters_before_await() {
        let notify = Arc::new(Notify::new());
        let waiter = NativeCacheFillWaiter::new(notify.clone(), Duration::from_secs(1));
        notify.notify_waiters();

        let mut budget = NativeCacheFillWaitBudget::new();
        assert!(budget.wait(waiter).await);
    }

    #[tokio::test]
    async fn wait_budget_keeps_one_total_deadline() {
        let first_notify = Arc::new(Notify::new());
        let first = NativeCacheFillWaiter::new(first_notify.clone(), Duration::from_millis(25));
        first_notify.notify_waiters();

        let mut budget = NativeCacheFillWaitBudget::new();
        assert!(budget.wait(first).await);
        let deadline = budget.deadline;

        let second = NativeCacheFillWaiter::new(Arc::new(Notify::new()), Duration::from_secs(30));
        assert!(!budget.wait(second).await);
        assert_eq!(budget.deadline, deadline);
    }
}
