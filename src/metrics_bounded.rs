//! Admission happens before Prometheus allocates a child. No eviction of counters:
//! removing and recreating a resource must not silently reset its lifetime total.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use prometheus::core::{Collector, Desc, Metric};
use prometheus::proto::MetricFamily;
use prometheus::{Error, HistogramOpts, Opts};

// Leave 1,000 samples for fixed scalar/control collectors. Tests inventory those.
pub(super) const SERIES_LIMIT: usize = 20_000;
const VECTOR_LIMIT: usize = SERIES_LIMIT - 1_000;
const FAMILY_LIMIT: usize = 2_048;
const LABEL_BYTES: usize = 128;
const LABEL_COUNT: usize = 6;
struct Budget {
    used: AtomicUsize,
    limit: usize,
}
fn budget() -> Arc<Budget> {
    static BUDGET: OnceLock<Arc<Budget>> = OnceLock::new();
    BUDGET
        .get_or_init(|| {
            Arc::new(Budget {
                used: AtomicUsize::new(0),
                limit: VECTOR_LIMIT,
            })
        })
        .clone()
}
static OVERFLOW: AtomicU64 = AtomicU64::new(0);

pub(super) fn usage() -> (usize, u64) {
    (
        budget().used.load(Ordering::Relaxed),
        OVERFLOW.load(Ordering::Relaxed),
    )
}

impl Budget {
    fn reserve(&self, cost: usize) -> bool {
        self.used
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(cost).filter(|next| *next <= self.limit)
            })
            .is_ok()
    }
}

struct Admission<T> {
    keys: HashMap<Vec<u8>, T>,
    cost: usize,
    labels: usize,
    budget: Arc<Budget>,
}

impl<T: Clone> Admission<T> {
    fn new(cost: usize, labels: usize, budget: Arc<Budget>) -> Result<Self, Error> {
        if labels == 0 || labels > LABEL_COUNT || cost > FAMILY_LIMIT || !budget.reserve(cost) {
            return Err(Error::Msg("metric series budget unavailable".into()));
        }
        Ok(Self {
            keys: HashMap::new(),
            cost,
            labels,
            budget,
        })
    }

    fn get(&mut self, labels: &[&str], create: impl FnOnce() -> Result<T, Error>) -> Option<T> {
        if labels.len() != self.labels
            || labels.iter().any(|v| v.len() > LABEL_BYTES)
            || labels.iter().all(|v| *v == "overflow")
        {
            return None;
        }
        // Length-prefixed tuples cannot alias (including embedded separators).
        // Build on the stack; only a new admitted identity allocates a stored key.
        let mut key = [0_u8; LABEL_COUNT * (LABEL_BYTES + 1)];
        let mut end = 0;
        for value in labels {
            key[end] = value.len() as u8;
            end += 1;
            key[end..end + value.len()].copy_from_slice(value.as_bytes());
            end += value.len();
        }
        if let Some(child) = self.keys.get(&key[..end]) {
            return Some(child.clone());
        }
        if (self.keys.len() + 2) * self.cost > FAMILY_LIMIT || !self.budget.reserve(self.cost) {
            return None;
        }
        match create() {
            Ok(child) => {
                self.keys.insert(key[..end].to_vec(), child.clone());
                Some(child)
            }
            Err(_) => {
                self.budget.used.fetch_sub(self.cost, Ordering::Relaxed);
                None
            }
        }
    }

    fn clear(&mut self) {
        self.budget
            .used
            .fetch_sub(self.keys.len() * self.cost, Ordering::Relaxed);
        self.keys.clear();
    }
}

impl<T> Drop for Admission<T> {
    fn drop(&mut self) {
        self.budget
            .used
            .fetch_sub((self.keys.len() + 1) * self.cost, Ordering::Relaxed);
    }
}

macro_rules! bounded_vec {
    ($name:ident, $child:ty, $opts:ty, $cost:expr, $export_overflow:expr) => {
        #[derive(Clone)]
        pub(super) struct $name {
            inner: prometheus::$name,
            admission: Arc<Mutex<Admission<$child>>>,
            overflow: $child,
            opts: $opts,
            labels: Arc<Vec<String>>,
        }

        impl $name {
            pub(super) fn new(opts: $opts, labels: &[&str]) -> Result<Self, Error> {
                Self::with_budget(opts, labels, budget())
            }

            fn with_budget(opts: $opts, labels: &[&str], budget: Arc<Budget>) -> Result<Self, Error> {
                let cost = ($cost)(&opts);
                let admission = Admission::new(cost, labels.len(), budget)?;
                let inner = prometheus::$name::new(opts.clone(), labels)?;
                let overflow = if $export_overflow {
                    inner.get_metric_with_label_values(&vec!["overflow"; labels.len()])?
                } else {
                    // Excess gauges cannot be summed: keep their sink unregistered.
                    prometheus::$name::new(opts.clone(), labels)?
                        .get_metric_with_label_values(&vec!["overflow"; labels.len()])?
                };
                Ok(Self { inner, admission: Arc::new(Mutex::new(admission)), overflow, opts,
                    labels: Arc::new(labels.iter().map(|s| (*s).to_owned()).collect()) })
            }

            pub(super) fn with_label_values(&self, labels: &[&str]) -> $child {
                let mut admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(child) = admission.get(labels, || {
                    // One independent child per length-prefixed tuple avoids the
                    // upstream Vec's concatenated-label hash aliasing.
                    let names: Vec<_> = self.labels.iter().map(String::as_str).collect();
                    prometheus::$name::new(self.opts.clone(), &names)?.get_metric_with_label_values(labels)
                }) {
                    return child;
                }
                let _ = OVERFLOW.try_update(Ordering::Relaxed, Ordering::Relaxed,
                    |n| Some(n.saturating_add(1)));
                self.overflow.clone()
            }
        }

        impl Collector for $name {
            fn desc(&self) -> Vec<&Desc> { self.inner.desc() }
            fn collect(&self) -> Vec<MetricFamily> {
                let children: Vec<_> = self.admission.lock().unwrap_or_else(|e| e.into_inner()).keys.values().cloned().collect();
                let mut families = self.inner.collect();
                if let Some(family) = families.first_mut() {
                    let mut samples: Vec<_> = children.iter().map(Metric::metric).collect();
                    if $export_overflow { samples.push(self.overflow.metric()); }
                    family.set_metric(samples);
                }
                families
            }
        }
    };
}

bounded_vec!(
    IntCounterVec,
    prometheus::IntCounter,
    Opts,
    |_: &Opts| 1,
    true
);
bounded_vec!(IntGaugeVec, prometheus::IntGauge, Opts, |_: &Opts| 1, false);
bounded_vec!(
    HistogramVec,
    prometheus::Histogram,
    HistogramOpts,
    |opts: &HistogramOpts| {
        let buckets = if opts.buckets.is_empty() {
            prometheus::DEFAULT_BUCKETS.len()
        } else {
            opts.buckets.len()
        };
        // +Inf, sum, count. An explicit +Inf conservatively costs one extra sample.
        buckets.saturating_add(3)
    },
    true
);

impl IntGaugeVec {
    pub(super) fn reset(&self) {
        let mut admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        self.inner.reset();
        admission.clear();
    }
}

#[cfg(test)]
#[path = "metrics_bounded_tests.rs"]
mod tests;
