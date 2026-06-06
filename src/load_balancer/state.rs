use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::config::{
    LoadBalanceHealthCheckExpectedStatusRange, LoadBalancePassiveHealthConfig,
    LoadBalanceSlowStartConfig,
};

use super::LoadBalancedUpstreamOutcome;
use super::backend::BackendIdentity;
use super::key::backend_key;
use super::selection::fnv1a64_with_seed;

#[derive(Debug)]
pub struct LoadBalancedConnectionPermit {
    counter: Arc<AtomicUsize>,
}

impl Drop for LoadBalancedConnectionPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone)]
pub struct LoadBalancedUpstreamReporter {
    backend_key: u64,
    passive_health: Option<Arc<PassiveHealthState>>,
    slow_start: Option<Arc<SlowStartState>>,
    latency: Option<Arc<BackendLatencyState>>,
}

impl LoadBalancedUpstreamReporter {
    pub(super) fn new(
        backend_key: u64,
        passive_health: Option<Arc<PassiveHealthState>>,
        slow_start: Option<Arc<SlowStartState>>,
        latency: Option<Arc<BackendLatencyState>>,
    ) -> Self {
        Self {
            backend_key,
            passive_health,
            slow_start,
            latency,
        }
    }

    pub fn record_status(
        &self,
        status: u16,
        latency: Option<Duration>,
    ) -> LoadBalancedUpstreamOutcome {
        if let (Some(latency_state), Some(latency)) = (&self.latency, latency) {
            latency_state.record_latency(self.backend_key, latency);
        }
        let Some(passive_health) = &self.passive_health else {
            return LoadBalancedUpstreamOutcome {
                failed: false,
                ejected: false,
            };
        };
        let failed = passive_health.status_is_failure(status, latency);
        let ejected_at = passive_health.record_status(self.backend_key, status, latency);
        if let Some(restart_at) = ejected_at {
            self.reset_slow_start(restart_at);
        }
        LoadBalancedUpstreamOutcome {
            failed,
            ejected: ejected_at.is_some(),
        }
    }

    pub fn record_failure(&self) -> LoadBalancedUpstreamOutcome {
        let Some(passive_health) = &self.passive_health else {
            return LoadBalancedUpstreamOutcome {
                failed: true,
                ejected: false,
            };
        };
        let ejected_at = passive_health.record_failure(self.backend_key);
        if let Some(restart_at) = ejected_at {
            self.reset_slow_start(restart_at);
        }
        LoadBalancedUpstreamOutcome {
            failed: true,
            ejected: ejected_at.is_some(),
        }
    }

    fn reset_slow_start(&self, restart_at: Instant) {
        if let Some(slow_start) = &self.slow_start {
            slow_start.reset_at(self.backend_key, restart_at);
        }
    }
}

impl Debug for LoadBalancedUpstreamReporter {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoadBalancedUpstreamReporter")
            .field("backend_key", &self.backend_key)
            .finish_non_exhaustive()
    }
}

pub(super) struct PassiveHealthState {
    consecutive_failure: usize,
    ejection: Duration,
    max_latency: Option<Duration>,
    failure_statuses: Arc<[u16]>,
    failure_status_ranges: Arc<[LoadBalanceHealthCheckExpectedStatusRange]>,
    pub(super) backends: Arc<Mutex<std::collections::HashMap<u64, PassiveBackendHealth>>>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PassiveBackendHealth {
    pub(super) consecutive_failures: usize,
    pub(super) ejected_until: Option<Instant>,
}

impl PassiveHealthState {
    pub(super) fn from_config(config: &LoadBalancePassiveHealthConfig) -> Self {
        Self {
            consecutive_failure: config.consecutive_failure,
            ejection: Duration::from_secs(config.ejection_secs),
            max_latency: (config.max_latency_ms > 0)
                .then(|| Duration::from_millis(config.max_latency_ms)),
            failure_statuses: config.failure_statuses.clone().into(),
            failure_status_ranges: config.failure_status_ranges.clone().into(),
            backends: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    pub(super) fn is_ejected(&self, backend: &impl BackendIdentity) -> bool {
        let key = backend_key(backend);
        self.key_is_ejected(key)
    }

    fn key_is_ejected(&self, key: u64) -> bool {
        let mut backends = self
            .backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(state) = backends.get_mut(&key) else {
            return false;
        };
        if state
            .ejected_until
            .is_some_and(|until| Instant::now() < until)
        {
            return true;
        }
        state.ejected_until = None;
        false
    }

    pub(super) fn key_is_currently_ejected(&self, key: u64) -> bool {
        self.backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .and_then(|state| state.ejected_until)
            .is_some_and(|until| Instant::now() < until)
    }

    pub(super) fn key_consecutive_failures(&self, key: u64) -> Option<usize> {
        self.backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .map(|state| state.consecutive_failures)
    }

    pub(super) fn key_ejection_remaining_secs(&self, key: u64) -> Option<u64> {
        self.backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .and_then(|state| state.ejected_until)
            .and_then(|until| {
                until
                    .checked_duration_since(Instant::now())
                    .map(|remaining| remaining.as_secs().saturating_add(1))
            })
    }

    fn record_status(&self, key: u64, status: u16, latency: Option<Duration>) -> Option<Instant> {
        if self.status_is_failure(status, latency) {
            self.record_failure(key)
        } else {
            self.record_success(key);
            None
        }
    }

    pub(super) fn record_failure(&self, key: u64) -> Option<Instant> {
        let mut backends = self
            .backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = backends.entry(key).or_default();
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= self.consecutive_failure {
            state.consecutive_failures = 0;
            let ejected_until = Instant::now() + self.ejection;
            state.ejected_until = Some(ejected_until);
            return Some(ejected_until);
        }
        None
    }

    fn record_success(&self, key: u64) {
        let mut backends = self
            .backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(state) = backends.get_mut(&key) {
            state.consecutive_failures = 0;
            state.ejected_until = None;
        }
    }

    pub(super) fn clear_key(&self, key: u64) {
        self.backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key);
    }

    pub(super) fn prune_stale(&self, live_keys: &std::collections::HashSet<u64>) {
        let now = Instant::now();
        self.backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|key, state| {
                live_keys.contains(key) || state.ejected_until.is_some_and(|until| now < until)
            });
    }

    pub(super) fn failure_status(&self, status: u16) -> bool {
        if self.failure_statuses.is_empty() && self.failure_status_ranges.is_empty() {
            return (500..=599).contains(&status);
        }
        self.failure_statuses.contains(&status)
            || self
                .failure_status_ranges
                .iter()
                .any(|range| (range.start..=range.end).contains(&status))
    }

    pub(super) fn status_is_failure(&self, status: u16, latency: Option<Duration>) -> bool {
        self.failure_status(status)
            || latency.is_some_and(|latency| {
                self.max_latency
                    .is_some_and(|max_latency| latency >= max_latency)
            })
    }
}

#[derive(Debug)]
pub(super) struct SlowStartState {
    duration: Duration,
    pub(super) backends: Mutex<std::collections::HashMap<u64, Instant>>,
    pub(super) sample_counter: AtomicU64,
}

impl SlowStartState {
    pub(super) fn from_config(config: &LoadBalanceSlowStartConfig) -> Self {
        Self {
            duration: Duration::from_secs(config.duration_secs),
            backends: Mutex::new(std::collections::HashMap::new()),
            sample_counter: AtomicU64::new(0),
        }
    }

    pub(super) fn permits(&self, backend: &impl BackendIdentity) -> bool {
        let now = Instant::now();
        let key = backend_key(backend);
        let mut backends = self
            .backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let started_at = *backends.entry(key).or_insert(now);
        let elapsed = now.saturating_duration_since(started_at);
        if self.duration.is_zero() || elapsed >= self.duration {
            return true;
        }

        let progress_per_mille =
            ((elapsed.as_millis() * 1000) / self.duration.as_millis()).clamp(1, 1000) as u64;
        let sample = self.sample_counter.fetch_add(1, Ordering::Relaxed);
        let bucket = fnv1a64_with_seed(&sample.to_le_bytes(), key) % 1000;
        bucket < progress_per_mille
    }

    pub(super) fn reset_at(&self, key: u64, restart_at: Instant) {
        self.backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key, restart_at);
    }

    pub(super) fn prune_stale(&self, live_keys: &std::collections::HashSet<u64>) {
        self.backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|key, _| live_keys.contains(key));
    }

    pub(super) fn permits_read_only(&self, backend: &impl BackendIdentity) -> bool {
        let now = Instant::now();
        let key = backend_key(backend);
        let Some(started_at) = self
            .backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .copied()
        else {
            return true;
        };
        if self.duration.is_zero() {
            return true;
        }
        let elapsed = now.saturating_duration_since(started_at);
        if elapsed >= self.duration {
            return true;
        }

        let progress_per_mille =
            ((elapsed.as_millis() * 1000) / self.duration.as_millis()).clamp(1, 1000) as u64;
        progress_per_mille >= 500
    }
}

#[derive(Default)]
pub(super) struct BackendConnectionCounters {
    counters: Mutex<std::collections::HashMap<u64, Arc<AtomicUsize>>>,
}

impl BackendConnectionCounters {
    pub(super) fn count(&self, backend: &impl BackendIdentity) -> usize {
        self.counter(backend).load(Ordering::Acquire)
    }

    pub(super) fn count_existing(&self, backend: &impl BackendIdentity) -> usize {
        self.counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&backend_key(backend))
            .map(|counter| counter.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    pub(super) fn permit(
        &self,
        backend: &impl BackendIdentity,
        max_in_flight: Option<usize>,
    ) -> Option<LoadBalancedConnectionPermit> {
        let counter = self.counter(backend);
        let mut current = counter.load(Ordering::Acquire);
        loop {
            if max_in_flight.is_some_and(|limit| current >= limit) {
                return None;
            }
            let next = current.checked_add(1)?;
            match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Some(LoadBalancedConnectionPermit { counter }),
                Err(observed) => current = observed,
            }
        }
    }

    fn counter(&self, backend: &impl BackendIdentity) -> Arc<AtomicUsize> {
        let mut counters = self
            .counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        counters
            .entry(backend_key(backend))
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone()
    }

    pub(super) fn prune_stale(&self, live_keys: &std::collections::HashSet<u64>) {
        self.counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|key, counter| live_keys.contains(key) || counter.load(Ordering::Acquire) > 0);
    }
}

#[derive(Default)]
pub(super) struct BackendLatencyState {
    latency_micros: Mutex<std::collections::HashMap<u64, u64>>,
}

impl BackendLatencyState {
    pub(super) fn record_latency(&self, key: u64, latency: Duration) {
        let sample = latency.as_micros().clamp(1, u128::from(u64::MAX)) as u64;
        let mut latency_micros = self
            .latency_micros
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        latency_micros
            .entry(key)
            .and_modify(|stored| {
                *stored = stored
                    .saturating_mul(3)
                    .saturating_add(sample)
                    .saturating_add(2)
                    / 4;
            })
            .or_insert(sample);
    }

    pub(super) fn score(&self, backend: &impl BackendIdentity) -> Option<u64> {
        self.score_key(backend_key(backend))
    }

    pub(super) fn score_key(&self, key: u64) -> Option<u64> {
        self.latency_micros
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .copied()
    }

    pub(super) fn prune_stale(&self, live_keys: &std::collections::HashSet<u64>) {
        self.latency_micros
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|key, _| live_keys.contains(key));
    }
}

#[cfg(test)]
mod tests {
    use super::super::backend::FluxBackend;
    use super::*;

    #[test]
    fn slow_start_zero_duration_permits_without_division() {
        let backend = FluxBackend::new("127.0.0.1:3000").unwrap();
        let state = SlowStartState::from_config(&LoadBalanceSlowStartConfig {
            enabled: true,
            duration_secs: 0,
        });

        assert!(state.permits(&backend));
        assert!(state.permits_read_only(&backend));
    }

    #[test]
    fn latency_ewma_rounds_instead_of_sticking_on_fractional_update() {
        let state = BackendLatencyState::default();

        state.record_latency(1, Duration::from_micros(1000));
        state.record_latency(1, Duration::from_micros(1003));

        assert_eq!(state.score_key(1), Some(1001));
    }
}
