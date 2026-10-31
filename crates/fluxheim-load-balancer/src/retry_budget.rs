use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(super) struct RetryBudget {
    limit: u32,
    window: Duration,
    state: Mutex<Window>,
    admitted: AtomicU64,
}

#[derive(Debug)]
struct Window {
    started: Instant,
    used: u32,
}

pub(super) struct RetryBudgetReservation {
    budget: Arc<RetryBudget>,
    window: Option<Instant>,
}

impl RetryBudget {
    pub(super) fn new(limit: u32, window_secs: u64) -> Self {
        Self {
            limit,
            window: Duration::from_secs(window_secs),
            state: Mutex::new(Window {
                started: Instant::now(),
                used: 0,
            }),
            admitted: AtomicU64::new(0),
        }
    }

    pub(super) fn reserve(self: &Arc<Self>) -> Option<RetryBudgetReservation> {
        self.reserve_at(Instant::now())
    }

    pub(super) fn admitted(&self) -> u64 {
        self.admitted.load(Ordering::Relaxed)
    }

    fn reserve_at(self: &Arc<Self>, now: Instant) -> Option<RetryBudgetReservation> {
        // Also fail closed for programmatic callers that bypass config validation.
        if self.limit > 1_000_000
            || self.window.is_zero()
            || self.window > Duration::from_secs(3600)
        {
            return None;
        }
        if self.limit == 0 {
            return Some(RetryBudgetReservation {
                budget: self.clone(),
                window: None,
            });
        }
        let mut state = self.state.lock().ok()?;
        if now.saturating_duration_since(state.started) >= self.window {
            state.started = now;
            state.used = 0;
        }
        if state.used >= self.limit {
            return None;
        }
        state.used = state.used.checked_add(1)?;
        Some(RetryBudgetReservation {
            budget: self.clone(),
            window: Some(state.started),
        })
    }
}

impl RetryBudgetReservation {
    pub(super) fn commit(mut self) {
        let _ = self
            .budget
            .admitted
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_add(1))
            });
        self.window = None;
    }
}

impl Drop for RetryBudgetReservation {
    fn drop(&mut self) {
        if let Some(window) = self.window
            && let Ok(mut state) = self.budget.state.lock()
            && state.started == window
        {
            state.used = state.used.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unused_reservation_returns_capacity_but_committed_retry_does_not() {
        let budget = Arc::new(RetryBudget::new(1, 60));
        let reserved = budget.reserve().unwrap();
        assert!(budget.reserve().is_none());
        drop(reserved);
        budget.reserve().unwrap().commit();
        assert!(budget.reserve().is_none());
    }

    #[test]
    fn window_rollover_does_not_refund_an_old_reservation_into_the_new_window() {
        let budget = Arc::new(RetryBudget::new(1, 2));
        let start = budget.state.lock().unwrap().started;
        let old = budget.reserve_at(start).unwrap();
        assert!(
            budget
                .reserve_at(start + Duration::from_millis(1999))
                .is_none()
        );
        let next = start + Duration::from_secs(2);
        budget.reserve_at(next).unwrap().commit();
        drop(old);
        assert!(budget.reserve_at(next).is_none());
        assert!(budget.reserve_at(next + Duration::from_secs(2)).is_some());
    }

    #[test]
    fn concurrent_reservations_cannot_exceed_pool_budget() {
        let budget = Arc::new(RetryBudget::new(7, 3600));
        let successes = std::sync::atomic::AtomicUsize::new(0);
        let barrier = std::sync::Barrier::new(32);
        std::thread::scope(|scope| {
            for _ in 0..32 {
                scope.spawn(|| {
                    barrier.wait();
                    if let Some(permit) = budget.reserve() {
                        permit.commit();
                        successes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(successes.load(std::sync::atomic::Ordering::Relaxed), 7);
    }

    #[test]
    fn zero_budget_is_unlimited_but_invalid_programmatic_limits_are_denied() {
        let budget = Arc::new(RetryBudget::new(0, 1));
        for _ in 0..100 {
            budget.reserve().unwrap().commit();
        }
        for (limit, window) in [(1_000_001, 1), (1, 0), (0, 0), (1, 3601)] {
            assert!(
                Arc::new(RetryBudget::new(limit, window))
                    .reserve()
                    .is_none()
            );
        }
    }

    #[test]
    fn poisoned_budget_denies_admission() {
        let budget = Arc::new(RetryBudget::new(1, 60));
        let poisoned = budget.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.state.lock().unwrap();
            panic!("injected budget lock poisoning");
        })
        .join();
        assert!(budget.reserve().is_none());
    }
}
