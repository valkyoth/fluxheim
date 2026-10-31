use super::retry_budget::RetryBudgetReservation;
use super::{LoadBalancerRetryRuntimeStats, UpstreamLoadBalancer};

/// Admission for one request's redispatches, excluding its initial attempt.
///
/// The caller must establish replay safety before creating this sequence: no
/// request body, no upgrade/tunnel, and no response committed to the downstream.
/// It must not use a new sequence to reset the limit within the same dispatch.
pub struct LoadBalancerRetrySequence<'a> {
    pool: &'a UpstreamLoadBalancer,
    remaining: u8,
}

/// A reservation holds both the pool-wide slot and exclusive request admission.
/// Dropping it before `commit` returns the slot without consuming a retry.
#[must_use]
pub struct LoadBalancerRetryPermit<'a, 'pool> {
    sequence: &'a mut LoadBalancerRetrySequence<'pool>,
    budget: RetryBudgetReservation,
}

impl UpstreamLoadBalancer {
    /// Select an unattempted member without entering the initial-admission queue.
    /// Exclusions apply to persistence and every selection algorithm, but do not
    /// mutate the shared administrative member state. No alternative means stop.
    pub fn select_excluding<R: super::LoadBalancerRequestView>(
        &self,
        request: &R,
        client_ip: Option<std::net::IpAddr>,
        attempted: &[std::net::SocketAddr],
    ) -> Option<super::SelectedUpstream> {
        let mut selection = self.clone();
        if !selection.backend_policy.exclude_attempted(attempted) {
            return None;
        }
        selection.select(request, client_ip)
    }

    /// Start retry accounting after determining request replay safety.
    ///
    /// Clones of this pool share one monotonic fixed-window budget. A separately
    /// constructed pool has a separate budget; rebuilding configuration resets it.
    /// A zero pool budget disables that cap, not the per-request retry limit.
    pub fn retry_sequence(&self, method: &str, replayable: bool) -> LoadBalancerRetrySequence<'_> {
        let allowed = replayable
            && self.retry.enabled
            && self.retry.max_retries <= 10
            && safe_method(method)
            && self
                .retry
                .methods
                .iter()
                .any(|configured| configured == method);
        LoadBalancerRetrySequence {
            pool: self,
            remaining: if allowed { self.retry.max_retries } else { 0 },
        }
    }
}

impl<'pool> LoadBalancerRetrySequence<'pool> {
    /// Reserve another attempt after a transport failure (`None`) or a complete
    /// retryable HTTP response. No sleep or asynchronous work occurs here.
    pub fn reserve(&mut self, status: Option<u16>) -> Option<LoadBalancerRetryPermit<'_, 'pool>> {
        if self.remaining == 0
            || status.is_some_and(|status| !retryable_status(&self.pool.retry, status))
        {
            return None;
        }
        let budget = self.pool.retry_budget.reserve()?;
        Some(LoadBalancerRetryPermit {
            sequence: self,
            budget,
        })
    }
}

impl LoadBalancerRetryPermit<'_, '_> {
    /// Charge admission immediately before starting the selected retry, with no
    /// intervening await. Once charged, cancellation does not refund the budget:
    /// a failed/cancelled transport may already have reached the origin.
    pub fn commit(self) {
        self.sequence.remaining = self.sequence.remaining.saturating_sub(1);
        self.budget.commit();
    }
}

fn safe_method(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE")
}

fn retryable_status(config: &LoadBalancerRetryRuntimeStats, status: u16) -> bool {
    (500..=599).contains(&status)
        && (config.statuses.contains(&status)
            || config.status_ranges.iter().any(|range| {
                (500..=599).contains(&range.start)
                    && (500..=599).contains(&range.end)
                    && (range.start..=range.end).contains(&status)
            }))
}

#[cfg(test)]
#[path = "retry_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "retry_selection_tests.rs"]
mod selection_tests;
