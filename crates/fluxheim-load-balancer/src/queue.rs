use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::{
    LoadBalancerQueueOutcome, LoadBalancerRequestView, LoadBalancerSelectionResult,
    SelectedUpstream, UpstreamLoadBalancer,
};

#[derive(Debug)]
struct LoadBalancerQueueSlot {
    waiting: Arc<AtomicUsize>,
}

impl Drop for LoadBalancerQueueSlot {
    fn drop(&mut self) {
        self.waiting.fetch_sub(1, Ordering::AcqRel);
    }
}

impl UpstreamLoadBalancer {
    pub async fn select_or_wait<R>(
        &self,
        request: &R,
        client_ip: Option<std::net::IpAddr>,
    ) -> Option<SelectedUpstream>
    where
        R: LoadBalancerRequestView,
    {
        self.select_or_wait_result(request, client_ip)
            .await
            .selected
    }

    pub async fn select_or_wait_result<R>(
        &self,
        request: &R,
        client_ip: Option<std::net::IpAddr>,
    ) -> LoadBalancerSelectionResult
    where
        R: LoadBalancerRequestView,
    {
        if let Some(selected) = self.select(request, client_ip) {
            return LoadBalancerSelectionResult {
                selected: Some(selected),
                queue_outcome: None,
                queue_wait: None,
            };
        }
        if !self.queue_policy.enabled() {
            return LoadBalancerSelectionResult {
                selected: None,
                queue_outcome: None,
                queue_wait: None,
            };
        }
        let Some(_slot) = self.acquire_queue_slot() else {
            return LoadBalancerSelectionResult {
                selected: None,
                queue_outcome: Some(LoadBalancerQueueOutcome::Full),
                queue_wait: None,
            };
        };
        let queued_at = Instant::now();
        let deadline = queued_at + Duration::from_millis(self.queue_policy.timeout_ms);
        loop {
            if let Some(selected) = self.select(request, client_ip) {
                return LoadBalancerSelectionResult {
                    selected: Some(selected),
                    queue_outcome: Some(LoadBalancerQueueOutcome::Waited),
                    queue_wait: Some(queued_at.elapsed()),
                };
            }
            let now = Instant::now();
            if now >= deadline {
                return LoadBalancerSelectionResult {
                    selected: None,
                    queue_outcome: Some(LoadBalancerQueueOutcome::Timeout),
                    queue_wait: Some(queued_at.elapsed()),
                };
            }
            let sleep_for = deadline
                .saturating_duration_since(now)
                .min(Duration::from_millis(self.queue_policy.retry_interval_ms));
            tokio::time::sleep(sleep_for).await;
        }
    }

    fn acquire_queue_slot(&self) -> Option<LoadBalancerQueueSlot> {
        let max_waiting = self.queue_policy.max_waiting;
        let mut current = self.queue_waiting.load(Ordering::Acquire);
        loop {
            if current >= max_waiting {
                return None;
            }
            match self.queue_waiting.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(LoadBalancerQueueSlot {
                        waiting: self.queue_waiting.clone(),
                    });
                }
                Err(next) => current = next,
            }
        }
    }
}
