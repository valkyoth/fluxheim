use super::*;
use std::collections::HashMap;
use std::time::Instant;

const EMERGENCY_RETRY_MAX: Duration = Duration::from_secs(3600);

/// Retry state belongs to one worker and its immutable configuration. Vhost
/// names are unique in that configuration; a replacement worker starts cold.
pub struct BackgroundRenewals<'a> {
    config: &'a Config,
    failures: HashMap<String, Failure>,
}

struct Failure {
    count: u32,
    finished: Instant,
    delay: Duration,
}

impl<'a> BackgroundRenewals<'a> {
    pub fn new(config: &'a Config) -> Self {
        Self {
            config,
            failures: HashMap::new(),
        }
    }

    pub async fn tick(&mut self, now: SystemTime) -> Result<AcmeRenewalRun, AcmeRenewalError> {
        self.tick_with_clock(now, Instant::now).await
    }

    pub(super) async fn tick_with_clock(
        &mut self,
        now: SystemTime,
        clock: impl Fn() -> Instant,
    ) -> Result<AcmeRenewalRun, AcmeRenewalError> {
        let config = self.config;
        let observed = observe_configured_certificates(config);
        let mut queue = plan_renewal_queue(config, &observed, now);
        let start = clock();
        queue.retain(|item| {
            self.failures
                .get(&item.target.vhost_name)
                .is_none_or(|failure| {
                    // Reevaluate expiry each tick: a routine failure can become urgent.
                    let delay = if acme_queue::emergency_at(item.not_after, now) <= now {
                        failure.delay.min(EMERGENCY_RETRY_MAX)
                    } else {
                        failure.delay
                    };
                    start.saturating_duration_since(failure.finished) >= delay
                })
        });
        acme_ari::execute_due_queue_reporting(config, &queue, now, |name, success| {
            self.record(name, success, clock());
        })
        .await
    }

    fn record(&mut self, name: &str, success: bool, finished: Instant) {
        if success {
            self.failures.remove(name);
            return;
        }
        let prior = self.failures.get(name).map_or(0, |failure| failure.count);
        let policy = &self.config.tls.acme.renewal;
        self.failures.insert(
            name.to_owned(),
            Failure {
                count: prior.saturating_add(1),
                finished,
                delay: acme_queue::retry_delay(
                    prior,
                    policy.retry_initial_secs,
                    policy.retry_max_secs,
                ),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_discards_only_its_own_streak_and_extreme_delays_do_not_wrap() {
        let config = Config::default();
        let mut worker = BackgroundRenewals::new(&config);
        let now = Instant::now();
        for name in ["first", "second", "first"] {
            worker.record(name, false, now);
        }
        worker.record("first", true, now);
        assert!(!worker.failures.contains_key("first"));
        assert_eq!(worker.failures["second"].count, 1);
        worker.record("first", false, now);
        assert_eq!(
            worker.failures["first"].delay.as_secs(),
            config.tls.acme.renewal.retry_initial_secs
        );
        assert!(next_retry_at(UNIX_EPOCH, u32::MAX, u64::MAX, u64::MAX).is_none());
    }
}
