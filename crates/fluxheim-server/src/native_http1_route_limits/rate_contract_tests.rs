use super::*;
use fluxheim_config::RateLimitConfig;

#[test]
fn configured_single_entry_table_can_admit_sixteen_identities() {
    let config = RateLimitConfig {
        enabled: true,
        requests_per_second: 1,
        table_max_entries: 1,
        ..Default::default()
    };
    config.validate("vhosts.rate_limit").unwrap();
    let limiter = NativeRateLimit::from_config(&config);
    let mut seen = [false; NATIVE_RATE_LIMIT_SHARDS];
    for last in 1..=254 {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, last));
        let shard = native_rate_limit_shard(NativeRateLimitKey::Ip(ip));
        if !seen[shard] {
            assert_eq!(limiter.check(Some(ip)), NativeRateLimitDecision::Allow);
            seen[shard] = true;
        }
    }
    assert!(seen.into_iter().all(|value| value));
    let count: usize = limiter
        .state
        .shards
        .iter()
        .map(|shard| shard.lock().unwrap().entries.len())
        .sum();
    assert_eq!(count, 16); // documented contract: configured total is one, not sixteen.
}

#[test]
fn zero_burst_uses_rate_and_absent_identity_has_a_shared_bucket() {
    let config = RateLimitConfig {
        enabled: true,
        requests_per_second: 2,
        ..Default::default()
    };
    let limiter = NativeRateLimit::from_config(&config);
    assert_eq!(limiter.burst, 2.0);
    assert_eq!(limiter.check(None), NativeRateLimitDecision::Allow);
    assert_eq!(limiter.check(None), NativeRateLimitDecision::Allow);
    // Freeze elapsed refill independently of scheduler speed.
    let shard = native_rate_limit_shard(NativeRateLimitKey::Indeterminate);
    limiter.state.shards[shard]
        .lock()
        .unwrap()
        .entries
        .get_mut(&NativeRateLimitKey::Indeterminate)
        .unwrap()
        .updated_at = Instant::now() + Duration::from_secs(60);
    assert_eq!(limiter.check(None), NativeRateLimitDecision::Reject(429));
    let closed = NativeRateLimit::from_config(&RateLimitConfig {
        reject_indeterminate: true,
        ..config
    });
    assert_eq!(closed.check(None), NativeRateLimitDecision::Reject(429));
}

#[test]
fn delay_reserves_future_capacity_and_respects_max_delay() {
    let config = RateLimitConfig {
        enabled: true,
        requests_per_second: 1,
        burst: 1,
        mode: RateLimitMode::Delay,
        max_delay_ms: 1000,
        ..Default::default()
    };
    let limiter = NativeRateLimit::from_config(&config);
    let key = NativeRateLimitKey::Indeterminate;
    let shard = native_rate_limit_shard(key);
    assert_eq!(limiter.check(None), NativeRateLimitDecision::Allow);
    limiter.state.shards[shard]
        .lock()
        .unwrap()
        .entries
        .get_mut(&key)
        .unwrap()
        .updated_at = Instant::now() + Duration::from_secs(60);
    assert_eq!(
        limiter.check(None),
        NativeRateLimitDecision::Delay(Duration::from_secs(1))
    );
    let mut buckets = limiter.state.shards[shard].lock().unwrap();
    assert_eq!(buckets.entries[&key].tokens, -1.0);
    buckets.entries.get_mut(&key).unwrap().updated_at = Instant::now() + Duration::from_secs(60);
    drop(buckets);
    assert_eq!(limiter.check(None), NativeRateLimitDecision::Reject(429));
}
