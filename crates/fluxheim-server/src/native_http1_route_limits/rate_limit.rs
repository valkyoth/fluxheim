use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use fluxheim_config::RateLimitMode;

const NATIVE_RATE_LIMIT_MIN_PRUNE_INTERVAL: Duration = Duration::from_secs(1);
const NATIVE_RATE_LIMIT_PRUNE_SCAN_LIMIT: usize = 128;
const NATIVE_RATE_LIMIT_SHARDS: usize = 16;
const NATIVE_RATE_LIMIT_SHARD_HASH_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const NATIVE_RATE_LIMIT_SHARD_HASH_PRIME: u64 = 0x0000_0100_0000_01b3;
static NATIVE_RATE_LIMIT_SHARD_SEED: OnceLock<u64> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum NativeRateLimitKey {
    Ip(IpAddr),
    Indeterminate,
}

impl From<Option<IpAddr>> for NativeRateLimitKey {
    fn from(value: Option<IpAddr>) -> Self {
        value.map(Self::Ip).unwrap_or(Self::Indeterminate)
    }
}

#[derive(Clone, Copy, Debug)]
struct NativeRateLimitBucket {
    tokens: f64,
    updated_at: Instant,
    last_seen: Instant,
}

#[derive(Debug)]
struct NativeRateLimitState {
    shards: Box<[Mutex<NativeRateLimitBuckets>]>,
}

#[derive(Debug)]
struct NativeRateLimitBuckets {
    entries: HashMap<NativeRateLimitKey, NativeRateLimitBucket>,
    prune_queue: VecDeque<NativeRateLimitKey>,
    last_pruned_at: Option<Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum NativeRateLimitDecision {
    Allow,
    Delay(Duration),
    Reject(u16),
}

#[derive(Clone, Debug)]
pub(crate) struct NativeRateLimit {
    enabled: bool,
    requests_per_second: f64,
    burst: f64,
    status: u16,
    table_max_entries: usize,
    entry_ttl: Duration,
    mode: RateLimitMode,
    max_delay: Duration,
    reject_indeterminate: bool,
    state: Arc<NativeRateLimitState>,
}

impl PartialEq for NativeRateLimit {
    fn eq(&self, other: &Self) -> bool {
        self.enabled == other.enabled
            && self.requests_per_second == other.requests_per_second
            && self.burst == other.burst
            && self.status == other.status
            && self.table_max_entries == other.table_max_entries
            && self.entry_ttl == other.entry_ttl
            && self.mode == other.mode
            && self.max_delay == other.max_delay
            && self.reject_indeterminate == other.reject_indeterminate
    }
}

impl Eq for NativeRateLimit {}

impl Default for NativeRateLimit {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_second: 0.0,
            burst: 0.0,
            status: 429,
            table_max_entries: 0,
            entry_ttl: Duration::from_secs(300),
            mode: RateLimitMode::Nodelay,
            max_delay: Duration::from_millis(1000),
            reject_indeterminate: false,
            state: Arc::new(NativeRateLimitState {
                shards: native_rate_limit_shards(),
            }),
        }
    }
}

impl NativeRateLimit {
    pub(crate) fn from_config(config: &fluxheim_config::RateLimitConfig) -> Self {
        let burst = if config.burst == 0 {
            config.requests_per_second.max(1)
        } else {
            config.burst
        };
        Self {
            enabled: config.enabled,
            requests_per_second: f64::from(config.requests_per_second),
            burst: f64::from(burst),
            status: config.status,
            table_max_entries: config.table_max_entries,
            entry_ttl: Duration::from_secs(config.entry_ttl_secs),
            mode: config.mode,
            max_delay: Duration::from_millis(config.max_delay_ms),
            reject_indeterminate: config.reject_indeterminate,
            state: Arc::new(NativeRateLimitState {
                shards: native_rate_limit_shards(),
            }),
        }
    }

    pub(crate) fn check(&self, client_ip: Option<IpAddr>) -> NativeRateLimitDecision {
        if !self.enabled {
            return NativeRateLimitDecision::Allow;
        }

        let now = Instant::now();
        let key = NativeRateLimitKey::from(client_ip);
        if matches!(key, NativeRateLimitKey::Indeterminate) && self.reject_indeterminate {
            return NativeRateLimitDecision::Reject(self.status);
        }
        let shard = native_rate_limit_shard(key);
        let max_entries = self
            .table_max_entries
            .div_ceil(NATIVE_RATE_LIMIT_SHARDS)
            .max(1);
        let mut buckets = match self.state.shards[shard].lock() {
            Ok(guard) => guard,
            Err(_) => {
                log::error!(
                    target: "fluxheim::security",
                    "native rate-limit bucket lock poisoned; aborting to avoid inconsistent edge limits"
                );
                std::process::abort();
            }
        };
        if !buckets.entries.contains_key(&key) && buckets.entries.len() >= max_entries {
            let should_prune = buckets.last_pruned_at.is_none_or(|last_pruned_at| {
                now.saturating_duration_since(last_pruned_at)
                    >= NATIVE_RATE_LIMIT_MIN_PRUNE_INTERVAL
            });
            if should_prune {
                prune_native_rate_limit_entries(
                    &mut buckets,
                    now,
                    self.entry_ttl,
                    NATIVE_RATE_LIMIT_PRUNE_SCAN_LIMIT,
                );
                buckets.last_pruned_at = Some(now);
            }
            if buckets.entries.len() >= max_entries {
                return NativeRateLimitDecision::Reject(self.status);
            }
        }

        if !buckets.entries.contains_key(&key) {
            buckets.prune_queue.push_back(key);
            buckets.entries.insert(
                key,
                NativeRateLimitBucket {
                    tokens: self.burst,
                    updated_at: now,
                    last_seen: now,
                },
            );
        }
        let bucket = buckets.entries.get_mut(&key).unwrap_or_else(|| {
            log::error!(
                target: "fluxheim::security",
                "native rate-limit bucket vanished during locked update; aborting to avoid inconsistent edge limits"
            );
            std::process::abort();
        });
        let elapsed = now
            .saturating_duration_since(bucket.updated_at)
            .as_secs_f64();
        bucket.tokens = self
            .burst
            .min(bucket.tokens + elapsed * self.requests_per_second);
        bucket.updated_at = now;
        bucket.last_seen = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return NativeRateLimitDecision::Allow;
        }

        if !matches!(self.mode, RateLimitMode::Delay) || bucket.tokens <= -self.burst {
            return NativeRateLimitDecision::Reject(self.status);
        }

        if !self.requests_per_second.is_finite() || self.requests_per_second <= 0.0 {
            return NativeRateLimitDecision::Reject(self.status);
        }
        let wait = Duration::from_secs_f64((1.0 - bucket.tokens) / self.requests_per_second);
        if wait > self.max_delay {
            return NativeRateLimitDecision::Reject(self.status);
        }

        bucket.tokens -= 1.0;
        NativeRateLimitDecision::Delay(wait)
    }
}

fn native_rate_limit_shards() -> Box<[Mutex<NativeRateLimitBuckets>]> {
    (0..NATIVE_RATE_LIMIT_SHARDS)
        .map(|_| {
            Mutex::new(NativeRateLimitBuckets {
                entries: HashMap::new(),
                prune_queue: VecDeque::new(),
                last_pruned_at: None,
            })
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

fn prune_native_rate_limit_entries(
    buckets: &mut NativeRateLimitBuckets,
    now: Instant,
    ttl: Duration,
    scan_limit: usize,
) {
    let scans = scan_limit.min(buckets.prune_queue.len());
    for _ in 0..scans {
        let Some(key) = buckets.prune_queue.pop_front() else {
            return;
        };
        let Some(bucket) = buckets.entries.get(&key) else {
            continue;
        };
        if now.saturating_duration_since(bucket.last_seen) > ttl {
            buckets.entries.remove(&key);
        } else {
            buckets.prune_queue.push_back(key);
        }
    }
}

fn native_rate_limit_shard(key: NativeRateLimitKey) -> usize {
    match key {
        NativeRateLimitKey::Ip(IpAddr::V4(address)) => {
            native_rate_limit_shard_hash(&address.octets()) & (NATIVE_RATE_LIMIT_SHARDS - 1)
        }
        NativeRateLimitKey::Ip(IpAddr::V6(address)) => {
            native_rate_limit_shard_hash(&address.octets()) & (NATIVE_RATE_LIMIT_SHARDS - 1)
        }
        NativeRateLimitKey::Indeterminate => {
            native_rate_limit_shard_hash(b"indeterminate") & (NATIVE_RATE_LIMIT_SHARDS - 1)
        }
    }
}

fn native_rate_limit_shard_hash(bytes: &[u8]) -> usize {
    let mut hash = native_rate_limit_shard_seed();
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(NATIVE_RATE_LIMIT_SHARD_HASH_PRIME);
    }
    hash as usize
}

fn native_rate_limit_shard_seed() -> u64 {
    *NATIVE_RATE_LIMIT_SHARD_SEED.get_or_init(|| {
        let mut bytes = [0_u8; 8];
        if let Err(error) = getrandom::fill(&mut bytes) {
            log::error!(
                target: "fluxheim::security",
                "native rate-limit shard seed generation failed: {error}; aborting"
            );
            std::process::abort();
        }
        u64::from_le_bytes(bytes) ^ NATIVE_RATE_LIMIT_SHARD_HASH_OFFSET
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn native_rate_limit_prune_is_bounded_and_incremental() {
        let now = Instant::now();
        let expired_at = now - Duration::from_secs(10);
        let fresh_at = now - Duration::from_secs(1);
        let first = NativeRateLimitKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let second = NativeRateLimitKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)));
        let third = NativeRateLimitKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)));
        let mut buckets = NativeRateLimitBuckets {
            entries: HashMap::from([
                (
                    first,
                    NativeRateLimitBucket {
                        tokens: 1.0,
                        updated_at: expired_at,
                        last_seen: expired_at,
                    },
                ),
                (
                    second,
                    NativeRateLimitBucket {
                        tokens: 1.0,
                        updated_at: expired_at,
                        last_seen: expired_at,
                    },
                ),
                (
                    third,
                    NativeRateLimitBucket {
                        tokens: 1.0,
                        updated_at: fresh_at,
                        last_seen: fresh_at,
                    },
                ),
            ]),
            prune_queue: VecDeque::from([first, second, third]),
            last_pruned_at: None,
        };

        prune_native_rate_limit_entries(&mut buckets, now, Duration::from_secs(5), 1);
        assert!(!buckets.entries.contains_key(&first));
        assert!(buckets.entries.contains_key(&second));
        assert!(buckets.entries.contains_key(&third));

        prune_native_rate_limit_entries(&mut buckets, now, Duration::from_secs(5), 2);
        assert!(!buckets.entries.contains_key(&second));
        assert!(buckets.entries.contains_key(&third));
        assert_eq!(buckets.prune_queue, VecDeque::from([third]));
    }

    #[test]
    fn native_rate_limit_prune_tolerates_future_bucket_times() {
        let now = Instant::now();
        let future = now + Duration::from_secs(5);
        let key = NativeRateLimitKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
        let mut buckets = NativeRateLimitBuckets {
            entries: HashMap::from([(
                key,
                NativeRateLimitBucket {
                    tokens: 1.0,
                    updated_at: future,
                    last_seen: future,
                },
            )]),
            prune_queue: VecDeque::from([key]),
            last_pruned_at: None,
        };

        prune_native_rate_limit_entries(&mut buckets, now, Duration::from_secs(1), 1);

        assert!(buckets.entries.contains_key(&key));
        assert_eq!(buckets.prune_queue, VecDeque::from([key]));
    }

    #[test]
    fn native_rate_limit_check_tolerates_future_bucket_update_time() {
        let limiter = NativeRateLimit {
            enabled: true,
            requests_per_second: 1.0,
            burst: 1.0,
            status: 429,
            table_max_entries: 16,
            entry_ttl: Duration::from_secs(60),
            mode: RateLimitMode::Nodelay,
            max_delay: Duration::from_millis(100),
            reject_indeterminate: false,
            state: Arc::new(NativeRateLimitState {
                shards: native_rate_limit_shards(),
            }),
        };
        let key = NativeRateLimitKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)));
        let shard = native_rate_limit_shard(key);
        let future = Instant::now() + Duration::from_secs(5);
        {
            let mut buckets = limiter.state.shards[shard].lock().unwrap();
            buckets.prune_queue.push_back(key);
            buckets.entries.insert(
                key,
                NativeRateLimitBucket {
                    tokens: 0.0,
                    updated_at: future,
                    last_seen: future,
                },
            );
        }

        assert_eq!(
            limiter.check(Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)))),
            NativeRateLimitDecision::Reject(429)
        );
    }

    #[test]
    fn native_rate_limit_shard_uses_full_ipv4_address() {
        let first = NativeRateLimitKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42)));
        let first_shard = native_rate_limit_shard(first);
        let differs = (1..=254).any(|octet| {
            let candidate = NativeRateLimitKey::Ip(IpAddr::V4(Ipv4Addr::new(octet, 51, 100, 42)));
            native_rate_limit_shard(candidate) != first_shard
        });

        assert!(differs);
    }

    #[test]
    fn native_rate_limit_shard_uses_full_ipv6_address() {
        let first = NativeRateLimitKey::Ip(IpAddr::V6(Ipv6Addr::from([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
        ])));
        let first_shard = native_rate_limit_shard(first);
        let differs = (0..=255).any(|byte| {
            let candidate = NativeRateLimitKey::Ip(IpAddr::V6(Ipv6Addr::from([
                0x20, 0x01, 0x0d, byte, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
            ])));
            native_rate_limit_shard(candidate) != first_shard
        });

        assert!(differs);
    }

    #[test]
    fn native_rate_limit_indeterminate_key_is_seeded() {
        assert!(
            native_rate_limit_shard(NativeRateLimitKey::Indeterminate) < NATIVE_RATE_LIMIT_SHARDS
        );
    }
}
