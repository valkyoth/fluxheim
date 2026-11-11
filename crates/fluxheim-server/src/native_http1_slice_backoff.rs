use std::collections::HashMap;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

const CAPACITY: usize = 1024;
const TTL: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct UnsupportedSlice {
    primary: [u8; 32],
    expires_at: Instant,
}

/// Short-lived policy metadata, independent of retained response-body tiers.
#[derive(Debug, Default)]
pub(crate) struct NativeSliceBackoff {
    entries: HashMap<[u8; 32], UnsupportedSlice>,
}

impl NativeSliceBackoff {
    pub(crate) fn contains(&mut self, variant: &str, now: Instant) -> bool {
        let key = digest(variant);
        if self
            .entries
            .get(&key)
            .is_some_and(|entry| entry.expires_at > now)
        {
            return true;
        }
        self.entries.remove(&key);
        false
    }

    pub(crate) fn record(&mut self, primary: &str, variant: &str, now: Instant) {
        self.entries.retain(|_, entry| entry.expires_at > now);
        let key = digest(variant);
        // Neither repeated reads nor concurrent failed fills extend a live mark.
        if self.entries.contains_key(&key) || self.entries.len() >= CAPACITY {
            return;
        }
        let Some(expires_at) = now.checked_add(TTL) else {
            return;
        };
        self.entries.insert(
            key,
            UnsupportedSlice {
                primary: digest(primary),
                expires_at,
            },
        );
    }

    pub(crate) fn clear_primary(&mut self, primary: &str) {
        let primary = digest(primary);
        self.entries.retain(|_, entry| entry.primary != primary);
    }

    pub(crate) fn clear_variant(&mut self, variant: &str) {
        self.entries.remove(&digest(variant));
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }
}

fn digest(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_is_not_extended_by_reads_or_repeated_failures() {
        let mut backoff = NativeSliceBackoff::default();
        let now = Instant::now();
        backoff.record("primary", "en", now);
        assert!(backoff.contains("en", now + Duration::from_secs(4)));
        backoff.record("primary", "en", now + Duration::from_secs(4));
        assert!(!backoff.contains("en", now + TTL));
        backoff.record("primary", "en", now + TTL);
        assert!(backoff.contains("en", now + TTL));
    }

    #[test]
    fn capacity_and_key_storage_are_bounded_under_churn() {
        let mut backoff = NativeSliceBackoff::default();
        let now = Instant::now();
        for index in 0..100_000 {
            backoff.record("primary", &index.to_string(), now);
        }
        assert_eq!(backoff.entries.len(), CAPACITY);
        assert!(!backoff.contains("99999", now));
        backoff.record("other", "new", now + TTL);
        assert_eq!(backoff.entries.len(), 1);
    }

    #[test]
    fn variants_are_isolated_and_primary_purge_clears_all_its_marks() {
        let mut backoff = NativeSliceBackoff::default();
        let now = Instant::now();
        backoff.record("a", "a-en", now);
        backoff.record("a", "a-sv", now);
        backoff.record("b", "b-en", now);
        assert!(!backoff.contains("a-fr", now));
        backoff.clear_primary("a");
        assert!(!backoff.contains("a-en", now));
        assert!(!backoff.contains("a-sv", now));
        assert!(backoff.contains("b-en", now));
        backoff.clear();
        assert!(backoff.entries.is_empty());
    }
}
