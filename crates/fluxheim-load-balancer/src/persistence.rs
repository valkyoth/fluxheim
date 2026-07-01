use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use fluxheim_config::{LoadBalancePersistenceConfig, LoadBalancePersistenceMode};

pub(super) use super::persistence_cookie::ManagedAffinityCookie;
use super::persistence_cookie::{
    MANAGED_COOKIE_KEY_BYTES, ManagedCookieConfig, managed_cookie_key, managed_cookie_token,
};
pub(super) use super::persistence_request::{LoadBalanceKeySource, cookie_key, request_header_key};

pub(super) const MAX_PERSISTENCE_KEY_BYTES: usize =
    super::persistence_request::MAX_PERSISTENCE_KEY_BYTES;

pub trait LoadBalancerRequestView {
    fn uri_key(&self) -> Vec<u8>;

    fn header_values<'a>(&'a self, name: &str) -> Box<dyn Iterator<Item = &'a [u8]> + 'a>;

    fn cookie_headers<'a>(&'a self) -> Box<dyn Iterator<Item = &'a str> + 'a>;
}

#[derive(Debug)]
pub(super) struct LoadBalancerPersistenceState {
    mode: LoadBalancePersistenceMode,
    header: Option<String>,
    cookie: Option<String>,
    ttl: Duration,
    table_max_entries: usize,
    managed_cookie: Option<ManagedCookieConfig>,
    table: Mutex<std::collections::HashMap<Vec<u8>, LoadBalancerPersistenceEntry>>,
}

#[derive(Clone, Copy, Debug)]
struct LoadBalancerPersistenceEntry {
    backend_key: u64,
    expires_at: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct LoadBalancerPersistenceSnapshot {
    pub(crate) entries: Vec<LoadBalancerPersistenceEntrySnapshot>,
}

#[derive(Debug)]
pub(super) struct PreparedLoadBalancerPersistenceSnapshot {
    entries: std::collections::HashMap<Vec<u8>, LoadBalancerPersistenceEntry>,
}

impl PreparedLoadBalancerPersistenceSnapshot {
    pub(super) fn restored_entries(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct LoadBalancerPersistenceEntrySnapshot {
    pub(crate) key: Vec<u8>,
    pub(crate) backend_key: u64,
    pub(crate) ttl_remaining_secs: u64,
}

impl LoadBalancerPersistenceState {
    pub(super) fn from_config(config: &LoadBalancePersistenceConfig) -> Self {
        Self {
            mode: config.mode,
            header: config.header.clone(),
            cookie: config.cookie.clone(),
            ttl: Duration::from_secs(config.ttl_secs),
            table_max_entries: config.table_max_entries,
            managed_cookie: (config.mode == LoadBalancePersistenceMode::ManagedCookie)
                .then(|| ManagedCookieConfig::from_config(config)),
            table: Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub(super) fn key(
        &self,
        request: &impl LoadBalancerRequestView,
        client_ip: Option<IpAddr>,
    ) -> Option<Vec<u8>> {
        match self.mode {
            LoadBalancePersistenceMode::SourceIp => client_ip.map(|ip| ip.to_string().into_bytes()),
            LoadBalancePersistenceMode::Header => self
                .header
                .as_deref()
                .and_then(|header| request_header_key(request, header)),
            LoadBalancePersistenceMode::Cookie => self
                .cookie
                .as_deref()
                .and_then(|cookie| cookie_key(request, cookie)),
            LoadBalancePersistenceMode::ManagedCookie => self
                .managed_cookie
                .as_ref()
                .and_then(|config| managed_cookie_key(request, config.name.as_str())),
        }
    }

    pub(super) fn is_managed_cookie(&self) -> bool {
        self.mode == LoadBalancePersistenceMode::ManagedCookie
    }

    pub(super) fn lookup(&self, key: &[u8]) -> Option<u64> {
        let now = Instant::now();
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = table.get(key).copied()?;
        if entry.expires_at <= now {
            table.remove(key);
            return None;
        }
        Some(entry.backend_key)
    }

    pub(super) fn record(&self, key: &[u8], backend_key: u64) {
        let now = Instant::now();
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if table.len() >= self.table_max_entries && !table.contains_key(key) {
            table.retain(|_, entry| entry.expires_at > now);
            if table.len() >= self.table_max_entries
                && let Some(stale_key) = table
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires_at)
                    .map(|(key, _)| key.clone())
            {
                table.remove(&stale_key);
            }
        }
        if table.len() < self.table_max_entries || table.contains_key(key) {
            table.insert(
                key.to_vec(),
                LoadBalancerPersistenceEntry {
                    backend_key,
                    expires_at: now + self.ttl,
                },
            );
        }
    }

    pub(super) fn clear(&self) -> usize {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = table.len();
        table.clear();
        removed
    }

    pub(super) fn runtime_counts(&self) -> (usize, std::collections::HashMap<u64, usize>) {
        self.runtime_counts_for_live_backends(None)
    }

    pub(super) fn runtime_counts_for_live_backends(
        &self,
        live_backend_keys: Option<&std::collections::HashSet<u64>>,
    ) -> (usize, std::collections::HashMap<u64, usize>) {
        let now = Instant::now();
        let table = self
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut backend_counts = std::collections::HashMap::new();
        let mut entry_count = 0;
        for entry in table.values().filter(|entry| {
            entry.expires_at > now
                && live_backend_keys.is_none_or(|live_keys| live_keys.contains(&entry.backend_key))
        }) {
            entry_count += 1;
            *backend_counts.entry(entry.backend_key).or_insert(0) += 1;
        }
        (entry_count, backend_counts)
    }

    pub(super) fn prune_stale_for_live_backends(
        &self,
        live_backend_keys: &std::collections::HashSet<u64>,
    ) {
        let now = Instant::now();
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        table.retain(|_, entry| {
            entry.expires_at > now && live_backend_keys.contains(&entry.backend_key)
        });
    }

    pub(crate) fn snapshot(
        &self,
        live_backend_keys: &std::collections::HashSet<u64>,
    ) -> LoadBalancerPersistenceSnapshot {
        let now = Instant::now();
        let table = self
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut entries = table
            .iter()
            .filter(|(_, entry)| {
                entry.expires_at > now && live_backend_keys.contains(&entry.backend_key)
            })
            .map(|(key, entry)| LoadBalancerPersistenceEntrySnapshot {
                key: key.clone(),
                backend_key: entry.backend_key,
                ttl_remaining_secs: entry
                    .expires_at
                    .saturating_duration_since(now)
                    .as_secs()
                    .max(1)
                    .min(self.ttl.as_secs()),
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            left.backend_key
                .cmp(&right.backend_key)
                .then_with(|| left.key.cmp(&right.key))
        });
        LoadBalancerPersistenceSnapshot { entries }
    }

    #[cfg(test)]
    pub(crate) fn restore_snapshot(
        &self,
        snapshot: &LoadBalancerPersistenceSnapshot,
        live_backend_keys: &std::collections::HashSet<u64>,
    ) -> Result<usize, &'static str> {
        let prepared = self.prepare_snapshot(snapshot, live_backend_keys)?;
        let restored = prepared.restored_entries();
        self.commit_snapshot(prepared);
        Ok(restored)
    }

    pub(super) fn prepare_snapshot(
        &self,
        snapshot: &LoadBalancerPersistenceSnapshot,
        live_backend_keys: &std::collections::HashSet<u64>,
    ) -> Result<PreparedLoadBalancerPersistenceSnapshot, &'static str> {
        if snapshot.entries.len() > self.table_max_entries {
            return Err("load balancer persistence snapshot exceeds table limit");
        }
        let mut next = std::collections::HashMap::with_capacity(snapshot.entries.len());
        let now = Instant::now();
        for entry in &snapshot.entries {
            if entry.key.is_empty() || entry.key.len() > MAX_PERSISTENCE_KEY_BYTES {
                return Err("load balancer persistence snapshot has invalid key");
            }
            if entry.ttl_remaining_secs == 0 || entry.ttl_remaining_secs > self.ttl.as_secs() {
                return Err("load balancer persistence snapshot has invalid ttl");
            }
            if !live_backend_keys.contains(&entry.backend_key) {
                continue;
            }
            if next
                .insert(
                    entry.key.clone(),
                    LoadBalancerPersistenceEntry {
                        backend_key: entry.backend_key,
                        expires_at: now + Duration::from_secs(entry.ttl_remaining_secs),
                    },
                )
                .is_some()
            {
                return Err("load balancer persistence snapshot has duplicate keys");
            }
        }
        Ok(PreparedLoadBalancerPersistenceSnapshot { entries: next })
    }

    pub(super) fn commit_snapshot(&self, prepared: PreparedLoadBalancerPersistenceSnapshot) {
        *self
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = prepared.entries;
    }

    pub(super) fn new_managed_cookie(&self) -> Option<(Vec<u8>, ManagedAffinityCookie)> {
        let config = self.managed_cookie.as_ref()?;
        let mut key = vec![0_u8; MANAGED_COOKIE_KEY_BYTES];
        if let Err(error) = getrandom::fill(&mut key) {
            log::error!("fatal: managed load-balancer cookie key generation failed: {error}");
            std::process::abort();
        }
        let token = managed_cookie_token(config.name.as_bytes(), &key)?;
        Some((
            key,
            ManagedAffinityCookie {
                header_value: config.header_value(&token),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_counts_filter_removed_backend_keys_without_pruning() {
        let state = LoadBalancerPersistenceState::from_config(&LoadBalancePersistenceConfig {
            enabled: true,
            ttl_secs: 60,
            table_max_entries: 16,
            ..LoadBalancePersistenceConfig::default()
        });
        state.record(b"client-a", 10);
        state.record(b"client-b", 20);

        let live_keys = [20].into_iter().collect::<std::collections::HashSet<_>>();
        let (entry_count, backend_counts) =
            state.runtime_counts_for_live_backends(Some(&live_keys));

        assert_eq!(entry_count, 1);
        assert_eq!(backend_counts.get(&10), None);
        assert_eq!(backend_counts.get(&20).copied(), Some(1));
        assert_eq!(state.lookup(b"client-a"), Some(10));
        assert_eq!(state.lookup(b"client-b"), Some(20));
    }

    #[test]
    fn prune_stale_for_live_backends_removes_removed_backend_keys() {
        let state = LoadBalancerPersistenceState::from_config(&LoadBalancePersistenceConfig {
            enabled: true,
            ttl_secs: 60,
            table_max_entries: 16,
            ..LoadBalancePersistenceConfig::default()
        });
        state.record(b"client-a", 10);
        state.record(b"client-b", 20);

        let live_keys = [20].into_iter().collect::<std::collections::HashSet<_>>();
        state.prune_stale_for_live_backends(&live_keys);

        assert_eq!(state.lookup(b"client-a"), None);
        assert_eq!(state.lookup(b"client-b"), Some(20));
    }

    #[test]
    fn persistence_snapshot_restores_live_entries_with_remaining_ttl() {
        let state = LoadBalancerPersistenceState::from_config(&LoadBalancePersistenceConfig {
            enabled: true,
            ttl_secs: 60,
            table_max_entries: 16,
            ..LoadBalancePersistenceConfig::default()
        });
        state.record(b"client-a", 10);
        state.record(b"client-b", 20);

        let live_keys = [10].into_iter().collect::<std::collections::HashSet<_>>();
        let snapshot = state.snapshot(&live_keys);
        assert_eq!(snapshot.entries.len(), 1);
        assert_eq!(snapshot.entries[0].key, b"client-a");

        let restored = LoadBalancerPersistenceState::from_config(&LoadBalancePersistenceConfig {
            enabled: true,
            ttl_secs: 60,
            table_max_entries: 16,
            ..LoadBalancePersistenceConfig::default()
        });
        assert_eq!(restored.restore_snapshot(&snapshot, &live_keys).unwrap(), 1);
        assert_eq!(restored.lookup(b"client-a"), Some(10));
        assert_eq!(restored.lookup(b"client-b"), None);
    }

    #[test]
    fn persistence_snapshot_rejects_invalid_entries_before_replacing() {
        let state = LoadBalancerPersistenceState::from_config(&LoadBalancePersistenceConfig {
            enabled: true,
            ttl_secs: 60,
            table_max_entries: 16,
            ..LoadBalancePersistenceConfig::default()
        });
        state.record(b"client-a", 10);

        let live_keys = [10].into_iter().collect::<std::collections::HashSet<_>>();
        let invalid = LoadBalancerPersistenceSnapshot {
            entries: vec![LoadBalancerPersistenceEntrySnapshot {
                key: b"client-b".to_vec(),
                backend_key: 10,
                ttl_remaining_secs: 0,
            }],
        };

        assert!(state.restore_snapshot(&invalid, &live_keys).is_err());
        assert_eq!(state.lookup(b"client-a"), Some(10));
        assert_eq!(state.lookup(b"client-b"), None);
    }
}
