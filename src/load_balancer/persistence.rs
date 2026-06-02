use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use pingora::http::RequestHeader;

use crate::config::{
    LoadBalancePersistenceConfig, LoadBalancePersistenceMode, LoadBalanceSelection, ProxyConfig,
};

pub(super) const MAX_PERSISTENCE_KEY_BYTES: usize = 512;

#[derive(Debug)]
pub(super) struct LoadBalancerPersistenceState {
    mode: LoadBalancePersistenceMode,
    header: Option<String>,
    cookie: Option<String>,
    ttl: Duration,
    table_max_entries: usize,
    table: Mutex<std::collections::HashMap<Vec<u8>, LoadBalancerPersistenceEntry>>,
}

#[derive(Clone, Copy, Debug)]
struct LoadBalancerPersistenceEntry {
    backend_key: u64,
    expires_at: Instant,
}

impl LoadBalancerPersistenceState {
    pub(super) fn from_config(config: &LoadBalancePersistenceConfig) -> Self {
        Self {
            mode: config.mode,
            header: config.header.clone(),
            cookie: config.cookie.clone(),
            ttl: Duration::from_secs(config.ttl_secs),
            table_max_entries: config.table_max_entries,
            table: Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub(super) fn key(
        &self,
        request: &RequestHeader,
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
        }
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
        let now = Instant::now();
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        table.retain(|_, entry| entry.expires_at > now);
        let mut backend_counts = std::collections::HashMap::new();
        for entry in table.values() {
            *backend_counts.entry(entry.backend_key).or_insert(0) += 1;
        }
        (table.len(), backend_counts)
    }
}

#[derive(Clone, Debug)]
pub(super) enum LoadBalanceKeySource {
    None,
    SourceIp,
    Uri,
    Header(String),
    Cookie(String),
}

impl LoadBalanceKeySource {
    pub(super) fn from_config(config: &ProxyConfig) -> Self {
        match config.load_balance.selection {
            LoadBalanceSelection::RoundRobin => Self::None,
            LoadBalanceSelection::LeastConnections => Self::None,
            LoadBalanceSelection::LeastSessions => Self::None,
            LoadBalanceSelection::LeastTime => Self::None,
            LoadBalanceSelection::PowerOfTwo => Self::None,
            LoadBalanceSelection::SourceHash
            | LoadBalanceSelection::ConsistentSourceHash
            | LoadBalanceSelection::BoundedLoadConsistentSourceHash
            | LoadBalanceSelection::MaglevSourceHash => Self::SourceIp,
            LoadBalanceSelection::UriHash
            | LoadBalanceSelection::ConsistentUriHash
            | LoadBalanceSelection::BoundedLoadConsistentUriHash
            | LoadBalanceSelection::MaglevUriHash => Self::Uri,
            LoadBalanceSelection::HeaderHash
            | LoadBalanceSelection::ConsistentHeaderHash
            | LoadBalanceSelection::BoundedLoadConsistentHeaderHash
            | LoadBalanceSelection::MaglevHeaderHash => config
                .load_balance
                .hash_header
                .clone()
                .map(Self::Header)
                .unwrap_or(Self::None),
            LoadBalanceSelection::CookieHash
            | LoadBalanceSelection::ConsistentCookieHash
            | LoadBalanceSelection::BoundedLoadConsistentCookieHash
            | LoadBalanceSelection::MaglevCookieHash => config
                .load_balance
                .hash_cookie
                .clone()
                .map(Self::Cookie)
                .unwrap_or(Self::None),
        }
    }

    pub(super) fn request_key(
        &self,
        request: &RequestHeader,
        client_ip: Option<IpAddr>,
    ) -> Option<Vec<u8>> {
        match self {
            Self::None => None,
            Self::SourceIp => client_ip.map(|ip| ip.to_string().into_bytes()),
            Self::Uri => Some(request.uri.to_string().into_bytes()),
            Self::Header(name) => request_header_key(request, name),
            Self::Cookie(name) => cookie_key(request, name),
        }
    }
}

pub(super) fn request_header_key(request: &RequestHeader, name: &str) -> Option<Vec<u8>> {
    let mut key = Vec::new();
    for value in request.headers.get_all(name) {
        let bytes = value.as_bytes();
        key.extend_from_slice(&bytes.len().to_le_bytes());
        key.extend_from_slice(bytes);
        if key.len() > MAX_PERSISTENCE_KEY_BYTES {
            return None;
        }
    }
    (!key.is_empty()).then_some(key)
}

pub(super) fn cookie_key(request: &RequestHeader, name: &str) -> Option<Vec<u8>> {
    for header in request.headers.get_all("cookie") {
        let Ok(header) = header.to_str() else {
            continue;
        };
        for part in header.split(';') {
            let Some((candidate, value)) = part.trim().split_once('=') else {
                continue;
            };
            if candidate.trim() == name {
                let bytes = value.trim().as_bytes();
                if bytes.len() > MAX_PERSISTENCE_KEY_BYTES {
                    return None;
                }
                return Some(bytes.to_vec());
            }
        }
    }
    None
}
