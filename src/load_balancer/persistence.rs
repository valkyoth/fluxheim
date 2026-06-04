use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use pingora::http::RequestHeader;
use subtle::ConstantTimeEq;

use crate::config::{
    LoadBalanceManagedCookieSameSite, LoadBalancePersistenceConfig, LoadBalancePersistenceMode,
    LoadBalanceSelection, ProxyConfig,
};

pub(super) const MAX_PERSISTENCE_KEY_BYTES: usize = 512;
const MANAGED_COOKIE_KEY_BYTES: usize = 16;
const MANAGED_COOKIE_TAG_BYTES: usize = 32;
const MANAGED_COOKIE_TOKEN_BYTES: usize = MANAGED_COOKIE_KEY_BYTES + MANAGED_COOKIE_TAG_BYTES;

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

#[derive(Clone, Debug)]
pub(crate) struct ManagedAffinityCookie {
    pub(crate) header_value: String,
}

#[derive(Clone, Debug)]
struct ManagedCookieConfig {
    name: String,
    domain: Option<String>,
    path: String,
    secure: bool,
    http_only: bool,
    same_site: LoadBalanceManagedCookieSameSite,
    max_age_secs: u64,
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
            managed_cookie: (config.mode == LoadBalancePersistenceMode::ManagedCookie).then(|| {
                ManagedCookieConfig {
                    name: config.cookie.clone().unwrap_or_default(),
                    domain: config.managed_cookie_domain.clone(),
                    path: config
                        .managed_cookie_path
                        .clone()
                        .unwrap_or_else(|| "/".to_owned()),
                    secure: config.managed_cookie_secure,
                    http_only: config.managed_cookie_http_only,
                    same_site: config.managed_cookie_same_site,
                    max_age_secs: config
                        .managed_cookie_max_age_secs
                        .unwrap_or(config.ttl_secs),
                }
            }),
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
            LoadBalancePersistenceMode::ManagedCookie => self
                .managed_cookie
                .as_ref()
                .and_then(|config| managed_cookie_key(request, config.name.as_str())),
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

    pub(super) fn new_managed_cookie(&self) -> Option<(Vec<u8>, ManagedAffinityCookie)> {
        let config = self.managed_cookie.as_ref()?;
        let mut key = vec![0_u8; MANAGED_COOKIE_KEY_BYTES];
        if let Err(error) = getrandom::fill(&mut key) {
            log::error!("fatal: managed load-balancer cookie key generation failed: {error}");
            std::process::abort();
        }
        let token = managed_cookie_token(&key)?;
        Some((
            key,
            ManagedAffinityCookie {
                header_value: config.header_value(&token),
            },
        ))
    }
}

impl ManagedCookieConfig {
    fn header_value(&self, value: &str) -> String {
        let mut header = format!("{}={}; Path={}", self.name, value, self.path);
        if let Some(domain) = &self.domain {
            header.push_str("; Domain=");
            header.push_str(domain);
        }
        header.push_str("; Max-Age=");
        header.push_str(&self.max_age_secs.to_string());
        if self.http_only {
            header.push_str("; HttpOnly");
        }
        if self.secure {
            header.push_str("; Secure");
        }
        header.push_str("; SameSite=");
        header.push_str(self.same_site.as_str());
        header
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

fn managed_cookie_key(request: &RequestHeader, name: &str) -> Option<Vec<u8>> {
    let encoded = cookie_key(request, name)?;
    let token = base64_ng::URL_SAFE_NO_PAD.decode_vec(&encoded).ok()?;
    if token.len() != MANAGED_COOKIE_TOKEN_BYTES {
        return None;
    }
    let (key, tag) = token.split_at(MANAGED_COOKIE_KEY_BYTES);
    let expected = managed_cookie_tag(key);
    if expected.as_slice().ct_eq(tag).unwrap_u8() != 1 {
        return None;
    }
    Some(key.to_vec())
}

fn managed_cookie_token(key: &[u8]) -> Option<String> {
    if key.len() != MANAGED_COOKIE_KEY_BYTES {
        return None;
    }
    let tag = managed_cookie_tag(key);
    let mut token = Vec::with_capacity(MANAGED_COOKIE_TOKEN_BYTES);
    token.extend_from_slice(key);
    token.extend_from_slice(&tag);
    base64_ng::URL_SAFE_NO_PAD.encode_string(&token).ok()
}

fn managed_cookie_tag(key: &[u8]) -> [u8; MANAGED_COOKIE_TAG_BYTES] {
    crate::internal_crypto::admin_hmac_sha256_or_abort(
        crate::internal_crypto::admin_mac_provider(),
        managed_cookie_hmac_key(),
        key,
    )
}

fn managed_cookie_hmac_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut key = [0_u8; 32];
        if let Err(error) = getrandom::fill(&mut key) {
            log::error!("fatal: managed load-balancer cookie HMAC key generation failed: {error}");
            std::process::abort();
        }
        key
    })
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
}
