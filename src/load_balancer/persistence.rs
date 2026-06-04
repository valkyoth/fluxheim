use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use pingora::http::RequestHeader;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::config::{
    LoadBalanceManagedCookieSameSite, LoadBalancePersistenceConfig, LoadBalancePersistenceMode,
    LoadBalanceSelection, ProxyConfig,
};

pub(super) const MAX_PERSISTENCE_KEY_BYTES: usize = 512;
const MANAGED_COOKIE_KEY_BYTES: usize = 16;
const MANAGED_COOKIE_TAG_BYTES: usize = 32;
const MANAGED_COOKIE_TOKEN_BYTES: usize = MANAGED_COOKIE_KEY_BYTES + MANAGED_COOKIE_TAG_BYTES;
const MANAGED_COOKIE_HMAC_ROTATION: Duration = Duration::from_secs(86_400);

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
        let token = managed_cookie_token(config.name.as_bytes(), &key)?;
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
    let mut matched = 0_u8;
    for hmac_key in managed_cookie_hmac_keys_for_verify() {
        let expected = managed_cookie_tag_with_key(&hmac_key, name.as_bytes(), key);
        matched |= expected.as_slice().ct_eq(tag).unwrap_u8();
    }
    if matched != 1 {
        return None;
    }
    Some(key.to_vec())
}

fn managed_cookie_token(cookie_name: &[u8], key: &[u8]) -> Option<String> {
    if key.len() != MANAGED_COOKIE_KEY_BYTES {
        return None;
    }
    let tag = managed_cookie_tag_with_key(&managed_cookie_hmac_key_for_sign(), cookie_name, key);
    let mut token = Vec::with_capacity(MANAGED_COOKIE_TOKEN_BYTES);
    token.extend_from_slice(key);
    token.extend_from_slice(&tag);
    base64_ng::URL_SAFE_NO_PAD.encode_string(&token).ok()
}

fn managed_cookie_tag_with_key(
    hmac_key: &[u8; 32],
    cookie_name: &[u8],
    key: &[u8],
) -> [u8; MANAGED_COOKIE_TAG_BYTES] {
    let cookie_name_len = u16::try_from(cookie_name.len()).unwrap_or_else(|_| {
        log::error!("fatal: managed load-balancer cookie name exceeds HMAC context limit");
        std::process::abort();
    });
    let mut message = Vec::with_capacity(2 + cookie_name.len() + key.len());
    message.extend_from_slice(&cookie_name_len.to_le_bytes());
    message.extend_from_slice(cookie_name);
    message.extend_from_slice(key);
    crate::internal_crypto::admin_hmac_sha256_or_abort(
        crate::internal_crypto::admin_mac_provider(),
        "lb managed-cookie",
        hmac_key,
        &message,
    )
}

fn managed_cookie_hmac_key_for_sign() -> [u8; 32] {
    let mut key_ring = managed_cookie_hmac_key_ring()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    key_ring.current_key(Instant::now())
}

fn managed_cookie_hmac_keys_for_verify() -> Vec<[u8; 32]> {
    let mut key_ring = managed_cookie_hmac_key_ring()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    key_ring.verify_keys(Instant::now())
}

fn managed_cookie_hmac_key_ring() -> &'static Mutex<ManagedCookieHmacKeyRing> {
    static KEY_RING: OnceLock<Mutex<ManagedCookieHmacKeyRing>> = OnceLock::new();
    KEY_RING.get_or_init(|| Mutex::new(ManagedCookieHmacKeyRing::new(Instant::now())))
}

#[derive(Debug)]
struct ManagedCookieHmacKey {
    key: [u8; 32],
    created_at: Instant,
}

impl Drop for ManagedCookieHmacKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Debug)]
struct ManagedCookieHmacKeyRing {
    current: ManagedCookieHmacKey,
    previous: Option<ManagedCookieHmacKey>,
}

impl ManagedCookieHmacKeyRing {
    fn new(now: Instant) -> Self {
        Self {
            current: ManagedCookieHmacKey {
                key: random_managed_cookie_hmac_key(),
                created_at: now,
            },
            previous: None,
        }
    }

    #[cfg(test)]
    fn with_current_key(key: [u8; 32], created_at: Instant) -> Self {
        Self {
            current: ManagedCookieHmacKey { key, created_at },
            previous: None,
        }
    }

    fn current_key(&mut self, now: Instant) -> [u8; 32] {
        self.rotate_if_due(now);
        self.current.key
    }

    fn verify_keys(&mut self, now: Instant) -> Vec<[u8; 32]> {
        self.rotate_if_due(now);
        let mut keys = Vec::with_capacity(2);
        keys.push(self.current.key);
        if let Some(previous) = &self.previous {
            keys.push(previous.key);
        }
        keys
    }

    fn rotate_if_due(&mut self, now: Instant) {
        if now.saturating_duration_since(self.current.created_at) < MANAGED_COOKIE_HMAC_ROTATION {
            return;
        }
        let new_current = ManagedCookieHmacKey {
            key: random_managed_cookie_hmac_key(),
            created_at: now,
        };
        let old_current = std::mem::replace(&mut self.current, new_current);
        if let Some(mut previous) = self.previous.take() {
            previous.key.zeroize();
        }
        self.previous = Some(old_current);
    }
}

fn random_managed_cookie_hmac_key() -> [u8; 32] {
    let mut key = [0_u8; 32];
    if let Err(error) = getrandom::fill(&mut key) {
        log::error!("fatal: managed load-balancer cookie HMAC key generation failed: {error}");
        std::process::abort();
    }
    key
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
    fn managed_cookie_hmac_rotation_retains_previous_key() {
        let now = Instant::now();
        let first_key = [7_u8; 32];
        let mut key_ring = ManagedCookieHmacKeyRing::with_current_key(first_key, now);

        assert_eq!(key_ring.current_key(now), first_key);

        let rotated_at = now + MANAGED_COOKIE_HMAC_ROTATION + Duration::from_secs(1);
        let current = key_ring.current_key(rotated_at);
        assert_ne!(current, first_key);
        let verify_keys = key_ring.verify_keys(rotated_at);

        assert_eq!(verify_keys.len(), 2);
        assert!(verify_keys.contains(&current));
        assert!(verify_keys.contains(&first_key));
    }

    #[test]
    fn managed_cookie_hmac_binds_cookie_name() {
        let key = [9_u8; MANAGED_COOKIE_KEY_BYTES];
        let token = managed_cookie_token(b"fluxheim_lb", &key).unwrap();
        let mut request = RequestHeader::build("GET", b"/", None).unwrap();
        request
            .append_header("cookie", format!("fluxheim_lb={token}"))
            .unwrap();

        assert_eq!(
            managed_cookie_key(&request, "fluxheim_lb").as_deref(),
            Some(key.as_slice())
        );
        assert_eq!(managed_cookie_key(&request, "other_lb"), None);

        let mut replay = RequestHeader::build("GET", b"/", None).unwrap();
        replay
            .append_header("cookie", format!("other_lb={token}"))
            .unwrap();
        assert_eq!(managed_cookie_key(&replay, "other_lb"), None);
    }
}
