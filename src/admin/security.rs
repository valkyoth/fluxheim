use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use http::{HeaderMap, StatusCode, header};

use sanitization::{SecureSanitize, ct::ConstantTimeEq};

use zeroize::Zeroizing;

use crate::config::{AdminAuthThrottleConfig, AdminConfig};

use super::unix_secs;

mod token_store;
pub(in crate::admin) use token_store::{
    load_admin_token, read_bounded_secret_file, read_secret_file,
};

pub(super) const MAX_ADMIN_TOKEN_BYTES: usize = 8 * 1024;
pub(super) const MAX_ADMIN_TOKEN_FILE_BYTES: u64 = MAX_ADMIN_TOKEN_BYTES as u64;
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct AdminClientCertificatePolicy {
    required: bool,
    sha256_header: String,
    allow_sha256: Vec<String>,
    deny_sha256: Vec<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum AdminClientCertificateDecision {
    Allowed,
    Required,
    Denied,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum AdminClientCertificateHeader {
    Missing,
    Present(String),
    Invalid,
}

#[derive(Clone)]
pub(super) struct AdminToken {
    len: usize,
    digest: [u8; 32],
    mac_provider: crate::internal_crypto::AdminMacProvider,
}

impl AdminToken {
    pub(super) fn new(token: &str, compliance_required: bool) -> Self {
        let mac_provider =
            crate::internal_crypto::admin_mac_provider_for_compliance_required(compliance_required);
        Self {
            len: token.len(),
            digest: digest_admin_token(token.as_bytes(), mac_provider),
            mac_provider,
        }
    }
}

impl Drop for AdminToken {
    fn drop(&mut self) {
        self.digest.secure_sanitize();
        self.len.secure_sanitize();
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct AdminResponse {
    pub(super) status: StatusCode,
    pub(super) content_type: &'static str,
    pub(super) body: Vec<u8>,
}

#[derive(Clone)]
pub(super) struct AdminAuthThrottle {
    config: AdminAuthThrottleConfig,
    state: Arc<Mutex<AdminAuthThrottleState>>,
}

#[derive(Debug, Default)]
struct AdminAuthThrottleState {
    global_failures: VecDeque<u64>,
    global_locked_until: u64,
    global_lockouts: u32,
    sources: HashMap<AuthSource, AdminAuthSourceState>,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
enum AuthSource {
    Ip(IpAddr),
    Unknown,
}

#[derive(Debug, Default)]
struct AdminAuthSourceState {
    failures: VecDeque<u64>,
    locked_until: u64,
    lockouts: u32,
    last_seen: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum AdminAuthThrottleScope {
    Source,
    Global,
}

impl AdminAuthThrottle {
    pub(super) fn new(config: AdminAuthThrottleConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(AdminAuthThrottleState::default())),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, AdminAuthThrottleState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => {
                log::error!(
                    target: "fluxheim::security",
                    "admin auth throttle lock poisoned; aborting to avoid using inconsistent security state"
                );
                std::process::abort();
            }
        }
    }

    pub(super) fn pre_auth_check(&self, source: Option<IpAddr>) -> Option<AdminAuthThrottleScope> {
        if !self.config.enabled {
            return None;
        }
        let now = unix_secs();
        let source = AuthSource::from(source);
        let mut state = self.lock_state();
        state.prune(now, &self.config);

        if state.global_locked_until > now {
            return Some(AdminAuthThrottleScope::Global);
        }
        if source == AuthSource::Unknown {
            return None;
        }
        state.sources.get(&source).and_then(|record| {
            (record.locked_until > now).then_some(AdminAuthThrottleScope::Source)
        })
    }

    pub(super) fn record_failure(&self, source: Option<IpAddr>) -> Option<AdminAuthThrottleScope> {
        if !self.config.enabled {
            return None;
        }
        let now = unix_secs();
        let source = AuthSource::from(source);
        let mut state = self.lock_state();
        state.prune(now, &self.config);
        state.global_failures.push_back(now);
        if source == AuthSource::Unknown {
            log::warn!(
                target: "fluxheim::security",
                "admin auth failure from indeterminate source; applying global throttle only"
            );
            if state.global_failures.len() >= self.config.global_failures {
                state.global_lockouts = state.global_lockouts.saturating_add(1);
                state.global_locked_until =
                    now.saturating_add(lockout_secs(&self.config, state.global_lockouts));
                state.global_failures.clear();
                return Some(AdminAuthThrottleScope::Global);
            }
            return None;
        }
        if !state.ensure_source_capacity(&self.config, source) {
            log::warn!(
                target: "fluxheim::security",
                "admin auth throttle source table full; applying global failure accounting"
            );
            if state.global_failures.len() >= self.config.global_failures {
                state.global_lockouts = state.global_lockouts.saturating_add(1);
                state.global_locked_until =
                    now.saturating_add(lockout_secs(&self.config, state.global_lockouts));
                state.global_failures.clear();
                return Some(AdminAuthThrottleScope::Global);
            }
            return None;
        }

        let source_locked = {
            let source_record = state.sources.entry(source).or_default();
            source_record.last_seen = now;
            source_record.failures.push_back(now);
            if source_record.failures.len() >= self.config.per_source_failures {
                source_record.lockouts = source_record.lockouts.saturating_add(1);
                source_record.locked_until =
                    now.saturating_add(lockout_secs(&self.config, source_record.lockouts));
                source_record.failures.clear();
                true
            } else {
                false
            }
        };

        if state.global_failures.len() >= self.config.global_failures {
            state.global_lockouts = state.global_lockouts.saturating_add(1);
            state.global_locked_until =
                now.saturating_add(lockout_secs(&self.config, state.global_lockouts));
            state.global_failures.clear();
            return Some(AdminAuthThrottleScope::Global);
        }

        source_locked.then_some(AdminAuthThrottleScope::Source)
    }

    pub(super) fn record_success(&self, source: Option<IpAddr>) {
        if !self.config.enabled {
            return;
        }
        let source = AuthSource::from(source);
        if source == AuthSource::Unknown {
            return;
        }
        let mut state = self.lock_state();
        state.sources.remove(&source);
    }
}

impl AdminAuthThrottleState {
    fn prune(&mut self, now: u64, config: &AdminAuthThrottleConfig) {
        let cutoff = now.saturating_sub(config.window_secs);
        prune_failures(&mut self.global_failures, cutoff);
        self.sources.retain(|_, record| {
            prune_failures(&mut record.failures, cutoff);
            record.locked_until > now || !record.failures.is_empty()
        });
    }

    fn ensure_source_capacity(
        &mut self,
        config: &AdminAuthThrottleConfig,
        source: AuthSource,
    ) -> bool {
        if self.sources.contains_key(&source) || self.sources.len() < config.max_sources {
            return true;
        }
        if let Some(stale_key) = self
            .sources
            .iter()
            .filter(|(_, record)| record.locked_until == 0)
            .min_by_key(|(_, record)| record.last_seen)
            .map(|(source, _)| *source)
            .or_else(|| {
                self.sources
                    .iter()
                    .min_by_key(|(_, record)| record.last_seen)
                    .map(|(source, _)| *source)
            })
        {
            self.sources.remove(&stale_key);
            log::warn!(
                target: "fluxheim::security",
                "admin auth throttle source table full; evicted stale source entry"
            );
            return true;
        }
        false
    }
}

impl From<Option<IpAddr>> for AuthSource {
    fn from(source: Option<IpAddr>) -> Self {
        source.map(Self::Ip).unwrap_or(Self::Unknown)
    }
}

impl AdminAuthThrottleScope {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Global => "global",
        }
    }
}

fn prune_failures(failures: &mut VecDeque<u64>, cutoff: u64) {
    while failures.front().is_some_and(|seen_at| *seen_at < cutoff) {
        failures.pop_front();
    }
}

fn lockout_secs(config: &AdminAuthThrottleConfig, lockouts: u32) -> u64 {
    let exponent = lockouts.saturating_sub(1).min(20);
    let multiplier = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
    config
        .base_lockout_secs
        .saturating_mul(multiplier)
        .min(config.max_lockout_secs)
}

pub(super) fn auth_source_label(source: Option<IpAddr>) -> String {
    source
        .map(|source| source.to_string())
        .unwrap_or_else(|| "unknown".to_owned())
}
pub(super) fn authorization_header(headers: &HeaderMap) -> Option<&str> {
    header_value(headers, header::AUTHORIZATION.as_str())
}

impl AdminClientCertificatePolicy {
    pub(super) fn from_config(config: &AdminConfig) -> Self {
        Self {
            required: config.admin_client_certificate_required(),
            sha256_header: config.client_certificate.sha256_header.to_ascii_lowercase(),
            allow_sha256: normalized_sha256_fingerprints(&config.client_certificate.allow_sha256),
            deny_sha256: normalized_sha256_fingerprints(&config.client_certificate.deny_sha256),
        }
    }

    pub(super) fn allows(&self, headers: &HeaderMap) -> AdminClientCertificateDecision {
        if !self.active() {
            return AdminClientCertificateDecision::Allowed;
        }

        let fingerprint = match single_sha256_header(headers, &self.sha256_header) {
            AdminClientCertificateHeader::Present(fingerprint) => fingerprint,
            AdminClientCertificateHeader::Invalid => {
                return AdminClientCertificateDecision::Denied;
            }
            AdminClientCertificateHeader::Missing
                if self.required || !self.allow_sha256.is_empty() =>
            {
                return AdminClientCertificateDecision::Required;
            }
            AdminClientCertificateHeader::Missing => {
                return AdminClientCertificateDecision::Allowed;
            }
        };

        if admin_fingerprint_list_contains(&self.deny_sha256, &fingerprint) {
            return AdminClientCertificateDecision::Denied;
        }

        if !self.allow_sha256.is_empty()
            && !admin_fingerprint_list_contains(&self.allow_sha256, &fingerprint)
        {
            return AdminClientCertificateDecision::Denied;
        }

        AdminClientCertificateDecision::Allowed
    }

    fn active(&self) -> bool {
        self.required || !self.allow_sha256.is_empty() || !self.deny_sha256.is_empty()
    }
}

fn single_sha256_header(headers: &HeaderMap, name: &str) -> AdminClientCertificateHeader {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return AdminClientCertificateHeader::Missing;
    };
    if values.next().is_some() {
        return AdminClientCertificateHeader::Invalid;
    }
    let Ok(value) = value.to_str() else {
        return AdminClientCertificateHeader::Invalid;
    };
    let value = value.trim();
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        AdminClientCertificateHeader::Present(value.to_ascii_lowercase())
    } else {
        AdminClientCertificateHeader::Invalid
    }
}

fn normalized_sha256_fingerprints(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

pub(super) fn admin_fingerprint_list_contains(values: &[String], fingerprint: &str) -> bool {
    let fingerprint = fingerprint.as_bytes();
    let mut matched = 0u8;
    for value in values {
        matched |= value.as_bytes().ct_eq(fingerprint).unwrap_u8();
    }
    matched == 1
}

pub(super) fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

pub(super) fn authorized(header: Option<&str>, token: &AdminToken) -> bool {
    let Some(header) = header else {
        return false;
    };
    let Some(candidate) = header.trim().strip_prefix("Bearer ") else {
        return false;
    };
    let candidate = candidate.trim();
    let candidate = Zeroizing::new(candidate.as_bytes().to_vec());
    let within_limit = candidate.len() <= MAX_ADMIN_TOKEN_BYTES;
    constant_time_eq(candidate.as_slice(), token) & within_limit
}

pub(super) fn constant_time_eq(candidate: &[u8], token: &AdminToken) -> bool {
    let candidate_digest = digest_admin_token(candidate, token.mac_provider);
    let candidate_len = (candidate.len() as u64).to_le_bytes();
    let token_len = (token.len as u64).to_le_bytes();
    (candidate_digest.ct_eq(&token.digest) & candidate_len.ct_eq(&token_len))
        .declassify("admin bearer-token comparison result is public")
}

fn digest_admin_token(
    token: &[u8],
    mac_provider: crate::internal_crypto::AdminMacProvider,
) -> [u8; 32] {
    crate::internal_crypto::admin_hmac_sha256_or_abort(
        mac_provider,
        "admin bearer-token",
        token_mac_key(),
        token,
    )
}

fn token_mac_key() -> &'static [u8; 32] {
    static TOKEN_MAC_KEY: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();
    TOKEN_MAC_KEY.get_or_init(|| {
        let mut key = [0_u8; 32];
        if let Err(error) = getrandom::fill(&mut key) {
            log::error!(
                "fatal: admin token MAC key generation failed; cannot continue without entropy: {error}"
            );
            std::process::abort();
        }
        Zeroizing::new(key)
    })
}
