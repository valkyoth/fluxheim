use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use sanitization::{SecureSanitize, ct::ConstantTimeEq};
use zeroize::Zeroizing;

use fluxheim_config::{LoadBalanceManagedCookieSameSite, LoadBalancePersistenceConfig};

use super::persistence::LoadBalancerRequestView;
use super::persistence_request::cookie_key;

pub(super) const MANAGED_COOKIE_KEY_BYTES: usize = 16;
const MANAGED_COOKIE_TAG_BYTES: usize = 32;
const MANAGED_COOKIE_TOKEN_BYTES: usize = MANAGED_COOKIE_KEY_BYTES + MANAGED_COOKIE_TAG_BYTES;
const MANAGED_COOKIE_HMAC_ROTATION: Duration = Duration::from_secs(86_400);

#[derive(Clone, Debug)]
pub struct ManagedAffinityCookie {
    pub header_value: String,
}

#[derive(Clone, Debug)]
pub(super) struct ManagedCookieConfig {
    pub(super) name: String,
    domain: Option<String>,
    path: String,
    secure: bool,
    http_only: bool,
    same_site: LoadBalanceManagedCookieSameSite,
    max_age_secs: u64,
}

impl ManagedCookieConfig {
    pub(super) fn from_config(config: &LoadBalancePersistenceConfig) -> Self {
        Self {
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
    }

    pub(super) fn header_value(&self, value: &str) -> String {
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

pub(super) fn managed_cookie_key(
    request: &impl LoadBalancerRequestView,
    name: &str,
) -> Option<Vec<u8>> {
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

pub(super) fn managed_cookie_token(cookie_name: &[u8], key: &[u8]) -> Option<String> {
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
    crate::crypto::admin_hmac_sha256_or_abort("lb managed-cookie", hmac_key, &message)
}

fn managed_cookie_hmac_key_for_sign() -> Zeroizing<[u8; 32]> {
    let mut key_ring = managed_cookie_hmac_key_ring()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    key_ring.current_key(Instant::now())
}

fn managed_cookie_hmac_keys_for_verify() -> Vec<Zeroizing<[u8; 32]>> {
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
        self.key.secure_sanitize();
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

    fn current_key(&mut self, now: Instant) -> Zeroizing<[u8; 32]> {
        self.rotate_if_due(now);
        Zeroizing::new(self.current.key)
    }

    fn verify_keys(&mut self, now: Instant) -> Vec<Zeroizing<[u8; 32]>> {
        self.rotate_if_due(now);
        let mut keys = Vec::with_capacity(2);
        keys.push(Zeroizing::new(self.current.key));
        if let Some(previous) = &self.previous {
            keys.push(Zeroizing::new(previous.key));
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
            previous.key.secure_sanitize();
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

    #[derive(Default)]
    struct TestRequest {
        headers: Vec<(String, Vec<u8>)>,
    }

    impl TestRequest {
        fn with_header(mut self, name: &str, value: impl Into<Vec<u8>>) -> Self {
            self.headers.push((name.to_ascii_lowercase(), value.into()));
            self
        }
    }

    impl LoadBalancerRequestView for TestRequest {
        fn uri_key(&self) -> Vec<u8> {
            Vec::new()
        }

        fn header_values<'a>(&'a self, name: &str) -> Box<dyn Iterator<Item = &'a [u8]> + 'a> {
            let name = name.to_ascii_lowercase();
            Box::new(
                self.headers
                    .iter()
                    .filter(move |(header, _)| header == &name)
                    .map(|(_, value)| value.as_slice()),
            )
        }

        fn cookie_headers<'a>(&'a self) -> Box<dyn Iterator<Item = &'a str> + 'a> {
            Box::new(
                self.header_values("cookie")
                    .filter_map(|value| std::str::from_utf8(value).ok()),
            )
        }
    }

    #[test]
    fn managed_cookie_hmac_rotation_retains_previous_key() {
        let now = Instant::now();
        let first_key = [7_u8; 32];
        let mut key_ring = ManagedCookieHmacKeyRing::with_current_key(first_key, now);

        assert_eq!(*key_ring.current_key(now), first_key);

        let rotated_at = now + MANAGED_COOKIE_HMAC_ROTATION + Duration::from_secs(1);
        let current = key_ring.current_key(rotated_at);
        assert_ne!(*current, first_key);
        let verify_keys = key_ring.verify_keys(rotated_at);

        assert_eq!(verify_keys.len(), 2);
        assert!(verify_keys.iter().any(|key| **key == *current));
        assert!(verify_keys.iter().any(|key| **key == first_key));
    }

    #[test]
    fn managed_cookie_hmac_binds_cookie_name() {
        let key = [9_u8; MANAGED_COOKIE_KEY_BYTES];
        let token = managed_cookie_token(b"fluxheim_lb", &key).unwrap();
        let request = TestRequest::default().with_header("cookie", format!("fluxheim_lb={token}"));

        assert_eq!(
            managed_cookie_key(&request, "fluxheim_lb").as_deref(),
            Some(key.as_slice())
        );
        assert_eq!(managed_cookie_key(&request, "other_lb"), None);

        let replay = TestRequest::default().with_header("cookie", format!("other_lb={token}"));
        assert_eq!(managed_cookie_key(&replay, "other_lb"), None);
    }

    #[test]
    fn managed_cookie_hmac_rejects_tampered_tag() {
        let key = [3_u8; MANAGED_COOKIE_KEY_BYTES];
        let token = managed_cookie_token(b"fluxheim_lb", &key).unwrap();
        let mut tampered = token.into_bytes();
        let last = tampered
            .last_mut()
            .expect("managed-cookie token is non-empty");
        *last = if *last == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
        let request =
            TestRequest::default().with_header("cookie", format!("fluxheim_lb={tampered}"));

        assert_eq!(managed_cookie_key(&request, "fluxheim_lb"), None);
    }
}
