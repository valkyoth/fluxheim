use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use sanitization::ct::ConstantTimeEq;

use crate::NativeHttp1Request;

const NATIVE_TRAFFIC_MIRROR_INFLIGHT_MAX_KEYS: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeTrafficMirror {
    base_url: String,
    sample_per_mille: u16,
    methods: Vec<String>,
    forward_headers: Vec<String>,
    timeout: Duration,
    max_response_bytes: u64,
    max_in_flight: usize,
    slot_key: String,
}

#[derive(Debug)]
struct NativeTrafficMirrorRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    timeout: Duration,
    max_response_bytes: u64,
    max_in_flight: usize,
    slot_key: String,
}

impl NativeTrafficMirror {
    pub(crate) fn from_config(config: &fluxheim_config::TrafficMirrorConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        Some(Self {
            base_url: config.base_url.clone()?,
            sample_per_mille: config.sample_per_mille,
            methods: config.methods.clone(),
            forward_headers: config.forward_headers.clone(),
            timeout: Duration::from_secs(config.timeout_secs),
            max_response_bytes: config.max_response_bytes.as_u64(),
            max_in_flight: config.max_in_flight,
            slot_key: config.base_url.as_deref().unwrap_or_default().to_owned(),
        })
    }

    pub(crate) fn spawn_if_selected(&self, request: &NativeHttp1Request) {
        let Some(mirror_request) = self.request(request) else {
            return;
        };
        let Some(slot) = acquire_native_traffic_mirror_slot(
            &mirror_request.slot_key,
            mirror_request.max_in_flight,
        ) else {
            return;
        };
        let Ok(blocking_permit) = crate::blocking_work::try_acquire_request_blocking_work() else {
            return;
        };
        tokio::task::spawn_blocking(move || {
            let _permits = (slot, blocking_permit);
            if let Err(error) = send_native_traffic_mirror_request(&mirror_request) {
                log::debug!(
                    target: "fluxheim::traffic_mirror",
                    "native traffic mirror request failed: {error}"
                );
            }
        });
    }

    fn request(&self, request: &NativeHttp1Request) -> Option<NativeTrafficMirrorRequest> {
        if native_request_has_valid_mirror_marker(request)
            || !self.methods.iter().any(|method| method == &request.method)
            || !native_traffic_mirror_sample_selected(request, self.sample_per_mille)
        {
            return None;
        }
        let path_and_query = native_request_path_and_query(request)?;
        let url = native_traffic_mirror_url(&self.base_url, path_and_query)?;
        let mut headers = Vec::new();
        for name in &self.forward_headers {
            if let Some(value) = native_request_header_values_joined(request, name) {
                headers.push((name.clone(), value));
            }
        }
        Some(NativeTrafficMirrorRequest {
            method: request.method.clone(),
            url,
            headers,
            timeout: self.timeout,
            max_response_bytes: self.max_response_bytes,
            max_in_flight: self.max_in_flight,
            slot_key: self.slot_key.clone(),
        })
    }
}

struct NativeTrafficMirrorSlot {
    counter: Arc<AtomicUsize>,
}

impl Drop for NativeTrafficMirrorSlot {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

fn acquire_native_traffic_mirror_slot(
    key: &str,
    max_in_flight: usize,
) -> Option<NativeTrafficMirrorSlot> {
    static NATIVE_TRAFFIC_MIRROR_INFLIGHT: OnceLock<Mutex<HashMap<String, Arc<AtomicUsize>>>> =
        OnceLock::new();
    let mut map = NATIVE_TRAFFIC_MIRROR_INFLIGHT
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|_| {
            log::error!(
                target: "fluxheim::security",
                "native traffic mirror in-flight lock poisoned; aborting"
            );
            std::process::abort();
        });
    if map.len() >= NATIVE_TRAFFIC_MIRROR_INFLIGHT_MAX_KEYS && !map.contains_key(key) {
        map.retain(|_, counter| counter.load(Ordering::Acquire) > 0);
        if map.len() >= NATIVE_TRAFFIC_MIRROR_INFLIGHT_MAX_KEYS {
            return None;
        }
    }
    let counter = map
        .entry(key.to_owned())
        .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
        .clone();
    drop(map);

    loop {
        let current = counter.load(Ordering::Acquire);
        if current >= max_in_flight {
            return None;
        }
        let next = current.checked_add(1)?;
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(NativeTrafficMirrorSlot { counter }),
            Err(_) => continue,
        }
    }
}

fn native_traffic_mirror_url(base_url: &str, path_and_query: &str) -> Option<String> {
    if path_and_query.contains('#')
        || !fluxheim_common::path_safety::safe_forward_path_and_query(path_and_query)
    {
        return None;
    }
    let mut url = base_url.trim_end_matches('/').to_owned();
    url.push_str(path_and_query);
    Some(url)
}

fn native_request_path_and_query(request: &NativeHttp1Request) -> Option<&str> {
    if request.target.starts_with('/') {
        return Some(request.target.as_str());
    }
    None
}

fn native_traffic_mirror_sample_selected(
    request: &NativeHttp1Request,
    sample_per_mille: u16,
) -> bool {
    if sample_per_mille >= 1000 {
        return true;
    }
    use sha2::{Digest, Sha256};

    static NATIVE_TRAFFIC_MIRROR_SAMPLE_SALT: OnceLock<[u8; 16]> = OnceLock::new();
    let salt = NATIVE_TRAFFIC_MIRROR_SAMPLE_SALT.get_or_init(|| {
        let mut salt = [0_u8; 16];
        if let Err(error) = getrandom::fill(&mut salt) {
            log::error!(
                target: "fluxheim::security",
                "native traffic mirror sampling salt generation failed: {error}; aborting"
            );
            std::process::abort();
        }
        salt
    });

    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(b"\n");
    hasher.update(request.method.as_bytes());
    hasher.update(b"\n");
    hasher.update(request.target.as_bytes());
    if let Some(host) = native_request_header_values(request, "host").next() {
        hasher.update(b"\n");
        hasher.update(host.as_bytes());
    }
    let digest = hasher.finalize();
    let bucket = u16::from_be_bytes([digest[0], digest[1]]) % 1000;
    bucket < sample_per_mille
}

fn send_native_traffic_mirror_request(request: &NativeTrafficMirrorRequest) -> std::io::Result<()> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(request.timeout))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into();
    let mut builder = match request.method.as_str() {
        "GET" => agent.get(&request.url),
        "HEAD" => agent.head(&request.url),
        "OPTIONS" => agent.options(&request.url),
        "TRACE" => agent.trace(&request.url),
        _ => {
            return Err(std::io::Error::other(
                "traffic mirror method is not supported",
            ));
        }
    }
    .header("cache-control", "no-store")
    .header("x-fluxheim-mirror", "1")
    .header(
        "x-fluxheim-mirror-signature",
        native_traffic_mirror_marker_signature(),
    );
    for (name, value) in &request.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let mut response = builder
        .call()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let body = response
        .body_mut()
        .with_config()
        .limit(request.max_response_bytes.saturating_add(1))
        .read_to_vec()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    if body.len() as u64 > request.max_response_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "traffic mirror response exceeds configured body limit",
        ));
    }
    Ok(())
}

pub(crate) fn native_request_has_valid_mirror_marker(request: &NativeHttp1Request) -> bool {
    let marker_present =
        native_request_header_values(request, "x-fluxheim-mirror").any(|value| value.trim() == "1");
    if !marker_present {
        return false;
    }
    native_request_header_values(request, "x-fluxheim-mirror-signature")
        .any(native_traffic_mirror_marker_signature_matches)
}

pub(crate) fn strip_native_traffic_mirror_headers(request: &mut NativeHttp1Request) {
    request.headers.retain(|(name, _)| {
        !name.eq_ignore_ascii_case("x-fluxheim-mirror")
            && !name.eq_ignore_ascii_case("x-fluxheim-mirror-signature")
    });
}

fn native_traffic_mirror_marker_signature_matches(value: &str) -> bool {
    let candidate = value.trim().as_bytes();
    let expected = native_traffic_mirror_marker_signature().as_bytes();
    candidate.len() == expected.len()
        && candidate
            .ct_eq(expected)
            .declassify("native traffic mirror marker match result is public")
}

fn native_traffic_mirror_marker_signature() -> &'static str {
    static SIGNATURE: OnceLock<String> = OnceLock::new();
    SIGNATURE.get_or_init(|| {
        use sha2::{Digest, Sha256};
        let mut secret = [0_u8; 32];
        if let Err(error) = getrandom::fill(&mut secret) {
            log::error!(
                target: "fluxheim::security",
                "native traffic mirror marker secret generation failed: {error}; aborting"
            );
            std::process::abort();
        }
        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(b"\nfluxheim-native-mirror-v1");
        let digest = hasher.finalize();
        let mut signature = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(&mut signature, "{byte:02x}");
        }
        signature
    })
}

fn native_request_header_values<'a>(
    request: &'a NativeHttp1Request,
    name: &'a str,
) -> impl Iterator<Item = &'a str> {
    request
        .headers
        .iter()
        .filter(move |(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn native_request_header_values_joined(request: &NativeHttp1Request, name: &str) -> Option<String> {
    fluxheim_headers::join_header_values(
        native_request_header_values(request, name).filter(|value| !value.trim().is_empty()),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        native_traffic_mirror_marker_signature, native_traffic_mirror_marker_signature_matches,
    };

    #[test]
    fn native_mirror_marker_signature_uses_sanitization_constant_time_match() {
        let signature = native_traffic_mirror_marker_signature();

        assert!(native_traffic_mirror_marker_signature_matches(signature));
        assert!(native_traffic_mirror_marker_signature_matches(&format!(
            " {signature} "
        )));
        assert!(!native_traffic_mirror_marker_signature_matches("attacker"));
        assert!(!native_traffic_mirror_marker_signature_matches(
            &signature[..signature.len() - 1]
        ));
    }
}
