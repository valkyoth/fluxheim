use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::http_types::PingoraRequestHeader as RequestHeader;
use sha2::{Digest, Sha256};

const TRAFFIC_MIRROR_INFLIGHT_MAX_KEYS: usize = 4096;

#[derive(Clone, Copy, Debug)]
pub(crate) struct TrafficMirrorRouteContext<'a> {
    pub(crate) vhost_name: &'a str,
    pub(crate) route_name: Option<&'a str>,
}

#[derive(Debug)]
struct TrafficMirrorRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    timeout_secs: u64,
    max_response_bytes: u64,
    max_in_flight: usize,
    slot_key: String,
    #[cfg(feature = "metrics")]
    metric_vhost: String,
    #[cfg(feature = "metrics")]
    metric_route: Option<String>,
}

pub(crate) fn spawn_proxy_mirror_if_enabled(
    request: &RequestHeader,
    mirror: &crate::config::TrafficMirrorConfig,
    context: TrafficMirrorRouteContext<'_>,
) {
    let Some(mirror_request) = traffic_mirror_request(request, mirror, context) else {
        return;
    };
    let Some(mirror_slot) =
        acquire_traffic_mirror_slot(&mirror_request.slot_key, mirror_request.max_in_flight)
    else {
        #[cfg(feature = "metrics")]
        crate::metrics::record_edge_policy_event(
            &mirror_request.metric_vhost,
            mirror_request.metric_route.as_deref(),
            "mirror",
            "skipped",
        );
        return;
    };
    tokio::task::spawn_blocking(move || {
        let _mirror_slot = mirror_slot;
        let result = send_traffic_mirror_request(&mirror_request);
        if let Err(error) = &result {
            log::debug!(
                target: "fluxheim::traffic_mirror",
                "traffic mirror request failed: {error}"
            );
        }
        #[cfg(feature = "metrics")]
        {
            let outcome = if result.is_ok() { "success" } else { "error" };
            crate::metrics::record_edge_policy_event(
                &mirror_request.metric_vhost,
                mirror_request.metric_route.as_deref(),
                "mirror",
                outcome,
            );
        }
    });
}

fn traffic_mirror_request(
    request: &RequestHeader,
    mirror: &crate::config::TrafficMirrorConfig,
    context: TrafficMirrorRouteContext<'_>,
) -> Option<TrafficMirrorRequest> {
    if !mirror.enabled
        || !mirror
            .methods
            .iter()
            .any(|method| method == request.method.as_str())
        || !traffic_mirror_sample_selected(request, mirror.sample_per_mille)
    {
        return None;
    }
    let base_url = mirror.base_url.as_deref()?;
    let url = traffic_mirror_url(
        base_url,
        request.uri.path_and_query().map_or("/", |pq| pq.as_str()),
    )?;
    let headers = traffic_mirror_forwarded_headers(request, mirror);
    Some(TrafficMirrorRequest {
        method: request.method.as_str().to_owned(),
        url,
        headers,
        timeout_secs: mirror.timeout_secs,
        max_response_bytes: mirror.max_response_bytes.as_u64(),
        max_in_flight: mirror.max_in_flight,
        slot_key: traffic_mirror_slot_key(context),
        #[cfg(feature = "metrics")]
        metric_vhost: context.vhost_name.to_owned(),
        #[cfg(feature = "metrics")]
        metric_route: context.route_name.map(str::to_owned),
    })
}

fn traffic_mirror_slot_key(context: TrafficMirrorRouteContext<'_>) -> String {
    format!(
        "{}\n{}",
        context.vhost_name,
        context.route_name.unwrap_or("-")
    )
}

pub(crate) struct TrafficMirrorSlot {
    counter: Arc<AtomicUsize>,
}

impl Drop for TrafficMirrorSlot {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn acquire_traffic_mirror_slot(
    key: &str,
    max_in_flight: usize,
) -> Option<TrafficMirrorSlot> {
    static TRAFFIC_MIRROR_INFLIGHT: OnceLock<Mutex<HashMap<String, Arc<AtomicUsize>>>> =
        OnceLock::new();
    let mut map = TRAFFIC_MIRROR_INFLIGHT
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|_| {
            log::error!(
                target: "fluxheim::security",
                "traffic mirror in-flight lock poisoned; aborting"
            );
            std::process::abort();
        });
    if map.len() >= TRAFFIC_MIRROR_INFLIGHT_MAX_KEYS && !map.contains_key(key) {
        map.retain(|_, counter| counter.load(Ordering::Acquire) > 0);
        if map.len() >= TRAFFIC_MIRROR_INFLIGHT_MAX_KEYS {
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
            Ok(_) => return Some(TrafficMirrorSlot { counter }),
            Err(_) => continue,
        }
    }
}

pub(crate) fn traffic_mirror_forwarded_headers(
    request: &RequestHeader,
    mirror: &crate::config::TrafficMirrorConfig,
) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    for name in &mirror.forward_headers {
        if let Some(value) = request_header_values_joined(request, name) {
            headers.push((name.clone(), value));
        }
    }
    headers
}

pub(crate) fn traffic_mirror_sample_selected(
    request: &RequestHeader,
    sample_per_mille: u16,
) -> bool {
    traffic_mirror_sample_selected_with_salt(
        request,
        sample_per_mille,
        traffic_mirror_sample_salt(),
    )
}

fn traffic_mirror_sample_salt() -> &'static [u8; 16] {
    static TRAFFIC_MIRROR_SAMPLE_SALT: OnceLock<[u8; 16]> = OnceLock::new();
    TRAFFIC_MIRROR_SAMPLE_SALT.get_or_init(|| {
        let mut salt = [0_u8; 16];
        if let Err(error) = getrandom::fill(&mut salt) {
            log::error!(
                target: "fluxheim::security",
                "traffic mirror sampling salt generation failed: {error}; aborting"
            );
            std::process::abort();
        }
        salt
    })
}

fn traffic_mirror_sample_selected_with_salt(
    request: &RequestHeader,
    sample_per_mille: u16,
    salt: &[u8; 16],
) -> bool {
    if sample_per_mille >= 1000 {
        return true;
    }
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(b"\n");
    hasher.update(request.method.as_str().as_bytes());
    hasher.update(b"\n");
    hasher.update(
        request
            .uri
            .path_and_query()
            .map_or("/", |pq| pq.as_str())
            .as_bytes(),
    );
    if let Some(host) = request_host_header(request) {
        hasher.update(b"\n");
        hasher.update(host.as_bytes());
    }
    let digest = hasher.finalize();
    let bucket = u16::from_be_bytes([digest[0], digest[1]]) % 1000;
    bucket < sample_per_mille
}

pub(crate) fn traffic_mirror_url(base_url: &str, path_and_query: &str) -> Option<String> {
    if !path_and_query.starts_with('/') {
        return None;
    }
    let mut url = base_url.trim_end_matches('/').to_owned();
    url.push_str(path_and_query);
    Some(url)
}

fn send_traffic_mirror_request(request: &TrafficMirrorRequest) -> io::Result<()> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(request.timeout_secs)))
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
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "traffic mirror method is not supported",
            ));
        }
    }
    .header("cache-control", "no-store")
    .header("x-fluxheim-mirror", "1");
    for (name, value) in &request.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let mut response = builder.call().map_err(traffic_mirror_io_error)?;
    let body = response
        .body_mut()
        .with_config()
        .limit(request.max_response_bytes.saturating_add(1))
        .read_to_vec()
        .map_err(traffic_mirror_io_error)?;
    if body.len() as u64 > request.max_response_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "traffic mirror response exceeds configured body limit",
        ));
    }
    Ok(())
}

fn traffic_mirror_io_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

fn request_header_values_joined(request: &RequestHeader, name: &str) -> Option<String> {
    let mut values = request
        .headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok());
    let first = values.next()?.to_owned();
    Some(values.fold(first, |mut joined, value| {
        joined.push_str(", ");
        joined.push_str(value);
        joined
    }))
}

fn request_host_header(request: &RequestHeader) -> Option<&str> {
    request
        .headers
        .get("host")
        .and_then(|value| value.to_str().ok())
}
