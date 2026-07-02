use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fluxheim_cache::{
    CachePurgeIndex, remaining_fresh_ttl_secs, response_age_secs, response_cache_control_max_age,
};
use fluxheim_config::CacheConfig;
use tokio::sync::Notify;

use crate::NativeHttp1Response;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeMemoryCacheEntry {
    pub(crate) status: u16,
    pub(crate) reason: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) content_length: Option<u64>,
    pub(crate) body: Arc<[u8]>,
    pub(crate) expires_at: Instant,
    pub(crate) stale_while_revalidate_until: Option<Instant>,
    pub(crate) stale_if_error_until: Option<Instant>,
    pub(crate) stored_at: Instant,
    pub(crate) weight: u64,
}

#[derive(Debug, Default)]
pub(crate) struct NativeMemoryCacheState {
    pub(crate) objects: HashMap<String, NativeMemoryCacheEntry>,
    pub(crate) variants: HashMap<String, Vec<NativeMemoryCacheVariant>>,
    pub(crate) purge_index: CachePurgeIndex,
    pub(crate) min_uses: HashMap<String, NativeMemoryCacheCounter>,
    pub(crate) cache_pass: HashMap<String, NativeMemoryCacheCounter>,
    pub(crate) revalidating: HashSet<String>,
    pub(crate) filling: HashMap<String, NativeMemoryCacheFill>,
    pub(crate) bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeMemoryCacheCounter {
    pub(crate) uses: u32,
    pub(crate) seen_at: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeMemoryCacheVariant {
    pub(crate) fields: Vec<String>,
    pub(crate) key: String,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeMemoryCacheFill {
    pub(crate) notify: Arc<Notify>,
    pub(crate) started_at: Instant,
}

impl NativeMemoryCacheEntry {
    pub(crate) fn to_response(&self) -> NativeHttp1Response {
        let mut response =
            NativeHttp1Response::new(self.status, self.reason.clone(), self.body.to_vec());
        for (name, value) in &self.headers {
            response = response.with_header(name.clone(), value.clone());
        }
        if let Some(content_length) = self.content_length {
            response = response.with_content_length(content_length);
        }
        response
    }

    pub(crate) fn age_secs(&self) -> u64 {
        Instant::now()
            .saturating_duration_since(self.stored_at)
            .as_secs()
    }
}

pub(crate) fn lock_native_memory_cache<'a>(
    state: &'a Mutex<NativeMemoryCacheState>,
    label: &str,
) -> std::sync::MutexGuard<'a, NativeMemoryCacheState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(error) => {
            log::error!(
                target: "fluxheim::native_http1",
                "{label} memory cache mutex poisoned: {error}"
            );
            std::process::abort();
        }
    }
}

pub(crate) fn native_response_header_map(response: &NativeHttp1Response) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    for (name, value) in response.headers() {
        let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = http::HeaderValue::from_str(value) else {
            continue;
        };
        headers.append(name, value);
    }
    if let Some(content_length) = response.content_length()
        && let Ok(value) = http::HeaderValue::from_str(&content_length.to_string())
    {
        headers.insert(http::header::CONTENT_LENGTH, value);
    }
    headers
}

pub(crate) fn native_cache_ttl(
    status: u16,
    headers: &http::HeaderMap,
    cache: &CacheConfig,
) -> Option<Duration> {
    cache
        .status_ttls
        .get(&status)
        .copied()
        .or(cache.default_status_ttl_secs)
        .or_else(|| response_cache_control_max_age(headers))
        .map(u64::from)
        .map(Duration::from_secs)
}

pub(crate) fn native_peer_fill_cache_ttl(
    status: u16,
    headers: &http::HeaderMap,
    cache: &CacheConfig,
) -> Option<Duration> {
    let ttl_secs = cache
        .status_ttls
        .get(&status)
        .copied()
        .or(cache.default_status_ttl_secs)
        .or_else(|| response_cache_control_max_age(headers))?;
    remaining_fresh_ttl_secs(ttl_secs, response_age_secs(headers))
        .map(u64::from)
        .map(Duration::from_secs)
}

pub(crate) fn native_cache_entry_weight(
    key: &str,
    response: &NativeHttp1Response,
    body_len: u64,
) -> u64 {
    const ENTRY_OVERHEAD: u64 = 256;

    response.headers().iter().fold(
        body_len
            .saturating_add(ENTRY_OVERHEAD)
            .saturating_add(key.len() as u64)
            .saturating_add(response.reason().len() as u64),
        |weight, (name, value)| {
            weight
                .saturating_add(name.len() as u64)
                .saturating_add(value.len() as u64)
                .saturating_add(4)
        },
    )
}

pub(crate) fn prune_native_memory_cache(state: &mut NativeMemoryCacheState, max_bytes: u64) {
    let now = Instant::now();
    let expired = state
        .objects
        .iter()
        .filter_map(|(key, entry)| {
            let stale_until = [
                entry.stale_while_revalidate_until,
                entry.stale_if_error_until,
            ]
            .into_iter()
            .flatten()
            .max()
            .unwrap_or(entry.expires_at);
            (stale_until <= now).then_some(key.clone())
        })
        .collect::<Vec<_>>();
    let expired_bytes = expired
        .iter()
        .filter_map(|key| remove_native_memory_cache_entry(state, key))
        .fold(0_u64, |total, entry| total.saturating_add(entry.weight));
    state.bytes = state.bytes.saturating_sub(expired_bytes);

    if state.bytes > max_bytes {
        let mut by_age = state
            .objects
            .iter()
            .map(|(key, entry)| (entry.stored_at, key.clone()))
            .collect::<Vec<_>>();
        by_age.sort_unstable_by_key(|(stored_at, _)| *stored_at);
        for (_, key) in by_age {
            if state.bytes <= max_bytes {
                break;
            }
            if let Some(entry) = remove_native_memory_cache_entry(state, &key) {
                state.bytes = state.bytes.saturating_sub(entry.weight);
            }
        }
        if state.objects.is_empty() && state.bytes > max_bytes {
            state.bytes = 0;
        } else {
            let actual_bytes = state
                .objects
                .values()
                .fold(0_u64, |total, entry| total.saturating_add(entry.weight));
            state.bytes = state.bytes.min(actual_bytes);
        }
    }
}

pub(crate) fn remove_native_memory_cache_entry(
    state: &mut NativeMemoryCacheState,
    key: &str,
) -> Option<NativeMemoryCacheEntry> {
    let removed = state.objects.remove(key);
    if removed.is_some() {
        state.purge_index.remove_combined(key);
        prune_native_memory_cache_variants_for_key(state, key);
    }
    removed
}

pub(crate) fn remove_native_memory_cache_variants(
    state: &mut NativeMemoryCacheState,
    base_key: &str,
) -> u64 {
    let Some(variants) = state.variants.remove(base_key) else {
        return 0;
    };
    variants.into_iter().fold(0_u64, |removed_bytes, variant| {
        let Some(entry) = state.objects.remove(&variant.key) else {
            return removed_bytes;
        };
        state.purge_index.remove_combined(&variant.key);
        removed_bytes.saturating_add(entry.weight)
    })
}

fn prune_native_memory_cache_variants_for_key(state: &mut NativeMemoryCacheState, key: &str) {
    state.variants.retain(|_, variants| {
        variants.retain(|variant| variant.key != key);
        !variants.is_empty()
    });
}

pub(crate) fn with_native_cache_status(
    mut response: NativeHttp1Response,
    cache: &CacheConfig,
    status: &str,
    reason: Option<&str>,
    age_secs: Option<u64>,
) -> NativeHttp1Response {
    if let Some(header) = &cache.status_header {
        response.push_header(header.clone(), status.to_owned());
    }
    if let (Some(header), Some(reason)) = (&cache.status_reason_header, reason) {
        response.push_header(header.clone(), reason.to_owned());
    }
    if let Some(age_secs) = age_secs {
        response.remove_header("age");
        response.push_header("age", age_secs.to_string());
    }
    response
}
