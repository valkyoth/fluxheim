use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::native_http1_cache::{NativeMemoryCacheCounter, NativeMemoryCacheEntry};
use fluxheim_cache::CacheStaleEvent;
use fluxheim_config::CacheStaleErrorKind;

const NATIVE_CACHE_PREDICTOR_COUNTER_TTL: Duration = Duration::from_secs(600);

pub(crate) fn prune_native_predictor_counters(
    counters: &mut HashMap<String, NativeMemoryCacheCounter>,
    capacity: usize,
) {
    let capacity = capacity.max(1);
    if counters.len() < capacity {
        return;
    }

    while counters.len() >= capacity {
        let Some(key) = counters.keys().next().cloned() else {
            break;
        };
        counters.remove(&key);
    }
}

pub(crate) fn native_predictor_counter_uses(
    counters: &mut HashMap<String, NativeMemoryCacheCounter>,
    key: &str,
) -> Option<u32> {
    let counter = counters.get(key).copied()?;
    if Instant::now().saturating_duration_since(counter.seen_at)
        >= NATIVE_CACHE_PREDICTOR_COUNTER_TTL
    {
        counters.remove(key);
        return None;
    }
    Some(counter.uses)
}

pub(crate) fn native_cache_entry_has_stale_window(
    entry: &NativeMemoryCacheEntry,
    now: Instant,
) -> bool {
    entry
        .stale_while_revalidate_until
        .is_some_and(|until| until > now)
        || entry.stale_if_error_until.is_some_and(|until| until > now)
}

pub(crate) fn native_cache_entry_serve_stale_while_revalidate(
    entry: &NativeMemoryCacheEntry,
    now: Instant,
) -> bool {
    entry.expires_at <= now
        && entry
            .stale_while_revalidate_until
            .is_some_and(|until| until > now)
}

pub(crate) fn native_cache_stale_event_for_error(
    error: &crate::NativeHttp1Error,
) -> CacheStaleEvent {
    CacheStaleEvent::UpstreamError(native_cache_stale_error_kind(error))
}

fn native_cache_stale_error_kind(error: &crate::NativeHttp1Error) -> CacheStaleErrorKind {
    match error {
        crate::NativeHttp1Error::Io(error) => match error.kind() {
            std::io::ErrorKind::TimedOut => CacheStaleErrorKind::Timeout,
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::AddrInUse
            | std::io::ErrorKind::AddrNotAvailable => CacheStaleErrorKind::Connect,
            std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof => CacheStaleErrorKind::ConnectionClosed,
            std::io::ErrorKind::InvalidData => CacheStaleErrorKind::Protocol,
            std::io::ErrorKind::PermissionDenied => CacheStaleErrorKind::Other,
            _ => CacheStaleErrorKind::Other,
        },
        crate::NativeHttp1Error::Parse(_) => CacheStaleErrorKind::Protocol,
    }
}

pub(crate) fn native_cache_expiry_times(
    now: Instant,
    ttl: Duration,
    stale_while_revalidate_secs: Option<u32>,
    stale_if_error_secs: Option<u32>,
) -> Option<(Instant, Option<Instant>, Option<Instant>)> {
    let expires_at = now.checked_add(ttl)?;
    let stale_while_revalidate_until = match stale_while_revalidate_secs {
        Some(stale_secs) => {
            Some(expires_at.checked_add(Duration::from_secs(u64::from(stale_secs)))?)
        }
        None => None,
    };
    let stale_if_error_until = match stale_if_error_secs {
        Some(stale_secs) => {
            Some(expires_at.checked_add(Duration::from_secs(u64::from(stale_secs)))?)
        }
        None => None,
    };
    Some((
        expires_at,
        stale_while_revalidate_until,
        stale_if_error_until,
    ))
}
