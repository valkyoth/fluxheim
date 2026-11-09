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
    !entry.stale_reuse_forbidden
        && (entry
            .stale_while_revalidate_until
            .is_some_and(|until| until > now)
            || entry.stale_if_error_until.is_some_and(|until| until > now))
}

pub(crate) fn native_cache_entry_serve_stale_while_revalidate(
    entry: &NativeMemoryCacheEntry,
    now: Instant,
) -> bool {
    !entry.stale_reuse_forbidden
        && entry.expires_at <= now
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
    use crate::native_upstream_error::{UpstreamPhase, upstream_error_kind, upstream_phase};
    if let crate::NativeHttp1Error::Io(error) = error {
        if upstream_error_kind(error) == std::io::ErrorKind::TimedOut {
            return CacheStaleErrorKind::Timeout;
        }
        if upstream_phase(error) == Some(UpstreamPhase::Tls) {
            return CacheStaleErrorKind::Tls;
        }
        if !matches!(
            upstream_error_kind(error),
            std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::InvalidData
                | std::io::ErrorKind::PermissionDenied
        ) {
            match upstream_phase(error) {
                Some(UpstreamPhase::Connect) => return CacheStaleErrorKind::Connect,
                Some(UpstreamPhase::Read) => return CacheStaleErrorKind::Read,
                Some(UpstreamPhase::Write) => return CacheStaleErrorKind::Write,
                _ => {}
            }
        }
    }
    match error {
        crate::NativeHttp1Error::Io(error) => match upstream_error_kind(error) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn untagged_stale_errors_keep_legacy_classification() {
        for (kind, expected) in [
            (ErrorKind::TimedOut, CacheStaleErrorKind::Timeout),
            (ErrorKind::ConnectionRefused, CacheStaleErrorKind::Connect),
            (ErrorKind::BrokenPipe, CacheStaleErrorKind::ConnectionClosed),
            (
                ErrorKind::UnexpectedEof,
                CacheStaleErrorKind::ConnectionClosed,
            ),
            (ErrorKind::InvalidData, CacheStaleErrorKind::Protocol),
            (ErrorKind::Other, CacheStaleErrorKind::Other),
        ] {
            for phase in ["read", "write", "tls"] {
                let error = crate::NativeHttp1Error::Io(Error::new(kind, phase));
                assert_eq!(native_cache_stale_error_kind(&error), expected);
            }
        }
    }

    #[test]
    fn stale_error_phase_and_reason_precedence() {
        use crate::native_upstream_error::UpstreamPhase as Phase;
        for (phase, fallback) in [
            (Phase::Read, CacheStaleErrorKind::Read),
            (Phase::Write, CacheStaleErrorKind::Write),
            (Phase::Connect, CacheStaleErrorKind::Connect),
            (Phase::Tls, CacheStaleErrorKind::Tls),
        ] {
            for (kind, reason) in [
                (ErrorKind::Other, fallback),
                (ErrorKind::TimedOut, CacheStaleErrorKind::Timeout),
                (
                    ErrorKind::ConnectionReset,
                    CacheStaleErrorKind::ConnectionClosed,
                ),
                (ErrorKind::BrokenPipe, CacheStaleErrorKind::ConnectionClosed),
                (
                    ErrorKind::UnexpectedEof,
                    CacheStaleErrorKind::ConnectionClosed,
                ),
                (ErrorKind::InvalidData, CacheStaleErrorKind::Protocol),
                (ErrorKind::PermissionDenied, CacheStaleErrorKind::Other),
            ] {
                let error = crate::NativeHttp1Error::Io(Error::new(kind, "secret-canary"))
                    .with_upstream_phase(phase);
                let expected = if phase == Phase::Tls && kind != ErrorKind::TimedOut {
                    CacheStaleErrorKind::Tls
                } else {
                    reason
                };
                assert_eq!(native_cache_stale_error_kind(&error), expected);
                assert!(!error.to_string().contains("secret-canary"));
                let crate::NativeHttp1Error::Io(io) = error else {
                    panic!("wrong variant")
                };
                assert_eq!(io.kind(), kind, "transport retry kind must not change");
            }
        }
    }

    #[test]
    fn stale_phase_metadata_is_not_overwritten_and_h2_reason_is_preserved() {
        use crate::native_upstream_error::UpstreamPhase;
        let tls = crate::NativeHttp1Error::Io(Error::other("opaque"))
            .with_upstream_phase(UpstreamPhase::Tls)
            .with_upstream_phase(UpstreamPhase::Read);
        assert_eq!(
            native_cache_stale_error_kind(&tls),
            CacheStaleErrorKind::Tls
        );
        let h2 = crate::NativeHttp1Error::Io(Error::other("opaque"))
            .with_upstream_failure(UpstreamPhase::Read, ErrorKind::InvalidData);
        assert_eq!(
            native_cache_stale_error_kind(&h2),
            CacheStaleErrorKind::Protocol
        );
        let crate::NativeHttp1Error::Io(io) = h2 else {
            panic!("wrong variant")
        };
        assert_eq!(io.kind(), ErrorKind::Other);
    }

    #[test]
    fn phase_classification_does_not_broaden_stale_allowlists() {
        use crate::native_upstream_error::UpstreamPhase;
        use CacheStaleErrorKind as Kind;
        use fluxheim_cache::{StoredCachePolicy, cache_should_serve_stale};
        let all = [
            Kind::Connect,
            Kind::Timeout,
            Kind::Read,
            Kind::Write,
            Kind::ConnectionClosed,
            Kind::HttpStatus,
            Kind::Protocol,
            Kind::Tls,
            Kind::Other,
        ];
        for (phase, expected) in [
            (UpstreamPhase::Connect, Kind::Connect),
            (UpstreamPhase::Read, Kind::Read),
            (UpstreamPhase::Write, Kind::Write),
            (UpstreamPhase::Tls, Kind::Tls),
        ] {
            let event = native_cache_stale_event_for_error(
                &crate::NativeHttp1Error::Io(Error::other("opaque")).with_upstream_phase(phase),
            );
            for allowed in all {
                let mut cache = fluxheim_config::CacheConfig {
                    stale_if_error_secs: Some(60),
                    stale_if_error_on: vec![allowed],
                    ..Default::default()
                };
                assert_eq!(
                    cache_should_serve_stale(&cache, event, StoredCachePolicy::default()),
                    allowed == expected
                );
                assert!(!cache_should_serve_stale(
                    &cache,
                    event,
                    StoredCachePolicy {
                        stale_reuse_forbidden: true
                    }
                ));
                cache.stale_if_error_secs = None;
                assert!(!cache_should_serve_stale(
                    &cache,
                    event,
                    StoredCachePolicy::default()
                ));
            }
        }
    }
}
