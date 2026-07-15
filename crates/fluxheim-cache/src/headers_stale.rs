#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheStaleEvent {
    Updating,
    UpstreamError(fluxheim_config::CacheStaleErrorKind),
    UpstreamHttpStatus(u16),
    OtherError,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StoredCachePolicy {
    pub stale_reuse_forbidden: bool,
}

pub fn cache_should_serve_stale(
    cache: &fluxheim_config::CacheConfig,
    event: CacheStaleEvent,
    policy: StoredCachePolicy,
) -> bool {
    if policy.stale_reuse_forbidden {
        return false;
    }
    match event {
        CacheStaleEvent::UpstreamError(kind) => {
            cache.stale_if_error_secs.is_some() && cache.stale_if_error_on.contains(&kind)
        }
        CacheStaleEvent::UpstreamHttpStatus(status) => {
            cache.stale_if_error_secs.is_some()
                && cache
                    .stale_if_error_on
                    .contains(&fluxheim_config::CacheStaleErrorKind::HttpStatus)
                && cache_stale_status_allows(cache, status)
        }
        CacheStaleEvent::OtherError => false,
        CacheStaleEvent::Updating => cache.stale_while_revalidate_secs.is_some(),
    }
}

pub fn cache_stale_status_allows(cache: &fluxheim_config::CacheConfig, status: u16) -> bool {
    (500..=599).contains(&status)
        && (cache.stale_if_error_statuses.is_empty()
            || cache.stale_if_error_statuses.contains(&status))
}
