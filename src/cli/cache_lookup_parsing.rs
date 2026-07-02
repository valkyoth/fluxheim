use std::error::Error;

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn parse_cache_lookup_freshness_states(
    states: &[String],
) -> Result<Vec<fluxheim_cache::CacheObjectFreshnessState>, Box<dyn Error + Send + Sync>> {
    states
        .iter()
        .map(|state| match state.trim().to_ascii_lowercase().as_str() {
            "fresh" => Ok(fluxheim_cache::CacheObjectFreshnessState::Fresh),
            "stale" => Ok(fluxheim_cache::CacheObjectFreshnessState::Stale),
            "expired" => Ok(fluxheim_cache::CacheObjectFreshnessState::Expired),
            other => Err(format!(
                "cache-lookup --expect-freshness-state must be fresh, stale, or expired; got {other:?}"
            )
            .into()),
        })
        .collect()
}

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn parse_cache_lookup_tiers(
    tiers: &[String],
) -> Result<Vec<fluxheim_cache::CacheObjectTier>, Box<dyn Error + Send + Sync>> {
    tiers
        .iter()
        .map(|tier| match tier.trim().to_ascii_lowercase().as_str() {
            "memory" => Ok(fluxheim_cache::CacheObjectTier::Memory),
            "disk" => Ok(fluxheim_cache::CacheObjectTier::Disk),
            other => Err(format!(
                "cache-lookup --expect-tier must be memory or disk; got {other:?}"
            )
            .into()),
        })
        .collect()
}

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn parse_cache_lookup_header_names(
    names: &[String],
) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    if names.len() > 32 {
        return Err("cache-lookup accepts at most 32 --expect-header-name values".into());
    }

    names
        .iter()
        .map(|name| {
            let name = name.trim();
            if name.is_empty() || name.len() > 64 || !fluxheim_protocol::http_token_valid(name) {
                return Err(format!(
                    "cache-lookup --expect-header-name must be a valid HTTP header name, got {name:?}"
                )
                .into());
            }
            Ok(name.to_ascii_lowercase())
        })
        .collect()
}

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn parse_cache_lookup_headers(
    headers: &[String],
) -> Result<Vec<(String, String)>, Box<dyn Error + Send + Sync>> {
    if headers.len() > 32 {
        return Err("cache-lookup accepts at most 32 --expect-header values".into());
    }
    headers
        .iter()
        .map(|header| parse_cache_lookup_header(header))
        .collect()
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn parse_cache_lookup_header(
    header: &str,
) -> Result<(String, String), Box<dyn Error + Send + Sync>> {
    if header.len() > 8192 {
        return Err("cache-lookup --expect-header must be at most 8192 bytes".into());
    }
    let (name, value) = header
        .split_once(':')
        .ok_or("cache-lookup --expect-header must use \"Name: value\" syntax")?;
    let name = name.trim();
    if name.is_empty() || name.len() > 64 || !fluxheim_protocol::http_token_valid(name) {
        return Err("cache-lookup --expect-header name must be a valid HTTP header name".into());
    }
    let value = value.trim();
    if value.len() > 8192 {
        return Err("cache-lookup --expect-header value must be at most 8192 bytes".into());
    }
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err("cache-lookup --expect-header value must not contain control bytes".into());
    }
    Ok((name.to_ascii_lowercase(), value.to_owned()))
}

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn parse_cache_lookup_cache_tags(
    tags: &[String],
) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    if tags.len() > 32 {
        return Err("cache-lookup accepts at most 32 --expect-cache-tag values".into());
    }

    tags.iter()
        .map(|tag| {
            let tag = tag.trim();
            if !is_cache_lookup_tag(tag) {
                return Err(format!(
                    "cache-lookup --expect-cache-tag must be a valid cache tag, got {tag:?}"
                )
                .into());
            }
            Ok(tag.to_owned())
        })
        .collect()
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn is_cache_lookup_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 128
        && tag.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/' | b'=')
        })
}

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn validate_cache_lookup_expected_statuses(
    statuses: &[u16],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    for status in statuses {
        if !(100..=599).contains(status) {
            return Err(format!(
                "cache-lookup --expect-status must be an HTTP status code, got {status}"
            )
            .into());
        }
    }
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn validate_cache_lookup_expected_fresh_ttls(
    ttls: &[u64],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if ttls.len() > 32 {
        return Err("cache-lookup accepts at most 32 --expect-fresh-ttl-secs values".into());
    }
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn validate_cache_lookup_expected_body_bytes(
    sizes: &[u64],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if sizes.len() > 32 {
        return Err("cache-lookup accepts at most 32 --expect-body-bytes values".into());
    }
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn validate_cache_lookup_expected_objects(
    objects: Option<usize>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Some(objects) = objects
        && objects > 2
    {
        return Err(
            format!("cache-lookup --expect-objects must be 0, 1, or 2; got {objects}").into(),
        );
    }
    Ok(())
}
