use std::error::Error;

#[cfg(all(feature = "cache", feature = "proxy"))]
use super::cache_common::{CacheKeyPreviewExpectations, validate_cache_key_preview_expectations};

#[cfg(all(feature = "cache", feature = "proxy"))]
#[derive(Clone, Copy)]
pub(super) struct CacheLookupExpectations<'a> {
    pub(super) require_object: bool,
    pub(super) expected_states: &'a [fluxheim_cache::CacheObjectFreshnessState],
    pub(super) expected_statuses: &'a [u16],
    pub(super) expected_tiers: &'a [fluxheim_cache::CacheObjectTier],
    pub(super) expected_fresh_ttl_secs: &'a [u64],
    pub(super) expected_body_bytes: &'a [u64],
    pub(super) expected_header_names: &'a [String],
    pub(super) expected_headers: &'a [(String, String)],
    pub(super) expected_cache_tags: &'a [String],
    pub(super) expected_objects: Option<usize>,
    pub(super) expect_purge_indexed: bool,
    pub(super) expect_ineligible: bool,
    pub(super) expected_reason: Option<&'a str>,
    pub(super) expect_cache_lock_enabled: bool,
    pub(super) expected_cache_lock_wait_timeout_secs: Option<u64>,
    pub(super) expect_cache_predictor_enabled: bool,
    pub(super) expect_origin_protection_enabled: bool,
    pub(super) expected_origin_protection_max_concurrent_fills: Option<usize>,
    pub(super) expect_peer_fill_enabled: bool,
    pub(super) expected_peer_fill_peers: Option<usize>,
    pub(super) expected_peer_fill_max_concurrent_requests: Option<usize>,
    pub(super) expect_memory_tier_enabled: bool,
    pub(super) expect_disk_tier_enabled: bool,
    pub(super) expect_storage_tiers: Option<u8>,
    pub(super) expected_scope: Option<&'a str>,
    pub(super) expected_vhost: Option<&'a str>,
    pub(super) expected_route: Option<&'a str>,
    pub(super) expected_namespace: Option<&'a str>,
    pub(super) expected_key_namespace: Option<&'a str>,
    pub(super) expected_user_tag: Option<&'a str>,
    pub(super) expect_serve_stale_if_error: bool,
    pub(super) expect_serve_stale_while_revalidate: bool,
}

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn validate_cache_lookup_expectations(
    lookup: &fluxheim_cache::CacheObjectLookup,
    expectations: &CacheLookupExpectations<'_>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let CacheLookupExpectations {
        require_object,
        expected_states,
        expected_statuses,
        expected_tiers,
        expected_fresh_ttl_secs,
        expected_body_bytes,
        expected_header_names,
        expected_headers,
        expected_cache_tags,
        expected_objects,
        expect_purge_indexed,
        expect_ineligible,
        expected_reason,
        expect_cache_lock_enabled,
        expected_cache_lock_wait_timeout_secs,
        expect_cache_predictor_enabled,
        expect_origin_protection_enabled,
        expected_origin_protection_max_concurrent_fills,
        expect_peer_fill_enabled,
        expected_peer_fill_peers,
        expected_peer_fill_max_concurrent_requests,
        expect_memory_tier_enabled,
        expect_disk_tier_enabled,
        expect_storage_tiers,
        expected_scope,
        expected_vhost,
        expected_route,
        expected_namespace,
        expected_key_namespace,
        expected_user_tag,
        expect_serve_stale_if_error,
        expect_serve_stale_while_revalidate,
    } = expectations;

    validate_cache_key_preview_expectations(
        &lookup.preview,
        CacheKeyPreviewExpectations {
            expect_eligible: false,
            expect_ineligible: *expect_ineligible,
            expected_reason: *expected_reason,
            expect_cache_lock_enabled: *expect_cache_lock_enabled,
            expected_cache_lock_wait_timeout_secs: *expected_cache_lock_wait_timeout_secs,
            expect_cache_predictor_enabled: *expect_cache_predictor_enabled,
            expect_origin_protection_enabled: *expect_origin_protection_enabled,
            expected_origin_protection_max_concurrent_fills:
                *expected_origin_protection_max_concurrent_fills,
            expect_peer_fill_enabled: *expect_peer_fill_enabled,
            expected_peer_fill_peers: *expected_peer_fill_peers,
            expected_peer_fill_max_concurrent_requests: *expected_peer_fill_max_concurrent_requests,
            expect_memory_tier_enabled: *expect_memory_tier_enabled,
            expect_disk_tier_enabled: *expect_disk_tier_enabled,
            expect_storage_tiers: *expect_storage_tiers,
            expected_scope: *expected_scope,
            expected_vhost: *expected_vhost,
            expected_route: *expected_route,
            expected_namespace: *expected_namespace,
            expected_key_namespace: *expected_key_namespace,
            expected_user_tag: *expected_user_tag,
        },
    )
    .map_err(|error| {
        Box::<dyn Error + Send + Sync>::from(error.to_string().replacen(
            "cache-key expected",
            "cache-lookup expected",
            1,
        ))
    })?;

    if *require_object && lookup.objects.is_empty() {
        return Err("cache-lookup expected at least one cached object, found none".into());
    }
    if let Some(expected_objects) = expected_objects
        && lookup.objects.len() != *expected_objects
    {
        return Err(format!(
            "cache-lookup expected {expected_objects} cached objects, found {}",
            lookup.objects.len()
        )
        .into());
    }
    if !expected_states.is_empty() {
        validate_cache_lookup_contains_state(lookup, expected_states)?;
    }
    if !expected_statuses.is_empty() {
        validate_cache_lookup_contains_status(lookup, expected_statuses)?;
    }
    if !expected_tiers.is_empty() {
        validate_cache_lookup_contains_tier(lookup, expected_tiers)?;
    }
    if !expected_fresh_ttl_secs.is_empty() {
        validate_cache_lookup_contains_fresh_ttl(lookup, expected_fresh_ttl_secs)?;
    }
    if !expected_body_bytes.is_empty() {
        validate_cache_lookup_contains_body_bytes(lookup, expected_body_bytes)?;
    }
    for expected in *expected_header_names {
        let matched = lookup.objects.iter().any(|object| {
            object
                .header_names
                .iter()
                .any(|header| header.eq_ignore_ascii_case(expected))
        });
        if !matched {
            let found = fluxheim_cache::cache_object_lookup_header_names_summary(lookup);
            return Err(format!(
                "cache-lookup expected stored header name {expected}, found {found}"
            )
            .into());
        }
    }
    for (expected_name, expected_value) in *expected_headers {
        let matched = lookup.objects.iter().any(|object| {
            object.header_values.iter().any(|header| {
                header.name.eq_ignore_ascii_case(expected_name) && header.value == *expected_value
            })
        });
        if !matched {
            let found =
                fluxheim_cache::cache_object_lookup_header_values_summary(lookup, expected_name);
            return Err(format!(
                "cache-lookup expected stored header {expected_name}: {expected_value}, found {found}"
            )
            .into());
        }
    }
    for expected in *expected_cache_tags {
        let matched = lookup.objects.iter().any(|object| {
            object
                .cache_tags
                .iter()
                .any(|cache_tag| cache_tag == expected)
        });
        if !matched {
            let found = fluxheim_cache::cache_object_lookup_cache_tags_summary(lookup);
            return Err(
                format!("cache-lookup expected cache tag {expected}, found {found}").into(),
            );
        }
    }
    if *expect_purge_indexed && !lookup.objects.iter().any(|object| object.purge_indexed) {
        return Err("cache-lookup expected at least one purge-indexed object, found none".into());
    }
    if *expect_serve_stale_if_error
        && !lookup
            .objects
            .iter()
            .any(|object| object.serve_stale_if_error)
    {
        let found = fluxheim_cache::cache_object_lookup_bool_summary(lookup, |object| {
            object.serve_stale_if_error
        });
        return Err(
            format!("cache-lookup expected stale-if-error eligible object, found {found}").into(),
        );
    }
    if *expect_serve_stale_while_revalidate
        && !lookup
            .objects
            .iter()
            .any(|object| object.serve_stale_while_revalidate)
    {
        let found = fluxheim_cache::cache_object_lookup_bool_summary(lookup, |object| {
            object.serve_stale_while_revalidate
        });
        return Err(format!(
            "cache-lookup expected stale-while-revalidate eligible object, found {found}"
        )
        .into());
    }
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn validate_cache_lookup_contains_state(
    lookup: &fluxheim_cache::CacheObjectLookup,
    expected_states: &[fluxheim_cache::CacheObjectFreshnessState],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let matched = lookup
        .objects
        .iter()
        .any(|object| expected_states.contains(&object.freshness_state));
    if matched {
        return Ok(());
    }
    let expected = expected_states
        .iter()
        .map(|state| state.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let found = if lookup.objects.is_empty() {
        "none".to_owned()
    } else {
        lookup
            .objects
            .iter()
            .map(|object| object.freshness_state.as_str())
            .collect::<Vec<_>>()
            .join(",")
    };
    Err(format!("cache-lookup expected freshness state {expected}, found {found}").into())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn validate_cache_lookup_contains_status(
    lookup: &fluxheim_cache::CacheObjectLookup,
    expected_statuses: &[u16],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let matched = lookup
        .objects
        .iter()
        .any(|object| expected_statuses.contains(&object.status));
    if matched {
        return Ok(());
    }
    let expected = expected_statuses
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let found = if lookup.objects.is_empty() {
        "none".to_owned()
    } else {
        lookup
            .objects
            .iter()
            .map(|object| object.status.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    Err(format!("cache-lookup expected status {expected}, found {found}").into())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn validate_cache_lookup_contains_tier(
    lookup: &fluxheim_cache::CacheObjectLookup,
    expected_tiers: &[fluxheim_cache::CacheObjectTier],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let matched = lookup
        .objects
        .iter()
        .any(|object| expected_tiers.contains(&object.tier));
    if matched {
        return Ok(());
    }
    let expected = expected_tiers
        .iter()
        .map(|tier| tier.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let found = if lookup.objects.is_empty() {
        "none".to_owned()
    } else {
        lookup
            .objects
            .iter()
            .map(|object| object.tier.as_str())
            .collect::<Vec<_>>()
            .join(",")
    };
    Err(format!("cache-lookup expected tier {expected}, found {found}").into())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn validate_cache_lookup_contains_fresh_ttl(
    lookup: &fluxheim_cache::CacheObjectLookup,
    expected_fresh_ttl_secs: &[u64],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let matched = lookup
        .objects
        .iter()
        .any(|object| expected_fresh_ttl_secs.contains(&object.fresh_ttl_secs));
    if matched {
        return Ok(());
    }
    let expected = expected_fresh_ttl_secs
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let found = fluxheim_cache::cache_object_lookup_fresh_ttl_summary(lookup);
    Err(format!("cache-lookup expected fresh TTL seconds {expected}, found {found}").into())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn validate_cache_lookup_contains_body_bytes(
    lookup: &fluxheim_cache::CacheObjectLookup,
    expected_body_bytes: &[u64],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let matched = lookup
        .objects
        .iter()
        .any(|object| expected_body_bytes.contains(&object.body_bytes));
    if matched {
        return Ok(());
    }
    let expected = expected_body_bytes
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let found = fluxheim_cache::cache_object_lookup_body_bytes_summary(lookup);
    Err(format!("cache-lookup expected body bytes {expected}, found {found}").into())
}
