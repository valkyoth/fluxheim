use std::error::Error;

use super::CacheKeyOptions;

#[cfg(all(feature = "cache", feature = "proxy"))]
use super::cache_common::{
    CacheKeyPreviewExpectations, cache_key_command_request, parse_cache_key_preview_name,
    parse_cache_key_preview_reason, parse_cache_key_preview_route, parse_cache_key_preview_scope,
    parse_cache_key_preview_value, validate_cache_key_preview_expectations,
    validate_cache_lookup_expected_storage_tiers,
};

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn run_cache_key_command(
    options: CacheKeyOptions<'_>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    validate_cache_lookup_expected_storage_tiers(options.expect_storage_tiers)?;
    let expected_scope = parse_cache_key_preview_scope("cache-key", options.expect_scope.as_ref())?;
    let expected_vhost =
        parse_cache_key_preview_name("cache-key", "--expect-vhost", options.expect_vhost.as_ref())?;
    let expected_route = parse_cache_key_preview_route("cache-key", options.expect_route.as_ref())?;
    let expected_namespace = parse_cache_key_preview_value(
        "cache-key",
        "--expect-namespace",
        options.expect_namespace.as_ref(),
    )?;
    let expected_key_namespace = parse_cache_key_preview_value(
        "cache-key",
        "--expect-key-namespace",
        options.expect_key_namespace.as_ref(),
    )?;
    let expected_user_tag = parse_cache_key_preview_value(
        "cache-key",
        "--expect-user-tag",
        options.expect_user_tag.as_ref(),
    )?;
    let expected_reason = parse_cache_key_preview_reason(
        "cache-key",
        "--expect-reason",
        options.expect_reason.as_ref(),
    )?;
    let (config, request) = cache_key_command_request(&options)?;
    let proxy = crate::native_proxy::FluxProxy::from_config(&config)?;
    let preview = proxy
        .snapshot()
        .native_image_cache_key_preview_for_request(&request);
    validate_cache_key_preview_expectations(
        &preview,
        CacheKeyPreviewExpectations {
            expect_eligible: options.expect_eligible,
            expect_ineligible: options.expect_ineligible,
            expected_reason: expected_reason.as_deref(),
            expect_cache_lock_enabled: options.expect_cache_lock_enabled,
            expected_cache_lock_wait_timeout_secs: options.expect_cache_lock_wait_timeout_secs,
            expect_cache_predictor_enabled: options.expect_cache_predictor_enabled,
            expect_origin_protection_enabled: options.expect_origin_protection_enabled,
            expected_origin_protection_max_concurrent_fills: options
                .expect_origin_protection_max_concurrent_fills,
            expect_peer_fill_enabled: options.expect_peer_fill_enabled,
            expected_peer_fill_peers: options.expect_peer_fill_peers,
            expected_peer_fill_max_concurrent_requests: options
                .expect_peer_fill_max_concurrent_requests,
            expect_memory_tier_enabled: options.expect_memory_tier_enabled,
            expect_disk_tier_enabled: options.expect_disk_tier_enabled,
            expect_storage_tiers: options.expect_storage_tiers,
            expected_scope: expected_scope.as_deref(),
            expected_vhost: expected_vhost.as_deref(),
            expected_route: expected_route.as_deref(),
            expected_namespace: expected_namespace.as_deref(),
            expected_key_namespace: expected_key_namespace.as_deref(),
            expected_user_tag: expected_user_tag.as_deref(),
        },
    )?;

    println!("cache key preview:");
    println!("vhost: {}", preview.vhost);
    println!("scope: {}", preview.scope.as_str());
    if let Some(route) = preview.route.as_deref() {
        println!("route: {route}");
    }
    println!("eligible: {}", preview.eligible);
    println!("cache_lock_enabled: {}", preview.cache_lock_enabled);
    println!(
        "cache_lock_wait_timeout_secs: {}",
        preview.cache_lock_wait_timeout_secs
    );
    println!(
        "cache_predictor_enabled: {}",
        preview.cache_predictor_enabled
    );
    println!(
        "origin_protection_enabled: {}",
        preview.origin_protection_enabled
    );
    println!(
        "origin_protection_max_concurrent_fills: {}",
        preview.origin_protection_max_concurrent_fills
    );
    println!("peer_fill_enabled: {}", preview.peer_fill_enabled);
    println!("peer_fill_peers: {}", preview.peer_fill_peer_count);
    println!(
        "peer_fill_max_concurrent_requests: {}",
        preview.peer_fill_max_concurrent_requests
    );
    println!("peer_fill_fail_open: {}", preview.peer_fill_fail_open);
    println!("memory_tier_enabled: {}", preview.memory_tier_enabled);
    println!("disk_tier_enabled: {}", preview.disk_tier_enabled);
    println!("storage_tiers: {}", preview.storage_tiers);
    if let Some(reason) = preview.reason.as_deref() {
        println!("reason: {reason}");
    }
    if let Some(namespace) = preview.namespace.as_deref() {
        println!("namespace: {namespace}");
    }
    if let Some(key_namespace) = preview.key_namespace.as_deref() {
        println!("key_namespace: {key_namespace}");
    }
    if let Some(primary_key) = preview.primary_key.as_deref() {
        println!("primary_key: {primary_key}");
    }
    if let Some(primary_hash) = preview.primary_hash.as_deref() {
        println!("primary_hash: {primary_hash}");
    }
    if let Some(variance_hash) = preview.variance_hash.as_deref() {
        println!("variance_hash: {variance_hash}");
    }
    if let Some(combined_hash) = preview.combined_hash.as_deref() {
        println!("combined_hash: {combined_hash}");
    }
    if let Some(user_tag) = preview.user_tag.as_deref() {
        println!("user_tag: {user_tag}");
    }

    Ok(())
}

#[cfg(not(all(feature = "cache", feature = "proxy")))]
pub(super) fn run_cache_key_command(
    options: CacheKeyOptions<'_>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let CacheKeyOptions {
        config_path,
        host,
        headers,
        method,
        path,
        query,
        expect_eligible,
        expect_ineligible,
        expect_reason,
        expect_cache_lock_enabled,
        expect_cache_lock_wait_timeout_secs,
        expect_cache_predictor_enabled,
        expect_origin_protection_enabled,
        expect_origin_protection_max_concurrent_fills,
        expect_memory_tier_enabled,
        expect_disk_tier_enabled,
        expect_storage_tiers,
        expect_scope,
        expect_vhost,
        expect_route,
        expect_namespace,
        expect_key_namespace,
        expect_user_tag,
        expect_peer_fill_enabled,
        expect_peer_fill_peers,
        expect_peer_fill_max_concurrent_requests,
    } = options;
    let _ = (
        config_path,
        host,
        headers,
        method,
        path,
        query,
        expect_eligible,
        expect_ineligible,
        expect_reason,
        expect_cache_lock_enabled,
        expect_cache_lock_wait_timeout_secs,
        expect_cache_predictor_enabled,
        expect_origin_protection_enabled,
        expect_origin_protection_max_concurrent_fills,
        expect_memory_tier_enabled,
        expect_disk_tier_enabled,
        expect_storage_tiers,
        expect_scope,
        expect_vhost,
        expect_route,
        expect_namespace,
        expect_key_namespace,
        expect_user_tag,
        expect_peer_fill_enabled,
        expect_peer_fill_peers,
        expect_peer_fill_max_concurrent_requests,
    );
    Err("cache-key requires the proxy and cache features".into())
}
