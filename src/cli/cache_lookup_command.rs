use std::error::Error;

#[cfg(all(feature = "cache", feature = "proxy"))]
use super::command_options::CacheKeyOptions;
use super::command_options::CacheLookupOptions;

#[cfg(all(feature = "cache", feature = "proxy"))]
use super::{
    cache_common::{
        cache_key_command_request, parse_cache_key_preview_name, parse_cache_key_preview_reason,
        parse_cache_key_preview_route, parse_cache_key_preview_scope,
        parse_cache_key_preview_value, print_optional_unix,
        validate_cache_lookup_expected_storage_tiers,
    },
    cache_lookup_expectations::{CacheLookupExpectations, validate_cache_lookup_expectations},
    cache_lookup_parsing::{
        parse_cache_lookup_cache_tags, parse_cache_lookup_freshness_states,
        parse_cache_lookup_header_names, parse_cache_lookup_headers, parse_cache_lookup_tiers,
        validate_cache_lookup_expected_body_bytes, validate_cache_lookup_expected_fresh_ttls,
        validate_cache_lookup_expected_objects, validate_cache_lookup_expected_statuses,
    },
};

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn run_cache_lookup_command(
    options: CacheLookupOptions<'_>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let cache_key_options = CacheKeyOptions {
        config_path: options.config_path,
        host: options.host,
        headers: options.headers,
        method: options.method,
        path: options.path,
        query: options.query,
        expect_eligible: false,
        expect_ineligible: false,
        expect_reason: None,
        expect_cache_lock_enabled: false,
        expect_cache_lock_wait_timeout_secs: None,
        expect_cache_predictor_enabled: false,
        expect_origin_protection_enabled: false,
        expect_origin_protection_max_concurrent_fills: None,
        expect_peer_fill_enabled: false,
        expect_peer_fill_peers: None,
        expect_peer_fill_max_concurrent_requests: None,
        expect_memory_tier_enabled: false,
        expect_disk_tier_enabled: false,
        expect_storage_tiers: None,
        expect_scope: None,
        expect_vhost: None,
        expect_route: None,
        expect_namespace: None,
        expect_key_namespace: None,
        expect_user_tag: None,
    };
    let require_object = options.require_object;
    let expected_states = parse_cache_lookup_freshness_states(&options.expect_freshness_states)?;
    let expected_tiers = parse_cache_lookup_tiers(&options.expect_tiers)?;
    let expected_header_names = parse_cache_lookup_header_names(&options.expect_header_names)?;
    let expected_headers = parse_cache_lookup_headers(&options.expect_headers)?;
    let expected_cache_tags = parse_cache_lookup_cache_tags(&options.expect_cache_tags)?;
    let expected_scope =
        parse_cache_key_preview_scope("cache-lookup", options.expect_scope.as_ref())?;
    let expected_vhost = parse_cache_key_preview_name(
        "cache-lookup",
        "--expect-vhost",
        options.expect_vhost.as_ref(),
    )?;
    let expected_route =
        parse_cache_key_preview_route("cache-lookup", options.expect_route.as_ref())?;
    let expected_namespace = parse_cache_key_preview_value(
        "cache-lookup",
        "--expect-namespace",
        options.expect_namespace.as_ref(),
    )?;
    let expected_key_namespace = parse_cache_key_preview_value(
        "cache-lookup",
        "--expect-key-namespace",
        options.expect_key_namespace.as_ref(),
    )?;
    let expected_user_tag = parse_cache_key_preview_value(
        "cache-lookup",
        "--expect-user-tag",
        options.expect_user_tag.as_ref(),
    )?;
    let expected_reason = parse_cache_key_preview_reason(
        "cache-lookup",
        "--expect-reason",
        options.expect_reason.as_ref(),
    )?;
    validate_cache_lookup_expected_statuses(&options.expect_statuses)?;
    validate_cache_lookup_expected_fresh_ttls(&options.expect_fresh_ttl_secs)?;
    validate_cache_lookup_expected_body_bytes(&options.expect_body_bytes)?;
    validate_cache_lookup_expected_objects(options.expect_objects)?;
    validate_cache_lookup_expected_storage_tiers(options.expect_storage_tiers)?;
    let (config, request) = cache_key_command_request(&cache_key_options)?;
    let proxy = crate::native_proxy::FluxProxy::from_config(&config)?;
    let lookup = proxy
        .snapshot()
        .native_image_cache_object_lookup_for_request(&request)?;
    let expectations = CacheLookupExpectations {
        require_object,
        expected_states: &expected_states,
        expected_statuses: &options.expect_statuses,
        expected_tiers: &expected_tiers,
        expected_fresh_ttl_secs: &options.expect_fresh_ttl_secs,
        expected_body_bytes: &options.expect_body_bytes,
        expected_header_names: &expected_header_names,
        expected_headers: &expected_headers,
        expected_cache_tags: &expected_cache_tags,
        expected_objects: options.expect_objects,
        expect_purge_indexed: options.expect_purge_indexed,
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
        expect_serve_stale_if_error: options.expect_serve_stale_if_error,
        expect_serve_stale_while_revalidate: options.expect_serve_stale_while_revalidate,
    };
    validate_cache_lookup_expectations(&lookup, &expectations)?;
    print_cache_lookup(&lookup);
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn print_cache_lookup(lookup: &fluxheim_cache::CacheObjectLookup) {
    println!("cache object lookup:");
    println!("vhost: {}", lookup.preview.vhost);
    println!("scope: {}", lookup.preview.scope.as_str());
    if let Some(route) = lookup.preview.route.as_deref() {
        println!("route: {route}");
    }
    println!("eligible: {}", lookup.preview.eligible);
    println!("cache_lock_enabled: {}", lookup.preview.cache_lock_enabled);
    println!(
        "cache_lock_wait_timeout_secs: {}",
        lookup.preview.cache_lock_wait_timeout_secs
    );
    println!(
        "cache_predictor_enabled: {}",
        lookup.preview.cache_predictor_enabled
    );
    println!(
        "origin_protection_enabled: {}",
        lookup.preview.origin_protection_enabled
    );
    println!(
        "origin_protection_max_concurrent_fills: {}",
        lookup.preview.origin_protection_max_concurrent_fills
    );
    println!("peer_fill_enabled: {}", lookup.preview.peer_fill_enabled);
    println!("peer_fill_peers: {}", lookup.preview.peer_fill_peer_count);
    println!(
        "peer_fill_max_concurrent_requests: {}",
        lookup.preview.peer_fill_max_concurrent_requests
    );
    println!(
        "peer_fill_fail_open: {}",
        lookup.preview.peer_fill_fail_open
    );
    println!(
        "memory_tier_enabled: {}",
        lookup.preview.memory_tier_enabled
    );
    println!("disk_tier_enabled: {}", lookup.preview.disk_tier_enabled);
    println!("storage_tiers: {}", lookup.preview.storage_tiers);
    if let Some(reason) = lookup.preview.reason.as_deref() {
        println!("reason: {reason}");
    }
    if let Some(combined_hash) = lookup.preview.combined_hash.as_deref() {
        println!("combined_hash: {combined_hash}");
    }
    if let Some(namespace) = lookup.preview.namespace.as_deref() {
        println!("namespace: {namespace}");
    }
    if let Some(key_namespace) = lookup.preview.key_namespace.as_deref() {
        println!("key_namespace: {key_namespace}");
    }
    if let Some(user_tag) = lookup.preview.user_tag.as_deref() {
        println!("user_tag: {user_tag}");
    }
    println!("objects: {}", lookup.objects.len());
    for object in &lookup.objects {
        println!("object:");
        println!("  tier: {}", object.tier.as_str());
        println!("  purge_indexed: {}", object.purge_indexed);
        println!("  status: {}", object.status);
        println!("  fresh: {}", object.fresh);
        println!("  freshness_state: {}", object.freshness_state.as_str());
        println!(
            "  serve_stale_while_revalidate: {}",
            object.serve_stale_while_revalidate
        );
        println!("  serve_stale_if_error: {}", object.serve_stale_if_error);
        println!("  body_bytes: {}", object.body_bytes);
        println!("  weight_bytes: {}", object.weight_bytes);
        print_optional_unix("  created_unix_secs", object.created_unix_secs);
        print_optional_unix("  updated_unix_secs", object.updated_unix_secs);
        print_optional_unix("  fresh_until_unix_secs", object.fresh_until_unix_secs);
        println!("  age_secs: {}", object.age_secs);
        println!("  fresh_ttl_secs: {}", object.fresh_ttl_secs);
        println!(
            "  stale_while_revalidate_secs: {}",
            object.stale_while_revalidate_secs
        );
        println!("  stale_if_error_secs: {}", object.stale_if_error_secs);
        println!("  cache_tags: {}", object.cache_tags.join(","));
        println!("  header_names: {}", object.header_names.join(","));
    }
}

#[cfg(not(all(feature = "cache", feature = "proxy")))]
pub(super) fn run_cache_lookup_command(
    options: CacheLookupOptions<'_>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let CacheLookupOptions {
        config_path,
        host,
        headers,
        method,
        path,
        query,
        require_object,
        expect_objects,
        expect_ineligible,
        expect_reason,
        expect_freshness_states,
        expect_statuses,
        expect_tiers,
        expect_fresh_ttl_secs,
        expect_body_bytes,
        expect_header_names,
        expect_headers,
        expect_cache_tags,
        expect_purge_indexed,
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
        expect_serve_stale_if_error,
        expect_serve_stale_while_revalidate,
        expect_peer_fill_enabled,
        expect_peer_fill_peers,
        expect_peer_fill_max_concurrent_requests,
    } = options;
    let _ = (config_path, host, headers, method, path, query);
    let _ = (
        require_object,
        expect_objects,
        expect_ineligible,
        expect_reason,
        expect_freshness_states,
        expect_statuses,
        expect_tiers,
        expect_fresh_ttl_secs,
        expect_body_bytes,
        expect_header_names,
        expect_headers,
        expect_cache_tags,
        expect_purge_indexed,
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
        expect_serve_stale_if_error,
        expect_serve_stale_while_revalidate,
        expect_peer_fill_enabled,
        expect_peer_fill_peers,
        expect_peer_fill_max_concurrent_requests,
    );
    Err("cache-lookup requires the proxy and cache features".into())
}
