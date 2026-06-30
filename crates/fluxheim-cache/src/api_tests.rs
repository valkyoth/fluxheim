use crate::api::{
    CacheKeyPreview, CacheKeyPreviewScope, CacheObjectFreshnessState, CacheObjectHeaderValue,
    CacheObjectLookup, CacheObjectMetadata, CacheObjectTier, cache_average_bytes,
    cache_object_lookup_body_bytes_summary, cache_object_lookup_bool_summary,
    cache_object_lookup_cache_tags_summary, cache_object_lookup_fresh_ttl_summary,
    cache_object_lookup_header_names_summary, cache_object_lookup_header_values_summary,
    cache_ratio_per_mille, cache_ratio_per_mille_usize, cache_stale_would_purge,
    cache_storage_tiers, cache_warm_counts_summary, cache_warm_increment_count,
    cache_warm_safe_label,
};

#[test]
fn cache_admin_math_handles_zero_denominators_and_saturation() {
    assert_eq!(cache_ratio_per_mille(5, 10), 500);
    assert_eq!(cache_ratio_per_mille(5, 0), 0);
    assert_eq!(cache_ratio_per_mille(u64::MAX, 1), u64::MAX);
    assert_eq!(cache_ratio_per_mille_usize(1, 4), 250);
    assert_eq!(cache_average_bytes(100, 4), 25);
    assert_eq!(cache_average_bytes(100, 0), 0);
}

#[test]
fn cache_admin_policy_helpers_report_tiers_and_dry_run_counts() {
    assert_eq!(cache_storage_tiers(false, false), 0);
    assert_eq!(cache_storage_tiers(true, false), 1);
    assert_eq!(cache_storage_tiers(false, true), 1);
    assert_eq!(cache_storage_tiers(true, true), 2);
    assert_eq!(cache_stale_would_purge(true, 7), 7);
    assert_eq!(cache_stale_would_purge(false, 7), 0);
}

#[test]
fn cache_warm_summaries_are_stable_and_bounded() {
    let empty = std::collections::BTreeMap::<String, usize>::new();
    assert_eq!(cache_warm_counts_summary(&empty), None);

    let mut counts = std::collections::BTreeMap::new();
    cache_warm_increment_count(&mut counts, "unexpected_status".to_owned());
    cache_warm_increment_count(&mut counts, "unexpected_status".to_owned());
    cache_warm_increment_count(&mut counts, "request_error".to_owned());
    cache_warm_increment_count(&mut counts, "unexpected_cache_status".to_owned());
    cache_warm_increment_count(&mut counts, "unexpected_cache_status".to_owned());
    cache_warm_increment_count(&mut counts, "unexpected_cache_status".to_owned());

    assert_eq!(
        cache_warm_counts_summary(&counts).as_deref(),
        Some("request_error=1 unexpected_cache_status=3 unexpected_status=2")
    );
    assert_eq!(cache_warm_safe_label(Some("HIT")), "HIT");
    assert_eq!(cache_warm_safe_label(None), "-");
    assert_eq!(cache_warm_safe_label(Some("bad value")), "other");
    assert_eq!(cache_warm_safe_label(Some("bad=value")), "other");
}

#[test]
fn cache_object_lookup_summaries_are_stable_and_bounded() {
    let lookup = CacheObjectLookup {
        preview: CacheKeyPreview {
            vhost: "cache.test".to_owned(),
            route: None,
            scope: CacheKeyPreviewScope::Vhost,
            eligible: true,
            cache_lock_enabled: true,
            cache_lock_wait_timeout_secs: 30,
            cache_predictor_enabled: true,
            origin_protection_enabled: false,
            origin_protection_max_concurrent_fills: 32,
            peer_fill_enabled: false,
            peer_fill_peer_count: 0,
            peer_fill_max_concurrent_requests: 64,
            peer_fill_fail_open: true,
            memory_tier_enabled: true,
            disk_tier_enabled: true,
            storage_tiers: 2,
            reason: None,
            namespace: None,
            key_namespace: None,
            primary_key: None,
            primary_hash: None,
            variance_hash: None,
            combined_hash: None,
            user_tag: None,
        },
        objects: vec![
            CacheObjectMetadata {
                tier: CacheObjectTier::Memory,
                purge_indexed: true,
                status: 200,
                fresh: true,
                freshness_state: CacheObjectFreshnessState::Fresh,
                serve_stale_while_revalidate: false,
                serve_stale_if_error: true,
                body_bytes: 42,
                weight_bytes: 64,
                created_unix_secs: None,
                updated_unix_secs: None,
                fresh_until_unix_secs: None,
                age_secs: 0,
                fresh_ttl_secs: 120,
                stale_while_revalidate_secs: 0,
                stale_if_error_secs: 60,
                cache_tags: vec!["asset".to_owned(), "shared".to_owned()],
                header_names: vec!["cache-control".to_owned(), "etag".to_owned()],
                header_values: vec![
                    CacheObjectHeaderValue {
                        name: "etag".to_owned(),
                        value: "\"a\"".to_owned(),
                    },
                    CacheObjectHeaderValue {
                        name: "x-other".to_owned(),
                        value: "ignored".to_owned(),
                    },
                ],
            },
            CacheObjectMetadata {
                tier: CacheObjectTier::Disk,
                purge_indexed: false,
                status: 200,
                fresh: true,
                freshness_state: CacheObjectFreshnessState::Fresh,
                serve_stale_while_revalidate: false,
                serve_stale_if_error: false,
                body_bytes: 42,
                weight_bytes: 64,
                created_unix_secs: None,
                updated_unix_secs: None,
                fresh_until_unix_secs: None,
                age_secs: 0,
                fresh_ttl_secs: 60,
                stale_while_revalidate_secs: 0,
                stale_if_error_secs: 60,
                cache_tags: vec!["asset".to_owned()],
                header_names: vec!["etag".to_owned()],
                header_values: vec![CacheObjectHeaderValue {
                    name: "ETag".to_owned(),
                    value: "\"b\"".to_owned(),
                }],
            },
        ],
    };

    assert_eq!(
        cache_object_lookup_bool_summary(&lookup, |object| object.serve_stale_if_error),
        "false,true"
    );
    assert_eq!(cache_object_lookup_fresh_ttl_summary(&lookup), "120,60");
    assert_eq!(cache_object_lookup_body_bytes_summary(&lookup), "42");
    assert_eq!(
        cache_object_lookup_header_names_summary(&lookup),
        "cache-control,etag"
    );
    assert_eq!(
        cache_object_lookup_header_values_summary(&lookup, "etag"),
        "etag: \"a\",etag: \"b\""
    );
    assert_eq!(
        cache_object_lookup_cache_tags_summary(&lookup),
        "asset,shared"
    );
}
