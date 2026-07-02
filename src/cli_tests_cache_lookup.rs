#[cfg(all(feature = "cache", feature = "proxy"))]
use super::*;
#[cfg(all(feature = "cache", feature = "proxy"))]
#[test]
fn cache_lookup_expectations_validate_object_and_freshness_state() {
    let lookup = cache_lookup_with_state(fluxheim_cache::CacheObjectFreshnessState::Stale);
    let states =
        super::super::parse_cache_lookup_freshness_states(&[" Stale ".to_owned()]).unwrap();
    let tiers = super::super::parse_cache_lookup_tiers(&[" Memory ".to_owned()]).unwrap();
    let no_states = &[] as &[fluxheim_cache::CacheObjectFreshnessState];
    let no_statuses = &[] as &[u16];
    let no_tiers = &[] as &[fluxheim_cache::CacheObjectTier];
    let no_ttls = &[] as &[u64];
    let no_strings = &[] as &[String];
    let no_headers = &[] as &[(String, String)];
    let default_expectations = super::super::CacheLookupExpectations {
        require_object: false,
        expected_states: no_states,
        expected_statuses: no_statuses,
        expected_tiers: no_tiers,
        expected_fresh_ttl_secs: no_ttls,
        expected_body_bytes: no_ttls,
        expected_header_names: no_strings,
        expected_headers: no_headers,
        expected_cache_tags: no_strings,
        expected_objects: None,
        expect_purge_indexed: false,
        expect_ineligible: false,
        expected_reason: None,
        expect_cache_lock_enabled: false,
        expected_cache_lock_wait_timeout_secs: None,
        expect_cache_predictor_enabled: false,
        expect_origin_protection_enabled: false,
        expected_origin_protection_max_concurrent_fills: None,
        expect_peer_fill_enabled: false,
        expected_peer_fill_peers: None,
        expected_peer_fill_max_concurrent_requests: None,
        expect_memory_tier_enabled: false,
        expect_disk_tier_enabled: false,
        expect_storage_tiers: None,
        expected_scope: None,
        expected_vhost: None,
        expected_route: None,
        expected_namespace: None,
        expected_key_namespace: None,
        expected_user_tag: None,
        expect_serve_stale_if_error: false,
        expect_serve_stale_while_revalidate: false,
    };

    assert!(
        super::super::validate_cache_lookup_expectations(
            &lookup,
            &super::super::CacheLookupExpectations {
                require_object: true,
                expected_states: &states,
                expected_statuses: &[200],
                expected_tiers: &tiers,
                expected_fresh_ttl_secs: &[0],
                expected_body_bytes: &[4],
                expected_header_names: &["etag".to_owned()],
                expected_cache_tags: &["asset:logo".to_owned()],
                expect_purge_indexed: true,
                expect_cache_lock_enabled: true,
                expected_cache_lock_wait_timeout_secs: Some(30),
                expect_cache_predictor_enabled: false,
                expect_origin_protection_enabled: false,
                expected_origin_protection_max_concurrent_fills: None,
                expect_peer_fill_enabled: false,
                expected_peer_fill_peers: None,
                expected_peer_fill_max_concurrent_requests: None,
                expect_memory_tier_enabled: true,
                expect_storage_tiers: Some(1),
                expect_serve_stale_while_revalidate: true,
                ..default_expectations
            }
        )
        .is_ok()
    );
    assert!(
        super::super::validate_cache_lookup_expectations(
            &lookup,
            &super::super::CacheLookupExpectations {
                expected_states: &[fluxheim_cache::CacheObjectFreshnessState::Fresh],
                ..default_expectations
            }
        )
        .unwrap_err()
        .to_string()
        .contains("expected freshness state fresh, found stale")
    );
    assert!(
        super::super::validate_cache_lookup_expectations(
            &lookup,
            &super::super::CacheLookupExpectations {
                expected_statuses: &[404],
                ..default_expectations
            }
        )
        .unwrap_err()
        .to_string()
        .contains("expected status 404, found 200")
    );
    assert!(
        super::super::validate_cache_lookup_expectations(
            &lookup,
            &super::super::CacheLookupExpectations {
                expected_tiers: &[fluxheim_cache::CacheObjectTier::Disk],
                ..default_expectations
            }
        )
        .unwrap_err()
        .to_string()
        .contains("expected tier disk, found memory")
    );
    assert!(
        super::super::validate_cache_lookup_expectations(
            &lookup,
            &super::super::CacheLookupExpectations {
                expected_fresh_ttl_secs: &[120],
                ..default_expectations
            }
        )
        .unwrap_err()
        .to_string()
        .contains("expected fresh TTL seconds 120, found 0")
    );
    assert!(super::super::validate_cache_lookup_expected_fresh_ttls(&[0]).is_ok());
    assert!(
        super::super::validate_cache_lookup_expected_fresh_ttls(&[1; 33])
            .unwrap_err()
            .to_string()
            .contains("at most 32")
    );
    assert!(
        super::super::validate_cache_lookup_expectations(
            &lookup,
            &super::super::CacheLookupExpectations {
                expected_body_bytes: &[5],
                ..default_expectations
            }
        )
        .unwrap_err()
        .to_string()
        .contains("expected body bytes 5, found 4")
    );
    assert!(
        super::super::validate_cache_lookup_expectations(
            &lookup,
            &super::super::CacheLookupExpectations {
                expect_disk_tier_enabled: true,
                ..default_expectations
            }
        )
        .unwrap_err()
        .to_string()
        .contains("expected disk tier enabled, found false")
    );
    assert!(
        super::super::validate_cache_lookup_expectations(
            &lookup,
            &super::super::CacheLookupExpectations {
                expect_storage_tiers: Some(2),
                ..default_expectations
            }
        )
        .unwrap_err()
        .to_string()
        .contains("expected storage tiers 2, found 1")
    );
    assert!(super::super::validate_cache_lookup_expected_storage_tiers(Some(2)).is_ok());
    assert!(
        super::super::validate_cache_lookup_expected_storage_tiers(Some(3))
            .unwrap_err()
            .to_string()
            .contains("must be 0, 1, or 2")
    );
    assert!(
        super::super::validate_cache_lookup_expectations(
            &lookup,
            &super::super::CacheLookupExpectations {
                expect_serve_stale_if_error: true,
                ..default_expectations
            }
        )
        .unwrap_err()
        .to_string()
        .contains("expected stale-if-error eligible object, found false")
    );
    let mut stale_if_error_lookup = lookup.clone();
    stale_if_error_lookup.objects[0].serve_stale_if_error = true;
    assert!(
        super::super::validate_cache_lookup_expectations(
            &stale_if_error_lookup,
            &super::super::CacheLookupExpectations {
                expect_serve_stale_if_error: true,
                ..default_expectations
            }
        )
        .is_ok()
    );
    assert!(super::super::validate_cache_lookup_expected_body_bytes(&[4]).is_ok());
    assert!(
        super::super::validate_cache_lookup_expected_body_bytes(&[1; 33])
            .unwrap_err()
            .to_string()
            .contains("at most 32")
    );
    assert!(
        super::super::validate_cache_lookup_expectations(
            &lookup,
            &super::super::CacheLookupExpectations {
                expected_objects: Some(1),
                ..default_expectations
            }
        )
        .is_ok()
    );
    assert!(
        super::super::validate_cache_lookup_expectations(
            &lookup,
            &super::super::CacheLookupExpectations {
                expected_objects: Some(0),
                ..default_expectations
            }
        )
        .unwrap_err()
        .to_string()
        .contains("expected 0 cached objects, found 1")
    );
    assert!(super::super::validate_cache_lookup_expected_objects(Some(2)).is_ok());
    assert!(
        super::super::validate_cache_lookup_expected_objects(Some(3))
            .unwrap_err()
            .to_string()
            .contains("must be 0, 1, or 2")
    );
    assert_eq!(
        super::super::parse_cache_lookup_header_names(&[" ETag ".to_owned()]).unwrap(),
        vec!["etag"]
    );
    assert!(
        super::super::parse_cache_lookup_header_names(&["bad header".to_owned()])
            .unwrap_err()
            .to_string()
            .contains("valid HTTP header name")
    );
    assert!(
        super::super::validate_cache_lookup_expectations(
            &lookup,
            &super::super::CacheLookupExpectations {
                expected_header_names: &["last-modified".to_owned()],
                ..default_expectations
            }
        )
        .unwrap_err()
        .to_string()
        .contains("expected stored header name last-modified, found cache-control,etag,vary")
    );
    assert_eq!(
        super::super::parse_cache_lookup_headers(&[" ETag: \"cached\" ".to_owned()]).unwrap(),
        vec![("etag".to_owned(), "\"cached\"".to_owned())]
    );
    assert!(
        super::super::parse_cache_lookup_headers(&["Bad Header: value".to_owned()])
            .unwrap_err()
            .to_string()
            .contains("valid HTTP header name")
    );
    assert!(
        super::super::validate_cache_lookup_expectations(
            &lookup,
            &super::super::CacheLookupExpectations {
                expected_headers: &[("etag".to_owned(), "\"cached\"".to_owned())],
                ..default_expectations
            }
        )
        .is_ok()
    );
    assert!(
        super::super::validate_cache_lookup_expectations(
            &lookup,
            &super::super::CacheLookupExpectations {
                expected_headers: &[("etag".to_owned(), "\"missing\"".to_owned())],
                ..default_expectations
            }
        )
        .unwrap_err()
        .to_string()
        .contains("expected stored header etag: \"missing\", found etag: \"cached\"")
    );
    assert_eq!(
        super::super::parse_cache_lookup_cache_tags(&[" asset:logo ".to_owned()]).unwrap(),
        vec!["asset:logo"]
    );
    assert!(
        super::super::parse_cache_lookup_cache_tags(&["bad tag".to_owned()])
            .unwrap_err()
            .to_string()
            .contains("valid cache tag")
    );
    assert!(
        super::super::validate_cache_lookup_expectations(
            &lookup,
            &super::super::CacheLookupExpectations {
                expected_cache_tags: &["article:missing".to_owned()],
                ..default_expectations
            }
        )
        .unwrap_err()
        .to_string()
        .contains("expected cache tag article:missing, found asset:logo")
    );
    assert!(
        super::super::parse_cache_lookup_freshness_states(&["invalid".to_owned()])
            .unwrap_err()
            .to_string()
            .contains("fresh, stale, or expired")
    );
    assert!(
        super::super::parse_cache_lookup_tiers(&["invalid".to_owned()])
            .unwrap_err()
            .to_string()
            .contains("memory or disk")
    );
    assert!(super::super::validate_cache_lookup_expected_statuses(&[99]).is_err());
    assert!(
        super::super::validate_cache_lookup_expectations(
            &cache_lookup_without_objects(),
            &super::super::CacheLookupExpectations {
                require_object: true,
                ..default_expectations
            }
        )
        .unwrap_err()
        .to_string()
        .contains("expected at least one cached object")
    );
    assert!(
        super::super::validate_cache_lookup_expectations(
            &cache_lookup_without_objects(),
            &super::super::CacheLookupExpectations {
                expect_purge_indexed: true,
                ..default_expectations
            }
        )
        .unwrap_err()
        .to_string()
        .contains("expected at least one purge-indexed object")
    );
}
