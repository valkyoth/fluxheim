#[cfg(all(feature = "cache", feature = "proxy"))]
use super::*;

#[cfg(all(feature = "cache", feature = "proxy"))]
#[test]
fn cache_key_preview_expectations_validate_policy_layout() {
    let preview = cache_lookup_without_objects().preview;

    let mut expected = default_preview_expectations();
    expected.expect_eligible = true;
    expected.expect_cache_lock_enabled = true;
    expected.expected_cache_lock_wait_timeout_secs = Some(30);
    expected.expect_memory_tier_enabled = true;
    expected.expect_disk_tier_enabled = false;
    expected.expect_storage_tiers = Some(1);
    expected.expected_scope = Some("route");
    expected.expected_vhost = Some("cached");
    expected.expected_route = Some("assets");
    expected.expected_namespace = Some("fluxheim-image-v1");
    expected.expected_key_namespace = Some("route-assets-v1");
    expected.expected_user_tag = Some("cached:route:assets");
    assert!(super::super::validate_cache_key_preview_expectations(&preview, expected).is_ok());

    let mut peer_preview = preview.clone();
    peer_preview.peer_fill_enabled = true;
    peer_preview.peer_fill_peer_count = 2;
    peer_preview.peer_fill_max_concurrent_requests = 128;
    let mut expected = default_preview_expectations();
    expected.expect_peer_fill_enabled = true;
    expected.expected_peer_fill_peers = Some(2);
    expected.expected_peer_fill_max_concurrent_requests = Some(128);
    assert!(super::super::validate_cache_key_preview_expectations(&peer_preview, expected).is_ok());

    let mut origin_preview = preview.clone();
    origin_preview.origin_protection_enabled = true;
    origin_preview.origin_protection_max_concurrent_fills = 96;
    let mut expected = default_preview_expectations();
    expected.expect_origin_protection_enabled = true;
    expected.expected_origin_protection_max_concurrent_fills = Some(96);
    assert!(
        super::super::validate_cache_key_preview_expectations(&origin_preview, expected).is_ok()
    );

    assert_preview_error(
        &preview,
        |expected| expected.expect_cache_predictor_enabled = true,
        "expected cache predictor enabled, found false",
    );
    assert_preview_error(
        &preview,
        |expected| expected.expect_disk_tier_enabled = true,
        "expected disk tier enabled, found false",
    );
    assert_preview_error(
        &preview,
        |expected| expected.expected_cache_lock_wait_timeout_secs = Some(5),
        "expected cache lock wait timeout seconds 5, found 30",
    );
    assert_preview_error(
        &preview,
        |expected| expected.expect_storage_tiers = Some(2),
        "expected storage tiers 2, found 1",
    );
    assert_preview_error(
        &preview,
        |expected| expected.expected_scope = Some("vhost"),
        "expected scope vhost, found route",
    );
    assert_preview_error(
        &preview,
        |expected| expected.expected_vhost = Some("other"),
        "expected vhost other, found cached",
    );
    assert_preview_error(
        &preview,
        |expected| expected.expected_route = Some("other"),
        "expected route other, found assets",
    );
    assert_preview_error(
        &preview,
        |expected| expected.expected_namespace = Some("other-v1"),
        "expected namespace other-v1, found fluxheim-image-v1",
    );
    assert_preview_error(
        &preview,
        |expected| expected.expected_key_namespace = Some("other-v1"),
        "expected key namespace other-v1, found route-assets-v1",
    );
    assert_preview_error(
        &preview,
        |expected| expected.expected_user_tag = Some("cached"),
        "expected user tag cached, found cached:route:assets",
    );
    assert_preview_error(
        &preview,
        |expected| expected.expect_ineligible = true,
        "expected ineligible request, found true",
    );

    let mut ineligible = preview.clone();
    ineligible.eligible = false;
    ineligible.reason = Some("method HEAD currently bypasses proxy cache storage".to_owned());
    let mut expected = default_preview_expectations();
    expected.expect_ineligible = true;
    expected.expected_reason = Some("method HEAD currently bypasses proxy cache storage");
    assert!(super::super::validate_cache_key_preview_expectations(&ineligible, expected).is_ok());
    assert_preview_error(
        &ineligible,
        |expected| expected.expected_reason = Some("other"),
        "expected reason other",
    );

    assert_eq!(
        super::super::parse_cache_key_preview_scope("cache-key", Some(&" Route ".to_owned()))
            .unwrap()
            .as_deref(),
        Some("route")
    );
    assert!(
        super::super::parse_cache_key_preview_scope("cache-key", Some(&"bad".to_owned()))
            .unwrap_err()
            .to_string()
            .contains("vhost or route")
    );
    let expected_reason = " method HEAD currently bypasses proxy cache storage ".to_owned();
    assert_eq!(
        super::super::parse_cache_key_preview_reason(
            "cache-key",
            "--expect-reason",
            Some(&expected_reason),
        )
        .unwrap()
        .as_deref(),
        Some("method HEAD currently bypasses proxy cache storage")
    );
    let expected_namespace = " fluxheim-image-v1 ".to_owned();
    assert_eq!(
        super::super::parse_cache_key_preview_value(
            "cache-key",
            "--expect-namespace",
            Some(&expected_namespace),
        )
        .unwrap()
        .as_deref(),
        Some("fluxheim-image-v1")
    );
    assert!(
        super::super::parse_cache_key_preview_value(
            "cache-key",
            "--expect-user-tag",
            Some(&"\n".to_owned()),
        )
        .is_err()
    );
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn assert_preview_error(
    preview: &fluxheim_cache::CacheKeyPreview,
    mutate: impl FnOnce(&mut super::super::CacheKeyPreviewExpectations<'_>),
    contains: &str,
) {
    let mut expected = default_preview_expectations();
    mutate(&mut expected);
    assert!(
        super::super::validate_cache_key_preview_expectations(preview, expected)
            .unwrap_err()
            .to_string()
            .contains(contains)
    );
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn default_preview_expectations() -> super::super::CacheKeyPreviewExpectations<'static> {
    super::super::CacheKeyPreviewExpectations {
        expect_eligible: false,
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
    }
}
