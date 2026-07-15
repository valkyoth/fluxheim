#[test]
fn detects_response_shared_cache_rejections() {
    for (value, reason) in [
        ("no-store", "cache-control-no-store"),
        ("private", "cache-control-private"),
        ("public, no-cache", "cache-control-no-cache"),
        ("max-age=0", "cache-control-zero-freshness"),
        ("s-maxage=\"0\"", "cache-control-zero-freshness"),
    ] {
        assert_eq!(
            super::response_values_forbid_shared_cache([value]),
            Some(reason),
            "cache-control: {value}"
        );
    }

    assert_eq!(
        super::response_values_forbid_shared_cache(["public, max-age=60", "immutable"]),
        None
    );
    assert_eq!(
        super::response_values_forbid_shared_cache(["public, max-age=60", "private"]),
        Some("cache-control-private")
    );
}

#[test]
fn response_admission_policy_checks_status_headers_and_ranges() {
    let mut headers = http::HeaderMap::new();
    headers.insert("content-type", http::HeaderValue::from_static("image/png"));
    assert_eq!(
        super::response_cache_admission_rejection(
            302,
            &headers,
            &fluxheim_config::CacheConfig::default()
        ),
        Some("status-not-cacheable")
    );

    let cache = fluxheim_config::CacheConfig {
        default_status_ttl_secs: Some(30),
        ..fluxheim_config::CacheConfig::default()
    };
    assert_eq!(
        super::response_cache_admission_rejection(302, &headers, &cache),
        None
    );

    headers.insert("set-cookie", http::HeaderValue::from_static("session=1"));
    assert_eq!(
        super::response_cache_admission_rejection(200, &headers, &cache),
        Some("set-cookie")
    );

    let mut headers = http::HeaderMap::new();
    headers.insert("content-type", http::HeaderValue::from_static("image/png"));
    headers.insert("x-cache-mode", http::HeaderValue::from_static("private"));
    let cache = fluxheim_config::CacheConfig {
        no_store_response_header_values: std::collections::BTreeMap::from([(
            "x-cache-mode".to_owned(),
            "private".to_owned(),
        )]),
        ..fluxheim_config::CacheConfig::default()
    };
    assert_eq!(
        super::response_cache_admission_rejection(200, &headers, &cache),
        Some("configured-no-store-response-header-value")
    );

    let mut headers = http::HeaderMap::new();
    headers.insert(
        "content-range",
        http::HeaderValue::from_static("bytes 10-19/100"),
    );
    headers.insert("content-length", http::HeaderValue::from_static("10"));
    assert_eq!(
        super::range_response_cache_admission_rejection(
            206,
            &headers,
            Some(crate::CacheRangeRequest { start: 10, end: 19 })
        ),
        None
    );
    assert_eq!(
        super::range_response_cache_admission_rejection(206, &headers, None),
        Some("range-response")
    );
}

#[test]
fn stale_policy_respects_error_and_status_controls() {
    let cache = fluxheim_config::CacheConfig {
        stale_if_error_secs: None,
        stale_if_error_on: vec![fluxheim_config::CacheStaleErrorKind::Connect],
        ..fluxheim_config::CacheConfig::default()
    };
    assert!(!super::cache_should_serve_stale(
        &cache,
        super::CacheStaleEvent::UpstreamError(fluxheim_config::CacheStaleErrorKind::Connect),
        super::StoredCachePolicy::default()
    ));

    let cache = fluxheim_config::CacheConfig {
        stale_if_error_secs: Some(60),
        stale_if_error_on: vec![fluxheim_config::CacheStaleErrorKind::Connect],
        ..fluxheim_config::CacheConfig::default()
    };
    assert!(super::cache_should_serve_stale(
        &cache,
        super::CacheStaleEvent::UpstreamError(fluxheim_config::CacheStaleErrorKind::Connect),
        super::StoredCachePolicy::default()
    ));
    assert!(!super::cache_should_serve_stale(
        &cache,
        super::CacheStaleEvent::OtherError,
        super::StoredCachePolicy::default()
    ));

    let cache = fluxheim_config::CacheConfig {
        stale_if_error_secs: Some(60),
        stale_if_error_on: vec![fluxheim_config::CacheStaleErrorKind::HttpStatus],
        ..fluxheim_config::CacheConfig::default()
    };
    assert!(super::cache_should_serve_stale(
        &cache,
        super::CacheStaleEvent::UpstreamHttpStatus(500),
        super::StoredCachePolicy::default()
    ));
    assert!(!super::cache_should_serve_stale(
        &cache,
        super::CacheStaleEvent::UpstreamHttpStatus(404),
        super::StoredCachePolicy::default()
    ));

    let narrowed = fluxheim_config::CacheConfig {
        stale_if_error_secs: Some(60),
        stale_if_error_on: vec![fluxheim_config::CacheStaleErrorKind::HttpStatus],
        stale_if_error_statuses: vec![502],
        ..fluxheim_config::CacheConfig::default()
    };
    assert!(super::cache_stale_status_allows(&narrowed, 502));
    assert!(!super::cache_stale_status_allows(&narrowed, 500));
}

#[test]
fn stale_policy_respects_revalidation_controls() {
    let cache = fluxheim_config::CacheConfig::default();
    assert!(!super::cache_should_serve_stale(
        &cache,
        super::CacheStaleEvent::Updating,
        super::StoredCachePolicy::default()
    ));

    let cache = fluxheim_config::CacheConfig {
        stale_while_revalidate_secs: Some(30),
        ..fluxheim_config::CacheConfig::default()
    };
    assert!(super::cache_should_serve_stale(
        &cache,
        super::CacheStaleEvent::Updating,
        super::StoredCachePolicy::default()
    ));
    assert!(!super::cache_should_serve_stale(
        &cache,
        super::CacheStaleEvent::Updating,
        super::StoredCachePolicy {
            stale_reuse_forbidden: true,
        }
    ));
}

#[test]
fn computes_remaining_fresh_ttl() {
    assert_eq!(super::remaining_fresh_ttl_secs(120, 0), Some(120));
    assert_eq!(super::remaining_fresh_ttl_secs(120, 119), Some(1));
    assert_eq!(super::remaining_fresh_ttl_secs(120, 120), None);
    assert_eq!(super::remaining_fresh_ttl_secs(120, 121), None);
}

#[test]
fn builds_cache_control_freshness_value() {
    assert_eq!(
        super::cache_control_freshness_value(60, Some(5), Some(10)),
        "max-age=60, stale-while-revalidate=5, stale-if-error=10"
    );
    assert_eq!(
        super::cache_control_freshness_value(60, None, None),
        "max-age=60"
    );
}

#[test]
fn replaces_cache_control_directive_without_duplicate() {
    assert_eq!(
        super::cache_control_with_directive(
            ["public, max-age=60", "stale-if-error=10"],
            "stale-if-error=30",
            "stale-if-error",
        ),
        "public, max-age=60, stale-if-error=30"
    );
    assert_eq!(
        super::cache_control_with_directive(
            ["max-age=60, stale-while-revalidate=5"],
            "stale-while-revalidate=15",
            "stale-while-revalidate",
        ),
        "max-age=60, stale-while-revalidate=15"
    );
}

#[test]
fn parses_response_age_and_max_age_headers() {
    let response = http::Response::builder()
        .header("age", "42")
        .header("cache-control", "public, max-age=60")
        .body(())
        .unwrap();

    assert_eq!(super::response_age_secs(response.headers()), 42);
    assert_eq!(
        super::response_cache_control_max_age(response.headers()),
        Some(60)
    );

    let response = http::Response::builder()
        .header("age", "not-a-number")
        .header("cache-control", "public, s-maxage=\"120\"")
        .body(())
        .unwrap();

    assert_eq!(super::response_age_secs(response.headers()), u64::MAX);
    assert_eq!(
        super::response_cache_control_max_age(response.headers()),
        Some(120)
    );
}

#[test]
fn strict_response_freshness_prefers_shared_age_and_rejects_ambiguity() {
    let response = http::Response::builder()
        .header("age", "500, 0")
        .header(
            "cache-control",
            "max-age=60, extension=\"a,b\", s-maxage=120",
        )
        .body(())
        .unwrap();
    assert_eq!(super::response_age_secs(response.headers()), 500);
    assert_eq!(
        super::response_cache_control_freshness(response.headers()),
        super::ResponseFreshness::Seconds(120)
    );

    for value in [
        "max-age=60, max-age=120",
        "s-maxage=60, s-maxage=120",
        "private, private",
        "max-age=60, extension=\"unterminated",
        "max-age=sixty",
    ] {
        let response = http::Response::builder()
            .header("content-type", "image/png")
            .header("cache-control", value)
            .body(())
            .unwrap();
        assert_eq!(
            super::response_cache_control_freshness(response.headers()),
            super::ResponseFreshness::Invalid,
            "cache-control: {value}"
        );
        assert_eq!(
            super::response_cache_admission_rejection(
                200,
                response.headers(),
                &fluxheim_config::CacheConfig::default()
            ),
            Some("cache-control-invalid"),
            "cache-control: {value}"
        );
    }

    let mut headers = http::HeaderMap::new();
    headers.insert("content-type", http::HeaderValue::from_static("image/png"));
    headers.insert(
        "cache-control",
        http::HeaderValue::from_bytes(b"no-store, \xff").unwrap(),
    );
    assert_eq!(
        super::response_cache_admission_rejection(
            200,
            &headers,
            &fluxheim_config::CacheConfig::default()
        ),
        Some("cache-control-invalid")
    );
}

#[test]
fn response_policy_forbids_stale_reuse_when_revalidation_is_mandatory() {
    for value in ["must-revalidate", "proxy-revalidate", "s-maxage=60"] {
        let response = http::Response::builder()
            .header("cache-control", value)
            .body(())
            .unwrap();
        assert!(super::response_cache_control_stale_reuse_forbidden(
            response.headers()
        ));
    }
    let response = http::Response::builder()
        .header("cache-control", "public, max-age=60")
        .body(())
        .unwrap();
    assert!(!super::response_cache_control_stale_reuse_forbidden(
        response.headers()
    ));
}

#[test]
fn response_content_type_matches_exact_and_wildcard_patterns() {
    let mut cache = fluxheim_config::CacheConfig {
        content_types: vec!["image/*".to_owned(), "text/css".to_owned()],
        ..fluxheim_config::CacheConfig::default()
    };
    let response = http::Response::builder()
        .header("content-type", "Image/PNG; charset=binary")
        .body(())
        .unwrap();

    assert!(super::response_content_type_is_cacheable(
        response.headers(),
        &cache
    ));

    let response = http::Response::builder()
        .header("content-type", "text/html")
        .body(())
        .unwrap();
    assert!(!super::response_content_type_is_cacheable(
        response.headers(),
        &cache
    ));

    cache.content_types = vec!["text/html".to_owned()];
    assert!(super::response_content_type_is_cacheable(
        response.headers(),
        &cache
    ));
}

#[test]
fn multipart_content_type_sanitizer_strips_crlf() {
    assert_eq!(
        super::sanitize_multipart_content_type("text/plain\r\nX-Injected: yes"),
        "text/plainX-Injected: yes"
    );
    assert_eq!(
        super::sanitize_multipart_content_type("\r\n"),
        "application/octet-stream"
    );
}

#[test]
fn first_header_value_returns_first_valid_text_value() {
    let mut headers = http::HeaderMap::new();
    headers.append("etag", http::HeaderValue::from_bytes(b"\xff").unwrap());
    headers.append("etag", http::HeaderValue::from_static("\"abc\""));
    headers.append("etag", http::HeaderValue::from_static("\"def\""));

    assert_eq!(
        super::first_header_value(&headers, "etag").as_deref(),
        Some("\"abc\"")
    );
    assert_eq!(super::first_header_value(&headers, "missing"), None);
}
