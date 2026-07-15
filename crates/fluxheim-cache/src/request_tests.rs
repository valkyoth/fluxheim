use crate::request::{
    CacheClientRange, CacheContentRange, CacheRangeRequest, CacheRequest, CacheSliceBounds,
    FluxCacheKeyParts, StaticCacheRequest, append_cache_key_component, cache_key_with_component,
    cache_method_temporarily_bypassed, eligible_image_request, image_cache_key,
    parse_bounded_single_range, parse_cache_client_ranges, parse_cache_content_range,
    required_slice_bounds, resolve_client_slice_ranges, response_content_length_matches_range,
    response_content_range_matches, slice_request_within_policy, static_cache_key,
};
use fluxheim_config::{CacheConfig, CacheKeyPart, CacheMemoryConfig};

#[test]
fn appends_length_delimited_cache_key_component() {
    let mut key = String::from("prefix;");
    append_cache_key_component(&mut key, "range", "bytes=10-19");
    assert_eq!(key, "prefix;range:11:bytes=10-19;");
    assert_eq!(
        cache_key_with_component("prefix;", "slice", "bytes=10-19"),
        "prefix;slice:11:bytes=10-19;"
    );
}

#[test]
fn detects_temporarily_bypassed_cache_methods() {
    assert!(cache_method_temporarily_bypassed("HEAD"));
    assert!(!cache_method_temporarily_bypassed("GET"));
    assert!(!cache_method_temporarily_bypassed("head"));
}

#[test]
fn builds_image_cache_key_from_cache_policy() {
    let config = CacheConfig {
        key_namespace: Some("cache-vhost-v1".to_owned()),
        key_parts: vec![
            CacheKeyPart::Method,
            CacheKeyPart::Host,
            CacheKeyPart::Path,
            CacheKeyPart::Query,
        ],
        ..enabled_cache()
    };
    let request = CacheRequest {
        method: "GET",
        host: Some("Example.COM:443"),
        path: "/assets/logo.png",
        query: Some("v=1"),
    };

    let key = image_cache_key(&config, &request).expect("eligible key");

    assert!(eligible_image_request(&config, &request));
    assert_eq!(
        key.as_str(),
        "fluxheim-image-v1;namespace:14:cache-vhost-v1;method:3:GET;host:11:example.com;path:16:/assets/logo.png;query:3:v=1;"
    );
}

#[test]
fn image_cache_key_rejects_disabled_or_unmatched_requests() {
    let request = CacheRequest {
        method: "POST",
        host: Some("example.com"),
        path: "/assets/logo.png",
        query: None,
    };
    assert_eq!(image_cache_key(&enabled_cache(), &request), None);

    let request = CacheRequest {
        method: "GET",
        host: Some("example.com"),
        path: "/assets/logo.txt",
        query: None,
    };
    assert_eq!(image_cache_key(&enabled_cache(), &request), None);
    assert_eq!(image_cache_key(&CacheConfig::default(), &request), None);
}

#[test]
fn static_cache_key_requires_local_static_and_file_identity() {
    let config = CacheConfig {
        local_static: true,
        key_parts: vec![
            CacheKeyPart::Method,
            CacheKeyPart::Host,
            CacheKeyPart::Path,
            CacheKeyPart::Query,
        ],
        ..enabled_cache()
    };
    let request = StaticCacheRequest {
        method: "GET",
        host: Some("static.example"),
        path: "/img/photo.webp",
        query: Some("w=640"),
        file_identity: "dev:inode:mtime",
    };

    let key = static_cache_key(&config, &request).expect("eligible static key");

    assert_eq!(
        key.as_str(),
        "fluxheim-static-v1;method:3:GET;host:14:static.example;path:15:/img/photo.webp;query:5:w=640;file:15:dev:inode:mtime;"
    );

    let no_static = CacheConfig {
        local_static: false,
        ..config
    };
    assert_eq!(static_cache_key(&no_static, &request), None);
}

#[test]
fn parses_bounded_single_range() {
    assert_eq!(
        parse_bounded_single_range("bytes=10-19"),
        Some(CacheRangeRequest { start: 10, end: 19 })
    );
    assert_eq!(parse_bounded_single_range("bytes=19-10"), None);
    assert_eq!(parse_bounded_single_range("bytes=10-"), None);
    assert_eq!(parse_bounded_single_range("bytes=10-19,20-29"), None);
}

#[test]
fn parses_content_range() {
    assert_eq!(
        parse_cache_content_range("bytes 10-19/100"),
        Some(CacheContentRange {
            start: 10,
            end: 19,
            total: Some(100),
        })
    );
    assert_eq!(
        parse_cache_content_range("bytes 10-19/*"),
        Some(CacheContentRange {
            start: 10,
            end: 19,
            total: None,
        })
    );
    assert_eq!(parse_cache_content_range("bytes */100"), None);
    assert_eq!(parse_cache_content_range("bytes 19-10/100"), None);
    assert_eq!(parse_cache_content_range("bytes 10-19/19"), None);
    assert_eq!(parse_cache_content_range("items 10-19/100"), None);
}

#[test]
fn validates_response_range_headers_against_request() {
    let response = http::Response::builder()
        .header("content-range", "bytes 10-19/100")
        .header("content-length", "10")
        .body(())
        .unwrap();
    let expected = CacheRangeRequest { start: 10, end: 19 };

    assert!(response_content_range_matches(response.headers(), expected));
    assert!(response_content_length_matches_range(
        response.headers(),
        expected
    ));

    let wrong = CacheRangeRequest { start: 20, end: 29 };
    assert!(!response_content_range_matches(response.headers(), wrong));
    assert!(response_content_length_matches_range(
        response.headers(),
        wrong
    ));

    let duplicate = http::Response::builder()
        .header("content-range", "bytes 10-19/100")
        .header("content-range", "bytes 20-29/100")
        .header("content-length", "10")
        .header("content-length", "10")
        .body(())
        .unwrap();
    assert!(!response_content_range_matches(
        duplicate.headers(),
        expected
    ));
    assert!(!response_content_length_matches_range(
        duplicate.headers(),
        expected
    ));

    let unsatisfied = http::Response::builder()
        .header("content-range", "bytes */100")
        .header("content-length", "10")
        .body(())
        .unwrap();
    assert!(!response_content_range_matches(
        unsatisfied.headers(),
        CacheRangeRequest { start: 0, end: 0 }
    ));
}

#[test]
fn parses_client_ranges() {
    assert_eq!(
        parse_cache_client_ranges("bytes=0-9, 20-, -5"),
        Some(vec![
            CacheClientRange::Bounded { start: 0, end: 9 },
            CacheClientRange::OpenEnded { start: 20 },
            CacheClientRange::Suffix { len: 5 },
        ])
    );
    assert_eq!(parse_cache_client_ranges("bytes=-0"), None);
    assert_eq!(parse_cache_client_ranges("items=0-1"), None);
}

#[test]
fn resolves_client_ranges_against_total() {
    let ranges = parse_cache_client_ranges("bytes=0-99, 950-, -25").unwrap();

    assert_eq!(
        resolve_client_slice_ranges(&ranges, 1000).unwrap(),
        vec![
            CacheSliceBounds { start: 0, end: 99 },
            CacheSliceBounds {
                start: 950,
                end: 999
            },
            CacheSliceBounds {
                start: 975,
                end: 999
            },
        ]
    );
}

#[test]
fn computes_required_slice_bounds() {
    let ranges = [CacheSliceBounds {
        start: 10,
        end: 130,
    }];

    assert_eq!(
        required_slice_bounds(&ranges, 64, 200),
        vec![
            CacheSliceBounds { start: 0, end: 63 },
            CacheSliceBounds {
                start: 64,
                end: 127
            },
            CacheSliceBounds {
                start: 128,
                end: 191
            },
        ]
    );
    assert!(required_slice_bounds(&ranges, 0, 200).is_empty());
    assert!(required_slice_bounds(&ranges, 64, 0).is_empty());
}

#[test]
fn slice_policy_bounds_assembled_bytes_and_slice_count() {
    assert!(slice_request_within_policy(
        &[CacheSliceBounds { start: 0, end: 15 }],
        16,
        2,
        8
    ));
    assert!(!slice_request_within_policy(
        &[CacheSliceBounds { start: 0, end: 16 }],
        16,
        2,
        8
    ));
    assert!(!slice_request_within_policy(
        &[CacheSliceBounds { start: 0, end: 23 }],
        16,
        2,
        8
    ));
    assert!(!slice_request_within_policy(
        &[
            CacheSliceBounds { start: 0, end: 0 },
            CacheSliceBounds { start: 0, end: 0 },
        ],
        16,
        2,
        8
    ));
}

#[test]
fn flux_cache_key_parts_preserve_identity_fields() {
    let key = FluxCacheKeyParts::new("primary", "combined", "tag");

    assert_eq!(key.primary(), "primary");
    assert_eq!(key.combined(), "combined");
    assert_eq!(key.user_tag(), "tag");
}

fn enabled_cache() -> CacheConfig {
    CacheConfig {
        enabled: true,
        memory: CacheMemoryConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    }
}
