pub use crate::headers_request::{
    CacheRequestView, cookie_headers_match_cache_bypass, query_matches_cache_bypass,
    request_cache_bypass_reason, request_cache_revalidation_requested,
    request_forces_cache_refresh, request_values_forbid_cache_store,
    request_values_force_cache_refresh, request_values_force_cache_revalidation,
    selected_cache_range_request, selected_cache_slice_range_request,
};
pub use crate::headers_response::{
    cache_control_freshness_value, cache_control_with_directive, first_header_value,
    range_response_cache_admission_rejection, remaining_fresh_ttl_secs, response_age_secs,
    response_cache_admission_rejection, response_cache_control_max_age,
    response_cache_header_policy_rejection, response_content_type_is_cacheable,
    response_range_cache_admission_rejection, response_values_forbid_shared_cache,
    sanitize_multipart_content_type,
};
pub use crate::headers_vary::{
    MAX_VARY_FIELDS, VaryCachePolicy, VaryRequestHashField, cache_vary_policy, vary_cache_policy,
    vary_request_hash_material,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheStaleEvent {
    Updating,
    UpstreamError(fluxheim_config::CacheStaleErrorKind),
    UpstreamHttpStatus(u16),
    OtherError,
}

pub fn cache_should_serve_stale(
    cache: &fluxheim_config::CacheConfig,
    event: CacheStaleEvent,
) -> bool {
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

#[cfg(test)]
mod tests {
    use super::request_forces_cache_refresh;

    struct TestRequest {
        method: &'static str,
        path: &'static str,
        query: Option<&'static str>,
        headers: Vec<(&'static str, &'static str)>,
    }

    impl TestRequest {
        fn new(path: &'static str) -> Self {
            Self {
                method: "GET",
                path,
                query: None,
                headers: Vec::new(),
            }
        }

        fn with_method(mut self, method: &'static str) -> Self {
            self.method = method;
            self
        }

        fn with_query(mut self, query: &'static str) -> Self {
            self.query = Some(query);
            self
        }

        fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.headers.push((name, value));
            self
        }
    }

    impl super::CacheRequestView for TestRequest {
        fn method(&self) -> &str {
            self.method
        }

        fn path(&self) -> &str {
            self.path
        }

        fn query(&self) -> Option<&str> {
            self.query
        }

        fn contains_header(&self, name: &str) -> bool {
            self.headers
                .iter()
                .any(|(header, _)| header.eq_ignore_ascii_case(name))
        }

        fn visit_header_values(&self, name: &str, visitor: &mut dyn FnMut(&str)) {
            for (header, value) in &self.headers {
                if header.eq_ignore_ascii_case(name) {
                    visitor(value);
                }
            }
        }
    }

    #[test]
    fn detects_request_cache_refresh_directives() {
        for value in [
            "no-cache",
            "No-Cache",
            "no-store",
            "max-age=0",
            "max-age = 0",
            "public, max-age=0",
            "public, no-cache",
        ] {
            assert!(
                request_forces_cache_refresh(Some(value), None),
                "cache-control: {value}"
            );
        }

        assert!(request_forces_cache_refresh(None, Some("no-cache")));
        assert!(request_forces_cache_refresh(
            Some("public, max-age=60"),
            Some("no-cache")
        ));
    }

    #[test]
    fn ignores_normal_request_cache_directives() {
        for value in [
            "public",
            "private",
            "max-age=60",
            "min-fresh=0",
            "only-if-cached",
        ] {
            assert!(
                !request_forces_cache_refresh(Some(value), None),
                "cache-control: {value}"
            );
        }

        assert!(!request_forces_cache_refresh(None, Some("max-age=0")));
        assert!(!request_forces_cache_refresh(None, None));
    }

    #[test]
    fn detects_refresh_across_repeated_header_values() {
        assert!(super::request_values_force_cache_refresh(
            ["public, max-age=60", "no-cache"],
            []
        ));
        assert!(super::request_values_force_cache_refresh(
            ["public, max-age=60"],
            ["ignored", "no-cache"]
        ));
        assert!(!super::request_values_force_cache_refresh(
            ["public, max-age=60"],
            ["ignored"]
        ));
    }

    #[test]
    fn separates_request_revalidation_from_no_store() {
        for value in ["no-cache", "max-age=0", "max-age = 0", "public, no-cache"] {
            assert!(
                super::request_values_force_cache_revalidation([value], []),
                "cache-control: {value}"
            );
            assert!(
                !super::request_values_forbid_cache_store([value]),
                "cache-control: {value}"
            );
        }

        assert!(super::request_values_force_cache_revalidation(
            ["public, max-age=60"],
            ["no-cache"]
        ));
        assert!(super::request_values_forbid_cache_store(["no-store"]));
        assert!(super::request_values_forbid_cache_store([
            "public, no-store"
        ]));
        assert!(!super::request_values_force_cache_revalidation(
            ["no-store"],
            []
        ));
    }

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
    fn cookie_headers_match_configured_bypass_policy() {
        let values = std::collections::BTreeMap::from([("session".to_owned(), "admin".to_owned())]);

        assert!(super::cookie_headers_match_cache_bypass(
            ["theme=dark; session=admin"],
            &[],
            &[],
            &values
        ));
        assert!(super::cookie_headers_match_cache_bypass(
            ["theme=dark; wp_logged_in_123=1"],
            &[],
            &["wp_logged_in_".to_owned()],
            &std::collections::BTreeMap::new()
        ));
        assert!(super::cookie_headers_match_cache_bypass(
            ["theme=dark; auth=yes"],
            &["auth".to_owned()],
            &[],
            &std::collections::BTreeMap::new()
        ));
        assert!(!super::cookie_headers_match_cache_bypass(
            ["theme=dark"],
            &["auth".to_owned()],
            &[],
            &values
        ));
    }

    #[test]
    fn query_matches_configured_bypass_policy_with_percent_decoding() {
        let values = std::collections::BTreeMap::from([("preview".to_owned(), "true".to_owned())]);

        assert!(super::query_matches_cache_bypass(
            "preview=true",
            &[],
            &values
        ));
        assert!(super::query_matches_cache_bypass(
            "preview%5fmode=1",
            &["preview_mode".to_owned()],
            &std::collections::BTreeMap::new()
        ));
        assert!(super::query_matches_cache_bypass(
            "preview=t%72ue",
            &[],
            &values
        ));
        assert!(!super::query_matches_cache_bypass(
            "preview=false",
            &[],
            &values
        ));
    }

    #[test]
    fn request_view_reports_cache_bypass_reasons() {
        let cache = fluxheim_config::CacheConfig {
            bypass_path_prefixes: vec!["/admin/".to_owned()],
            bypass_request_header_values: std::collections::BTreeMap::from([(
                "x-preview".to_owned(),
                "1".to_owned(),
            )]),
            bypass_cookie_names: vec!["session".to_owned()],
            bypass_query_values: std::collections::BTreeMap::from([(
                "preview".to_owned(),
                "true".to_owned(),
            )]),
            ..fluxheim_config::CacheConfig::default()
        };

        assert_eq!(
            super::request_cache_bypass_reason(&TestRequest::new("/admin/panel"), &cache),
            Some("request-path")
        );
        assert_eq!(
            super::request_cache_bypass_reason(
                &TestRequest::new("/").with_header("x-preview", "1"),
                &cache
            ),
            Some("request-header-value")
        );
        assert_eq!(
            super::request_cache_bypass_reason(
                &TestRequest::new("/").with_header("cookie", "theme=dark; session=yes"),
                &cache
            ),
            Some("request-cookie")
        );
        assert_eq!(
            super::request_cache_bypass_reason(
                &TestRequest::new("/").with_query("preview=true"),
                &cache
            ),
            Some("request-query")
        );
        assert_eq!(
            super::request_cache_bypass_reason(
                &TestRequest::new("/").with_header("cache-control", "no-store"),
                &cache
            ),
            Some("request-no-store")
        );
    }

    #[test]
    fn request_view_handles_revalidation_and_range_selection() {
        let cache = fluxheim_config::CacheConfig {
            allow_client_cache_refresh: true,
            range: fluxheim_config::CacheRangeConfig {
                enabled: true,
                max_bytes: fluxheim_config::ByteSize::from_bytes(512),
                ..fluxheim_config::CacheRangeConfig::default()
            },
            ..fluxheim_config::CacheConfig::default()
        };
        let request = TestRequest::new("/asset")
            .with_header("cache-control", "max-age=0")
            .with_header("range", "bytes=10-19");

        assert!(super::request_cache_revalidation_requested(
            &request, &cache
        ));
        assert_eq!(
            super::selected_cache_range_request(&request, &cache),
            Some(crate::CacheRangeRequest { start: 10, end: 19 })
        );
        assert_eq!(
            super::selected_cache_range_request(
                &TestRequest::new("/asset")
                    .with_method("HEAD")
                    .with_header("range", "bytes=10-19"),
                &cache
            ),
            None
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
            super::CacheStaleEvent::UpstreamError(fluxheim_config::CacheStaleErrorKind::Connect)
        ));

        let cache = fluxheim_config::CacheConfig {
            stale_if_error_secs: Some(60),
            stale_if_error_on: vec![fluxheim_config::CacheStaleErrorKind::Connect],
            ..fluxheim_config::CacheConfig::default()
        };
        assert!(super::cache_should_serve_stale(
            &cache,
            super::CacheStaleEvent::UpstreamError(fluxheim_config::CacheStaleErrorKind::Connect)
        ));
        assert!(!super::cache_should_serve_stale(
            &cache,
            super::CacheStaleEvent::OtherError
        ));

        let cache = fluxheim_config::CacheConfig {
            stale_if_error_secs: Some(60),
            stale_if_error_on: vec![fluxheim_config::CacheStaleErrorKind::HttpStatus],
            ..fluxheim_config::CacheConfig::default()
        };
        assert!(super::cache_should_serve_stale(
            &cache,
            super::CacheStaleEvent::UpstreamHttpStatus(500)
        ));
        assert!(!super::cache_should_serve_stale(
            &cache,
            super::CacheStaleEvent::UpstreamHttpStatus(404)
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
            super::CacheStaleEvent::Updating
        ));

        let cache = fluxheim_config::CacheConfig {
            stale_while_revalidate_secs: Some(30),
            ..fluxheim_config::CacheConfig::default()
        };
        assert!(super::cache_should_serve_stale(
            &cache,
            super::CacheStaleEvent::Updating
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

        assert_eq!(super::response_age_secs(response.headers()), 0);
        assert_eq!(
            super::response_cache_control_max_age(response.headers()),
            Some(120)
        );
    }

    #[test]
    fn vary_cache_policy_rejects_unsafe_vary_headers() {
        let response = http::Response::builder().body(()).unwrap();
        assert_eq!(
            super::vary_cache_policy(response.headers()),
            super::VaryCachePolicy::None
        );

        let response = http::Response::builder()
            .header("vary", "*")
            .body(())
            .unwrap();
        assert_eq!(
            super::vary_cache_policy(response.headers()),
            super::VaryCachePolicy::Uncacheable("vary-star")
        );

        let response = http::Response::builder()
            .header("vary", "accept-encoding,,user-agent")
            .body(())
            .unwrap();
        assert_eq!(
            super::vary_cache_policy(response.headers()),
            super::VaryCachePolicy::Uncacheable("vary-invalid")
        );

        let mut vary = String::new();
        for index in 0..super::MAX_VARY_FIELDS {
            vary.push_str(&format!("x-test-{index},"));
        }
        vary.push_str("x-overflow");
        let response = http::Response::builder()
            .header("vary", vary)
            .body(())
            .unwrap();
        assert_eq!(
            super::vary_cache_policy(response.headers()),
            super::VaryCachePolicy::Uncacheable("vary-too-many-fields")
        );

        let response = http::Response::builder()
            .header("vary", "authorization")
            .body(())
            .unwrap();
        assert_eq!(
            super::vary_cache_policy(response.headers()),
            super::VaryCachePolicy::Uncacheable("vary-sensitive-field")
        );
    }

    #[test]
    fn vary_cache_policy_normalizes_repeated_vary_fields() {
        let response = http::Response::builder()
            .header("vary", "Accept-Encoding, User-Agent")
            .header("vary", "accept-encoding")
            .body(())
            .unwrap();

        assert_eq!(
            super::vary_cache_policy(response.headers()),
            super::VaryCachePolicy::Fields(vec![
                "accept-encoding".to_owned(),
                "user-agent".to_owned(),
            ])
        );
    }

    #[test]
    fn vary_hash_material_tracks_repeated_values() {
        let single = super::vary_request_hash_material([super::VaryRequestHashField {
            name: "accept-encoding",
            values: vec![b"br".as_slice()],
        }]);
        let repeated = super::vary_request_hash_material([super::VaryRequestHashField {
            name: "accept-encoding",
            values: vec![b"br".as_slice(), b"gzip".as_slice()],
        }]);
        let different_field = super::vary_request_hash_material([super::VaryRequestHashField {
            name: "x-mode",
            values: vec![b"br".as_slice()],
        }]);

        assert_ne!(single, repeated);
        assert_ne!(single, different_field);
        assert!(single.starts_with(b"fluxheim-vary-v2"));
    }

    #[test]
    fn cache_vary_policy_merges_configured_request_headers() {
        let mut cache = fluxheim_config::CacheConfig {
            vary_request_headers: vec!["Accept-Encoding".to_owned(), "X-Device".to_owned()],
            ..fluxheim_config::CacheConfig::default()
        };
        let response = http::Response::builder()
            .header("vary", "User-Agent")
            .body(())
            .unwrap();

        assert_eq!(
            super::cache_vary_policy(response.headers(), &cache),
            super::VaryCachePolicy::Fields(vec![
                "accept-encoding".to_owned(),
                "user-agent".to_owned(),
                "x-device".to_owned(),
            ])
        );

        cache.vary_request_headers = (0..super::MAX_VARY_FIELDS)
            .map(|index| format!("x-config-{index}"))
            .collect();
        assert_eq!(
            super::cache_vary_policy(response.headers(), &cache),
            super::VaryCachePolicy::Uncacheable("vary-too-many-fields")
        );
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
}
