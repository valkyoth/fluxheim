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
    assert_eq!(
        super::request_cache_bypass_reason(
            &TestRequest::new("/").with_header("authorization", "Bearer secret"),
            &cache
        ),
        Some("request-authorization")
    );
    assert_eq!(
        super::request_cache_bypass_reason(
            &TestRequest::new("/").with_header("proxy-authorization", "Basic secret"),
            &cache
        ),
        Some("request-proxy-authorization")
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
