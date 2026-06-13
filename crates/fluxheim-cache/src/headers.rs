pub fn request_forces_cache_refresh(cache_control: Option<&str>, pragma: Option<&str>) -> bool {
    pragma.is_some_and(is_pragma_no_cache)
        || cache_control.is_some_and(cache_control_forces_refresh)
}

pub fn request_values_force_cache_refresh<'a>(
    cache_control: impl IntoIterator<Item = &'a str>,
    pragma: impl IntoIterator<Item = &'a str>,
) -> bool {
    pragma.into_iter().any(is_pragma_no_cache)
        || cache_control.into_iter().any(cache_control_forces_refresh)
}

pub fn request_values_force_cache_revalidation<'a>(
    cache_control: impl IntoIterator<Item = &'a str>,
    pragma: impl IntoIterator<Item = &'a str>,
) -> bool {
    pragma.into_iter().any(is_pragma_no_cache)
        || cache_control
            .into_iter()
            .any(cache_control_forces_revalidation)
}

pub fn request_values_forbid_cache_store<'a>(
    cache_control: impl IntoIterator<Item = &'a str>,
) -> bool {
    cache_control.into_iter().any(cache_control_forbids_store)
}

pub fn response_values_forbid_shared_cache<'a>(
    cache_control: impl IntoIterator<Item = &'a str>,
) -> Option<&'static str> {
    cache_control
        .into_iter()
        .find_map(response_cache_control_shared_rejection)
}

pub fn cookie_headers_match_cache_bypass<'a>(
    cookie_headers: impl IntoIterator<Item = &'a str>,
    configured_names: &[String],
    configured_name_prefixes: &[String],
    configured_values: &std::collections::BTreeMap<String, String>,
) -> bool {
    if configured_names.is_empty()
        && configured_name_prefixes.is_empty()
        && configured_values.is_empty()
    {
        return false;
    }
    cookie_headers
        .into_iter()
        .flat_map(cookie_header_pairs)
        .any(|(name, value)| {
            configured_names.iter().any(|configured| configured == name)
                || configured_name_prefixes
                    .iter()
                    .any(|configured| name.starts_with(configured))
                || configured_values
                    .get(name)
                    .is_some_and(|configured| configured == value)
        })
}

fn cookie_header_pairs(header: &str) -> impl Iterator<Item = (&str, &str)> {
    header.split(';').filter_map(|part| {
        let (name, value) = part.trim_start().split_once('=')?;
        (!name.is_empty()).then_some((name, value))
    })
}

pub fn query_matches_cache_bypass(
    query: &str,
    configured_params: &[String],
    configured_values: &std::collections::BTreeMap<String, String>,
) -> bool {
    if configured_params.is_empty() && configured_values.is_empty() {
        return false;
    }
    query.split('&').any(|part| {
        let (name, value) = part.split_once('=').unwrap_or((part, ""));
        if name.is_empty() {
            return false;
        }

        query_component_matches_cache_bypass(name, value, configured_params, configured_values)
            || percent_decode_query_component(name).is_some_and(|decoded_name| {
                query_component_matches_cache_bypass(
                    &decoded_name,
                    value,
                    configured_params,
                    configured_values,
                ) || percent_decode_query_component(value).is_some_and(|decoded_value| {
                    query_component_matches_cache_bypass(
                        &decoded_name,
                        &decoded_value,
                        configured_params,
                        configured_values,
                    )
                })
            })
            || percent_decode_query_component(value).is_some_and(|decoded_value| {
                query_component_matches_cache_bypass(
                    name,
                    &decoded_value,
                    configured_params,
                    configured_values,
                )
            })
    })
}

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

fn query_component_matches_cache_bypass(
    name: &str,
    value: &str,
    configured_params: &[String],
    configured_values: &std::collections::BTreeMap<String, String>,
) -> bool {
    configured_params
        .iter()
        .any(|configured| configured == name)
        || configured_values
            .get(name)
            .is_some_and(|configured| configured == value)
}

fn percent_decode_query_component(component: &str) -> Option<String> {
    if !component.as_bytes().contains(&b'%') {
        return None;
    }

    let mut decoded = Vec::with_capacity(component.len());
    let mut index = 0usize;
    let bytes = component.as_bytes();
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = bytes.get(index + 1).and_then(|byte| hex_value(*byte))?;
            let low = bytes.get(index + 2).and_then(|byte| hex_value(*byte))?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(decoded).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn remaining_fresh_ttl_secs(ttl_secs: u32, age_secs: u64) -> Option<u32> {
    let remaining = u64::from(ttl_secs).checked_sub(age_secs)?;
    u32::try_from(remaining).ok().filter(|ttl| *ttl > 0)
}

pub fn cache_control_freshness_value(
    ttl_secs: u32,
    stale_while_revalidate_secs: Option<u32>,
    stale_if_error_secs: Option<u32>,
) -> String {
    let mut value = format!("max-age={ttl_secs}");
    if let Some(stale_while_revalidate_secs) = stale_while_revalidate_secs {
        value.push_str(", stale-while-revalidate=");
        value.push_str(&stale_while_revalidate_secs.to_string());
    }
    if let Some(stale_if_error_secs) = stale_if_error_secs {
        value.push_str(", stale-if-error=");
        value.push_str(&stale_if_error_secs.to_string());
    }
    value
}

pub fn response_age_secs(headers: &http::HeaderMap) -> u64 {
    headers
        .get_all("age")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

pub fn response_cache_control_max_age(headers: &http::HeaderMap) -> Option<u32> {
    headers
        .get_all("cache-control")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .find_map(|directive| {
            let (name, value) = directive.trim().split_once('=')?;
            if name.trim().eq_ignore_ascii_case("s-maxage")
                || name.trim().eq_ignore_ascii_case("max-age")
            {
                value.trim().trim_matches('"').parse::<u32>().ok()
            } else {
                None
            }
        })
}

pub fn response_content_type_is_cacheable(
    headers: &http::HeaderMap,
    cache: &fluxheim_config::CacheConfig,
) -> bool {
    let Some(media_type) = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
    else {
        return false;
    };
    cache
        .content_types
        .iter()
        .any(|candidate| content_type_pattern_matches(candidate, media_type))
}

fn content_type_pattern_matches(pattern: &str, media_type: &str) -> bool {
    let pattern = pattern.trim();
    let media_type = media_type.trim();
    if let Some(prefix) = pattern.strip_suffix("/*") {
        let Some((kind, _subtype)) = media_type.split_once('/') else {
            return false;
        };
        return kind.eq_ignore_ascii_case(prefix);
    }
    pattern.eq_ignore_ascii_case(media_type)
}

pub const MAX_VARY_FIELDS: usize = 16;
const MAX_VARY_HEADER_BYTES: usize = 2048;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum VaryCachePolicy {
    None,
    Fields(Vec<String>),
    Uncacheable(&'static str),
}

pub fn cache_vary_policy(
    headers: &http::HeaderMap,
    cache: &fluxheim_config::CacheConfig,
) -> VaryCachePolicy {
    let mut fields = match vary_cache_policy(headers) {
        VaryCachePolicy::None => Vec::new(),
        VaryCachePolicy::Fields(fields) => fields,
        VaryCachePolicy::Uncacheable(reason) => return VaryCachePolicy::Uncacheable(reason),
    };

    for configured in &cache.vary_request_headers {
        let field = configured.to_ascii_lowercase();
        if !fields.contains(&field) {
            fields.push(field);
        }
        if fields.len() > MAX_VARY_FIELDS {
            return VaryCachePolicy::Uncacheable("vary-too-many-fields");
        }
    }

    if fields.is_empty() {
        VaryCachePolicy::None
    } else {
        fields.sort();
        VaryCachePolicy::Fields(fields)
    }
}

pub fn vary_cache_policy(headers: &http::HeaderMap) -> VaryCachePolicy {
    let mut fields = Vec::new();
    let mut total_bytes = 0usize;

    for value in headers.get_all("vary").iter() {
        total_bytes = total_bytes.saturating_add(value.as_bytes().len());
        if total_bytes > MAX_VARY_HEADER_BYTES {
            return VaryCachePolicy::Uncacheable("vary-too-large");
        }

        let Ok(line) = value.to_str() else {
            return VaryCachePolicy::Uncacheable("vary-invalid");
        };

        for raw_field in line.split(',') {
            let field = raw_field.trim();
            if field.is_empty() {
                return VaryCachePolicy::Uncacheable("vary-invalid");
            }
            if field == "*" {
                return VaryCachePolicy::Uncacheable("vary-star");
            }
            if http::header::HeaderName::from_bytes(field.as_bytes()).is_err() {
                return VaryCachePolicy::Uncacheable("vary-invalid");
            }

            let field = field.to_ascii_lowercase();
            if is_sensitive_vary_field(&field) {
                return VaryCachePolicy::Uncacheable("vary-sensitive-field");
            }
            if !fields.contains(&field) {
                fields.push(field);
            }
            if fields.len() > MAX_VARY_FIELDS {
                return VaryCachePolicy::Uncacheable("vary-too-many-fields");
            }
        }
    }

    if fields.is_empty() {
        VaryCachePolicy::None
    } else {
        fields.sort();
        VaryCachePolicy::Fields(fields)
    }
}

fn is_sensitive_vary_field(field: &str) -> bool {
    matches!(field, "authorization" | "cookie" | "proxy-authorization")
}

fn is_pragma_no_cache(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("no-cache")
}

fn cache_control_forces_refresh(value: &str) -> bool {
    value.split(',').any(|directive| {
        let (name, value) = cache_control_directive_parts(directive);
        name.eq_ignore_ascii_case("no-cache")
            || name.eq_ignore_ascii_case("no-store")
            || (name.eq_ignore_ascii_case("max-age") && value == Some("0"))
    })
}

fn cache_control_forces_revalidation(value: &str) -> bool {
    value.split(',').any(|directive| {
        let (name, value) = cache_control_directive_parts(directive);
        name.eq_ignore_ascii_case("no-cache")
            || (name.eq_ignore_ascii_case("max-age") && value == Some("0"))
    })
}

fn cache_control_forbids_store(value: &str) -> bool {
    value.split(',').any(|directive| {
        let (name, _) = cache_control_directive_parts(directive);
        name.eq_ignore_ascii_case("no-store")
    })
}

fn cache_control_directive_parts(directive: &str) -> (&str, Option<&str>) {
    let directive = directive.trim();
    directive
        .split_once('=')
        .map_or((directive, None), |(name, value)| {
            (name.trim(), Some(value.trim()))
        })
}

fn response_cache_control_shared_rejection(value: &str) -> Option<&'static str> {
    value.split(',').find_map(|directive| {
        let directive = directive.trim();
        let (name, value) = directive
            .split_once('=')
            .map_or((directive, None), |(name, value)| {
                (name.trim(), Some(value.trim().trim_matches('"')))
            });

        if name.eq_ignore_ascii_case("no-store") {
            Some("cache-control-no-store")
        } else if name.eq_ignore_ascii_case("private") {
            Some("cache-control-private")
        } else if name.eq_ignore_ascii_case("no-cache") {
            Some("cache-control-no-cache")
        } else if (name.eq_ignore_ascii_case("max-age") || name.eq_ignore_ascii_case("s-maxage"))
            && value == Some("0")
        {
            Some("cache-control-zero-freshness")
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::request_forces_cache_refresh;

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
}
