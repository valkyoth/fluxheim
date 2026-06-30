use crate::headers_directives::{
    cache_control_forbids_store, cache_control_forces_refresh, cache_control_forces_revalidation,
    is_pragma_no_cache, response_cache_control_shared_rejection,
};
use crate::request::{
    parse_bounded_single_range, parse_cache_client_ranges, response_content_length_matches_range,
    response_content_range_matches,
};

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

pub trait CacheRequestView {
    fn method(&self) -> &str;

    fn path(&self) -> &str;

    fn query(&self) -> Option<&str>;

    fn contains_header(&self, name: &str) -> bool;

    fn visit_header_values(&self, name: &str, visitor: &mut dyn FnMut(&str));
}

pub fn request_cache_bypass_reason(
    request: &impl CacheRequestView,
    cache: &fluxheim_config::CacheConfig,
) -> Option<&'static str> {
    let path = request.path();
    if cache
        .bypass_path_exact
        .iter()
        .any(|configured| configured == path)
        || cache
            .bypass_path_prefixes
            .iter()
            .any(|configured| path.starts_with(configured))
    {
        return Some("request-path");
    }
    if cache
        .bypass_request_headers
        .iter()
        .any(|header| request.contains_header(header.as_str()))
    {
        return Some("request-header");
    }
    if request_headers_match_cache_bypass_value(request, &cache.bypass_request_header_values) {
        return Some("request-header-value");
    }
    if request_cookie_headers_match_cache_bypass(request, cache) {
        return Some("request-cookie");
    }
    if request.query().is_some_and(|query| {
        cache.bypass_query
            || query_matches_cache_bypass(
                query,
                &cache.bypass_query_params,
                &cache.bypass_query_values,
            )
    }) {
        return Some("request-query");
    }

    request_values_match(request, "cache-control", cache_control_forbids_store)
        .then_some("request-no-store")
}

pub fn request_cache_revalidation_requested(
    request: &impl CacheRequestView,
    cache: &fluxheim_config::CacheConfig,
) -> bool {
    cache.allow_client_cache_refresh
        && (request_values_match(request, "pragma", is_pragma_no_cache)
            || request_values_match(request, "cache-control", cache_control_forces_revalidation))
}

pub fn selected_cache_range_request(
    request: &impl CacheRequestView,
    cache: &fluxheim_config::CacheConfig,
) -> Option<crate::CacheRangeRequest> {
    if !cache.range.enabled || request.method() != "GET" {
        return None;
    }
    let mut range = None;
    let mut multiple_ranges = false;
    request.visit_header_values("range", &mut |value| {
        if range.is_some() {
            multiple_ranges = true;
        } else {
            range = Some(value.to_owned());
        }
    });
    if multiple_ranges {
        return None;
    }
    if request_has_header_value(request, "if-range") {
        return None;
    }
    let parsed = parse_bounded_single_range(range.as_deref()?)?;
    (parsed.len() <= cache.range.max_bytes.as_u64()).then_some(parsed)
}

pub fn selected_cache_slice_range_request(
    request: &impl CacheRequestView,
    cache: &fluxheim_config::CacheConfig,
) -> Option<crate::CacheSliceRangeRequest> {
    if !cache.range.enabled || !cache.range.slice.enabled || request.method() != "GET" {
        return None;
    }
    let mut range = None;
    let mut multiple_ranges = false;
    request.visit_header_values("range", &mut |value| {
        if range.is_some() {
            multiple_ranges = true;
        } else {
            range = Some(value.to_owned());
        }
    });
    if multiple_ranges {
        return None;
    }
    parse_cache_client_ranges(range.as_deref()?).map(|ranges| crate::CacheSliceRangeRequest {
        ranges,
        if_range: request_header_values_joined(request, "if-range"),
    })
}

pub fn response_values_forbid_shared_cache<'a>(
    cache_control: impl IntoIterator<Item = &'a str>,
) -> Option<&'static str> {
    cache_control
        .into_iter()
        .find_map(response_cache_control_shared_rejection)
}

pub fn sanitize_multipart_content_type(value: &str) -> String {
    let sanitized = value
        .chars()
        .filter(|character| *character != '\r' && *character != '\n')
        .collect::<String>();
    if sanitized.is_empty() {
        "application/octet-stream".to_owned()
    } else {
        sanitized
    }
}

pub fn first_header_value(headers: &http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .next()
        .map(ToOwned::to_owned)
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

fn request_headers_match_cache_bypass_value(
    request: &impl CacheRequestView,
    configured_values: &std::collections::BTreeMap<String, String>,
) -> bool {
    !configured_values.is_empty()
        && configured_values.iter().any(|(header, configured)| {
            let mut matched = false;
            request.visit_header_values(header, &mut |value| {
                matched |= value == configured;
            });
            matched
        })
}

fn request_cookie_headers_match_cache_bypass(
    request: &impl CacheRequestView,
    cache: &fluxheim_config::CacheConfig,
) -> bool {
    if cache.bypass_cookie_names.is_empty()
        && cache.bypass_cookie_name_prefixes.is_empty()
        && cache.bypass_cookie_values.is_empty()
    {
        return false;
    }

    let mut matched = false;
    request.visit_header_values("cookie", &mut |value| {
        matched |= cookie_headers_match_cache_bypass(
            [value],
            &cache.bypass_cookie_names,
            &cache.bypass_cookie_name_prefixes,
            &cache.bypass_cookie_values,
        );
    });
    matched
}

fn request_values_match(
    request: &impl CacheRequestView,
    name: &str,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    let mut matched = false;
    request.visit_header_values(name, &mut |value| {
        matched |= predicate(value);
    });
    matched
}

fn request_has_header_value(request: &impl CacheRequestView, name: &str) -> bool {
    let mut found = false;
    request.visit_header_values(name, &mut |_| {
        found = true;
    });
    found
}

fn request_header_values_joined(request: &impl CacheRequestView, name: &str) -> Option<String> {
    let mut joined = None::<String>;
    request.visit_header_values(name, &mut |value| {
        if let Some(joined) = &mut joined {
            joined.push_str(", ");
            joined.push_str(value);
        } else {
            joined = Some(value.to_owned());
        }
    });
    joined
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

pub fn cache_control_with_directive<S: AsRef<str>>(
    values: impl IntoIterator<Item = S>,
    directive: &str,
    directive_name: &str,
) -> String {
    let mut directives = Vec::new();
    for value in values {
        directives.extend(
            value
                .as_ref()
                .split(',')
                .map(str::trim)
                .filter(|part| {
                    !part.is_empty()
                        && !part
                            .split_once('=')
                            .map(|(name, _)| name.trim())
                            .unwrap_or(part)
                            .eq_ignore_ascii_case(directive_name)
                })
                .map(str::to_owned),
        );
    }

    directives.push(directive.to_owned());
    directives.join(", ")
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

pub fn range_response_cache_admission_rejection(
    status: u16,
    headers: &http::HeaderMap,
    range: Option<crate::CacheRangeRequest>,
) -> Option<&'static str> {
    match range {
        Some(range) => {
            if status != 206 {
                return Some("range-cache-non-partial");
            }
            if !response_content_range_matches(headers, range) {
                return Some("range-cache-content-range");
            }
            if !response_content_length_matches_range(headers, range) {
                return Some("range-cache-content-length");
            }
            None
        }
        None if status == 206 => Some("range-response"),
        None => None,
    }
}

pub fn response_cache_admission_rejection(
    status: u16,
    headers: &http::HeaderMap,
    cache: &fluxheim_config::CacheConfig,
) -> Option<&'static str> {
    let status_has_ttl =
        cache.status_ttls.contains_key(&status) || cache.default_status_ttl_secs.is_some();
    if status != 200 && !status_has_ttl {
        return Some("status-not-cacheable");
    }

    if status == 200 && !response_content_type_is_cacheable(headers, cache) {
        return if headers.contains_key("content-type") {
            Some("content-type-not-cacheable")
        } else {
            Some("content-type-missing")
        };
    }

    response_cache_header_policy_rejection(headers, cache)
}

pub fn response_range_cache_admission_rejection(
    headers: &http::HeaderMap,
    cache: &fluxheim_config::CacheConfig,
) -> Option<&'static str> {
    if !response_content_type_is_cacheable(headers, cache) {
        return if headers.contains_key("content-type") {
            Some("content-type-not-cacheable")
        } else {
            Some("content-type-missing")
        };
    }

    response_cache_header_policy_rejection(headers, cache)
}

pub fn response_cache_header_policy_rejection(
    headers: &http::HeaderMap,
    cache: &fluxheim_config::CacheConfig,
) -> Option<&'static str> {
    if headers.contains_key("set-cookie") {
        return Some("set-cookie");
    }
    if cache
        .no_store_response_headers
        .iter()
        .any(|header| headers.contains_key(header.as_str()))
    {
        return Some("configured-no-store-response-header");
    }
    if response_headers_match_cache_no_store_value(headers, &cache.no_store_response_header_values)
    {
        return Some("configured-no-store-response-header-value");
    }
    if let Some(reason) = response_values_forbid_shared_cache(
        headers
            .get_all("cache-control")
            .iter()
            .filter_map(|value| value.to_str().ok()),
    ) {
        return Some(reason);
    }
    match cache_vary_policy(headers, cache) {
        VaryCachePolicy::Uncacheable(reason) => Some(reason),
        VaryCachePolicy::None | VaryCachePolicy::Fields(_) => None,
    }
}

fn response_headers_match_cache_no_store_value(
    headers: &http::HeaderMap,
    configured_values: &std::collections::BTreeMap<String, String>,
) -> bool {
    !configured_values.is_empty()
        && configured_values.iter().any(|(header, configured)| {
            headers
                .get_all(header.as_str())
                .iter()
                .filter_map(|value| value.to_str().ok())
                .any(|value| value == configured)
        })
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

pub struct VaryRequestHashField<'a> {
    pub name: &'a str,
    pub values: Vec<&'a [u8]>,
}

pub fn vary_request_hash_material<'a>(
    fields: impl IntoIterator<Item = VaryRequestHashField<'a>>,
) -> Vec<u8> {
    let mut material = Vec::new();
    material.extend_from_slice(b"fluxheim-vary-v2");

    for field in fields {
        append_vary_hash_component(&mut material, field.name.as_bytes());
        material.extend_from_slice(&(field.values.len() as u32).to_le_bytes());
        for value in field.values {
            append_vary_hash_component(&mut material, value);
        }
    }

    material
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

fn append_vary_hash_component(material: &mut Vec<u8>, bytes: &[u8]) {
    material.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    material.extend_from_slice(bytes);
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
