use pingora::cache::CacheKey as PingoraCacheKey;
use pingora::cache::key::HashBinary;
use pingora::http::{RequestHeader, ResponseHeader, StatusCode};
use pingora::prelude::Result;
use pingora::{Error, ErrorType};

pub(crate) const MAX_VARY_FIELDS: usize = 16;
const MAX_VARY_HEADER_BYTES: usize = 2048;

pub(crate) fn cache_request_from_header(request: &RequestHeader) -> crate::cache::CacheRequest<'_> {
    crate::cache::CacheRequest {
        method: request.method.as_str(),
        host: request_host_header(request),
        path: request.uri.path(),
        query: request.uri.query(),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn request_cache_bypass(
    request: &RequestHeader,
    cache: &crate::config::CacheConfig,
) -> bool {
    request_cache_bypass_reason(request, cache).is_some()
}

pub(crate) fn request_cache_bypass_reason(
    request: &RequestHeader,
    cache: &crate::config::CacheConfig,
) -> Option<&'static str> {
    let path = request.uri.path();
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
        .any(|header| request.headers.contains_key(header.as_str()))
    {
        return Some("request-header");
    }
    if request_headers_match_cache_bypass_value(request, &cache.bypass_request_header_values) {
        return Some("request-header-value");
    }
    if request_cookies_match_cache_bypass(
        request_header_values(request, "cookie"),
        &cache.bypass_cookie_names,
        &cache.bypass_cookie_name_prefixes,
        &cache.bypass_cookie_values,
    ) {
        return Some("request-cookie");
    }
    if request.uri.query().is_some_and(|query| {
        cache.bypass_query
            || query_matches_cache_bypass(
                query,
                &cache.bypass_query_params,
                &cache.bypass_query_values,
            )
    }) {
        return Some("request-query");
    }

    crate::cache_headers::request_values_forbid_cache_store(request_header_values(
        request,
        "cache-control",
    ))
    .then_some("request-no-store")
}

pub(crate) fn request_cache_revalidation_requested(
    request: &RequestHeader,
    cache: &crate::config::CacheConfig,
) -> bool {
    if !cache.allow_client_cache_refresh {
        return false;
    }
    crate::cache_headers::request_values_force_cache_revalidation(
        request_header_values(request, "cache-control"),
        request_header_values(request, "pragma"),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CacheRangeRequest {
    pub(crate) start: u64,
    pub(crate) end: u64,
}

impl CacheRangeRequest {
    pub(crate) fn len(self) -> u64 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }

    pub(crate) fn component(self) -> String {
        format!("bytes={}-{}", self.start, self.end)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CacheClientRange {
    Bounded { start: u64, end: u64 },
    OpenEnded { start: u64 },
    Suffix { len: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CacheSliceRangeRequest {
    pub(crate) ranges: Vec<CacheClientRange>,
    pub(crate) if_range: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CacheSliceBounds {
    pub(crate) start: u64,
    pub(crate) end: u64,
}

impl CacheSliceBounds {
    pub(crate) fn len(self) -> u64 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }

    pub(crate) fn range_request(self) -> CacheRangeRequest {
        CacheRangeRequest {
            start: self.start,
            end: self.end,
        }
    }
}

pub(crate) fn selected_cache_range_request(
    request: &RequestHeader,
    cache: &crate::config::CacheConfig,
) -> Option<CacheRangeRequest> {
    if !cache.range.enabled || request.method.as_str() != "GET" {
        return None;
    }
    let mut values = request_header_values(request, "range");
    let range = values.next()?;
    if values.next().is_some() {
        return None;
    }
    if request_header_values(request, "if-range").next().is_some() {
        return None;
    }
    let parsed = parse_bounded_single_range(range)?;
    (parsed.len() <= cache.range.max_bytes.as_u64()).then_some(parsed)
}

pub(crate) fn parse_bounded_single_range(range: &str) -> Option<CacheRangeRequest> {
    let range = range.trim();
    let range = range.strip_prefix("bytes=")?;
    if range.contains(',') {
        return None;
    }
    let (start, end) = range.split_once('-')?;
    if start.is_empty() || end.is_empty() {
        return None;
    }
    let start = start.parse::<u64>().ok()?;
    let end = end.parse::<u64>().ok()?;
    if end < start {
        return None;
    }
    Some(CacheRangeRequest { start, end })
}

pub(crate) fn selected_cache_slice_range_request(
    request: &RequestHeader,
    cache: &crate::config::CacheConfig,
) -> Option<CacheSliceRangeRequest> {
    if !cache.range.enabled || !cache.range.slice.enabled || request.method.as_str() != "GET" {
        return None;
    }
    let mut values = request_header_values(request, "range");
    let range = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let if_range = request_header_values_joined(request, "if-range");
    parse_cache_client_ranges(range).map(|ranges| CacheSliceRangeRequest { ranges, if_range })
}

pub(crate) fn parse_cache_client_ranges(value: &str) -> Option<Vec<CacheClientRange>> {
    let value = value.trim();
    let value = value.strip_prefix("bytes=")?;
    let mut ranges = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        let (start, end) = part.split_once('-')?;
        if start.is_empty() {
            let len = end.parse::<u64>().ok()?;
            if len == 0 {
                return None;
            }
            ranges.push(CacheClientRange::Suffix { len });
        } else if end.is_empty() {
            ranges.push(CacheClientRange::OpenEnded {
                start: start.parse::<u64>().ok()?,
            });
        } else {
            let start = start.parse::<u64>().ok()?;
            let end = end.parse::<u64>().ok()?;
            if end < start {
                return None;
            }
            ranges.push(CacheClientRange::Bounded { start, end });
        }
    }
    (!ranges.is_empty()).then_some(ranges)
}

pub(crate) fn resolve_client_slice_ranges(
    ranges: &[CacheClientRange],
    total: u64,
) -> Option<Vec<CacheSliceBounds>> {
    if total == 0 {
        return Some(Vec::new());
    }
    let last = total.saturating_sub(1);
    let mut resolved = Vec::new();
    for range in ranges {
        match *range {
            CacheClientRange::Bounded { start, end } => {
                if start > last {
                    continue;
                }
                resolved.push(CacheSliceBounds {
                    start,
                    end: end.min(last),
                });
            }
            CacheClientRange::OpenEnded { start } => {
                if start > last {
                    continue;
                }
                resolved.push(CacheSliceBounds { start, end: last });
            }
            CacheClientRange::Suffix { len } => {
                if len == 0 {
                    continue;
                }
                resolved.push(CacheSliceBounds {
                    start: total.saturating_sub(len),
                    end: last,
                });
            }
        }
    }
    Some(resolved)
}

pub(crate) fn slice_request_within_policy(
    ranges: &[CacheSliceBounds],
    cache: &crate::config::CacheConfig,
    slice_size: u64,
) -> bool {
    let requested_bytes = ranges
        .iter()
        .try_fold(0_u64, |sum, range| sum.checked_add(range.len()));
    let Some(requested_bytes) = requested_bytes else {
        return false;
    };
    if requested_bytes > cache.range.max_bytes.as_u64() {
        return false;
    }
    let slices = required_slice_bounds(ranges, slice_size, u64::MAX);
    !slices.is_empty() && slices.len() <= cache.range.slice.max_slices as usize
}

pub(crate) fn required_slice_bounds(
    ranges: &[CacheSliceBounds],
    slice_size: u64,
    total: u64,
) -> Vec<CacheSliceBounds> {
    let mut slices = Vec::new();
    let last = total.saturating_sub(1);
    for range in ranges {
        let mut start = (range.start / slice_size).saturating_mul(slice_size);
        while start <= range.end && start <= last {
            let end = start.saturating_add(slice_size.saturating_sub(1)).min(last);
            let slice = CacheSliceBounds { start, end };
            if !slices.contains(&slice) {
                slices.push(slice);
            }
            let Some(next) = start.checked_add(slice_size) else {
                break;
            };
            start = next;
        }
    }
    slices.sort_by_key(|slice| slice.start);
    slices
}

pub(crate) fn range_cache_key(
    mut base: PingoraCacheKey,
    range: CacheRangeRequest,
) -> Result<PingoraCacheKey> {
    let namespace = base.namespace().to_vec();
    let user_tag = base.user_tag.clone();
    let Some(primary) = base.primary_key_str() else {
        return Error::e_explain(
            ErrorType::InternalError,
            "cache range key requires utf-8 primary key material",
        );
    };
    let mut primary = primary.to_owned();
    append_cache_key_component(&mut primary, "range", &range.component());
    base = PingoraCacheKey::new(namespace, primary, user_tag);
    Ok(base)
}

pub(crate) fn slice_cache_key(
    mut base: PingoraCacheKey,
    range: CacheRangeRequest,
) -> Result<PingoraCacheKey> {
    let namespace = base.namespace().to_vec();
    let user_tag = base.user_tag.clone();
    let Some(primary) = base.primary_key_str() else {
        return Error::e_explain(
            ErrorType::InternalError,
            "cache slice key requires utf-8 primary key material",
        );
    };
    let mut primary = primary.to_owned();
    append_cache_key_component(&mut primary, "slice", &range.component());
    base = PingoraCacheKey::new(namespace, primary, user_tag);
    Ok(base)
}

pub(crate) fn append_cache_key_component(key: &mut String, label: &str, value: &str) {
    use std::fmt::Write as _;
    let _ = write!(key, "{label}:{}:{value};", value.len());
}

pub(crate) fn range_response_cache_admission_rejection(
    response: &ResponseHeader,
    range: Option<CacheRangeRequest>,
) -> Option<&'static str> {
    match range {
        Some(range) => {
            if response.status != StatusCode::PARTIAL_CONTENT {
                return Some("range-cache-non-partial");
            }
            if !content_range_matches(response, range) {
                return Some("range-cache-content-range");
            }
            if !content_length_matches_range(response, range) {
                return Some("range-cache-content-length");
            }
            None
        }
        None if response.status == StatusCode::PARTIAL_CONTENT => Some("range-response"),
        None => None,
    }
}

fn content_range_matches(response: &ResponseHeader, expected: CacheRangeRequest) -> bool {
    response
        .headers
        .get_all("content-range")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            parse_content_range_bounds(value)
                .is_some_and(|range| range.start == expected.start && range.end == expected.end)
        })
}

fn parse_content_range_bounds(value: &str) -> Option<CacheRangeRequest> {
    let value = value.trim();
    let rest = value.strip_prefix("bytes ")?;
    let (range, _complete_len) = rest.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start = start.parse::<u64>().ok()?;
    let end = end.parse::<u64>().ok()?;
    if end < start {
        return None;
    }
    Some(CacheRangeRequest { start, end })
}

fn content_length_matches_range(response: &ResponseHeader, expected: CacheRangeRequest) -> bool {
    response
        .headers
        .get_all("content-length")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.trim().parse::<u64>().ok() == Some(expected.len()))
}

pub(crate) fn response_cache_admission_rejection(
    response: &ResponseHeader,
    cache: &crate::config::CacheConfig,
) -> Option<&'static str> {
    let headers = &response.headers;
    let status = response.status.as_u16();
    let status_has_ttl =
        cache.status_ttls.contains_key(&status) || cache.default_status_ttl_secs.is_some();
    if response.status != StatusCode::OK && !status_has_ttl {
        return Some("status-not-cacheable");
    }

    if response.status == StatusCode::OK && !response_content_type_is_cacheable(headers, cache) {
        return if headers.contains_key("content-type") {
            Some("content-type-not-cacheable")
        } else {
            Some("content-type-missing")
        };
    }

    response_cache_header_policy_rejection(response, cache)
}

pub(crate) fn response_range_cache_admission_rejection(
    response: &ResponseHeader,
    cache: &crate::config::CacheConfig,
) -> Option<&'static str> {
    let headers = &response.headers;
    if !response_content_type_is_cacheable(headers, cache) {
        return if headers.contains_key("content-type") {
            Some("content-type-not-cacheable")
        } else {
            Some("content-type-missing")
        };
    }

    response_cache_header_policy_rejection(response, cache)
}

fn response_cache_header_policy_rejection(
    response: &ResponseHeader,
    cache: &crate::config::CacheConfig,
) -> Option<&'static str> {
    let headers = &response.headers;
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
    if response_headers_match_cache_no_store_value(response, &cache.no_store_response_header_values)
    {
        return Some("configured-no-store-response-header-value");
    }
    if let Some(reason) = crate::cache_headers::response_values_forbid_shared_cache(
        response_header_values(response, "cache-control"),
    ) {
        return Some(reason);
    }
    match vary_cache_policy(headers) {
        VaryCachePolicy::Uncacheable(reason) => Some(reason),
        VaryCachePolicy::None | VaryCachePolicy::Fields(_) => None,
    }
}

fn response_headers_match_cache_no_store_value(
    response: &ResponseHeader,
    configured_values: &std::collections::BTreeMap<String, String>,
) -> bool {
    !configured_values.is_empty()
        && configured_values.iter().any(|(header, configured)| {
            response_header_values(response, header).any(|value| value == configured)
        })
}

pub(crate) fn cache_vary_policy(
    headers: &http::HeaderMap,
    cache: &crate::config::CacheConfig,
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

fn response_content_type_is_cacheable(
    headers: &http::HeaderMap,
    cache: &crate::config::CacheConfig,
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum VaryCachePolicy {
    None,
    Fields(Vec<String>),
    Uncacheable(&'static str),
}

pub(crate) fn vary_cache_policy(headers: &http::HeaderMap) -> VaryCachePolicy {
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

pub(crate) fn vary_request_hash(fields: &[String], request: &RequestHeader) -> HashBinary {
    let mut material = Vec::new();
    material.extend_from_slice(b"fluxheim-vary-v2");

    for field in fields {
        append_vary_hash_component(&mut material, field.as_bytes());
        let values = request.headers.get_all(field.as_str());
        material.extend_from_slice(&(values.iter().count() as u32).to_le_bytes());
        for value in request.headers.get_all(field.as_str()).iter() {
            append_vary_hash_component(&mut material, value.as_bytes());
        }
    }

    pingora::cache::key::hash_key(material)
}

fn append_vary_hash_component(material: &mut Vec<u8>, bytes: &[u8]) {
    material.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    material.extend_from_slice(bytes);
}

fn request_headers_match_cache_bypass_value(
    request: &RequestHeader,
    configured_values: &std::collections::BTreeMap<String, String>,
) -> bool {
    !configured_values.is_empty()
        && configured_values.iter().any(|(header, configured)| {
            request_header_values(request, header).any(|value| value == configured)
        })
}

fn request_cookies_match_cache_bypass<'a>(
    cookie_headers: impl Iterator<Item = &'a str>,
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

fn query_matches_cache_bypass(
    query: &str,
    configured_params: &[String],
    configured_values: &std::collections::BTreeMap<String, String>,
) -> bool {
    if configured_params.is_empty() && configured_values.is_empty() {
        return false;
    }
    query.split('&').any(|part| {
        let (name, value) = part.split_once('=').unwrap_or((part, ""));
        !name.is_empty()
            && (configured_params
                .iter()
                .any(|configured| configured == name)
                || configured_values
                    .get(name)
                    .is_some_and(|configured| configured == value))
    })
}

fn request_header_values<'a>(
    request: &'a RequestHeader,
    name: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    request
        .headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
}

fn request_header_values_joined(request: &RequestHeader, name: &str) -> Option<String> {
    let mut values = request_header_values(request, name);
    let first = values.next()?.to_owned();
    Some(values.fold(first, |mut joined, value| {
        joined.push_str(", ");
        joined.push_str(value);
        joined
    }))
}

fn response_header_values<'a>(
    response: &'a ResponseHeader,
    name: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    response
        .headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
}

fn request_host_header(request: &RequestHeader) -> Option<&str> {
    request
        .headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .or_else(|| request.uri.authority().map(|authority| authority.as_str()))
}
