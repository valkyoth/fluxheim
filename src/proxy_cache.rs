use crate::http_types::{
    PingoraRequestHeader as RequestHeader, PingoraResponseHeader as ResponseHeader, StatusCode,
};
use pingora::cache::key::HashBinary;
use pingora::cache::{CacheKey as PingoraCacheKey, CachePhase, NoCacheReason};
use pingora::prelude::Result;
use pingora::{Error, ErrorType};

use crate::flux_error::{FluxError, FluxErrorPingoraExt, FluxResult};

const MULTIPART_SLICE_OVERHEAD_BYTES_PER_RANGE: u64 = 256;
const MULTIPART_SLICE_CLOSING_OVERHEAD_BYTES: u64 = 128;
#[cfg(test)]
pub(crate) use crate::cache::CacheClientRange;
pub(crate) use crate::cache::{
    CacheContentRange, CacheRangeRequest, CacheSliceBounds, CacheSliceRangeRequest,
    CacheStaleEvent, VaryCachePolicy, cache_control_freshness_value, cache_control_with_directive,
    cache_should_serve_stale, cache_vary_policy, parse_bounded_single_range,
    parse_cache_client_ranges, parse_cache_content_range, remaining_fresh_ttl_secs,
    required_slice_bounds, resolve_client_slice_ranges, response_content_type_is_cacheable,
};
#[cfg(test)]
pub(crate) use crate::cache::{MAX_VARY_FIELDS, cache_stale_status_allows, vary_cache_policy};
use crate::cache::{cookie_headers_match_cache_bypass, query_matches_cache_bypass};
use crate::cache::{
    response_age_secs as response_header_age_secs,
    response_cache_control_max_age as response_header_cache_control_max_age,
};

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
    if cookie_headers_match_cache_bypass(
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
pub(crate) struct CacheStatusOverride {
    pub(crate) status: &'static str,
    pub(crate) reason: Option<&'static str>,
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
    if ranges.len() > 1 {
        let Some(multipart_bytes) = requested_bytes
            .checked_add(
                u64::try_from(ranges.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(MULTIPART_SLICE_OVERHEAD_BYTES_PER_RANGE),
            )
            .and_then(|bytes| bytes.checked_add(MULTIPART_SLICE_CLOSING_OVERHEAD_BYTES))
        else {
            return false;
        };
        if multipart_bytes > cache.range.max_bytes.as_u64() {
            return false;
        }
    }
    let slices = required_slice_bounds(ranges, slice_size, u64::MAX);
    !slices.is_empty() && slices.len() <= cache.range.slice.max_slices as usize
}

pub(crate) fn range_cache_key(
    base: PingoraCacheKey,
    range: CacheRangeRequest,
) -> Result<PingoraCacheKey> {
    try_range_cache_key(base, range).map_err(|error| error.into_pingora(ErrorType::InternalError))
}

fn try_range_cache_key(
    mut base: PingoraCacheKey,
    range: CacheRangeRequest,
) -> FluxResult<PingoraCacheKey> {
    let namespace = base.namespace().to_vec();
    let user_tag = base.user_tag.clone();
    let Some(primary) = base.primary_key_str() else {
        return Err(FluxError::InvalidInput(
            "cache range key requires utf-8 primary key material",
        ));
    };
    let mut primary = primary.to_owned();
    append_cache_key_component(&mut primary, "range", &range.component());
    base = PingoraCacheKey::new(namespace, primary, user_tag);
    Ok(base)
}

pub(crate) fn slice_cache_key(
    base: PingoraCacheKey,
    range: CacheRangeRequest,
) -> Result<PingoraCacheKey> {
    try_slice_cache_key(base, range).map_err(|error| error.into_pingora(ErrorType::InternalError))
}

fn try_slice_cache_key(
    mut base: PingoraCacheKey,
    range: CacheRangeRequest,
) -> FluxResult<PingoraCacheKey> {
    let namespace = base.namespace().to_vec();
    let user_tag = base.user_tag.clone();
    let Some(primary) = base.primary_key_str() else {
        return Err(FluxError::InvalidInput(
            "cache slice key requires utf-8 primary key material",
        ));
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
            parse_cache_content_range(value)
                .is_some_and(|range| range.start == expected.start && range.end == expected.end)
        })
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

pub(crate) fn cache_response_fresh_ttl_secs(
    cache: &crate::config::CacheConfig,
    response: &ResponseHeader,
) -> Option<u32> {
    cache
        .status_ttls
        .get(&response.status.as_u16())
        .copied()
        .or(cache.default_status_ttl_secs)
        .or_else(|| response_cache_control_max_age(response))
        .filter(|ttl| *ttl > 0)
}

pub(crate) fn response_age_secs(response: &ResponseHeader) -> u64 {
    response_header_age_secs(&response.headers)
}

pub(crate) fn response_cache_control_max_age(response: &ResponseHeader) -> Option<u32> {
    response_header_cache_control_max_age(&response.headers)
}

pub(crate) fn ignore_origin_cache_headers(
    response: &mut ResponseHeader,
    cache: &crate::config::CacheConfig,
    phase: CachePhase,
) {
    if !cache_request_participated(phase) || !cache.ignore_origin_cache_headers {
        return;
    }
    response.remove_header("cache-control");
    response.remove_header("expires");
}

pub(crate) fn apply_cache_status_ttl(
    response: &mut ResponseHeader,
    cache: &crate::config::CacheConfig,
    phase: CachePhase,
) -> Result<()> {
    if !cache_request_participated(phase) {
        return Ok(());
    }
    let status = response.status.as_u16();
    if let Some(ttl_secs) = cache
        .status_ttls
        .get(&status)
        .copied()
        .or(cache.default_status_ttl_secs)
    {
        if response_cache_header_policy_rejection(response, cache).is_some() {
            return Ok(());
        }
        response.remove_header("expires");
        return response.insert_header(
            "cache-control",
            cache_control_freshness_value(
                ttl_secs,
                cache.stale_while_revalidate_secs,
                cache.stale_if_error_secs,
            ),
        );
    }

    if !response.headers.contains_key("cache-control")
        || response_cache_admission_rejection(response, cache).is_some()
    {
        return Ok(());
    }

    if let Some(stale_while_revalidate_secs) = cache.stale_while_revalidate_secs {
        append_cache_control_directive(
            response,
            &format!("stale-while-revalidate={stale_while_revalidate_secs}"),
            "stale-while-revalidate",
        )?;
    }
    if let Some(stale_if_error_secs) = cache.stale_if_error_secs {
        append_cache_control_directive(
            response,
            &format!("stale-if-error={stale_if_error_secs}"),
            "stale-if-error",
        )?;
    }

    Ok(())
}

pub(crate) fn strip_cache_response_headers(
    response: &mut ResponseHeader,
    cache: &crate::config::CacheConfig,
    phase: CachePhase,
) {
    if !cache_request_participated(phase) {
        return;
    }
    for header in &cache.hide_response_headers {
        response.remove_header(header.as_str());
    }
}

pub(crate) fn cache_request_participated(phase: CachePhase) -> bool {
    !matches!(
        phase,
        CachePhase::Disabled(NoCacheReason::NeverEnabled) | CachePhase::Uninit | CachePhase::Bypass
    )
}

pub(crate) fn proxy_cache_method_temporarily_bypassed(method: &str) -> bool {
    method == "HEAD"
}

pub(crate) fn cache_stale_error_kind(error: &Error) -> crate::config::CacheStaleErrorKind {
    match error.etype() {
        ErrorType::ConnectTimedout
        | ErrorType::TLSHandshakeTimedout
        | ErrorType::ReadTimedout
        | ErrorType::WriteTimedout => crate::config::CacheStaleErrorKind::Timeout,
        ErrorType::ConnectRefused
        | ErrorType::ConnectNoRoute
        | ErrorType::ConnectError
        | ErrorType::SocketError
        | ErrorType::ConnectProxyFailure => crate::config::CacheStaleErrorKind::Connect,
        ErrorType::ReadError => crate::config::CacheStaleErrorKind::Read,
        ErrorType::WriteError => crate::config::CacheStaleErrorKind::Write,
        ErrorType::ConnectionClosed => crate::config::CacheStaleErrorKind::ConnectionClosed,
        ErrorType::InvalidHTTPHeader
        | ErrorType::H1Error
        | ErrorType::H2Error
        | ErrorType::H2Downgrade
        | ErrorType::InvalidH2 => crate::config::CacheStaleErrorKind::Protocol,
        ErrorType::TLSWantX509Lookup
        | ErrorType::TLSHandshakeFailure
        | ErrorType::InvalidCert
        | ErrorType::HandshakeError => crate::config::CacheStaleErrorKind::Tls,
        ErrorType::HTTPStatus(_) => crate::config::CacheStaleErrorKind::HttpStatus,
        _ => crate::config::CacheStaleErrorKind::Other,
    }
}

pub(crate) fn cache_status_header_value(
    phase: CachePhase,
    override_status: Option<CacheStatusOverride>,
) -> Option<&'static str> {
    if let Some(override_status) = override_status {
        return Some(override_status.status);
    }

    match phase {
        CachePhase::Disabled(NoCacheReason::NeverEnabled)
        | CachePhase::Uninit
        | CachePhase::CacheKey => None,
        CachePhase::Disabled(_) | CachePhase::Bypass => Some("BYPASS"),
        CachePhase::Hit => Some("HIT"),
        CachePhase::Miss => Some("MISS"),
        CachePhase::Stale => Some("STALE"),
        CachePhase::StaleUpdating => Some("STALE-UPDATING"),
        CachePhase::Expired => Some("EXPIRED"),
        CachePhase::Revalidated => Some("REVALIDATED"),
        CachePhase::RevalidatedNoCache(_) => Some("REVALIDATED-NOCACHE"),
    }
}

pub(crate) fn cache_status_reason_header_value(
    phase: CachePhase,
    override_status: Option<CacheStatusOverride>,
) -> Option<&'static str> {
    if let Some(override_status) = override_status {
        return override_status.reason;
    }

    match phase {
        CachePhase::Disabled(NoCacheReason::NeverEnabled)
        | CachePhase::Uninit
        | CachePhase::Bypass
        | CachePhase::CacheKey
        | CachePhase::Hit
        | CachePhase::Miss
        | CachePhase::Stale
        | CachePhase::StaleUpdating
        | CachePhase::Expired
        | CachePhase::Revalidated => None,
        CachePhase::Disabled(reason) | CachePhase::RevalidatedNoCache(reason) => {
            Some(reason.as_str())
        }
    }
}

pub(crate) fn append_cache_control_directive(
    response: &mut ResponseHeader,
    directive: &str,
    directive_name: &str,
) -> Result<()> {
    let mut values = Vec::new();
    for value in response.headers.get_all("cache-control").iter() {
        let Ok(value) = value.to_str() else {
            return Ok(());
        };
        values.push(value.to_owned());
    }
    response.remove_header("cache-control");
    response.insert_header(
        "cache-control",
        cache_control_with_directive(values, directive, directive_name),
    )
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
    match cache_vary_policy(headers, cache) {
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
