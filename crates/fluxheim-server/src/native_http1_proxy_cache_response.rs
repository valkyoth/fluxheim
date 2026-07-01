use crate::native_http1_cache::NativeMemoryCacheEntry;
use crate::native_http1_proxy_cache_slice::{
    native_cached_full_body_range_request, native_cached_range_response,
};
use crate::{NativeHttp1Request, NativeHttp1Response};
use fluxheim_cache::CacheRangeRequest;

pub(crate) fn native_entry_first_header(
    entry: &NativeMemoryCacheEntry,
    name: &str,
) -> Option<String> {
    entry
        .headers
        .iter()
        .find_map(|(header_name, value)| header_name.eq_ignore_ascii_case(name).then_some(value))
        .cloned()
}

pub(crate) fn native_cached_hit_response(
    entry: &NativeMemoryCacheEntry,
    request: &NativeHttp1Request,
    range: Option<CacheRangeRequest>,
) -> NativeHttp1Response {
    if native_cached_conditional_not_modified(entry, request) {
        return native_cached_not_modified_response(entry);
    }
    if entry.status == 206 {
        return entry.to_response();
    }
    if let Some(range) = range.or_else(|| native_cached_full_body_range_request(entry, request)) {
        native_cached_range_response(entry, range)
    } else {
        entry.to_response()
    }
}

fn native_cached_conditional_not_modified(
    entry: &NativeMemoryCacheEntry,
    request: &NativeHttp1Request,
) -> bool {
    if let Some(if_none_match) = native_joined_request_header_values(request, "if-none-match") {
        let Some(etag) = native_cached_header_value(entry, "etag") else {
            return false;
        };
        return native_if_none_match_matches(if_none_match.as_str(), etag);
    }

    let Some(if_modified_since) = native_joined_request_header_values(request, "if-modified-since")
    else {
        return false;
    };
    let Some(last_modified) = native_cached_header_value(entry, "last-modified") else {
        return false;
    };
    let Ok(request_time) = httpdate::parse_http_date(if_modified_since.trim()) else {
        return false;
    };
    let Ok(cached_time) = httpdate::parse_http_date(last_modified.trim()) else {
        return false;
    };
    cached_time <= request_time
}

fn native_cached_header_value<'a>(
    entry: &'a NativeMemoryCacheEntry,
    name: &str,
) -> Option<&'a str> {
    entry
        .headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn native_joined_request_header_values(request: &NativeHttp1Request, name: &str) -> Option<String> {
    fluxheim_headers::join_header_values(
        request
            .headers
            .iter()
            .filter(move |(header_name, value)| {
                header_name.eq_ignore_ascii_case(name) && !value.trim().is_empty()
            })
            .map(|(_, value)| value.as_str()),
    )
}

fn native_if_none_match_matches(if_none_match: &str, etag: &str) -> bool {
    let etag = native_weak_etag_value(etag.trim());
    if_none_match.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*" || native_weak_etag_value(candidate) == etag
    })
}

fn native_weak_etag_value(value: &str) -> &str {
    value.strip_prefix("W/").unwrap_or(value)
}

fn native_cached_not_modified_response(entry: &NativeMemoryCacheEntry) -> NativeHttp1Response {
    let mut response = NativeHttp1Response::new(304, "Not Modified", Vec::new());
    for (name, value) in &entry.headers {
        if native_cached_not_modified_response_header_preserved(name) {
            response.push_header(name.clone(), value.clone());
        }
    }
    response
}

fn native_cached_not_modified_response_header_preserved(name: &str) -> bool {
    !name.eq_ignore_ascii_case("content-length")
        && !name.eq_ignore_ascii_case("content-range")
        && !name.eq_ignore_ascii_case("accept-ranges")
}
