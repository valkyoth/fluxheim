use std::collections::HashMap;

use fluxheim_cache::{
    CacheRangeRequest, CacheSliceBounds, cache_key_with_component, parse_cache_content_range,
    sanitize_multipart_content_type,
};

use crate::native_http1_cache::NativeMemoryCacheEntry;
use crate::{NativeHttp1Request, NativeHttp1Response};

#[derive(Clone, Debug)]
pub(crate) struct NativeCacheSliceObject {
    pub(crate) entry: NativeMemoryCacheEntry,
    pub(crate) bounds: CacheSliceBounds,
    pub(crate) total: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeCacheSliceIdentity {
    total: u64,
    etag: Option<String>,
    last_modified: Option<String>,
}

#[derive(Debug)]
pub(crate) struct NativeCacheSliceResponse {
    pub(crate) response: NativeHttp1Response,
    pub(crate) filled: bool,
}

pub(crate) fn native_slice_cache_key(base_key: &str, range: CacheRangeRequest) -> String {
    cache_key_with_component(base_key, "slice", &range.component())
}

pub(crate) fn native_slice_object_from_entry(
    entry: NativeMemoryCacheEntry,
) -> Option<NativeCacheSliceObject> {
    let content_range = native_entry_first_header(&entry, "content-range")
        .and_then(|value| parse_cache_content_range(&value))?;
    let total = content_range.total?;
    let bounds = CacheSliceBounds {
        start: content_range.start,
        end: content_range.end,
    };
    (entry.body.len() as u64 == bounds.len()).then_some(NativeCacheSliceObject {
        entry,
        bounds,
        total,
    })
}

pub(crate) fn native_slice_identity(slice: &NativeCacheSliceObject) -> NativeCacheSliceIdentity {
    NativeCacheSliceIdentity {
        total: slice.total,
        etag: native_entry_first_header(&slice.entry, "etag"),
        last_modified: native_entry_first_header(&slice.entry, "last-modified"),
    }
}

pub(crate) fn native_if_range_matches_slice_identity(
    if_range: &str,
    identity: &NativeCacheSliceIdentity,
) -> bool {
    let if_range = if_range.trim();
    identity.etag.as_deref() == Some(if_range)
        || identity.last_modified.as_deref() == Some(if_range)
}

pub(crate) fn native_slice_request_within_policy(
    ranges: &[CacheSliceBounds],
    max_bytes: u64,
    max_slices: usize,
    slice_size: u64,
) -> bool {
    let Some(requested_bytes) = ranges
        .iter()
        .try_fold(0_u64, |sum, range| sum.checked_add(range.len()))
    else {
        return false;
    };
    requested_bytes <= max_bytes
        && !ranges.is_empty()
        && fluxheim_cache::required_slice_bounds(ranges, slice_size, u64::MAX).len() <= max_slices
}

pub(crate) fn native_response_has_non_identity_encoding(response: &NativeHttp1Response) -> bool {
    response.headers().iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-encoding")
            && !value.trim().eq_ignore_ascii_case("identity")
    })
}

pub(crate) fn native_origin_slice_request(
    request: &NativeHttp1Request,
    bounds: CacheSliceBounds,
) -> Option<NativeHttp1Request> {
    if !fluxheim_common::path_safety::safe_forward_path_and_query(&request.target) {
        return None;
    }
    let mut request = request.clone();
    request.method = "GET".to_owned();
    request.body = zeroize::Zeroizing::new(Vec::new());
    request.trailers.clear();
    request.headers.retain(|(name, _)| {
        !name.eq_ignore_ascii_case("range")
            && !name.eq_ignore_ascii_case("if-range")
            && !name.eq_ignore_ascii_case("accept-encoding")
            && !name.eq_ignore_ascii_case("content-length")
            && !name.eq_ignore_ascii_case("transfer-encoding")
    });
    request
        .headers
        .push(("range".to_owned(), bounds.range_request().component()));
    request
        .headers
        .push(("accept-encoding".to_owned(), "identity".to_owned()));
    Some(request)
}

pub(crate) fn native_compose_slice_response(
    ranges: &[CacheSliceBounds],
    slices: &HashMap<(u64, u64), NativeCacheSliceObject>,
    identity: &NativeCacheSliceIdentity,
    filled: bool,
) -> Option<NativeCacheSliceResponse> {
    let first_slice = slices.values().min_by_key(|slice| slice.bounds.start)?;
    if ranges.len() == 1 {
        let range = ranges[0];
        let body = native_compose_single_slice_body(range, slices)?;
        let mut response =
            NativeHttp1Response::new(206, "Partial Content", body).with_content_length(range.len());
        for (name, value) in &first_slice.entry.headers {
            if native_cached_range_response_header_preserved(name) {
                response.push_header(name.clone(), value.clone());
            }
        }
        response.push_header("accept-ranges", "bytes");
        response.push_header(
            "content-range",
            format!("bytes {}-{}/{}", range.start, range.end, identity.total),
        );
        response.push_header("age", native_max_slice_age_secs(slices).to_string());
        return Some(NativeCacheSliceResponse { response, filled });
    }

    let boundary = native_random_multipart_boundary();
    let body = native_compose_multipart_slice_body(ranges, slices, identity.total, &boundary)?;
    let content_length = body.len() as u64;
    let mut response =
        NativeHttp1Response::new(206, "Partial Content", body).with_content_length(content_length);
    for (name, value) in &first_slice.entry.headers {
        if native_cached_range_response_header_preserved(name)
            && !name.eq_ignore_ascii_case("content-type")
        {
            response.push_header(name.clone(), value.clone());
        }
    }
    response.push_header(
        "content-type",
        format!("multipart/byteranges; boundary={boundary}"),
    );
    response.push_header("age", native_max_slice_age_secs(slices).to_string());
    Some(NativeCacheSliceResponse { response, filled })
}

pub(crate) fn native_cached_full_body_range_request(
    entry: &NativeMemoryCacheEntry,
    request: &NativeHttp1Request,
) -> Option<CacheRangeRequest> {
    if request.method != "GET" {
        return None;
    }
    let mut range = None;
    for value in native_request_header_values(request, "range") {
        if range.is_some() {
            return None;
        }
        range = Some(value.trim());
    }
    if let Some(if_range) = native_joined_request_header_values(request, "if-range")
        && !native_if_range_matches_cache(entry, if_range.trim())
    {
        return None;
    }
    native_parse_bounded_single_range(range?)
}

pub(crate) fn native_cached_range_response(
    entry: &NativeMemoryCacheEntry,
    range: CacheRangeRequest,
) -> NativeHttp1Response {
    let total = entry.body.len() as u64;
    if total == 0 || range.start >= total {
        return native_cached_range_not_satisfiable_response(entry, total);
    }

    let end = range.end.min(total.saturating_sub(1));
    let Ok(start) = usize::try_from(range.start) else {
        return native_cached_range_not_satisfiable_response(entry, total);
    };
    let Ok(end_index) = usize::try_from(end) else {
        return native_cached_range_not_satisfiable_response(entry, total);
    };
    let body = entry.body[start..=end_index].to_vec();
    let content_length = body.len() as u64;
    let mut response =
        NativeHttp1Response::new(206, "Partial Content", body).with_content_length(content_length);
    for (name, value) in &entry.headers {
        if native_cached_range_response_header_preserved(name) {
            response.push_header(name.clone(), value.clone());
        }
    }
    response.push_header("accept-ranges", "bytes");
    response.push_header(
        "content-range",
        format!("bytes {}-{}/{}", range.start, end, total),
    );
    response
}

fn native_entry_first_header(entry: &NativeMemoryCacheEntry, name: &str) -> Option<String> {
    entry
        .headers
        .iter()
        .find_map(|(header_name, value)| header_name.eq_ignore_ascii_case(name).then_some(value))
        .cloned()
}

fn native_compose_single_slice_body(
    range: CacheSliceBounds,
    slices: &HashMap<(u64, u64), NativeCacheSliceObject>,
) -> Option<Vec<u8>> {
    let mut body = Vec::with_capacity(usize::try_from(range.len()).ok()?);
    for slice in native_slices_for_range(range, slices) {
        native_append_slice_overlap(&mut body, range, slice)?;
    }
    Some(body)
}

fn native_compose_multipart_slice_body(
    ranges: &[CacheSliceBounds],
    slices: &HashMap<(u64, u64), NativeCacheSliceObject>,
    total: u64,
    boundary: &str,
) -> Option<Vec<u8>> {
    let content_type = sanitize_multipart_content_type(
        &slices
            .values()
            .find_map(|slice| native_entry_first_header(&slice.entry, "content-type"))
            .unwrap_or_else(|| "application/octet-stream".to_owned()),
    );
    let mut body = Vec::new();
    for range in ranges {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Range: bytes {}-{}/{}\r\n\r\n",
                range.start, range.end, total
            )
            .as_bytes(),
        );
        for slice in native_slices_for_range(*range, slices) {
            native_append_slice_overlap(&mut body, *range, slice)?;
        }
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Some(body)
}

fn native_slices_for_range(
    range: CacheSliceBounds,
    slices: &HashMap<(u64, u64), NativeCacheSliceObject>,
) -> Vec<&NativeCacheSliceObject> {
    let mut selected = slices
        .values()
        .filter(|slice| slice.bounds.start <= range.end && slice.bounds.end >= range.start)
        .collect::<Vec<_>>();
    selected.sort_by_key(|slice| slice.bounds.start);
    selected
}

fn native_append_slice_overlap(
    body: &mut Vec<u8>,
    range: CacheSliceBounds,
    slice: &NativeCacheSliceObject,
) -> Option<()> {
    let start = range.start.max(slice.bounds.start);
    let end = range.end.min(slice.bounds.end);
    if end < start {
        return Some(());
    }
    let offset = usize::try_from(start.saturating_sub(slice.bounds.start)).ok()?;
    let len = usize::try_from(end.saturating_sub(start).saturating_add(1)).ok()?;
    let end_offset = offset.checked_add(len)?;
    if end_offset > slice.entry.body.len() {
        return None;
    }
    body.extend_from_slice(&slice.entry.body[offset..end_offset]);
    Some(())
}

fn native_max_slice_age_secs(slices: &HashMap<(u64, u64), NativeCacheSliceObject>) -> u64 {
    slices
        .values()
        .map(|slice| slice.entry.age_secs())
        .max()
        .unwrap_or(0)
}

pub(crate) fn native_slice_not_satisfiable_response(total: u64) -> NativeHttp1Response {
    NativeHttp1Response::new(416, "Range Not Satisfiable", Vec::new())
        .with_content_length(0)
        .with_header("content-range", format!("bytes */{total}"))
}

fn native_random_multipart_boundary() -> String {
    let mut raw = [0_u8; 16];
    if let Err(error) = getrandom::fill(&mut raw) {
        log::error!(
            target: "fluxheim::security",
            "native slice multipart boundary generation failed: {error}; aborting"
        );
        std::process::abort();
    }
    let mut boundary = String::with_capacity("fluxheim-".len() + raw.len() * 2);
    boundary.push_str("fluxheim-");
    for byte in raw {
        use std::fmt::Write as _;
        let _ = write!(&mut boundary, "{byte:02x}");
    }
    boundary
}

fn native_parse_bounded_single_range(value: &str) -> Option<CacheRangeRequest> {
    let value = value.strip_prefix("bytes=")?;
    if value.contains(',') {
        return None;
    }
    let (start, end) = value.split_once('-')?;
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

fn native_if_range_matches_cache(entry: &NativeMemoryCacheEntry, if_range: &str) -> bool {
    if if_range.starts_with('"') {
        return native_cached_header_value(entry, "etag")
            .is_some_and(|etag| etag.trim() == if_range);
    }
    let Some(last_modified) = native_cached_header_value(entry, "last-modified") else {
        return false;
    };
    let Ok(request_time) = httpdate::parse_http_date(if_range) else {
        return false;
    };
    let Ok(cached_time) = httpdate::parse_http_date(last_modified.trim()) else {
        return false;
    };
    cached_time <= request_time
}

fn native_cached_range_not_satisfiable_response(
    entry: &NativeMemoryCacheEntry,
    total: u64,
) -> NativeHttp1Response {
    let mut response =
        NativeHttp1Response::new(416, "Range Not Satisfiable", Vec::new()).with_content_length(0);
    for (name, value) in &entry.headers {
        if native_cached_range_response_header_preserved(name) {
            response.push_header(name.clone(), value.clone());
        }
    }
    response.push_header("accept-ranges", "bytes");
    response.push_header("content-range", format!("bytes */{total}"));
    response
}

fn native_cached_range_response_header_preserved(name: &str) -> bool {
    !name.eq_ignore_ascii_case("content-length")
        && !name.eq_ignore_ascii_case("content-range")
        && !name.eq_ignore_ascii_case("accept-ranges")
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

fn native_request_header_values<'a>(
    request: &'a NativeHttp1Request,
    name: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    request
        .headers
        .iter()
        .filter(move |(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn native_joined_request_header_values(request: &NativeHttp1Request, name: &str) -> Option<String> {
    fluxheim_headers::join_header_values(
        native_request_header_values(request, name).filter(|value| !value.trim().is_empty()),
    )
}
