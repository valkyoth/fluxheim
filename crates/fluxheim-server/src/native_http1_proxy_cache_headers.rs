use crate::native_http1_cache::NativeMemoryCacheEntry;
use crate::native_http1_proxy_cache_response::native_entry_first_header;
use crate::{NativeHttp1Request, NativeHttp1Response};
use fluxheim_cache::{
    CacheRequestView, VaryRequestHashField, collect_cache_tags, vary_request_hash_material,
};
use fluxheim_config::CacheConfig;

pub(crate) fn native_cache_entry_revalidatable(
    entry: &NativeMemoryCacheEntry,
    now: std::time::Instant,
) -> bool {
    entry.expires_at <= now
        && (native_entry_first_header(entry, "etag").is_some()
            || native_entry_first_header(entry, "last-modified").is_some())
}

pub(crate) fn native_cache_revalidation_request(
    mut request: NativeHttp1Request,
    entry: &NativeMemoryCacheEntry,
) -> NativeHttp1Request {
    if !request.contains_header("if-none-match")
        && let Some(etag) = native_entry_first_header(entry, "etag")
    {
        request.headers.push(("if-none-match".to_owned(), etag));
        return request;
    }
    if !request.contains_header("if-modified-since")
        && let Some(last_modified) = native_entry_first_header(entry, "last-modified")
    {
        request
            .headers
            .push(("if-modified-since".to_owned(), last_modified));
    }
    request
}

pub(crate) fn native_not_modified_refresh_header_skipped(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("content-range")
        || name.eq_ignore_ascii_case("transfer-encoding")
}

pub(crate) fn native_request_cache_only_if_cached(request: &NativeHttp1Request) -> bool {
    request
        .headers
        .iter()
        .filter(|(header_name, _)| header_name.eq_ignore_ascii_case("cache-control"))
        .any(|(_, value)| {
            value
                .split(',')
                .any(|directive| directive.trim().eq_ignore_ascii_case("only-if-cached"))
        })
}

pub(crate) fn cached_proxy_headers(
    response: &NativeHttp1Response,
    cache: &CacheConfig,
) -> Vec<(String, String)> {
    response
        .headers()
        .iter()
        .filter(|(name, _)| {
            !name.eq_ignore_ascii_case("age")
                && !cache
                    .hide_response_headers
                    .iter()
                    .any(|hidden| hidden.eq_ignore_ascii_case(name))
        })
        .cloned()
        .collect()
}

pub(crate) fn native_response_cache_tags(
    response: &NativeHttp1Response,
    cache: &CacheConfig,
) -> Vec<String> {
    let mut tags = Vec::new();
    let mut total_bytes = 0_usize;
    for tag_header in &cache.tag_headers {
        for (_, value) in response
            .headers()
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(tag_header))
        {
            collect_cache_tags(value, &mut tags, &mut total_bytes);
        }
    }
    tags
}

pub(crate) fn native_vary_cache_key(
    base_key: &str,
    fields: &[String],
    request: &NativeHttp1Request,
) -> Option<String> {
    let material = vary_request_hash_material(fields.iter().map(|field| {
        VaryRequestHashField {
            name: field.as_str(),
            values: request
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    name.eq_ignore_ascii_case(field).then_some(value.as_bytes())
                })
                .collect(),
        }
    }));
    let variance = base64_ng::URL_SAFE_NO_PAD.encode_string(&material).ok()?;
    Some(format!("{base_key};vary:{variance}"))
}
