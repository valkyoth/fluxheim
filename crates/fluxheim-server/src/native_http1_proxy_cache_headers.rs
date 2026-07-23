use crate::native_http1_cache::NativeMemoryCacheEntry;
use crate::native_http1_proxy_cache_response::native_entry_first_header;
use crate::{NativeHttp1Request, NativeHttp1Response};
use fluxheim_cache::{
    CacheRequestView, VaryRequestHashField, collect_cache_tags, vary_request_hash_material,
};
use fluxheim_config::CacheConfig;
use sha2::{Digest, Sha256};

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
    native_vary_cache_key_for_headers(base_key, fields, &request.headers)
}

pub(crate) fn native_vary_cache_key_for_headers(
    base_key: &str,
    fields: &[String],
    headers: &[(String, String)],
) -> Option<String> {
    let material = vary_request_hash_material(fields.iter().map(|field| {
        VaryRequestHashField {
            name: field.as_str(),
            values: headers
                .iter()
                .filter_map(|(name, value)| {
                    name.eq_ignore_ascii_case(field).then_some(value.as_bytes())
                })
                .collect(),
        }
    }));
    let digest = Sha256::digest(material);
    let variance = base64_ng::URL_SAFE_NO_PAD
        .encode_string(digest.as_ref())
        .ok()?;
    Some(format!("{base_key};vary-sha256:{variance}"))
}

#[cfg(test)]
mod tests {
    use super::native_vary_cache_key_for_headers;

    #[test]
    fn vary_cache_key_has_fixed_width_for_large_header_values() {
        let fields = vec!["accept-language".to_owned()];
        let short = native_vary_cache_key_for_headers(
            "base",
            &fields,
            &[("accept-language".to_owned(), "en".to_owned())],
        )
        .unwrap();
        let long = native_vary_cache_key_for_headers(
            "base",
            &fields,
            &[("accept-language".to_owned(), "x".repeat(32 * 1024))],
        )
        .unwrap();

        assert_eq!(short.len(), long.len());
        assert_eq!(short.len(), "base;vary-sha256:".len() + 43);
        assert_ne!(short, long);
    }
}
