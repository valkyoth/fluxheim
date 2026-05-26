use pingora::http::RequestHeader;

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

fn request_host_header(request: &RequestHeader) -> Option<&str> {
    request
        .headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .or_else(|| request.uri.authority().map(|authority| authority.as_str()))
}
