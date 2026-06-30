use crate::headers_directives::response_cache_control_shared_rejection;
use crate::headers_vary::{VaryCachePolicy, cache_vary_policy};
use crate::request::{response_content_length_matches_range, response_content_range_matches};

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
