use crate::headers_directives::{
    cache_control_forbids_store, cache_control_forces_refresh, cache_control_forces_revalidation,
    is_pragma_no_cache,
};
use crate::request::{parse_bounded_single_range, parse_cache_client_ranges};

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
    if request.contains_header("authorization") {
        return Some("request-authorization");
    }
    if request.contains_header("proxy-authorization") {
        return Some("request-proxy-authorization");
    }
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

fn cookie_header_pairs(header: &str) -> impl Iterator<Item = (&str, &str)> {
    header.split(';').filter_map(|part| {
        let (name, value) = part.trim_start().split_once('=')?;
        (!name.is_empty()).then_some((name, value))
    })
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
