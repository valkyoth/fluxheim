use std::collections::BTreeSet;

use self::config_cache_value_validate::{
    cache_sensitive_request_header, validate_cache_bypass_request_header_value,
    validate_cache_content_types, validate_cache_cookie_name, validate_cache_cookie_value,
    validate_cache_extensions, validate_cache_list_len, validate_cache_methods,
    validate_cache_no_store_response_header_value, validate_cache_query_param,
    validate_cache_query_value,
};
use crate::config::ConfigError;
use crate::config_cache::CacheConfig;
use crate::config_cache_policy::{CacheKeyPart, validate_cache_key_namespace};
use crate::config_header::validate_header_name;
use crate::config_route::validate_route_path;

#[path = "config_cache_value_validate.rs"]
mod config_cache_value_validate;

const MAX_CACHE_HEADER_LIST_ENTRIES: usize = 64;
pub const MAX_CACHE_BYPASS_PATHS: usize = 128;
const MAX_CACHE_BYPASS_HEADERS: usize = 64;
pub const MAX_CACHE_BYPASS_COOKIES: usize = 128;
const MAX_CACHE_BYPASS_QUERY_PARAMS: usize = 128;
pub const MAX_CACHE_VARY_REQUEST_HEADERS: usize = 16;
const MAX_CACHE_KEY_PARTS: usize = 4;
pub const MAX_CACHE_CONTENT_TYPES: usize = 64;
pub const MAX_CACHE_IMAGE_EXTENSIONS: usize = 128;
pub const MAX_CACHE_METHODS: usize = 16;
pub const MAX_CACHE_STATUS_TTLS: usize = 128;
const MAX_CACHE_STALE_IF_ERROR_STATUSES: usize = 100;

pub(crate) fn validate_cache_config(
    cache: &CacheConfig,
    scope: &'static str,
) -> Result<(), ConfigError> {
    validate_cache_list_len(
        scope,
        "hide_response_headers",
        cache.hide_response_headers.len(),
        MAX_CACHE_HEADER_LIST_ENTRIES,
    )?;
    validate_cache_list_len(
        scope,
        "tag_headers",
        cache.tag_headers.len(),
        MAX_CACHE_HEADER_LIST_ENTRIES,
    )?;
    validate_cache_list_len(
        scope,
        "no_store_response_headers",
        cache.no_store_response_headers.len(),
        MAX_CACHE_HEADER_LIST_ENTRIES,
    )?;
    validate_cache_list_len(
        scope,
        "no_store_response_header_values",
        cache.no_store_response_header_values.len(),
        MAX_CACHE_HEADER_LIST_ENTRIES,
    )?;
    validate_cache_list_len(
        scope,
        "bypass_path_prefixes",
        cache.bypass_path_prefixes.len(),
        MAX_CACHE_BYPASS_PATHS,
    )?;
    validate_cache_list_len(
        scope,
        "bypass_path_exact",
        cache.bypass_path_exact.len(),
        MAX_CACHE_BYPASS_PATHS,
    )?;
    validate_cache_list_len(
        scope,
        "bypass_request_headers",
        cache.bypass_request_headers.len(),
        MAX_CACHE_BYPASS_HEADERS,
    )?;
    validate_cache_list_len(
        scope,
        "bypass_request_header_values",
        cache.bypass_request_header_values.len(),
        MAX_CACHE_BYPASS_HEADERS,
    )?;
    validate_cache_list_len(
        scope,
        "bypass_cookie_names",
        cache.bypass_cookie_names.len(),
        MAX_CACHE_BYPASS_COOKIES,
    )?;
    validate_cache_list_len(
        scope,
        "bypass_cookie_name_prefixes",
        cache.bypass_cookie_name_prefixes.len(),
        MAX_CACHE_BYPASS_COOKIES,
    )?;
    validate_cache_list_len(
        scope,
        "bypass_cookie_values",
        cache.bypass_cookie_values.len(),
        MAX_CACHE_BYPASS_COOKIES,
    )?;
    validate_cache_list_len(
        scope,
        "bypass_query_params",
        cache.bypass_query_params.len(),
        MAX_CACHE_BYPASS_QUERY_PARAMS,
    )?;
    validate_cache_list_len(
        scope,
        "bypass_query_values",
        cache.bypass_query_values.len(),
        MAX_CACHE_BYPASS_QUERY_PARAMS,
    )?;
    validate_cache_list_len(
        scope,
        "vary_request_headers",
        cache.vary_request_headers.len(),
        MAX_CACHE_VARY_REQUEST_HEADERS,
    )?;
    validate_cache_list_len(
        scope,
        "status_ttls",
        cache.status_ttls.len(),
        MAX_CACHE_STATUS_TTLS,
    )?;
    validate_cache_list_len(
        scope,
        "stale_if_error_statuses",
        cache.stale_if_error_statuses.len(),
        MAX_CACHE_STALE_IF_ERROR_STATUSES,
    )?;
    validate_cache_list_len(
        scope,
        "content_types",
        cache.content_types.len(),
        MAX_CACHE_CONTENT_TYPES,
    )?;
    validate_cache_list_len(
        scope,
        "image_extensions",
        cache.image_extensions.len(),
        MAX_CACHE_IMAGE_EXTENSIONS,
    )?;
    validate_cache_list_len(scope, "methods", cache.methods.len(), MAX_CACHE_METHODS)?;

    if let Some(status_header) = &cache.status_header {
        validate_header_name(scope, status_header)?;
    }
    if let Some(status_reason_header) = &cache.status_reason_header {
        validate_header_name(scope, status_reason_header)?;
    }
    for header in &cache.hide_response_headers {
        validate_header_name(scope, header)?;
    }
    let mut seen_tag_headers = BTreeSet::new();
    for header in &cache.tag_headers {
        validate_header_name(scope, header)?;
        let normalized = header.to_ascii_lowercase();
        if !seen_tag_headers.insert(normalized) {
            return Err(ConfigError::DuplicateCacheTagHeader {
                scope,
                header: header.clone(),
            });
        }
    }
    for header in &cache.no_store_response_headers {
        validate_header_name(scope, header)?;
    }
    for (header, value) in &cache.no_store_response_header_values {
        validate_header_name(scope, header)?;
        validate_cache_no_store_response_header_value(scope, header, value)?;
    }
    for path in &cache.bypass_path_prefixes {
        validate_route_path(scope, path, true).map_err(|_| {
            ConfigError::InvalidCacheBypassPath {
                scope,
                path: path.clone(),
            }
        })?;
    }
    for path in &cache.bypass_path_exact {
        validate_route_path(scope, path, false).map_err(|_| {
            ConfigError::InvalidCacheBypassPath {
                scope,
                path: path.clone(),
            }
        })?;
    }
    for header in &cache.bypass_request_headers {
        validate_header_name(scope, header)?;
    }
    for (header, value) in &cache.bypass_request_header_values {
        validate_header_name(scope, header)?;
        validate_cache_bypass_request_header_value(scope, header, value)?;
    }
    for cookie in &cache.bypass_cookie_names {
        validate_cache_cookie_name(scope, cookie)?;
    }
    for cookie in &cache.bypass_cookie_name_prefixes {
        validate_cache_cookie_name(scope, cookie)?;
    }
    for (cookie, value) in &cache.bypass_cookie_values {
        validate_cache_cookie_name(scope, cookie)?;
        validate_cache_cookie_value(scope, cookie, value)?;
    }
    for param in &cache.bypass_query_params {
        validate_cache_query_param(scope, param)?;
    }
    for (param, value) in &cache.bypass_query_values {
        validate_cache_query_param(scope, param)?;
        validate_cache_query_value(scope, param, value)?;
    }
    for header in &cache.vary_request_headers {
        validate_header_name(scope, header)?;
        if cache_sensitive_request_header(header) {
            return Err(ConfigError::InvalidCacheVaryRequestHeader {
                scope,
                header: header.clone(),
            });
        }
    }
    if let Some(namespace) = &cache.key_namespace {
        validate_cache_key_namespace(scope, namespace)?;
    }
    if cache.key_parts.is_empty() {
        return Err(ConfigError::EmptyCacheKeyParts { scope });
    }
    validate_cache_list_len(
        scope,
        "key_parts",
        cache.key_parts.len(),
        MAX_CACHE_KEY_PARTS,
    )?;
    let mut seen_parts = BTreeSet::new();
    for part in &cache.key_parts {
        if !seen_parts.insert(*part) {
            return Err(ConfigError::DuplicateCacheKeyPart { scope, part: *part });
        }
    }
    if !seen_parts.contains(&CacheKeyPart::Path) {
        return Err(ConfigError::MissingCacheKeyPath { scope });
    }
    if cache.min_uses == 0 {
        return Err(ConfigError::InvalidCacheMinUses { scope });
    }
    for (status, ttl_secs) in &cache.status_ttls {
        if !(100..=599).contains(status) || *ttl_secs == 0 {
            return Err(ConfigError::InvalidCacheStatusTtl {
                scope,
                status: *status,
                ttl_secs: *ttl_secs,
            });
        }
    }
    if cache.default_status_ttl_secs == Some(0) {
        return Err(ConfigError::InvalidCacheDefaultStatusTtl { scope });
    }
    if cache.stale_if_error_secs == Some(0) {
        return Err(ConfigError::InvalidCacheStaleIfErrorTtl { scope });
    }
    if cache.stale_while_revalidate_secs == Some(0) {
        return Err(ConfigError::InvalidCacheStaleWhileRevalidateTtl { scope });
    }
    if cache.stale_if_error_secs.is_some() && cache.stale_if_error_on.is_empty() {
        return Err(ConfigError::EmptyCacheStaleIfErrorOn { scope });
    }
    for status in &cache.stale_if_error_statuses {
        if !(500..=599).contains(status) {
            return Err(ConfigError::InvalidCacheStaleIfErrorStatus {
                scope,
                status: *status,
            });
        }
    }

    validate_cache_content_types(cache, scope)?;
    validate_cache_extensions(cache, scope)?;
    validate_cache_methods(cache, scope)?;

    if cache.max_object_bytes.as_u64() == 0 {
        return Err(ConfigError::InvalidCacheMaxObjectBytes { scope });
    }

    cache.range.validate(scope, cache.max_object_bytes)?;
    cache.lock.validate(scope)?;
    cache.predictor.validate(scope)?;
    cache.origin_protection.validate(scope)?;
    cache.peer_fill.validate(scope)?;

    if cache.enabled && !cache.has_enabled_tier() {
        return Err(ConfigError::CacheEnabledWithoutStorageTier { scope });
    }
    if cache.origin_protection.enabled && !cache.enabled {
        return Err(ConfigError::InvalidCacheOriginProtectionPolicy {
            scope,
            field: "origin_protection.enabled",
            reason: "origin protection requires the cache policy to be enabled",
        });
    }
    if cache.peer_fill.enabled && !cache.enabled {
        return Err(ConfigError::InvalidCachePeerFillPolicy {
            scope,
            field: "peer_fill.enabled",
            reason: "peer fill requires the cache policy to be enabled",
        });
    }

    cache.memory.validate(scope, cache.max_object_bytes)?;
    cache.disk.validate(scope, cache.max_object_bytes)?;
    Ok(())
}
