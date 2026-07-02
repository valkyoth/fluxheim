use std::error::Error;

use crate::config::Config;

#[cfg(all(feature = "cache", feature = "proxy"))]
use crate::http_types::NativeCachePreviewRequest;

#[cfg(all(feature = "cache", feature = "proxy"))]
use super::{
    cache_warm_support::{
        cache_warm_default_host, validate_cache_warm_host, validate_cache_warm_path,
    },
    command_options::CacheKeyOptions,
};

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn cache_key_command_request(
    options: &CacheKeyOptions<'_>,
) -> Result<(Config, NativeCachePreviewRequest), Box<dyn Error + Send + Sync>> {
    let config = Config::load(options.config_path)?;
    config.validate()?;

    let host = match options.host.as_deref() {
        Some(host) => {
            validate_cache_warm_host(host)?;
            host.to_owned()
        }
        None => cache_warm_default_host(&config)
            .ok_or("cache-key requires --host when no default vhost host is configured")?,
    };
    let uri = cache_key_uri(&options.path, options.query.as_deref())?;
    validate_cache_key_method(&options.method)?;

    let mut request =
        NativeCachePreviewRequest::build(options.method.as_str(), uri.as_bytes(), None)?;
    request.insert_header("host", host.as_str())?;
    if options.headers.len() > 32 {
        return Err("cache-key accepts at most 32 --header values".into());
    }
    for (name, value) in parse_cache_cli_headers("cache-key", &options.headers)? {
        request.insert_header(name, value)?;
    }
    Ok((config, request))
}

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn print_optional_unix(label: &str, value: Option<u64>) {
    match value {
        Some(value) => println!("{label}: {value}"),
        None => println!("{label}: unavailable"),
    }
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn cache_key_uri(path: &str, query: Option<&str>) -> Result<String, Box<dyn Error + Send + Sync>> {
    validate_cache_warm_path(path)?;
    if path.contains('?') && query.is_some() {
        return Err("cache-key accepts query in either --path or --query, not both".into());
    }
    let Some(query) = query else {
        return Ok(path.to_owned());
    };
    validate_cache_key_query(query)?;
    Ok(format!("{path}?{query}"))
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn validate_cache_key_method(method: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    if method.is_empty() || method.len() > 32 {
        return Err("method must be 1-32 bytes".into());
    }
    if method
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err("method contains control or whitespace bytes".into());
    }
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn validate_cache_key_query(query: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    if query.len() > 8192 {
        return Err("query must be at most 8192 bytes".into());
    }
    if query
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err("query contains control or whitespace bytes".into());
    }
    if query.starts_with('?') || query.contains('#') {
        return Err("query must not start with ? or contain #".into());
    }
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
#[derive(Clone, Copy)]
pub(super) struct CacheKeyPreviewExpectations<'a> {
    pub(super) expect_eligible: bool,
    pub(super) expect_ineligible: bool,
    pub(super) expected_reason: Option<&'a str>,
    pub(super) expect_cache_lock_enabled: bool,
    pub(super) expected_cache_lock_wait_timeout_secs: Option<u64>,
    pub(super) expect_cache_predictor_enabled: bool,
    pub(super) expect_origin_protection_enabled: bool,
    pub(super) expected_origin_protection_max_concurrent_fills: Option<usize>,
    pub(super) expect_peer_fill_enabled: bool,
    pub(super) expected_peer_fill_peers: Option<usize>,
    pub(super) expected_peer_fill_max_concurrent_requests: Option<usize>,
    pub(super) expect_memory_tier_enabled: bool,
    pub(super) expect_disk_tier_enabled: bool,
    pub(super) expect_storage_tiers: Option<u8>,
    pub(super) expected_scope: Option<&'a str>,
    pub(super) expected_vhost: Option<&'a str>,
    pub(super) expected_route: Option<&'a str>,
    pub(super) expected_namespace: Option<&'a str>,
    pub(super) expected_key_namespace: Option<&'a str>,
    pub(super) expected_user_tag: Option<&'a str>,
}

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn validate_cache_key_preview_expectations(
    preview: &fluxheim_cache::CacheKeyPreview,
    expectations: CacheKeyPreviewExpectations<'_>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if expectations.expect_eligible && !preview.eligible {
        let reason = preview.reason.as_deref().unwrap_or("unknown");
        return Err(format!("cache-key expected eligible request, found false: {reason}").into());
    }
    if expectations.expect_ineligible && preview.eligible {
        return Err("cache-key expected ineligible request, found true".into());
    }
    if let Some(expected_reason) = expectations.expected_reason
        && preview.reason.as_deref() != Some(expected_reason)
    {
        let found = preview.reason.as_deref().unwrap_or("none");
        return Err(format!("cache-key expected reason {expected_reason}, found {found}").into());
    }
    if expectations.expect_cache_lock_enabled && !preview.cache_lock_enabled {
        return Err("cache-key expected cache lock enabled, found false".into());
    }
    if let Some(expected_timeout) = expectations.expected_cache_lock_wait_timeout_secs
        && preview.cache_lock_wait_timeout_secs != expected_timeout
    {
        return Err(format!(
            "cache-key expected cache lock wait timeout seconds {expected_timeout}, found {}",
            preview.cache_lock_wait_timeout_secs
        )
        .into());
    }
    if expectations.expect_cache_predictor_enabled && !preview.cache_predictor_enabled {
        return Err("cache-key expected cache predictor enabled, found false".into());
    }
    if expectations.expect_origin_protection_enabled && !preview.origin_protection_enabled {
        return Err("cache-key expected origin protection enabled, found false".into());
    }
    if let Some(expected_concurrency) = expectations.expected_origin_protection_max_concurrent_fills
        && preview.origin_protection_max_concurrent_fills != expected_concurrency
    {
        return Err(format!(
            "cache-key expected origin protection max concurrent fills {expected_concurrency}, found {}",
            preview.origin_protection_max_concurrent_fills
        )
        .into());
    }
    if expectations.expect_peer_fill_enabled && !preview.peer_fill_enabled {
        return Err("cache-key expected peer fill enabled, found false".into());
    }
    if let Some(expected_peers) = expectations.expected_peer_fill_peers
        && preview.peer_fill_peer_count != expected_peers
    {
        return Err(format!(
            "cache-key expected peer fill peers {expected_peers}, found {}",
            preview.peer_fill_peer_count
        )
        .into());
    }
    if let Some(expected_concurrency) = expectations.expected_peer_fill_max_concurrent_requests
        && preview.peer_fill_max_concurrent_requests != expected_concurrency
    {
        return Err(format!(
            "cache-key expected peer fill max concurrent requests {expected_concurrency}, found {}",
            preview.peer_fill_max_concurrent_requests
        )
        .into());
    }
    if expectations.expect_memory_tier_enabled && !preview.memory_tier_enabled {
        return Err("cache-key expected memory tier enabled, found false".into());
    }
    if expectations.expect_disk_tier_enabled && !preview.disk_tier_enabled {
        return Err("cache-key expected disk tier enabled, found false".into());
    }
    if let Some(expected_storage_tiers) = expectations.expect_storage_tiers
        && preview.storage_tiers != expected_storage_tiers
    {
        return Err(format!(
            "cache-key expected storage tiers {expected_storage_tiers}, found {}",
            preview.storage_tiers
        )
        .into());
    }
    if let Some(expected_scope) = expectations.expected_scope
        && preview.scope.as_str() != expected_scope
    {
        return Err(format!(
            "cache-key expected scope {expected_scope}, found {}",
            preview.scope.as_str()
        )
        .into());
    }
    if let Some(expected_vhost) = expectations.expected_vhost
        && preview.vhost != expected_vhost
    {
        return Err(format!(
            "cache-key expected vhost {expected_vhost}, found {}",
            preview.vhost
        )
        .into());
    }
    if let Some(expected_route) = expectations.expected_route
        && preview.route.as_deref() != Some(expected_route)
    {
        let found = preview.route.as_deref().unwrap_or("none");
        return Err(format!("cache-key expected route {expected_route}, found {found}").into());
    }
    if let Some(expected_namespace) = expectations.expected_namespace
        && preview.namespace.as_deref() != Some(expected_namespace)
    {
        let found = preview.namespace.as_deref().unwrap_or("none");
        return Err(
            format!("cache-key expected namespace {expected_namespace}, found {found}").into(),
        );
    }
    if let Some(expected_key_namespace) = expectations.expected_key_namespace
        && preview.key_namespace.as_deref() != Some(expected_key_namespace)
    {
        let found = preview.key_namespace.as_deref().unwrap_or("none");
        return Err(format!(
            "cache-key expected key namespace {expected_key_namespace}, found {found}"
        )
        .into());
    }
    if let Some(expected_user_tag) = expectations.expected_user_tag
        && preview.user_tag.as_deref() != Some(expected_user_tag)
    {
        let found = preview.user_tag.as_deref().unwrap_or("none");
        return Err(
            format!("cache-key expected user tag {expected_user_tag}, found {found}").into(),
        );
    }
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn validate_cache_lookup_expected_storage_tiers(
    storage_tiers: Option<u8>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Some(storage_tiers) = storage_tiers
        && storage_tiers > 2
    {
        return Err(format!(
            "cache-lookup --expect-storage-tiers must be 0, 1, or 2; got {storage_tiers}"
        )
        .into());
    }
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn parse_cache_key_preview_scope(
    command: &str,
    scope: Option<&String>,
) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    let Some(scope) = scope else {
        return Ok(None);
    };
    match scope.trim().to_ascii_lowercase().as_str() {
        "vhost" => Ok(Some("vhost".to_owned())),
        "route" => Ok(Some("route".to_owned())),
        other => {
            Err(format!("{command} --expect-scope must be vhost or route; got {other:?}").into())
        }
    }
}

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn parse_cache_key_preview_name(
    command: &str,
    flag: &str,
    name: Option<&String>,
) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    let Some(name) = name else {
        return Ok(None);
    };
    let name = name.trim();
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(format!("{command} {flag} must be a non-empty name").into());
    }
    Ok(Some(name.to_owned()))
}

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn parse_cache_key_preview_reason(
    command: &str,
    flag: &str,
    reason: Option<&String>,
) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    let Some(reason) = reason else {
        return Ok(None);
    };
    let reason = reason.trim();
    if reason.is_empty() || reason.len() > 256 || reason.chars().any(char::is_control) {
        return Err(format!("{command} {flag} must be a non-empty bounded reason").into());
    }
    Ok(Some(reason.to_owned()))
}

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn parse_cache_key_preview_value(
    command: &str,
    flag: &str,
    value: Option<&String>,
) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(format!("{command} {flag} must be a non-empty bounded value").into());
    }
    Ok(Some(value.to_owned()))
}

#[cfg(all(feature = "cache", feature = "proxy"))]
pub(super) fn parse_cache_key_preview_route(
    command: &str,
    route: Option<&String>,
) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    parse_cache_key_preview_name(command, "--expect-route", route)
}

pub(super) fn parse_cache_cli_headers(
    command: &str,
    headers: &[String],
) -> Result<Vec<(String, String)>, Box<dyn Error + Send + Sync>> {
    if headers.len() > 32 {
        return Err(format!("{command} accepts at most 32 --header values").into());
    }
    headers
        .iter()
        .map(|header| parse_cache_cli_header(command, header))
        .collect()
}

fn parse_cache_cli_header(
    command: &str,
    header: &str,
) -> Result<(String, String), Box<dyn Error + Send + Sync>> {
    if header.len() > 8192 {
        return Err(format!("{command} --header must be at most 8192 bytes").into());
    }
    let (name, value) = header
        .split_once(':')
        .ok_or_else(|| format!("{command} --header must use \"Name: value\" syntax"))?;
    let name = name.trim();
    if name.is_empty() || name.len() > 64 || !fluxheim_protocol::http_token_valid(name) {
        return Err(format!("{command} --header name must be a valid HTTP header name").into());
    }
    let normalized_name = name.to_ascii_lowercase();
    if matches!(
        normalized_name.as_str(),
        "host" | "connection" | "content-length" | "transfer-encoding"
    ) {
        return Err(format!(
            "{command} --header cannot set {name}; use explicit options or built-in request framing"
        )
        .into());
    }
    let value = value.trim();
    if value.len() > 8192 {
        return Err(format!("{command} --header value must be at most 8192 bytes").into());
    }
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(format!("{command} --header value must not contain control bytes").into());
    }
    Ok((normalized_name, value.to_owned()))
}
