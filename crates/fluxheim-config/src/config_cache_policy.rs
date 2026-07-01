use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::config::{ByteSize, ConfigError};

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheKeyPart {
    Method,
    Host,
    Path,
    Query,
}

impl Display for CacheKeyPart {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Method => formatter.write_str("method"),
            Self::Host => formatter.write_str("host"),
            Self::Path => formatter.write_str("path"),
            Self::Query => formatter.write_str("query"),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheStaleErrorKind {
    Connect,
    Timeout,
    Read,
    Write,
    ConnectionClosed,
    HttpStatus,
    Protocol,
    Tls,
    Other,
}

pub fn extend_unique(target: &mut Vec<String>, values: impl IntoIterator<Item = String>) {
    for value in values {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
        }
    }
}

pub(crate) fn default_cache_key_parts() -> Vec<CacheKeyPart> {
    vec![
        CacheKeyPart::Method,
        CacheKeyPart::Host,
        CacheKeyPart::Path,
        CacheKeyPart::Query,
    ]
}

pub(crate) fn default_cache_tag_headers() -> Vec<String> {
    ["surrogate-key", "cache-tag", "x-cache-tags"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

pub(crate) fn default_cache_stale_if_error_on() -> Vec<CacheStaleErrorKind> {
    vec![
        CacheStaleErrorKind::Connect,
        CacheStaleErrorKind::Timeout,
        CacheStaleErrorKind::Read,
        CacheStaleErrorKind::Write,
        CacheStaleErrorKind::ConnectionClosed,
        CacheStaleErrorKind::HttpStatus,
        CacheStaleErrorKind::Protocol,
        CacheStaleErrorKind::Tls,
        CacheStaleErrorKind::Other,
    ]
}

pub(crate) fn default_cache_include_query() -> bool {
    true
}

pub(crate) fn default_cache_min_uses() -> u32 {
    1
}

pub(crate) fn default_cache_content_types() -> Vec<String> {
    [
        "image/*",
        "text/css",
        "text/javascript",
        "application/javascript",
        "application/wasm",
        "font/*",
        "application/font-woff",
        "application/vnd.ms-fontobject",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

pub(crate) fn default_cache_static_extensions() -> Vec<String> {
    [
        "avif", "css", "eot", "gif", "ico", "jpeg", "jpg", "js", "mjs", "otf", "png", "svg", "ttf",
        "wasm", "webp", "woff", "woff2",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

pub(crate) fn default_cache_methods() -> Vec<String> {
    ["GET", "HEAD"].into_iter().map(str::to_owned).collect()
}

pub(crate) fn default_cache_max_object_bytes() -> ByteSize {
    ByteSize::from_bytes(32 * 1024 * 1024)
}

pub(crate) fn validate_cache_key_namespace(
    scope: &'static str,
    namespace: &str,
) -> Result<(), ConfigError> {
    if namespace.is_empty()
        || namespace.len() > 128
        || namespace
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':')))
    {
        return Err(ConfigError::InvalidCacheKeyNamespace {
            scope,
            namespace: namespace.to_owned(),
        });
    }
    Ok(())
}
