use crate::config::{ConfigError, valid_http_token};
use crate::config_cache::CacheConfig;

pub(super) fn validate_cache_content_types(
    cache: &CacheConfig,
    scope: &'static str,
) -> Result<(), ConfigError> {
    if cache.content_types.is_empty() {
        return Err(ConfigError::EmptyCacheContentTypes { scope });
    }
    for content_type in &cache.content_types {
        let content_type = content_type.trim();
        let Some((kind, subtype)) = content_type.split_once('/') else {
            return Err(ConfigError::InvalidCacheContentType {
                scope,
                content_type: content_type.to_owned(),
            });
        };
        if kind.is_empty()
            || subtype.is_empty()
            || kind == "*"
            || content_type.contains(';')
            || content_type.chars().any(char::is_whitespace)
            || content_type.chars().any(char::is_control)
            || (subtype.contains('*') && subtype != "*")
        {
            return Err(ConfigError::InvalidCacheContentType {
                scope,
                content_type: content_type.to_owned(),
            });
        }
    }
    Ok(())
}

pub(super) fn validate_cache_extensions(
    cache: &CacheConfig,
    scope: &'static str,
) -> Result<(), ConfigError> {
    if cache.image_extensions.is_empty() {
        return Err(ConfigError::EmptyCacheImageExtensions { scope });
    }
    for extension in &cache.image_extensions {
        let extension = extension.trim();
        if extension.is_empty()
            || extension.starts_with('.')
            || extension.contains('/')
            || extension.contains('\\')
            || extension.chars().any(char::is_whitespace)
        {
            return Err(ConfigError::InvalidCacheImageExtension {
                scope,
                extension: extension.to_owned(),
            });
        }
    }
    Ok(())
}

pub(super) fn validate_cache_methods(
    cache: &CacheConfig,
    scope: &'static str,
) -> Result<(), ConfigError> {
    if cache.methods.is_empty() {
        return Err(ConfigError::EmptyCacheMethods { scope });
    }
    for method in &cache.methods {
        if !valid_http_token(method) || method.chars().any(char::is_lowercase) {
            return Err(ConfigError::InvalidCacheMethod {
                scope,
                method: method.clone(),
            });
        }
    }
    Ok(())
}

pub(super) fn cache_sensitive_request_header(header: &str) -> bool {
    matches!(
        header.to_ascii_lowercase().as_str(),
        "authorization" | "cookie" | "proxy-authorization"
    )
}

pub(super) fn validate_cache_query_param(
    scope: &'static str,
    param: &str,
) -> Result<(), ConfigError> {
    if param.is_empty()
        || param.len() > 128
        || param.chars().any(|ch| {
            ch.is_control() || ch.is_whitespace() || matches!(ch, '&' | '=' | '#' | '?' | ';')
        })
    {
        return Err(ConfigError::InvalidCacheBypassQueryParam {
            scope,
            param: param.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn validate_cache_query_value(
    scope: &'static str,
    param: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.trim().is_empty()
        || value.len() > 4096
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || matches!(ch, '&' | '#' | ';'))
    {
        return Err(ConfigError::InvalidCacheBypassQueryValue {
            scope,
            param: param.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn validate_cache_bypass_request_header_value(
    scope: &'static str,
    header: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.trim().is_empty()
        || value.len() > 4096
        || value
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, 0x00..=0x08 | 0x0a..=0x1f | 0x7f))
    {
        return Err(ConfigError::InvalidCacheBypassRequestHeaderValue {
            scope,
            header: header.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn validate_cache_no_store_response_header_value(
    scope: &'static str,
    header: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.trim().is_empty()
        || value.len() > 4096
        || value
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, 0x00..=0x08 | 0x0a..=0x1f | 0x7f))
    {
        return Err(ConfigError::InvalidCacheNoStoreResponseHeaderValue {
            scope,
            header: header.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn validate_cache_cookie_name(
    scope: &'static str,
    name: &str,
) -> Result<(), ConfigError> {
    if name.is_empty() || name.len() > 128 || !valid_cookie_name(name) {
        return Err(ConfigError::InvalidCacheBypassCookieName {
            scope,
            name: name.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn validate_cache_cookie_value(
    scope: &'static str,
    name: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.len() > 1024
        || value
            .bytes()
            .any(|byte| byte < 0x20 || byte == 0x7f || matches!(byte, b';' | b','))
    {
        return Err(ConfigError::InvalidCacheBypassCookieValue {
            scope,
            name: name.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn valid_cookie_name(value: &str) -> bool {
    value.bytes().all(|byte| {
        matches!(byte, 0x21 | 0x23..=0x27 | 0x2a..=0x2b | 0x2d..=0x2e | 0x30..=0x39 | 0x41..=0x5a | 0x5e..=0x7a | 0x7c | 0x7e)
    })
}

pub(super) fn validate_cache_list_len(
    scope: &'static str,
    field: &'static str,
    len: usize,
    max: usize,
) -> Result<(), ConfigError> {
    if len > max {
        return Err(ConfigError::InvalidCacheListLength { scope, field, max });
    }
    Ok(())
}
