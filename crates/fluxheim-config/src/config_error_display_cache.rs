use std::fmt::Formatter;

use super::kind::ConfigError;
use crate::config_cache_controls::CACHE_PREDICTOR_MAX_CAPACITY;

pub(super) fn format_cache_error(
    error: &ConfigError,
    formatter: &mut Formatter<'_>,
) -> std::fmt::Result {
    match error {
        ConfigError::EmptyCacheImageExtensions { scope } => {
            write!(formatter, "{scope}.image_extensions cannot be empty")
        }
        ConfigError::InvalidCacheImageExtension { scope, extension } => write!(
            formatter,
            "{scope}.image_extensions must contain bare file extensions, got {extension:?}"
        ),
        ConfigError::EmptyCacheMethods { scope } => {
            write!(formatter, "{scope}.methods cannot be empty")
        }
        ConfigError::InvalidCacheMethod { scope, method } => write!(
            formatter,
            "{scope}.methods must contain uppercase HTTP method tokens, got {method:?}"
        ),
        ConfigError::EmptyCacheContentTypes { scope } => {
            write!(formatter, "{scope}.content_types cannot be empty")
        }
        ConfigError::InvalidCacheContentType {
            scope,
            content_type,
        } => write!(
            formatter,
            "{scope}.content_types must contain media types such as \"image/*\" or \"text/css\", got {content_type:?}"
        ),
        ConfigError::InvalidCacheMaxObjectBytes { scope } => {
            write!(
                formatter,
                "{scope}.max_object_bytes must be greater than zero"
            )
        }
        ConfigError::InvalidCacheStatusTtl {
            scope,
            status,
            ttl_secs,
        } => write!(
            formatter,
            "{scope}.status_ttls[{status}] must use an HTTP status code from 100 to 599 and a positive TTL, got {ttl_secs}"
        ),
        ConfigError::InvalidCacheDefaultStatusTtl { scope } => {
            write!(
                formatter,
                "{scope}.default_status_ttl_secs must be greater than zero"
            )
        }
        ConfigError::InvalidCacheMinUses { scope } => {
            write!(formatter, "{scope}.min_uses must be greater than zero")
        }
        ConfigError::InvalidCacheRangePolicy {
            scope,
            field,
            reason,
        } => write!(formatter, "{scope}.{field} is invalid: {reason}"),
        ConfigError::InvalidCacheBypassPath { scope, path } => write!(
            formatter,
            "{scope}.bypass_path_prefixes and {scope}.bypass_path_exact must contain absolute normalized request paths, got {path:?}"
        ),
        ConfigError::InvalidCacheBypassQueryParam { scope, param } => write!(
            formatter,
            "{scope}.bypass_query_params must contain raw query parameter names without whitespace, controls, '&', '=', '#', '?', or ';', got {param:?}"
        ),
        ConfigError::InvalidCacheBypassQueryValue {
            scope,
            param,
            value,
        } => write!(
            formatter,
            "{scope}.bypass_query_values[{param:?}] must contain a non-empty safe raw query value without whitespace, controls, '&', '#', or ';', got {value:?}"
        ),
        ConfigError::InvalidCacheBypassRequestHeaderValue {
            scope,
            header,
            value,
        } => write!(
            formatter,
            "{scope}.bypass_request_header_values[{header:?}] must contain a non-empty safe header value without controls, got {value:?}"
        ),
        ConfigError::InvalidCacheNoStoreResponseHeaderValue {
            scope,
            header,
            value,
        } => write!(
            formatter,
            "{scope}.no_store_response_header_values[{header:?}] must contain a non-empty safe header value without controls, got {value:?}"
        ),
        ConfigError::InvalidCacheBypassCookieName { scope, name } => write!(
            formatter,
            "{scope}.bypass_cookie_names must contain cookie name tokens without whitespace or separators, got {name:?}"
        ),
        ConfigError::InvalidCacheBypassCookieValue { scope, name, value } => write!(
            formatter,
            "{scope}.bypass_cookie_values[{name:?}] must contain a safe cookie value without controls, ';', or ',', got {value:?}"
        ),
        ConfigError::InvalidCacheStaleIfErrorTtl { scope } => {
            write!(
                formatter,
                "{scope}.stale_if_error_secs must be greater than zero"
            )
        }
        ConfigError::InvalidCacheStaleWhileRevalidateTtl { scope } => {
            write!(
                formatter,
                "{scope}.stale_while_revalidate_secs must be greater than zero"
            )
        }
        ConfigError::EmptyCacheStaleIfErrorOn { scope } => {
            write!(
                formatter,
                "{scope}.stale_if_error_on must not be empty when stale_if_error_secs is set"
            )
        }
        ConfigError::InvalidCacheStaleIfErrorStatus { scope, status } => write!(
            formatter,
            "{scope}.stale_if_error_statuses must contain HTTP 5xx status codes, got {status}"
        ),
        ConfigError::InvalidCacheVaryRequestHeader { scope, header } => write!(
            formatter,
            "{scope}.vary_request_headers must not include sensitive request header {header:?}; use bypass_request_headers for request-specific responses"
        ),
        ConfigError::InvalidCacheListLength { scope, field, max } => write!(
            formatter,
            "{scope}.{field} must contain at most {max} entries"
        ),
        ConfigError::DuplicateCacheTagHeader { scope, header } => write!(
            formatter,
            "{scope}.tag_headers must not contain duplicate response headers, got {header:?}"
        ),
        ConfigError::InvalidCacheKeyNamespace { scope, namespace } => write!(
            formatter,
            "{scope}.key_namespace must be 1-128 characters and contain only ASCII letters, digits, '-', '_', '.', or ':', got {namespace:?}"
        ),
        ConfigError::EmptyCacheKeyParts { scope } => {
            write!(formatter, "{scope}.key_parts must not be empty")
        }
        ConfigError::DuplicateCacheKeyPart { scope, part } => write!(
            formatter,
            "{scope}.key_parts must not contain duplicate cache key part {part}"
        ),
        ConfigError::MissingCacheKeyPath { scope } => {
            write!(formatter, "{scope}.key_parts must include path")
        }
        ConfigError::InvalidCacheLockTimeout { field } => {
            write!(formatter, "{field} must be greater than zero")
        }
        ConfigError::InvalidCachePredictorCapacity { scope } => write!(
            formatter,
            "{scope}.predictor.capacity must be between 1 and {CACHE_PREDICTOR_MAX_CAPACITY} when the predictor is enabled"
        ),
        ConfigError::InvalidCacheOriginProtectionPolicy {
            scope,
            field,
            reason,
        } => write!(formatter, "{scope}.{field} is invalid: {reason}"),
        ConfigError::InvalidCachePeerFillPolicy {
            scope,
            field,
            reason,
        } => write!(formatter, "{scope}.{field} is invalid: {reason}"),
        ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer,
            reason,
        } => write!(
            formatter,
            "{scope}.peer_fill peer {peer:?} is invalid: {reason}"
        ),
        ConfigError::DuplicateCachePeerFillPeerName { scope, name } => write!(
            formatter,
            "{scope}.peer_fill.peers contains duplicate peer name {name:?}"
        ),
        ConfigError::DuplicateCachePeerFillPeerUrl { scope, url } => write!(
            formatter,
            "{scope}.peer_fill.peers contains duplicate peer base_url {url:?}"
        ),
        ConfigError::CachePeerFillNotCompiled => write!(
            formatter,
            "cache peer_fill.enabled requires building Fluxheim with the cache feature"
        ),
        ConfigError::CacheEnabledWithoutStorageTier { scope } => {
            write!(
                formatter,
                "{scope}.enabled requires cache.memory.enabled or cache.disk.enabled"
            )
        }
        ConfigError::InvalidCacheTierMaxSize { field } => {
            write!(formatter, "{field} must be greater than zero")
        }
        ConfigError::CacheTierSmallerThanMaxObject { tier } => write!(
            formatter,
            "{tier}.max_size_bytes must be at least cache.max_object_bytes"
        ),
        ConfigError::CacheStorageBinLargerThanDiskTier { scope } => write!(
            formatter,
            "{scope}.disk.storage_bin.bin_size_bytes must not exceed {scope}.disk.max_size_bytes"
        ),
        ConfigError::CacheStorageBinSmallerThanMaxObject { scope } => write!(
            formatter,
            "{scope}.disk.storage_bin.bin_size_bytes must be at least {scope}.max_object_bytes"
        ),
        ConfigError::InvalidCacheStorageBinMaxOpenBins { scope } => write!(
            formatter,
            "{scope}.disk.storage_bin.max_open_bins must be greater than zero"
        ),
        ConfigError::InvalidCacheEncryptionPolicy {
            scope,
            field,
            reason,
        } => write!(formatter, "{scope}.{field} is invalid: {reason}"),
        ConfigError::InvalidCacheEncryptionCredentialName {
            scope,
            field,
            credential,
        } => write!(
            formatter,
            "{scope}.disk.encryption.{field} credential name {credential:?} must be a safe credential name"
        ),
        ConfigError::UnsupportedCacheDiskBackend { scope, backend } => write!(
            formatter,
            "{scope}.disk.backend = {backend:?} is not supported by this build"
        ),
        ConfigError::CachePurgerNotCompiled => write!(
            formatter,
            "cache_purger.enabled requires building Fluxheim with the cache feature"
        ),
        ConfigError::InvalidCachePurgerPolicy { field, reason } => {
            write!(formatter, "{field} is invalid: {reason}")
        }
        ConfigError::MissingCacheDiskPath { scope } => {
            write!(
                formatter,
                "{scope}.disk.path is required when disk cache is enabled"
            )
        }
        ConfigError::EmptyCacheDiskPath { scope } => {
            write!(formatter, "{scope}.disk.path cannot be empty")
        }
        _ => formatter.write_str("invalid cache config error"),
    }
}
