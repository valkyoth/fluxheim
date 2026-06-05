//! Fluxheim-owned HTTP type boundary.
//!
//! Internal modules should prefer these standard `http` crate types for plain
//! HTTP values. Pingora request/response header wrappers remain narrow runtime
//! adapter types at service/proxy boundaries until the HTTP runtime is owned by
//! Fluxheim.

#[cfg(any(feature = "cache", feature = "compression", feature = "php-fpm"))]
pub(crate) use http::StatusCode;

#[cfg(feature = "proxy")]
pub(crate) type PingoraRequestHeader = pingora::http::RequestHeader;
#[cfg(feature = "proxy")]
pub(crate) type PingoraResponseHeader = pingora::http::ResponseHeader;
