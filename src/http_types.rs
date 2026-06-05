//! Fluxheim-owned HTTP type boundary.
//!
//! Internal modules should prefer these standard `http` crate types for plain
//! HTTP values. Pingora request/response header wrappers remain narrow runtime
//! adapter types at service/proxy boundaries until the HTTP runtime is owned by
//! Fluxheim.

#[allow(unused_imports)]
pub(crate) use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode, Uri, Version, header,
};

#[cfg(feature = "ingress")]
pub(crate) type PingoraRequestHeader = pingora::http::RequestHeader;
#[cfg(feature = "ingress")]
pub(crate) type PingoraResponseHeader = pingora::http::ResponseHeader;
