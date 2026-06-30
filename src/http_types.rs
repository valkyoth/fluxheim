//! Fluxheim-owned HTTP type boundary.
//!
//! Internal modules should prefer these standard `http` crate types for plain
//! HTTP values.

#[cfg(any(feature = "cache", feature = "compression", feature = "php-fpm"))]
#[allow(unused_imports)]
pub(crate) use http::StatusCode;

#[cfg(all(feature = "proxy", feature = "cache"))]
#[derive(Clone, Debug)]
pub(crate) struct NativeCachePreviewRequest {
    pub method: http::Method,
    pub uri: http::Uri,
    pub headers: http::HeaderMap,
}

#[cfg(all(feature = "proxy", feature = "cache"))]
impl NativeCachePreviewRequest {
    pub(crate) fn build(
        method: &str,
        uri: &[u8],
        _version: Option<http::Version>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let method = method.parse::<http::Method>()?;
        let uri = std::str::from_utf8(uri)?.parse::<http::Uri>()?;
        Ok(Self {
            method,
            uri,
            headers: http::HeaderMap::new(),
        })
    }

    pub(crate) fn insert_header(
        &mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let name = name.as_ref().parse::<http::HeaderName>()?;
        let value = http::HeaderValue::from_str(value.as_ref())?;
        self.headers.insert(name, value);
        Ok(())
    }
}
