//! Cache preview request DTO used by CLI/admin cache inspection paths.

#[derive(Clone, Debug)]
pub struct NativeCachePreviewRequest {
    pub method: http::Method,
    pub uri: http::Uri,
    pub headers: http::HeaderMap,
}

impl NativeCachePreviewRequest {
    pub fn build(
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

    pub fn insert_header(
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
