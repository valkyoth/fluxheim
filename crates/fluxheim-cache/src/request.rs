#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheRequest<'a> {
    pub method: &'a str,
    pub host: Option<&'a str>,
    pub path: &'a str,
    pub query: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
pub struct StaticCacheRequest<'a> {
    pub method: &'a str,
    pub host: Option<&'a str>,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub file_identity: &'a str,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct CacheKey(String);

impl CacheKey {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
