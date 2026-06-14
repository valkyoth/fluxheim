use std::sync::Arc;

use fluxheim_config::ByteSize;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CachedImageObject {
    pub status: u16,
    pub headers: Vec<CachedHeader>,
    pub body: Arc<[u8]>,
    pub fresh_until_unix_secs: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CachedHeader {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CacheStoreError {
    ObjectTooLarge {
        object_bytes: u64,
        max_object_bytes: ByteSize,
    },
    ObjectTooHeavy {
        object_bytes: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FluxCachePurgeType {
    Eviction,
    Invalidation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FluxCacheMissFinish {
    Created(usize),
    Appended(usize, Option<usize>),
}

#[cfg(test)]
mod tests {
    use super::{FluxCacheMissFinish, FluxCachePurgeType};

    #[test]
    fn cache_storage_interface_enums_are_stable() {
        assert_eq!(FluxCachePurgeType::Eviction, FluxCachePurgeType::Eviction);
        assert_eq!(
            FluxCacheMissFinish::Appended(10, Some(128)),
            FluxCacheMissFinish::Appended(10, Some(128))
        );
    }
}
