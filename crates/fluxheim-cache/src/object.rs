use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

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
pub struct SerializedCacheObject {
    pub combined_key: Option<String>,
    pub primary_key: Option<String>,
    pub user_tag: Option<String>,
    pub index_path: Option<String>,
    pub cache_tags: Vec<String>,
    pub internal_meta: Vec<u8>,
    pub response_header: Vec<u8>,
    pub body: Arc<[u8]>,
    pub weight: u32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DiskCacheEntry {
    pub combined_key: Option<String>,
    pub path: PathBuf,
    pub size: u64,
    pub modified: SystemTime,
    pub accessed: SystemTime,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct DiskObjectLruKey {
    pub accessed: SystemTime,
    pub modified: SystemTime,
    pub path: PathBuf,
}

impl DiskObjectLruKey {
    pub fn from_entry(entry: &DiskCacheEntry) -> Self {
        Self {
            accessed: entry.accessed,
            modified: entry.modified,
            path: entry.path.clone(),
        }
    }
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
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::SystemTime;

    use super::{
        DiskCacheEntry, DiskObjectLruKey, FluxCacheMissFinish, FluxCachePurgeType,
        SerializedCacheObject,
    };

    #[test]
    fn cache_storage_interface_enums_are_stable() {
        assert_eq!(FluxCachePurgeType::Eviction, FluxCachePurgeType::Eviction);
        assert_eq!(
            FluxCacheMissFinish::Appended(10, Some(128)),
            FluxCacheMissFinish::Appended(10, Some(128))
        );
    }

    #[test]
    fn serialized_cache_object_preserves_storage_envelope() {
        let object = SerializedCacheObject {
            combined_key: Some("combined".to_owned()),
            primary_key: Some("primary".to_owned()),
            user_tag: Some("tag".to_owned()),
            index_path: Some("/asset.png".to_owned()),
            cache_tags: vec!["asset".to_owned()],
            internal_meta: vec![1, 2],
            response_header: vec![3, 4],
            body: Arc::from([5_u8, 6].as_slice()),
            weight: 6,
        };

        assert_eq!(object.combined_key.as_deref(), Some("combined"));
        assert_eq!(object.primary_key.as_deref(), Some("primary"));
        assert_eq!(object.user_tag.as_deref(), Some("tag"));
        assert_eq!(object.index_path.as_deref(), Some("/asset.png"));
        assert_eq!(object.cache_tags, ["asset"]);
        assert_eq!(object.internal_meta, [1, 2]);
        assert_eq!(object.response_header, [3, 4]);
        assert_eq!(object.body.as_ref(), [5, 6]);
        assert_eq!(object.weight, 6);
    }

    #[test]
    fn disk_object_lru_key_matches_entry_ordering_fields() {
        let modified = SystemTime::UNIX_EPOCH;
        let accessed = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(5);
        let entry = DiskCacheEntry {
            combined_key: Some("combined".to_owned()),
            path: PathBuf::from("/cache/object"),
            size: 42,
            modified,
            accessed,
        };

        let key = DiskObjectLruKey::from_entry(&entry);

        assert_eq!(key.accessed, accessed);
        assert_eq!(key.modified, modified);
        assert_eq!(key.path, PathBuf::from("/cache/object"));
    }
}
