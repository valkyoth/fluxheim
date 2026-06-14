use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
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

#[derive(Debug, Clone)]
pub struct DiskObjectIndex {
    inner: Arc<RwLock<DiskObjectIndexInner>>,
}

#[derive(Debug, Default)]
struct DiskObjectIndexInner {
    entries: HashMap<PathBuf, DiskCacheEntry>,
    lru: BTreeSet<DiskObjectLruKey>,
    total_size: u64,
}

impl DiskObjectIndex {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(DiskObjectIndexInner::default())),
        }
    }

    pub fn replace_all(&self, entries: Vec<DiskCacheEntry>) {
        let Ok(mut inner) = self.inner.write() else {
            return;
        };
        inner.entries.clear();
        inner.lru.clear();
        inner.total_size = 0;
        for entry in entries {
            inner.total_size = inner.total_size.saturating_add(entry.size);
            inner.lru.insert(DiskObjectLruKey::from_entry(&entry));
            inner.entries.insert(entry.path.clone(), entry);
        }
    }

    pub fn upsert(&self, entry: DiskCacheEntry) {
        let Ok(mut inner) = self.inner.write() else {
            return;
        };
        if let Some(previous) = inner.entries.insert(entry.path.clone(), entry.clone()) {
            inner.total_size = inner.total_size.saturating_sub(previous.size);
            inner.lru.remove(&DiskObjectLruKey::from_entry(&previous));
        }
        inner.total_size = inner.total_size.saturating_add(entry.size);
        inner.lru.insert(DiskObjectLruKey::from_entry(&entry));
    }

    pub fn remove(&self, path: &Path) -> Option<DiskCacheEntry> {
        let Ok(mut inner) = self.inner.write() else {
            return None;
        };
        let previous = inner.entries.remove(path)?;
        inner.total_size = inner.total_size.saturating_sub(previous.size);
        inner.lru.remove(&DiskObjectLruKey::from_entry(&previous));
        Some(previous)
    }

    pub fn touch(&self, path: &Path, accessed: SystemTime) {
        let Ok(mut inner) = self.inner.write() else {
            return;
        };
        if let Some(entry) = inner.entries.get_mut(path) {
            let previous = DiskObjectLruKey::from_entry(entry);
            entry.accessed = accessed;
            let updated = DiskObjectLruKey::from_entry(entry);
            inner.lru.remove(&previous);
            inner.lru.insert(updated);
        }
    }

    pub fn snapshot(&self) -> (Vec<DiskCacheEntry>, u64) {
        let Ok(inner) = self.inner.read() else {
            return (Vec::new(), 0);
        };
        (inner.entries.values().cloned().collect(), inner.total_size)
    }

    pub fn entries(&self) -> Vec<DiskCacheEntry> {
        self.snapshot().0
    }

    pub fn total_size(&self) -> u64 {
        let Ok(inner) = self.inner.read() else {
            return 0;
        };
        inner.total_size
    }

    pub fn entry_size(&self, path: &Path) -> Option<u64> {
        let Ok(inner) = self.inner.read() else {
            return None;
        };
        inner.entries.get(path).map(|entry| entry.size)
    }

    pub fn oldest_entries_to_free(
        &self,
        excluded_path: &Path,
        bytes_to_free: u64,
    ) -> Vec<DiskCacheEntry> {
        if bytes_to_free == 0 {
            return Vec::new();
        }
        let Ok(inner) = self.inner.read() else {
            return Vec::new();
        };
        let mut selected = Vec::new();
        let mut selected_bytes = 0_u64;
        for key in &inner.lru {
            if key.path == excluded_path {
                continue;
            }
            let Some(entry) = inner.entries.get(&key.path) else {
                continue;
            };
            selected_bytes = selected_bytes.saturating_add(entry.size);
            selected.push(entry.clone());
            if selected_bytes >= bytes_to_free {
                break;
            }
        }
        selected
    }

    pub fn stats(&self) -> (usize, u64) {
        let Ok(inner) = self.inner.read() else {
            return (0, 0);
        };
        (inner.entries.len(), inner.total_size)
    }
}

impl Default for DiskObjectIndex {
    fn default() -> Self {
        Self::new()
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
        DiskCacheEntry, DiskObjectIndex, DiskObjectLruKey, FluxCacheMissFinish, FluxCachePurgeType,
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

    #[test]
    fn disk_object_index_tracks_size_and_lru_eviction_candidates() {
        let first_path = PathBuf::from("/cache/first");
        let second_path = PathBuf::from("/cache/second");
        let index = DiskObjectIndex::new();
        index.upsert(DiskCacheEntry {
            combined_key: Some("first".to_owned()),
            path: first_path.clone(),
            size: 10,
            modified: SystemTime::UNIX_EPOCH,
            accessed: SystemTime::UNIX_EPOCH,
        });
        index.upsert(DiskCacheEntry {
            combined_key: Some("second".to_owned()),
            path: second_path.clone(),
            size: 20,
            modified: SystemTime::UNIX_EPOCH,
            accessed: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1),
        });

        assert_eq!(index.stats(), (2, 30));
        assert_eq!(
            index
                .oldest_entries_to_free(&PathBuf::from("/cache/ignored"), 1)
                .first()
                .and_then(|entry| entry.combined_key.as_deref()),
            Some("first")
        );

        index.touch(
            &first_path,
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2),
        );
        assert_eq!(
            index
                .oldest_entries_to_free(&PathBuf::from("/cache/ignored"), 1)
                .first()
                .and_then(|entry| entry.combined_key.as_deref()),
            Some("second")
        );
        assert_eq!(index.remove(&second_path).map(|entry| entry.size), Some(20));
        assert_eq!(index.stats(), (1, 10));
    }
}
