use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

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
