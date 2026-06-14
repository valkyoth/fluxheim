use std::collections::{BTreeSet, HashMap};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use fluxheim_config::ByteSize;

use crate::{decode_cache_tags, encode_cache_tags, encoded_cache_tags_len};

pub const DISK_CACHE_MAGIC_V1: &[u8] = b"FLUXHEIM-CACHE-v1\n";
pub const DISK_CACHE_MAGIC_V2: &[u8] = b"FLUXHEIM-CACHE-v2\n";
pub const DISK_CACHE_MAGIC_V3: &[u8] = b"FLUXHEIM-CACHE-v3\n";
pub const DISK_CACHE_MAGIC_V4: &[u8] = b"FLUXHEIM-CACHE-v4\n";
pub const DISK_CACHE_MAGIC_V5: &[u8] = b"FLUXHEIM-CACHE-v5\n";

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
pub struct DiskCacheObjectKey {
    pub combined: String,
    pub primary: String,
    pub user_tag: String,
    pub index_path: Option<String>,
    pub cache_tags: Vec<String>,
}

pub fn disk_cache_header_overhead(key: &DiskCacheObjectKey) -> u64 {
    let combined_len = key.combined.len() as u64;
    let primary_len = key.primary.len() as u64;
    let user_tag_len = key.user_tag.len() as u64;
    let cache_tags_len = encoded_cache_tags_len(&key.cache_tags) as u64;
    let index_path_len = key.index_path.as_deref().unwrap_or_default().len() as u64;
    (DISK_CACHE_MAGIC_V5.len() as u64)
        .saturating_add(decimal_line_len(combined_len))
        .saturating_add(decimal_line_len(primary_len))
        .saturating_add(decimal_line_len(user_tag_len))
        .saturating_add(decimal_line_len(cache_tags_len))
        .saturating_add(decimal_line_len(index_path_len))
        .saturating_add(combined_len)
        .saturating_add(primary_len)
        .saturating_add(user_tag_len)
        .saturating_add(cache_tags_len)
        .saturating_add(index_path_len)
}

pub fn encode_disk_cache_object(
    key: &DiskCacheObjectKey,
    internal_meta: &[u8],
    response_header: &[u8],
    body: &[u8],
) -> io::Result<Vec<u8>> {
    let encoded_cache_tags = encode_cache_tags(&key.cache_tags);
    let index_path = key.index_path.as_deref().unwrap_or_default();

    let mut encoded = Vec::with_capacity(
        DISK_CACHE_MAGIC_V5.len()
            + 128
            + key.combined.len()
            + key.primary.len()
            + key.user_tag.len()
            + encoded_cache_tags.len()
            + index_path.len()
            + internal_meta.len()
            + response_header.len()
            + body.len(),
    );
    write_disk_cache_object_plaintext_prefix(
        &mut encoded,
        key,
        internal_meta,
        response_header,
        body.len() as u64,
    )?;
    encoded.write_all(body)?;
    Ok(encoded)
}

pub fn write_disk_cache_object_plaintext_prefix<W: io::Write>(
    writer: &mut W,
    key: &DiskCacheObjectKey,
    internal_meta: &[u8],
    response_header: &[u8],
    body_len: u64,
) -> io::Result<()> {
    let encoded_cache_tags = encode_cache_tags(&key.cache_tags);
    let index_path = key.index_path.as_deref().unwrap_or_default();

    writer.write_all(DISK_CACHE_MAGIC_V5)?;
    writeln!(writer, "{}", key.combined.len())?;
    writeln!(writer, "{}", key.primary.len())?;
    writeln!(writer, "{}", key.user_tag.len())?;
    writeln!(writer, "{}", encoded_cache_tags.len())?;
    writeln!(writer, "{}", index_path.len())?;
    writeln!(writer, "{}", internal_meta.len())?;
    writeln!(writer, "{}", response_header.len())?;
    writeln!(writer, "{body_len}")?;
    writer.write_all(key.combined.as_bytes())?;
    writer.write_all(key.primary.as_bytes())?;
    writer.write_all(key.user_tag.as_bytes())?;
    writer.write_all(encoded_cache_tags.as_bytes())?;
    writer.write_all(index_path.as_bytes())?;
    writer.write_all(internal_meta)?;
    writer.write_all(response_header)?;
    Ok(())
}

pub fn parse_disk_cache_object(
    bytes: &[u8],
    max_object_bytes: ByteSize,
) -> io::Result<SerializedCacheObject> {
    let (mut offset, format_version) =
        if bytes.get(..DISK_CACHE_MAGIC_V5.len()) == Some(DISK_CACHE_MAGIC_V5) {
            (DISK_CACHE_MAGIC_V5.len(), 5_u8)
        } else if bytes.get(..DISK_CACHE_MAGIC_V4.len()) == Some(DISK_CACHE_MAGIC_V4) {
            (DISK_CACHE_MAGIC_V4.len(), 4_u8)
        } else if bytes.get(..DISK_CACHE_MAGIC_V3.len()) == Some(DISK_CACHE_MAGIC_V3) {
            (DISK_CACHE_MAGIC_V3.len(), 3_u8)
        } else if bytes.get(..DISK_CACHE_MAGIC_V2.len()) == Some(DISK_CACHE_MAGIC_V2) {
            (DISK_CACHE_MAGIC_V2.len(), 2_u8)
        } else if bytes.get(..DISK_CACHE_MAGIC_V1.len()) == Some(DISK_CACHE_MAGIC_V1) {
            (DISK_CACHE_MAGIC_V1.len(), 1_u8)
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid cache object magic",
            ));
        };

    let combined_key_len = if format_version >= 3 {
        parse_disk_cache_len(bytes, &mut offset)?
    } else {
        0
    };
    let primary_key_len = if format_version >= 2 {
        parse_disk_cache_len(bytes, &mut offset)?
    } else {
        0
    };
    let user_tag_len = if format_version >= 3 {
        parse_disk_cache_len(bytes, &mut offset)?
    } else {
        0
    };
    let cache_tags_len = if format_version >= 4 {
        parse_disk_cache_len(bytes, &mut offset)?
    } else {
        0
    };
    let index_path_len = if format_version >= 5 {
        parse_disk_cache_len(bytes, &mut offset)?
    } else {
        0
    };
    let internal_meta_len = parse_disk_cache_len(bytes, &mut offset)?;
    let response_header_len = parse_disk_cache_len(bytes, &mut offset)?;
    let body_len = parse_disk_cache_len(bytes, &mut offset)?;
    let object_bytes = (internal_meta_len as u64)
        .saturating_add(response_header_len as u64)
        .saturating_add(body_len as u64);
    if object_bytes > max_object_bytes.as_u64() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache object exceeds max object size",
        ));
    }

    let total_len = offset
        .checked_add(combined_key_len)
        .and_then(|value| value.checked_add(primary_key_len))
        .and_then(|value| value.checked_add(user_tag_len))
        .and_then(|value| value.checked_add(cache_tags_len))
        .and_then(|value| value.checked_add(index_path_len))
        .and_then(|value| value.checked_add(internal_meta_len))
        .and_then(|value| value.checked_add(response_header_len))
        .and_then(|value| value.checked_add(body_len))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cache object size overflow"))?;
    if total_len != bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache object length mismatch",
        ));
    }

    let weight = u32::try_from(object_bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "cache object weight exceeds u32",
        )
    })?;
    let combined_key_end = offset + combined_key_len;
    let primary_key_end = combined_key_end + primary_key_len;
    let user_tag_end = primary_key_end + user_tag_len;
    let cache_tags_end = user_tag_end + cache_tags_len;
    let index_path_end = cache_tags_end + index_path_len;
    let internal_meta_end = index_path_end + internal_meta_len;
    let response_header_end = internal_meta_end + response_header_len;
    let combined_key = if format_version >= 3 {
        Some(cache_object_utf8(
            &bytes[offset..combined_key_end],
            "combined key",
        )?)
    } else {
        None
    };
    let primary_key = if format_version >= 2 {
        Some(cache_object_utf8(
            &bytes[combined_key_end..primary_key_end],
            "primary key",
        )?)
    } else {
        None
    };
    let user_tag = if format_version >= 3 {
        Some(cache_object_utf8(
            &bytes[primary_key_end..user_tag_end],
            "user tag",
        )?)
    } else {
        None
    };
    let cache_tags = if format_version >= 4 {
        decode_cache_tags(&bytes[user_tag_end..cache_tags_end])?
    } else {
        Vec::new()
    };
    let index_path = if format_version >= 5 {
        let value = cache_object_utf8(&bytes[cache_tags_end..index_path_end], "index path")?;
        (!value.is_empty()).then_some(value)
    } else {
        None
    };
    Ok(SerializedCacheObject {
        combined_key,
        primary_key,
        user_tag,
        index_path,
        cache_tags,
        internal_meta: bytes[index_path_end..internal_meta_end].to_vec(),
        response_header: bytes[internal_meta_end..response_header_end].to_vec(),
        body: Arc::from(&bytes[response_header_end..][..]),
        weight,
    })
}

fn parse_disk_cache_len(bytes: &[u8], offset: &mut usize) -> io::Result<usize> {
    let Some(relative_newline) = bytes[*offset..].iter().position(|byte| *byte == b'\n') else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache object header missing newline",
        ));
    };
    let line_start = *offset;
    let line_end = line_start + relative_newline;
    let line = std::str::from_utf8(&bytes[line_start..line_end]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "cache object header length is not utf-8",
        )
    })?;
    let len = line.parse::<usize>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "cache object header length is invalid",
        )
    })?;
    *offset = line_end + 1;
    Ok(len)
}

fn cache_object_utf8(bytes: &[u8], field: &str) -> io::Result<String> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("{field}: {error}")))
}

fn decimal_line_len(value: u64) -> u64 {
    if value == 0 {
        return 2;
    }
    let mut digits = 0_u64;
    let mut remaining = value;
    while remaining > 0 {
        digits = digits.saturating_add(1);
        remaining /= 10;
    }
    digits.saturating_add(1)
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
        DISK_CACHE_MAGIC_V5, DiskCacheEntry, DiskCacheObjectKey, DiskObjectIndex, DiskObjectLruKey,
        FluxCacheMissFinish, FluxCachePurgeType, SerializedCacheObject, disk_cache_header_overhead,
        encode_disk_cache_object, parse_disk_cache_object,
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
    fn disk_cache_object_envelope_round_trips_v5_fields() {
        let key = DiskCacheObjectKey {
            combined: "combined-key".to_owned(),
            primary: "primary-key".to_owned(),
            user_tag: "vhost".to_owned(),
            index_path: Some("/asset.png".to_owned()),
            cache_tags: vec!["asset".to_owned(), "blue".to_owned()],
        };
        let internal_meta = b"internal";
        let response_header = b"headers";
        let body = b"body";

        let encoded = encode_disk_cache_object(&key, internal_meta, response_header, body).unwrap();
        let parsed =
            parse_disk_cache_object(&encoded, fluxheim_config::ByteSize::from_bytes(1024)).unwrap();

        assert!((disk_cache_header_overhead(&key) as usize) > DISK_CACHE_MAGIC_V5.len());
        assert!((disk_cache_header_overhead(&key) as usize) < encoded.len() - body.len());
        assert_eq!(parsed.combined_key.as_deref(), Some("combined-key"));
        assert_eq!(parsed.primary_key.as_deref(), Some("primary-key"));
        assert_eq!(parsed.user_tag.as_deref(), Some("vhost"));
        assert_eq!(parsed.index_path.as_deref(), Some("/asset.png"));
        assert_eq!(parsed.cache_tags, ["asset", "blue"]);
        assert_eq!(parsed.internal_meta, internal_meta);
        assert_eq!(parsed.response_header, response_header);
        assert_eq!(parsed.body.as_ref(), body);
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
