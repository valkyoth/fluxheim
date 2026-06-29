use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fluxheim_cache::{
    CacheObjectFreshnessState, CachePurgeIndex, DiskCacheObjectKey, DiskTierPlan,
    STORAGE_BIN_DATA_DIR, STORAGE_BIN_MANIFEST_FILENAME, SerializedCacheObject, StorageBinFileSet,
    StorageBinFreeMap, StorageBinIndexEntry, StorageBinLayoutPlan, StorageBinObjectLocation,
    VaryRequestHashField, collect_cache_tags, encode_disk_cache_object, parse_disk_cache_object,
    prepare_storage_bin_layout, read_storage_bin_index, remaining_fresh_ttl_secs,
    response_age_secs, response_cache_control_max_age, vary_request_hash_material,
    write_storage_bin_index,
};
use fluxheim_config::{
    CacheConfig, CacheDiskBackend, CacheDiskEncryptionConfig, CacheDiskEncryptionProvider,
};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::{Digest as _, Sha256};
use tokio::sync::Notify;
use zeroize::Zeroizing;

use crate::NativeHttp1Response;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeMemoryCacheEntry {
    pub(crate) status: u16,
    pub(crate) reason: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) content_length: Option<u64>,
    pub(crate) body: Arc<[u8]>,
    pub(crate) expires_at: Instant,
    pub(crate) stale_while_revalidate_until: Option<Instant>,
    pub(crate) stale_if_error_until: Option<Instant>,
    pub(crate) stored_at: Instant,
    pub(crate) weight: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDiskCacheObjectMetadata {
    pub status: u16,
    pub fresh: bool,
    pub freshness_state: CacheObjectFreshnessState,
    pub serve_stale_while_revalidate: bool,
    pub serve_stale_if_error: bool,
    pub body_bytes: u64,
    pub weight_bytes: u64,
    pub created_unix_secs: Option<u64>,
    pub updated_unix_secs: Option<u64>,
    pub fresh_until_unix_secs: Option<u64>,
    pub age_secs: u64,
    pub fresh_ttl_secs: u64,
    pub stale_while_revalidate_secs: u32,
    pub stale_if_error_secs: u32,
    pub cache_tags: Vec<String>,
    pub header_names: Vec<String>,
    pub header_values: Vec<(String, String)>,
}

#[derive(Debug, Default)]
pub(crate) struct NativeMemoryCacheState {
    pub(crate) objects: HashMap<String, NativeMemoryCacheEntry>,
    pub(crate) variants: HashMap<String, Vec<NativeMemoryCacheVariant>>,
    pub(crate) purge_index: CachePurgeIndex,
    pub(crate) min_uses: HashMap<String, NativeMemoryCacheCounter>,
    pub(crate) cache_pass: HashMap<String, NativeMemoryCacheCounter>,
    pub(crate) revalidating: HashSet<String>,
    pub(crate) filling: HashMap<String, NativeMemoryCacheFill>,
    pub(crate) bytes: u64,
}

#[derive(Debug)]
pub(crate) struct NativeDiskCache {
    root: PathBuf,
    max_bytes: u64,
    max_object_bytes: fluxheim_config::ByteSize,
    backend: NativeDiskCacheBackend,
    encryption: Option<NativeDiskCacheEncryption>,
    state: Mutex<NativeDiskCacheState>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct NativeDiskCacheStats {
    pub(crate) entries: u64,
    pub(crate) size_bytes: u64,
    pub(crate) allocated_size_bytes: u64,
    pub(crate) free_size_bytes: u64,
    pub(crate) free_range_count: u64,
    pub(crate) largest_free_range_bytes: u64,
    pub(crate) bin_files: u64,
    pub(crate) max_size_bytes: u64,
    pub(crate) purge_index_entries: u64,
}

#[derive(Debug)]
enum NativeDiskCacheBackend {
    Filesystem,
    StorageBin(Box<NativeStorageBinBackend>),
}

#[derive(Debug)]
struct NativeStorageBinBackend {
    layout: StorageBinLayoutPlan,
    files: StorageBinFileSet,
    free_map: Mutex<StorageBinFreeMap>,
}

#[derive(Debug)]
struct NativeDiskCacheEncryption {
    key_id: Arc<str>,
    provider: NativeDiskCacheEncryptionProvider,
}

#[derive(Debug)]
enum NativeDiskCacheEncryptionProvider {
    Local {
        key: Arc<LessSafeKey>,
    },
    #[cfg(feature = "openbao-cache-encryption")]
    OpenBaoTransit {
        address: Arc<str>,
        mount: Arc<str>,
        key_name: Arc<str>,
        token: Zeroizing<String>,
    },
    #[cfg(not(feature = "openbao-cache-encryption"))]
    OpenBaoTransitDisabled,
}

#[derive(Debug, Default)]
struct NativeDiskCacheState {
    objects: HashMap<String, NativeDiskCacheRecord>,
    variants: HashMap<String, Vec<NativeMemoryCacheVariant>>,
    bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeDiskCacheRecord {
    location: NativeDiskCacheLocation,
    weight: u64,
    accessed_at: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NativeDiskCacheLocation {
    Filesystem(PathBuf),
    StorageBin(StorageBinObjectLocation),
}

impl NativeDiskCacheLocation {
    fn display(&self) -> String {
        match self {
            Self::Filesystem(path) => path.display().to_string(),
            Self::StorageBin(location) => format!(
                "storage-bin:{:016x}:{}+{}",
                location.bin_id, location.offset, location.len
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeDiskCacheStoreKey {
    pub(crate) combined: String,
    pub(crate) primary: String,
    pub(crate) user_tag: String,
    pub(crate) index_path: Option<String>,
    pub(crate) cache_tags: Vec<String>,
    pub(crate) vary_fields: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeDiskCacheMeta {
    status: u16,
    reason: String,
    content_length: Option<u64>,
    expires_at_unix_secs: u64,
    stale_while_revalidate_until_unix_secs: Option<u64>,
    stale_if_error_until_unix_secs: Option<u64>,
    stored_at_unix_secs: u64,
    vary_fields: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeMemoryCacheCounter {
    pub(crate) uses: u32,
    pub(crate) seen_at: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeMemoryCacheVariant {
    pub(crate) fields: Vec<String>,
    pub(crate) key: String,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeMemoryCacheFill {
    pub(crate) notify: Arc<Notify>,
    pub(crate) started_at: Instant,
}

impl NativeMemoryCacheEntry {
    pub(crate) fn to_response(&self) -> NativeHttp1Response {
        let mut response =
            NativeHttp1Response::new(self.status, self.reason.clone(), self.body.to_vec());
        for (name, value) in &self.headers {
            response = response.with_header(name.clone(), value.clone());
        }
        if let Some(content_length) = self.content_length {
            response = response.with_content_length(content_length);
        }
        response
    }

    pub(crate) fn age_secs(&self) -> u64 {
        Instant::now()
            .saturating_duration_since(self.stored_at)
            .as_secs()
    }
}

impl NativeDiskCacheBackend {
    fn from_config(config: &CacheConfig) -> std::io::Result<(PathBuf, Self)> {
        let path = config.disk.path.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "native disk cache requires cache.disk.path",
            )
        })?;
        match config.disk.backend {
            CacheDiskBackend::Filesystem => {
                let root = prepare_native_disk_cache_root(path)?;
                Ok((root, Self::Filesystem))
            }
            CacheDiskBackend::StorageBin => {
                let plan = DiskTierPlan {
                    backend: CacheDiskBackend::StorageBin,
                    path: path.clone(),
                    max_size_bytes: config.disk.max_size_bytes,
                    max_object_bytes: config.max_object_bytes,
                    cache_tag_headers: Vec::new(),
                    storage_bin: config.disk.storage_bin.clone(),
                    encryption: config.disk.encryption.clone(),
                };
                let mut layout = StorageBinLayoutPlan::from_disk_plan(&plan).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "native storage-bin cache requires a storage-bin disk plan",
                    )
                })?;
                prepare_storage_bin_layout(&layout)?;
                let root = layout.root.canonicalize()?;
                layout = StorageBinLayoutPlan {
                    root: root.clone(),
                    manifest_path: root.join(STORAGE_BIN_MANIFEST_FILENAME),
                    data_dir: root.join(STORAGE_BIN_DATA_DIR),
                    ..layout
                };
                let free_map = StorageBinFreeMap::new(&layout);
                let files = StorageBinFileSet::new(layout.clone());
                Ok((
                    root,
                    Self::StorageBin(Box::new(NativeStorageBinBackend {
                        layout,
                        files,
                        free_map: Mutex::new(free_map),
                    })),
                ))
            }
        }
    }
}

impl NativeDiskCache {
    pub(crate) fn from_config(config: &CacheConfig) -> Option<Self> {
        if !native_disk_cache_supported(config) {
            return None;
        }
        let (root, backend) = match NativeDiskCacheBackend::from_config(config) {
            Ok(backend) => backend,
            Err(error) => {
                log::error!(
                    target: "fluxheim::native_http1",
                    "native disk cache backend: {error}"
                );
                return None;
            }
        };
        let encryption = match NativeDiskCacheEncryption::from_config(&config.disk.encryption) {
            Ok(encryption) => encryption,
            Err(error) => {
                log::error!(
                    target: "fluxheim::native_http1",
                    "native disk cache encryption {}: {error}",
                    root.display()
                );
                return None;
            }
        };
        let mut cache = Self {
            root,
            max_bytes: config.disk.max_size_bytes.as_u64(),
            max_object_bytes: config.max_object_bytes,
            backend,
            encryption,
            state: Mutex::new(NativeDiskCacheState::default()),
        };
        if let Err(error) = cache.rebuild_index() {
            log::warn!(
                target: "fluxheim::native_http1",
                "native disk cache index rebuild {}: {error}",
                cache.root.display()
            );
        }
        Some(cache)
    }

    pub(crate) fn stats(&self) -> NativeDiskCacheStats {
        let (entries, size_bytes, weighted_size_bytes) = self.with_state(|state| {
            (
                state.objects.len() as u64,
                state.bytes,
                state
                    .objects
                    .values()
                    .fold(0_u64, |total, record| total.saturating_add(record.weight)),
            )
        });
        let mut stats = NativeDiskCacheStats {
            entries,
            size_bytes,
            allocated_size_bytes: weighted_size_bytes,
            free_size_bytes: self.max_bytes.saturating_sub(size_bytes),
            largest_free_range_bytes: self.max_bytes.saturating_sub(size_bytes),
            max_size_bytes: self.max_bytes,
            ..NativeDiskCacheStats::default()
        };
        if let NativeDiskCacheBackend::StorageBin(storage_bin) = &self.backend {
            let free_map = match storage_bin.free_map.lock() {
                Ok(free_map) => free_map,
                Err(error) => {
                    log::error!(
                        target: "fluxheim::security",
                        "native disk cache storage-bin free-map mutex poisoned: {error}"
                    );
                    std::process::abort();
                }
            };
            stats.allocated_size_bytes = free_map.allocated_size_bytes();
            stats.free_size_bytes = free_map.free_size_bytes();
            stats.free_range_count = free_map.free_range_count();
            stats.largest_free_range_bytes = free_map.largest_free_range_bytes();
            stats.bin_files = free_map.bin_files();
        }
        stats
    }

    pub(crate) fn get(
        &self,
        key: &str,
        request_variant_key: impl Fn(&[String]) -> Option<String>,
    ) -> Option<NativeMemoryCacheEntry> {
        if let Some(variants) = self.with_state(|state| state.variants.get(key).cloned()) {
            for variant in variants {
                let Some(variant_key) = request_variant_key(&variant.fields) else {
                    continue;
                };
                if variant_key != variant.key {
                    continue;
                }
                return self.get_combined(&variant.key);
            }
            return None;
        }
        self.get_combined(key)
    }

    pub(crate) fn store(
        &self,
        key: NativeDiskCacheStoreKey,
        entry: &NativeMemoryCacheEntry,
    ) -> std::io::Result<()> {
        let meta = NativeDiskCacheMeta::from_entry(entry, key.vary_fields.clone());
        let disk_key = DiskCacheObjectKey {
            combined: key.combined.clone(),
            primary: key.primary.clone(),
            user_tag: key.user_tag,
            index_path: key.index_path,
            cache_tags: key.cache_tags,
        };
        let encoded = encode_disk_cache_object(
            &disk_key,
            &meta.encode(),
            &native_disk_response_header_bytes(entry),
            &entry.body,
        )?;
        let encoded = if let Some(encryption) = &self.encryption {
            encryption.encrypt(&key.combined, &encoded)?
        } else {
            encoded
        };
        let encoded_len = encoded.len() as u64;
        if !self.evict_until_admissible(&key.combined, encoded_len)? {
            return Ok(());
        }
        self.remove_combined(&key.combined);
        let Some(location) = self.write_encoded_object(&key.combined, &encoded)? else {
            return Ok(());
        };
        self.with_state_mut(|state| {
            state.objects.insert(
                key.combined.clone(),
                NativeDiskCacheRecord {
                    location,
                    weight: encoded_len,
                    accessed_at: SystemTime::now(),
                },
            );
            if key.vary_fields.is_empty() {
                state.variants.remove(&key.primary);
            } else {
                let variants = state.variants.entry(key.primary).or_default();
                variants.retain(|variant| variant.key != key.combined);
                variants.push(NativeMemoryCacheVariant {
                    fields: key.vary_fields,
                    key: key.combined,
                });
            }
            state.bytes = state.bytes.saturating_add(encoded_len);
        });
        self.persist_storage_bin_index();
        Ok(())
    }

    fn evict_until_admissible(
        &self,
        incoming_key: &str,
        incoming_weight: u64,
    ) -> std::io::Result<bool> {
        if incoming_weight > self.max_bytes {
            return Ok(false);
        }
        loop {
            let admissible = self.with_state(|state| {
                let existing = state
                    .objects
                    .get(incoming_key)
                    .map(|record| record.weight)
                    .unwrap_or(0);
                state
                    .bytes
                    .saturating_sub(existing)
                    .saturating_add(incoming_weight)
                    <= self.max_bytes
            });
            if admissible {
                return Ok(true);
            }
            if !self.evict_oldest()? {
                return Ok(false);
            }
        }
    }

    fn write_encoded_object(
        &self,
        combined_key: &str,
        encoded: &[u8],
    ) -> std::io::Result<Option<NativeDiskCacheLocation>> {
        match &self.backend {
            NativeDiskCacheBackend::Filesystem => {
                let path = self.path_for_combined_key(combined_key);
                if let Some(parent) = path.parent() {
                    create_native_cache_dir_all(parent)?;
                }
                self.write_object_atomically(&path, encoded)?;
                Ok(Some(NativeDiskCacheLocation::Filesystem(path)))
            }
            NativeDiskCacheBackend::StorageBin(storage_bin) => {
                let encoded_len = encoded.len() as u64;
                let Some(location) = self.allocate_storage_bin_location(encoded_len)? else {
                    return Ok(None);
                };
                match storage_bin.files.write_object(location, encoded) {
                    Ok(()) => Ok(Some(NativeDiskCacheLocation::StorageBin(location))),
                    Err(error) => {
                        self.release_storage_bin_location(location)?;
                        Err(error)
                    }
                }
            }
        }
    }

    fn allocate_storage_bin_location(
        &self,
        len: u64,
    ) -> std::io::Result<Option<StorageBinObjectLocation>> {
        loop {
            let allocation = match &self.backend {
                NativeDiskCacheBackend::StorageBin(storage_bin) => {
                    let mut free_map = storage_bin.free_map.lock().map_err(|_| {
                        std::io::Error::other("native storage-bin free map mutex poisoned")
                    })?;
                    free_map.allocate(len)?
                }
                NativeDiskCacheBackend::Filesystem => return Ok(None),
            };
            if allocation.is_some() {
                return Ok(allocation);
            }
            if !self.evict_oldest()? {
                return Ok(None);
            }
        }
    }

    fn get_combined(&self, combined_key: &str) -> Option<NativeMemoryCacheEntry> {
        let record = self.with_state(|state| state.objects.get(combined_key).cloned())?;
        let object = match self.read_record(&record) {
            Ok(object) => object,
            Err(error) => {
                log::debug!(
                    target: "fluxheim::native_http1",
                    "native disk cache read {}: {error}",
                    record.location.display()
                );
                self.remove_combined(combined_key);
                return None;
            }
        };
        let entry = match native_memory_entry_from_disk_object(&object) {
            Some(entry) => entry,
            None => {
                self.remove_combined(combined_key);
                return None;
            }
        };
        self.with_state_mut(|state| {
            if let Some(record) = state.objects.get_mut(combined_key) {
                record.accessed_at = SystemTime::now();
            }
        });
        Some(entry)
    }

    fn rebuild_index(&mut self) -> std::io::Result<()> {
        let mut state = NativeDiskCacheState::default();
        match &self.backend {
            NativeDiskCacheBackend::Filesystem => self.rebuild_filesystem_index(&mut state)?,
            NativeDiskCacheBackend::StorageBin(storage_bin) => {
                let valid_entries = self.rebuild_storage_bin_index(
                    &mut state,
                    &storage_bin.layout,
                    &storage_bin.files,
                )?;
                let rebuilt =
                    StorageBinFreeMap::from_occupied(&storage_bin.layout, &valid_entries)?;
                let mut free_map = storage_bin.free_map.lock().map_err(|_| {
                    std::io::Error::other("native storage-bin free map mutex poisoned")
                })?;
                *free_map = rebuilt;
            }
        }
        self.state = Mutex::new(state);
        self.prune();
        Ok(())
    }

    fn rebuild_filesystem_index(&self, state: &mut NativeDiskCacheState) -> std::io::Result<()> {
        for shard in std::fs::read_dir(&self.root)? {
            let shard = shard?;
            let shard_path = shard.path();
            if !shard.file_type()?.is_dir()
                || native_cache_path_contains_symlink(&self.root, &shard_path)?
            {
                continue;
            }
            for object in std::fs::read_dir(&shard_path)? {
                let object = object?;
                let path = object.path();
                if object.file_type()?.is_dir()
                    || path.extension().and_then(|value| value.to_str()) != Some("fhc")
                    || native_cache_path_contains_symlink(&self.root, &path)?
                {
                    continue;
                }
                let bytes = match read_native_disk_cache_file(&path) {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };
                let bytes = match self.decrypt_if_needed(&bytes) {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };
                let parsed = match parse_disk_cache_object(&bytes, self.max_object_bytes) {
                    Ok(parsed) => parsed,
                    Err(_) => continue,
                };
                let Some(combined) = parsed.combined_key.clone() else {
                    continue;
                };
                let Some(primary) = parsed.primary_key.clone() else {
                    continue;
                };
                let Some(meta) = NativeDiskCacheMeta::decode(&parsed.internal_meta) else {
                    continue;
                };
                if native_memory_entry_from_disk_object(&parsed).is_none() {
                    continue;
                }
                let weight = bytes.len() as u64;
                state.bytes = state.bytes.saturating_add(weight);
                state.objects.insert(
                    combined.clone(),
                    NativeDiskCacheRecord {
                        location: NativeDiskCacheLocation::Filesystem(path),
                        weight,
                        accessed_at: SystemTime::now(),
                    },
                );
                if !meta.vary_fields.is_empty() {
                    state
                        .variants
                        .entry(primary)
                        .or_default()
                        .push(NativeMemoryCacheVariant {
                            fields: meta.vary_fields,
                            key: combined,
                        });
                }
            }
        }
        Ok(())
    }

    fn rebuild_storage_bin_index(
        &self,
        state: &mut NativeDiskCacheState,
        layout: &StorageBinLayoutPlan,
        files: &StorageBinFileSet,
    ) -> std::io::Result<Vec<StorageBinIndexEntry>> {
        let mut valid_entries = Vec::new();
        for entry in read_storage_bin_index(layout)? {
            let bytes = match files.read_object(entry.location) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let bytes = match self.decrypt_if_needed(&bytes) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let parsed = match parse_disk_cache_object(&bytes, self.max_object_bytes) {
                Ok(parsed) => parsed,
                Err(_) => continue,
            };
            if parsed.combined_key.as_deref() != Some(entry.combined_key.as_str()) {
                continue;
            }
            let Some(primary) = parsed.primary_key.clone() else {
                continue;
            };
            let Some(meta) = NativeDiskCacheMeta::decode(&parsed.internal_meta) else {
                continue;
            };
            if native_memory_entry_from_disk_object(&parsed).is_none() {
                continue;
            }
            let combined = entry.combined_key.clone();
            state.bytes = state.bytes.saturating_add(entry.location.len);
            state.objects.insert(
                combined.clone(),
                NativeDiskCacheRecord {
                    location: NativeDiskCacheLocation::StorageBin(entry.location),
                    weight: entry.location.len,
                    accessed_at: entry.accessed,
                },
            );
            if !meta.vary_fields.is_empty() {
                state
                    .variants
                    .entry(primary)
                    .or_default()
                    .push(NativeMemoryCacheVariant {
                        fields: meta.vary_fields,
                        key: combined,
                    });
            }
            valid_entries.push(entry);
        }
        Ok(valid_entries)
    }

    fn read_record(
        &self,
        record: &NativeDiskCacheRecord,
    ) -> std::io::Result<SerializedCacheObject> {
        let bytes = match (&self.backend, &record.location) {
            (NativeDiskCacheBackend::Filesystem, NativeDiskCacheLocation::Filesystem(path)) => {
                if native_cache_path_contains_symlink(&self.root, path)? {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "native disk cache object path crosses symlink",
                    ));
                }
                read_native_disk_cache_file(path)?
            }
            (
                NativeDiskCacheBackend::StorageBin(storage_bin),
                NativeDiskCacheLocation::StorageBin(location),
            ) => storage_bin.files.read_object(*location)?,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "native disk cache record backend mismatch",
                ));
            }
        };
        let bytes = self.decrypt_if_needed(&bytes)?;
        parse_disk_cache_object(&bytes, self.max_object_bytes)
    }

    fn decrypt_if_needed(&self, bytes: &[u8]) -> std::io::Result<Vec<u8>> {
        match &self.encryption {
            Some(encryption) => encryption.decrypt(bytes),
            None => {
                if bytes.get(..NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1.len())
                    == Some(NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1)
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "encrypted cache object found while native disk encryption is disabled",
                    ));
                }
                Ok(bytes.to_vec())
            }
        }
    }

    fn write_object_atomically(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        let mut last_error = None;
        for _ in 0..4 {
            let tmp_path = self.temp_path_for(path)?;
            let tmp_safe = NativeSafeDiskCachePath::from_path(tmp_path);
            let destination = NativeSafeDiskCachePath::from_path(path.to_path_buf());
            let write_result = (|| {
                let mut file = tmp_safe.create_new_file()?;
                file.write_all(bytes)?;
                file.sync_all()?;
                destination.rename_from(&tmp_safe)
            })();
            match write_result {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = tmp_safe.remove_file();
                    last_error = Some(error);
                }
                Err(error) => {
                    let _ = tmp_safe.remove_file();
                    return Err(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "native disk cache temporary path collision",
            )
        }))
    }

    fn temp_path_for(&self, path: &Path) -> std::io::Result<PathBuf> {
        let parent = path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "native disk cache object path has no parent",
            )
        })?;
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random)
            .map_err(|error| std::io::Error::other(format!("cache temp random: {error}")))?;
        let mut encoded = String::with_capacity(random.len() * 2);
        for byte in random {
            let _ = write!(&mut encoded, "{byte:02x}");
        }
        Ok(parent.join(format!(".{encoded}.tmp")))
    }

    fn path_for_combined_key(&self, key: &str) -> PathBuf {
        let digest = Sha256::digest(key.as_bytes());
        let mut encoded = String::with_capacity(digest.len() * 2);
        for byte in digest {
            let _ = write!(&mut encoded, "{byte:02x}");
        }
        self.root.join(&encoded[..2]).join(format!("{encoded}.fhc"))
    }

    fn prune(&self) {
        loop {
            let over_budget = self.with_state(|state| state.bytes > self.max_bytes);
            if !over_budget {
                break;
            }
            match self.evict_oldest() {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "native disk cache prune failed: {error}"
                    );
                    break;
                }
            }
        }
        self.persist_storage_bin_index();
    }

    fn purge_primary(&self, primary_key: &str, combined_key: &str) -> bool {
        let mut purged = self.remove_combined(combined_key);
        let variant_keys = self.with_state(|state| {
            state
                .variants
                .get(primary_key)
                .into_iter()
                .flatten()
                .map(|variant| variant.key.clone())
                .collect::<Vec<_>>()
        });
        for variant_key in variant_keys {
            purged |= self.remove_combined(&variant_key);
        }
        purged
    }

    fn remove_combined(&self, combined_key: &str) -> bool {
        let removed = self.with_state_mut(|state| {
            let removed = state.objects.remove(combined_key);
            if let Some(record) = &removed {
                state.bytes = state.bytes.saturating_sub(record.weight);
            }
            state.variants.retain(|_, variants| {
                variants.retain(|variant| variant.key != combined_key);
                !variants.is_empty()
            });
            removed
        });
        if let Some(record) = removed {
            let _ = self.remove_location(&record.location);
            self.persist_storage_bin_index();
            return true;
        }
        false
    }

    fn evict_oldest(&self) -> std::io::Result<bool> {
        let removed = self.with_state_mut(|state| {
            let key = state
                .objects
                .iter()
                .min_by_key(|(key, record)| (record.accessed_at, (*key).clone()))
                .map(|(key, _)| key.clone())?;
            let removed = state.objects.remove(&key);
            if let Some(record) = &removed {
                state.bytes = state.bytes.saturating_sub(record.weight);
            }
            state.variants.retain(|_, variants| {
                variants.retain(|variant| variant.key != key);
                !variants.is_empty()
            });
            removed
        });
        let Some(record) = removed else {
            return Ok(false);
        };
        self.remove_location(&record.location)?;
        self.persist_storage_bin_index();
        Ok(true)
    }

    fn remove_location(&self, location: &NativeDiskCacheLocation) -> std::io::Result<()> {
        match (&self.backend, location) {
            (NativeDiskCacheBackend::Filesystem, NativeDiskCacheLocation::Filesystem(path)) => {
                match NativeSafeDiskCachePath::from_path(path.clone()).remove_file() {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(error),
                }
            }
            (
                NativeDiskCacheBackend::StorageBin(_),
                NativeDiskCacheLocation::StorageBin(location),
            ) => self.release_storage_bin_location(*location),
            _ => Ok(()),
        }
    }

    fn release_storage_bin_location(
        &self,
        location: StorageBinObjectLocation,
    ) -> std::io::Result<()> {
        let NativeDiskCacheBackend::StorageBin(storage_bin) = &self.backend else {
            return Ok(());
        };
        {
            let mut free_map = storage_bin
                .free_map
                .lock()
                .map_err(|_| std::io::Error::other("native storage-bin free map mutex poisoned"))?;
            free_map.release(location)?;
            for bin_id in free_map.reclaim_free_tail_bins() {
                if let Err(error) = storage_bin.files.remove_bin(bin_id) {
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "native storage-bin tail reclaim failed for bin {bin_id}: {error}"
                    );
                }
            }
        }
        Ok(())
    }

    fn persist_storage_bin_index(&self) {
        let NativeDiskCacheBackend::StorageBin(storage_bin) = &self.backend else {
            return;
        };
        let entries = self.with_state(|state| {
            state
                .objects
                .iter()
                .filter_map(|(combined_key, record)| {
                    let NativeDiskCacheLocation::StorageBin(location) = &record.location else {
                        return None;
                    };
                    Some(StorageBinIndexEntry {
                        combined_key: combined_key.clone(),
                        location: *location,
                        accessed: record.accessed_at,
                    })
                })
                .collect::<Vec<_>>()
        });
        if let Err(error) = write_storage_bin_index(&storage_bin.layout, &entries) {
            log::warn!(
                target: "fluxheim::native_http1",
                "native storage-bin index write {}: {error}",
                storage_bin.layout.root.display()
            );
        }
    }

    fn with_state<R>(&self, f: impl FnOnce(&NativeDiskCacheState) -> R) -> R {
        match self.state.lock() {
            Ok(state) => f(&state),
            Err(error) => {
                log::error!(
                    target: "fluxheim::native_http1",
                    "native disk cache mutex poisoned: {error}"
                );
                std::process::abort();
            }
        }
    }

    fn with_state_mut<R>(&self, f: impl FnOnce(&mut NativeDiskCacheState) -> R) -> R {
        match self.state.lock() {
            Ok(mut state) => f(&mut state),
            Err(error) => {
                log::error!(
                    target: "fluxheim::native_http1",
                    "native disk cache mutex poisoned: {error}"
                );
                std::process::abort();
            }
        }
    }
}

pub fn inspect_native_disk_cache_object(
    config: &CacheConfig,
    primary_key: &str,
    request_headers: &[(String, String)],
) -> Option<NativeDiskCacheObjectMetadata> {
    let cache = NativeDiskCache::from_config(config)?;
    let entry = cache.get(primary_key, |fields| {
        native_inspection_vary_cache_key(primary_key, fields, request_headers)
    })?;
    let now = Instant::now();
    let fresh = entry.expires_at > now;
    let serve_stale_while_revalidate = !fresh
        && entry
            .stale_while_revalidate_until
            .is_some_and(|until| until > now);
    let serve_stale_if_error =
        !fresh && entry.stale_if_error_until.is_some_and(|until| until > now);
    let freshness_state = if fresh {
        CacheObjectFreshnessState::Fresh
    } else if serve_stale_while_revalidate || serve_stale_if_error {
        CacheObjectFreshnessState::Stale
    } else {
        CacheObjectFreshnessState::Expired
    };
    let mut header_names = entry
        .headers
        .iter()
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect::<Vec<_>>();
    header_names.sort();
    header_names.dedup();
    let mut cache_tags = Vec::new();
    let mut cache_tags_total_bytes = 0_usize;
    for tag_header in &config.tag_headers {
        for (_, value) in entry
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(tag_header))
        {
            collect_cache_tags(value, &mut cache_tags, &mut cache_tags_total_bytes);
        }
    }
    Some(NativeDiskCacheObjectMetadata {
        status: entry.status,
        fresh,
        freshness_state,
        serve_stale_while_revalidate,
        serve_stale_if_error,
        body_bytes: entry.body.len() as u64,
        weight_bytes: entry.weight,
        created_unix_secs: Some(native_instant_to_unix_secs(entry.stored_at)),
        updated_unix_secs: Some(native_instant_to_unix_secs(entry.stored_at)),
        fresh_until_unix_secs: Some(native_instant_to_unix_secs(entry.expires_at)),
        age_secs: entry.age_secs(),
        fresh_ttl_secs: entry
            .expires_at
            .saturating_duration_since(entry.stored_at)
            .as_secs(),
        stale_while_revalidate_secs: native_stale_window_secs(
            entry.expires_at,
            entry.stale_while_revalidate_until,
        ),
        stale_if_error_secs: native_stale_window_secs(entry.expires_at, entry.stale_if_error_until),
        cache_tags,
        header_names,
        header_values: entry.headers,
    })
}

pub fn purge_native_disk_cache_primary(
    config: &CacheConfig,
    primary_key: &str,
    combined_key: &str,
) -> bool {
    let Some(cache) = NativeDiskCache::from_config(config) else {
        return false;
    };
    cache.purge_primary(primary_key, combined_key)
}

fn native_inspection_vary_cache_key(
    base_key: &str,
    fields: &[String],
    request_headers: &[(String, String)],
) -> Option<String> {
    let material = vary_request_hash_material(fields.iter().map(|field| {
        VaryRequestHashField {
            name: field.as_str(),
            values: request_headers
                .iter()
                .filter_map(|(name, value)| {
                    name.eq_ignore_ascii_case(field).then_some(value.as_bytes())
                })
                .collect(),
        }
    }));
    let variance = base64_ng::URL_SAFE_NO_PAD.encode_string(&material).ok()?;
    Some(format!("{base_key};vary:{variance}"))
}

fn native_stale_window_secs(expires_at: Instant, until: Option<Instant>) -> u32 {
    let secs = until
        .map(|until| until.saturating_duration_since(expires_at).as_secs())
        .unwrap_or_default();
    u32::try_from(secs).unwrap_or(u32::MAX)
}

pub(crate) fn native_disk_cache_supported(cache: &CacheConfig) -> bool {
    !cache.disk.enabled
        || (matches!(
            cache.disk.backend,
            CacheDiskBackend::Filesystem | CacheDiskBackend::StorageBin
        ) && (!cache.disk.encryption.enabled || native_disk_cache_encryption_supported(cache)))
}

fn native_disk_cache_encryption_supported(cache: &CacheConfig) -> bool {
    match cache.disk.encryption.provider {
        CacheDiskEncryptionProvider::Local => true,
        CacheDiskEncryptionProvider::OpenbaoTransit => cfg!(feature = "openbao-cache-encryption"),
    }
}

const NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1: &[u8] = b"FLUXHEIM-CACHE-ENC-v1\n";
#[cfg(feature = "openbao-cache-encryption")]
const OPENBAO_TRANSIT_RESPONSE_OVERHEAD_BYTES: u64 = 4096;
#[cfg(feature = "openbao-cache-encryption")]
const OPENBAO_TRANSIT_MAX_RESPONSE_BYTES: u64 = 512 * 1024 * 1024;

impl NativeDiskCacheEncryption {
    fn from_config(config: &CacheDiskEncryptionConfig) -> std::io::Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }
        let key_id = Arc::from(config.key_id.as_deref().unwrap_or("local"));
        let provider = match config.provider {
            CacheDiskEncryptionProvider::Local => {
                let key_bytes = match (&config.key_file, config.key_credential.as_deref()) {
                    (Some(path), None) => read_native_cache_encryption_key_file(path)?,
                    (None, Some(credential)) => {
                        let path = native_cache_encryption_credential_path(credential);
                        read_native_cache_encryption_key_file(&path)?
                    }
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "native disk cache encryption requires exactly one local key source",
                        ));
                    }
                };
                let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid native disk cache encryption key",
                    )
                })?;
                NativeDiskCacheEncryptionProvider::Local {
                    key: Arc::new(LessSafeKey::new(unbound)),
                }
            }
            CacheDiskEncryptionProvider::OpenbaoTransit => native_openbao_transit_provider(config)?,
        };
        Ok(Some(Self { key_id, provider }))
    }

    fn encrypt(&self, combined_key: &str, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        let aad = native_cache_encryption_aad(&self.key_id, combined_key);
        let (nonce, ciphertext) = match &self.provider {
            NativeDiskCacheEncryptionProvider::Local { key } => {
                let mut nonce = [0_u8; 12];
                getrandom::fill(&mut nonce).map_err(|error| {
                    std::io::Error::other(format!(
                        "generate native cache encryption nonce: {error}"
                    ))
                })?;
                let mut ciphertext = plaintext.to_vec();
                key.seal_in_place_append_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(aad),
                    &mut ciphertext,
                )
                .map_err(|_| std::io::Error::other("encrypt native cache object"))?;
                (nonce.to_vec(), ciphertext)
            }
            #[cfg(feature = "openbao-cache-encryption")]
            NativeDiskCacheEncryptionProvider::OpenBaoTransit {
                address,
                mount,
                key_name,
                token,
            } => {
                let ciphertext = openbao_transit_encrypt(
                    address,
                    mount,
                    key_name,
                    token.as_str(),
                    plaintext,
                    &aad,
                )?;
                (Vec::new(), ciphertext.into_bytes())
            }
            #[cfg(not(feature = "openbao-cache-encryption"))]
            NativeDiskCacheEncryptionProvider::OpenBaoTransitDisabled => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "native disk cache OpenBao Transit encryption is not enabled in this build",
                ));
            }
        };

        let mut encoded = Vec::with_capacity(
            NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1.len()
                + 128
                + self.key_id.len()
                + combined_key.len()
                + nonce.len()
                + ciphertext.len(),
        );
        encoded.write_all(NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1)?;
        writeln!(encoded, "{}", self.key_id.len())?;
        writeln!(encoded, "{}", combined_key.len())?;
        writeln!(encoded, "{}", nonce.len())?;
        writeln!(encoded, "{}", ciphertext.len())?;
        encoded.write_all(self.key_id.as_bytes())?;
        encoded.write_all(combined_key.as_bytes())?;
        encoded.write_all(&nonce)?;
        encoded.write_all(&ciphertext)?;
        Ok(encoded)
    }

    fn decrypt(&self, bytes: &[u8]) -> std::io::Result<Vec<u8>> {
        if bytes.get(..NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1.len())
            != Some(NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unencrypted cache object found while native disk encryption is enabled",
            ));
        }

        let mut offset = NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1.len();
        let key_id_len = native_encrypted_disk_len(bytes, &mut offset)?;
        let combined_key_len = native_encrypted_disk_len(bytes, &mut offset)?;
        let nonce_len = native_encrypted_disk_len(bytes, &mut offset)?;
        let ciphertext_len = native_encrypted_disk_len(bytes, &mut offset)?;
        let total_len = offset
            .checked_add(key_id_len)
            .and_then(|value| value.checked_add(combined_key_len))
            .and_then(|value| value.checked_add(nonce_len))
            .and_then(|value| value.checked_add(ciphertext_len))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "encrypted native cache object size overflow",
                )
            })?;
        if total_len != bytes.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "encrypted native cache object length mismatch",
            ));
        }

        let key_id_end = offset + key_id_len;
        let combined_key_end = key_id_end + combined_key_len;
        let nonce_end = combined_key_end + nonce_len;
        let key_id = native_cache_utf8(&bytes[offset..key_id_end], "encryption key id")?;
        if key_id != self.key_id.as_ref() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "encrypted native cache object key id does not match configured key",
            ));
        }
        let combined_key = native_cache_utf8(&bytes[key_id_end..combined_key_end], "combined key")?;
        let aad = native_cache_encryption_aad(&self.key_id, &combined_key);
        match &self.provider {
            NativeDiskCacheEncryptionProvider::Local { key } => {
                if nonce_len != 12 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid encrypted native cache object nonce length",
                    ));
                }
                let mut nonce = [0_u8; 12];
                nonce.copy_from_slice(&bytes[combined_key_end..nonce_end]);
                let mut plaintext = bytes[nonce_end..].to_vec();
                key.open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(aad),
                    &mut plaintext,
                )
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "decrypt native cache object",
                    )
                })?;
                let plaintext_len = plaintext
                    .len()
                    .checked_sub(AES_256_GCM.tag_len())
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "short encrypted native cache object",
                        )
                    })?;
                plaintext.truncate(plaintext_len);
                Ok(plaintext)
            }
            #[cfg(feature = "openbao-cache-encryption")]
            NativeDiskCacheEncryptionProvider::OpenBaoTransit {
                address,
                mount,
                key_name,
                token,
            } => {
                if nonce_len != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid OpenBao encrypted native cache object nonce length",
                    ));
                }
                let ciphertext = native_cache_utf8(&bytes[nonce_end..], "openbao ciphertext")?;
                openbao_transit_decrypt(address, mount, key_name, token.as_str(), &ciphertext, &aad)
            }
            #[cfg(not(feature = "openbao-cache-encryption"))]
            NativeDiskCacheEncryptionProvider::OpenBaoTransitDisabled => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "native disk cache OpenBao Transit encryption is not enabled in this build",
            )),
        }
    }
}

#[cfg(feature = "openbao-cache-encryption")]
fn native_openbao_transit_provider(
    config: &CacheDiskEncryptionConfig,
) -> std::io::Result<NativeDiskCacheEncryptionProvider> {
    let token = match (
        &config.openbao.token_file,
        config.openbao.token_credential.as_deref(),
    ) {
        (Some(path), None) => read_native_cache_encryption_secret_file(path)?,
        (None, Some(credential)) => {
            let path = native_cache_encryption_credential_path(credential);
            read_native_cache_encryption_secret_file(&path)?
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "native disk cache encryption requires exactly one OpenBao token source",
            ));
        }
    };
    if token.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "native disk cache OpenBao token must not be empty",
        ));
    }
    let token = Zeroizing::new(token.trim().to_owned());
    Ok(NativeDiskCacheEncryptionProvider::OpenBaoTransit {
        address: Arc::from(
            config
                .openbao
                .address
                .as_deref()
                .unwrap_or_default()
                .trim()
                .trim_end_matches('/'),
        ),
        mount: Arc::from(
            config
                .openbao
                .mount
                .as_deref()
                .unwrap_or_default()
                .trim_matches('/'),
        ),
        key_name: Arc::from(
            config
                .openbao
                .key_name
                .as_deref()
                .unwrap_or_default()
                .trim_matches('/'),
        ),
        token,
    })
}

#[cfg(not(feature = "openbao-cache-encryption"))]
fn native_openbao_transit_provider(
    _config: &CacheDiskEncryptionConfig,
) -> std::io::Result<NativeDiskCacheEncryptionProvider> {
    Ok(NativeDiskCacheEncryptionProvider::OpenBaoTransitDisabled)
}

fn native_encrypted_disk_len(bytes: &[u8], offset: &mut usize) -> std::io::Result<usize> {
    let relative_newline = bytes
        .get(*offset..)
        .and_then(|tail| tail.iter().position(|byte| *byte == b'\n'))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "encrypted native cache object length line is truncated",
            )
        })?;
    let end = (*offset).checked_add(relative_newline).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted native cache object length offset overflow",
        )
    })?;
    let line = std::str::from_utf8(&bytes[*offset..end]).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted native cache object length is not UTF-8",
        )
    })?;
    *offset = end.checked_add(1).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted native cache object length offset overflow",
        )
    })?;
    line.parse::<usize>().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted native cache object length is invalid",
        )
    })
}

fn native_cache_encryption_aad(key_id: &str, combined_key: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + key_id.len() + combined_key.len());
    aad.extend_from_slice(b"fluxheim-cache-disk-v1\0");
    aad.extend_from_slice(key_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(combined_key.as_bytes());
    aad
}

#[cfg(feature = "openbao-cache-encryption")]
fn openbao_transit_encrypt(
    address: &str,
    mount: &str,
    key_name: &str,
    token: &str,
    plaintext: &[u8],
    aad: &[u8],
) -> std::io::Result<String> {
    let plaintext = base64_standard_encode(plaintext)?;
    let associated_data = base64_standard_encode(aad)?;
    let request = serde_json::json!({
        "plaintext": plaintext,
        "associated_data": associated_data,
    });
    let mut response = openbao_transit_agent()
        .post(openbao_transit_url(address, mount, "encrypt", key_name))
        .header("X-Vault-Token", token)
        .header("Accept", "application/json")
        .send_json(request)
        .map_err(|error| openbao_io_error("encrypt", error))?;
    let value = openbao_transit_read_json(
        &mut response,
        "encrypt response",
        openbao_transit_response_limit(plaintext.len().max(associated_data.len()) as u64),
    )?;
    value
        .pointer("/data/ciphertext")
        .and_then(serde_json::Value::as_str)
        .filter(|value| value.starts_with("vault:v"))
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "OpenBao Transit encrypt response did not include a ciphertext",
            )
        })
}

#[cfg(feature = "openbao-cache-encryption")]
fn openbao_transit_decrypt(
    address: &str,
    mount: &str,
    key_name: &str,
    token: &str,
    ciphertext: &str,
    aad: &[u8],
) -> std::io::Result<Vec<u8>> {
    let associated_data = base64_standard_encode(aad)?;
    let request = serde_json::json!({
        "ciphertext": ciphertext,
        "associated_data": associated_data,
    });
    let mut response = openbao_transit_agent()
        .post(openbao_transit_url(address, mount, "decrypt", key_name))
        .header("X-Vault-Token", token)
        .header("Accept", "application/json")
        .send_json(request)
        .map_err(|error| openbao_io_error("decrypt", error))?;
    let value = openbao_transit_read_json(
        &mut response,
        "decrypt response",
        openbao_transit_response_limit(ciphertext.len().max(associated_data.len()) as u64),
    )?;
    let plaintext = value
        .pointer("/data/plaintext")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "OpenBao Transit decrypt response did not include plaintext",
            )
        })?;
    base64_ng::STANDARD
        .decode_vec(plaintext.as_bytes())
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "OpenBao Transit decrypt response plaintext is not valid base64",
            )
        })
}

#[cfg(feature = "openbao-cache-encryption")]
fn openbao_transit_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into()
}

#[cfg(feature = "openbao-cache-encryption")]
fn openbao_transit_response_limit(input_bytes: u64) -> u64 {
    input_bytes
        .saturating_mul(2)
        .saturating_add(OPENBAO_TRANSIT_RESPONSE_OVERHEAD_BYTES)
        .min(OPENBAO_TRANSIT_MAX_RESPONSE_BYTES)
}

#[cfg(feature = "openbao-cache-encryption")]
fn openbao_transit_read_json(
    response: &mut ureq::http::Response<ureq::Body>,
    operation: &str,
    max_response_bytes: u64,
) -> std::io::Result<serde_json::Value> {
    let body = response
        .body_mut()
        .with_config()
        .limit(max_response_bytes.saturating_add(1))
        .read_to_vec()
        .map_err(|error| openbao_io_error(operation, error))?;
    if body.len() as u64 > max_response_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("OpenBao Transit {operation} exceeded response size limit"),
        ));
    }
    serde_json::from_slice(&body).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("OpenBao Transit {operation} returned invalid JSON: {error}"),
        )
    })
}

#[cfg(feature = "openbao-cache-encryption")]
fn base64_standard_encode(input: &[u8]) -> std::io::Result<String> {
    base64_ng::STANDARD.encode_string(input).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("base64 encode failed: {error}"),
        )
    })
}

#[cfg(feature = "openbao-cache-encryption")]
fn openbao_io_error(operation: &str, error: ureq::Error) -> std::io::Error {
    std::io::Error::other(format!("OpenBao Transit {operation} failed: {error}"))
}

#[cfg(feature = "openbao-cache-encryption")]
fn openbao_transit_url(address: &str, mount: &str, operation: &str, key_name: &str) -> String {
    format!(
        "{}/v1/{}/{}/{}",
        address.trim_end_matches('/'),
        openbao_path_encode(mount.trim_matches('/')),
        operation,
        openbao_path_encode(key_name.trim_matches('/'))
    )
}

#[cfg(feature = "openbao-cache-encryption")]
fn openbao_path_encode(value: &str) -> String {
    value
        .split('/')
        .map(percent_encode_openbao_path_segment)
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(feature = "openbao-cache-encryption")]
fn percent_encode_openbao_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn native_cache_encryption_credential_path(credential_name: &str) -> PathBuf {
    std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/secrets"))
        .join(credential_name)
}

fn read_native_cache_encryption_key_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let contents = read_native_cache_encryption_secret_file(path)?;
    parse_native_cache_encryption_hex_key(contents.trim())
}

fn read_native_cache_encryption_secret_file(path: &Path) -> std::io::Result<Zeroizing<String>> {
    let mut file = NativeSafeDiskCachePath::from_path(path.to_path_buf()).open_existing_file()?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native cache disk encryption secret must be a small regular file",
        ));
    }
    let mut contents = Zeroizing::new(String::new());
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn parse_native_cache_encryption_hex_key(value: &str) -> std::io::Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native cache disk encryption key must be 64 hex characters",
        ));
    }
    let mut key = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = native_hex_value(chunk[0])?;
        let low = native_hex_value(chunk[1])?;
        key[index] = (high << 4) | low;
    }
    Ok(key)
}

fn native_hex_value(byte: u8) -> std::io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid hex digit",
        )),
    }
}

fn native_cache_utf8(bytes: &[u8], field: &str) -> std::io::Result<String> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, field))
}

pub(crate) fn lock_native_memory_cache<'a>(
    state: &'a Mutex<NativeMemoryCacheState>,
    label: &str,
) -> std::sync::MutexGuard<'a, NativeMemoryCacheState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(error) => {
            log::error!(
                target: "fluxheim::native_http1",
                "{label} memory cache mutex poisoned: {error}"
            );
            std::process::abort();
        }
    }
}

impl NativeDiskCacheMeta {
    fn from_entry(entry: &NativeMemoryCacheEntry, vary_fields: Vec<String>) -> Self {
        Self {
            status: entry.status,
            reason: entry.reason.clone(),
            content_length: entry.content_length,
            expires_at_unix_secs: native_instant_to_unix_secs(entry.expires_at),
            stale_while_revalidate_until_unix_secs: entry
                .stale_while_revalidate_until
                .map(native_instant_to_unix_secs),
            stale_if_error_until_unix_secs: entry
                .stale_if_error_until
                .map(native_instant_to_unix_secs),
            stored_at_unix_secs: native_instant_to_unix_secs(entry.stored_at),
            vary_fields,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        let _ = writeln!(&mut encoded, "FLUXHEIM-NATIVE-PROXY-CACHE-v1");
        let _ = writeln!(&mut encoded, "{}", self.status);
        let _ = writeln!(&mut encoded, "{}", self.reason.len());
        let _ = writeln!(
            &mut encoded,
            "{}",
            self.content_length
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned())
        );
        let _ = writeln!(&mut encoded, "{}", self.expires_at_unix_secs);
        let _ = writeln!(
            &mut encoded,
            "{}",
            self.stale_while_revalidate_until_unix_secs
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned())
        );
        let _ = writeln!(
            &mut encoded,
            "{}",
            self.stale_if_error_until_unix_secs
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned())
        );
        let _ = writeln!(&mut encoded, "{}", self.stored_at_unix_secs);
        let _ = writeln!(&mut encoded, "{}", self.vary_fields.len());
        for field in &self.vary_fields {
            let _ = writeln!(&mut encoded, "{}", field.len());
        }
        encoded.extend_from_slice(self.reason.as_bytes());
        for field in &self.vary_fields {
            encoded.extend_from_slice(field.as_bytes());
        }
        encoded
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut offset = 0_usize;
        let magic = native_disk_meta_line(bytes, &mut offset)?;
        if magic != "FLUXHEIM-NATIVE-PROXY-CACHE-v1" {
            return None;
        }
        let status = native_disk_meta_line(bytes, &mut offset)?
            .parse::<u16>()
            .ok()?;
        let reason_len = native_disk_meta_line(bytes, &mut offset)?
            .parse::<usize>()
            .ok()?;
        let content_length =
            native_disk_meta_optional_u64(native_disk_meta_line(bytes, &mut offset)?)?;
        let expires_at_unix_secs = native_disk_meta_line(bytes, &mut offset)?
            .parse::<u64>()
            .ok()?;
        let stale_while_revalidate_until_unix_secs =
            native_disk_meta_optional_u64(native_disk_meta_line(bytes, &mut offset)?)?;
        let stale_if_error_until_unix_secs =
            native_disk_meta_optional_u64(native_disk_meta_line(bytes, &mut offset)?)?;
        let stored_at_unix_secs = native_disk_meta_line(bytes, &mut offset)?
            .parse::<u64>()
            .ok()?;
        let vary_count = native_disk_meta_line(bytes, &mut offset)?
            .parse::<usize>()
            .ok()?;
        let mut vary_lens = Vec::with_capacity(vary_count);
        for _ in 0..vary_count {
            vary_lens.push(
                native_disk_meta_line(bytes, &mut offset)?
                    .parse::<usize>()
                    .ok()?,
            );
        }
        let reason_end = offset.checked_add(reason_len)?;
        let reason = std::str::from_utf8(bytes.get(offset..reason_end)?)
            .ok()?
            .to_owned();
        offset = reason_end;
        let mut vary_fields = Vec::with_capacity(vary_count);
        for len in vary_lens {
            let end = offset.checked_add(len)?;
            vary_fields.push(
                std::str::from_utf8(bytes.get(offset..end)?)
                    .ok()?
                    .to_owned(),
            );
            offset = end;
        }
        (offset == bytes.len()).then_some(Self {
            status,
            reason,
            content_length,
            expires_at_unix_secs,
            stale_while_revalidate_until_unix_secs,
            stale_if_error_until_unix_secs,
            stored_at_unix_secs,
            vary_fields,
        })
    }
}

fn native_disk_meta_line<'a>(bytes: &'a [u8], offset: &mut usize) -> Option<&'a str> {
    let relative = bytes
        .get(*offset..)?
        .iter()
        .position(|byte| *byte == b'\n')?;
    let start = *offset;
    let end = start.checked_add(relative)?;
    *offset = end.checked_add(1)?;
    std::str::from_utf8(bytes.get(start..end)?).ok()
}

fn native_disk_meta_optional_u64(value: &str) -> Option<Option<u64>> {
    if value == "-" {
        return Some(None);
    }
    value.parse::<u64>().ok().map(Some)
}

fn native_disk_response_header_bytes(entry: &NativeMemoryCacheEntry) -> Vec<u8> {
    let mut encoded = Vec::new();
    let _ = writeln!(&mut encoded, "{}", entry.headers.len());
    for (name, value) in &entry.headers {
        let _ = writeln!(&mut encoded, "{}", name.len());
        let _ = writeln!(&mut encoded, "{}", value.len());
    }
    for (name, value) in &entry.headers {
        encoded.extend_from_slice(name.as_bytes());
        encoded.extend_from_slice(value.as_bytes());
    }
    encoded
}

fn native_disk_response_headers(bytes: &[u8]) -> Option<Vec<(String, String)>> {
    let mut offset = 0_usize;
    let count = native_disk_meta_line(bytes, &mut offset)?
        .parse::<usize>()
        .ok()?;
    let mut lengths = Vec::with_capacity(count);
    for _ in 0..count {
        let name_len = native_disk_meta_line(bytes, &mut offset)?
            .parse::<usize>()
            .ok()?;
        let value_len = native_disk_meta_line(bytes, &mut offset)?
            .parse::<usize>()
            .ok()?;
        lengths.push((name_len, value_len));
    }
    let mut headers = Vec::with_capacity(count);
    for (name_len, value_len) in lengths {
        let name_end = offset.checked_add(name_len)?;
        let name = std::str::from_utf8(bytes.get(offset..name_end)?)
            .ok()?
            .to_owned();
        offset = name_end;
        let value_end = offset.checked_add(value_len)?;
        let value = std::str::from_utf8(bytes.get(offset..value_end)?)
            .ok()?
            .to_owned();
        offset = value_end;
        headers.push((name, value));
    }
    (offset == bytes.len()).then_some(headers)
}

fn native_memory_entry_from_disk_object(
    object: &SerializedCacheObject,
) -> Option<NativeMemoryCacheEntry> {
    let meta = NativeDiskCacheMeta::decode(&object.internal_meta)?;
    let now_system = SystemTime::now();
    let now_instant = Instant::now();
    let entry = NativeMemoryCacheEntry {
        status: meta.status,
        reason: meta.reason,
        headers: native_disk_response_headers(&object.response_header)?,
        content_length: meta.content_length,
        body: object.body.clone(),
        expires_at: native_unix_secs_to_instant(meta.expires_at_unix_secs, now_system, now_instant),
        stale_while_revalidate_until: meta
            .stale_while_revalidate_until_unix_secs
            .map(|secs| native_unix_secs_to_instant(secs, now_system, now_instant)),
        stale_if_error_until: meta
            .stale_if_error_until_unix_secs
            .map(|secs| native_unix_secs_to_instant(secs, now_system, now_instant)),
        stored_at: native_unix_secs_to_instant(meta.stored_at_unix_secs, now_system, now_instant),
        weight: object.weight as u64,
    };
    let now = Instant::now();
    if entry.expires_at <= now && !native_cache_entry_has_stale_window_for_disk(&entry, now) {
        return None;
    }
    Some(entry)
}

fn native_cache_entry_has_stale_window_for_disk(
    entry: &NativeMemoryCacheEntry,
    now: Instant,
) -> bool {
    entry
        .stale_while_revalidate_until
        .is_some_and(|until| until > now)
        || entry.stale_if_error_until.is_some_and(|until| until > now)
}

fn native_instant_to_unix_secs(instant: Instant) -> u64 {
    let now_instant = Instant::now();
    let now_system = SystemTime::now();
    let system = if instant >= now_instant {
        now_system
            .checked_add(instant.saturating_duration_since(now_instant))
            .unwrap_or(now_system)
    } else {
        now_system
            .checked_sub(now_instant.saturating_duration_since(instant))
            .unwrap_or(UNIX_EPOCH)
    };
    system
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn native_unix_secs_to_instant(secs: u64, now_system: SystemTime, now_instant: Instant) -> Instant {
    let target = UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .unwrap_or(UNIX_EPOCH);
    if target >= now_system {
        now_instant
            .checked_add(target.duration_since(now_system).unwrap_or_default())
            .unwrap_or(now_instant)
    } else {
        now_instant
            .checked_sub(now_system.duration_since(target).unwrap_or_default())
            .unwrap_or(now_instant)
    }
}

fn prepare_native_disk_cache_root(root: &Path) -> std::io::Result<PathBuf> {
    if native_configured_cache_path_contains_symlink(root)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "native disk cache root must not cross symlinks",
        ));
    }
    create_native_cache_dir_all(root)?;
    if native_configured_cache_path_contains_symlink(root)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "native disk cache root must not cross symlinks",
        ));
    }
    root.canonicalize()
}

fn create_native_cache_dir_all(path: &Path) -> std::io::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(
            component,
            std::path::Component::Prefix(_)
                | std::path::Component::RootDir
                | std::path::Component::CurDir
        ) {
            continue;
        }
        if matches!(component, std::path::Component::ParentDir) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "native disk cache directory must not contain parent traversal",
            ));
        }
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "native disk cache path component is not a real directory",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                rustix::fs::mkdir(
                    &current,
                    rustix::fs::Mode::RWXU | rustix::fs::Mode::RGRP | rustix::fs::Mode::XGRP,
                )
                .map_err(native_rustix_to_io_error)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn native_configured_cache_path_contains_symlink(path: &Path) -> std::io::Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn native_cache_path_contains_symlink(root: &Path, path: &Path) -> std::io::Result<bool> {
    let Ok(relative) = path.strip_prefix(root) else {
        return Ok(true);
    };
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Ok(true);
        }
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn read_native_disk_cache_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut file = NativeSafeDiskCachePath::from_path(path.to_path_buf()).open_existing_file()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[derive(Debug, Clone)]
struct NativeSafeDiskCachePath {
    path: PathBuf,
}

impl NativeSafeDiskCachePath {
    fn from_path(path: PathBuf) -> Self {
        Self { path }
    }

    fn parent_and_name(&self) -> std::io::Result<(&Path, &std::ffi::OsStr)> {
        let parent = self.path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "native disk cache path has no parent",
            )
        })?;
        let name = self.path.file_name().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "native disk cache path has no file name",
            )
        })?;
        Ok((parent, name))
    }

    fn open_parent_dir(&self) -> std::io::Result<std::fs::File> {
        let (parent, _) = self.parent_and_name()?;
        let fd = rustix::fs::open(
            parent,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .map_err(native_rustix_to_io_error)?;
        Ok(fd.into())
    }

    fn create_new_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(native_rustix_to_io_error)?;
        Ok(fd.into())
    }

    fn open_existing_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(native_rustix_to_io_error)?;
        Ok(fd.into())
    }

    fn rename_from(&self, source: &Self) -> std::io::Result<()> {
        let (_, source_name) = source.parent_and_name()?;
        let (_, destination_name) = self.parent_and_name()?;
        let source_parent = source.open_parent_dir()?;
        let destination_parent = self.open_parent_dir()?;
        rustix::fs::renameat(
            &source_parent,
            source_name,
            &destination_parent,
            destination_name,
        )
        .map_err(native_rustix_to_io_error)
    }

    fn remove_file(&self) -> std::io::Result<()> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        rustix::fs::unlinkat(&parent, name, rustix::fs::AtFlags::empty())
            .map_err(native_rustix_to_io_error)
    }
}

fn native_rustix_to_io_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

pub(crate) fn native_response_header_map(response: &NativeHttp1Response) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    for (name, value) in response.headers() {
        let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = http::HeaderValue::from_str(value) else {
            continue;
        };
        headers.append(name, value);
    }
    if let Some(content_length) = response.content_length()
        && let Ok(value) = http::HeaderValue::from_str(&content_length.to_string())
    {
        headers.insert(http::header::CONTENT_LENGTH, value);
    }
    headers
}

pub(crate) fn native_cache_ttl(
    status: u16,
    headers: &http::HeaderMap,
    cache: &CacheConfig,
) -> Option<Duration> {
    cache
        .status_ttls
        .get(&status)
        .copied()
        .or(cache.default_status_ttl_secs)
        .or_else(|| response_cache_control_max_age(headers))
        .map(u64::from)
        .map(Duration::from_secs)
}

pub(crate) fn native_peer_fill_cache_ttl(
    status: u16,
    headers: &http::HeaderMap,
    cache: &CacheConfig,
) -> Option<Duration> {
    let ttl_secs = cache
        .status_ttls
        .get(&status)
        .copied()
        .or(cache.default_status_ttl_secs)
        .or_else(|| response_cache_control_max_age(headers))?;
    remaining_fresh_ttl_secs(ttl_secs, response_age_secs(headers))
        .map(u64::from)
        .map(Duration::from_secs)
}

pub(crate) fn native_cache_entry_weight(
    key: &str,
    response: &NativeHttp1Response,
    body_len: u64,
) -> u64 {
    const ENTRY_OVERHEAD: u64 = 256;

    response.headers().iter().fold(
        body_len
            .saturating_add(ENTRY_OVERHEAD)
            .saturating_add(key.len() as u64)
            .saturating_add(response.reason().len() as u64),
        |weight, (name, value)| {
            weight
                .saturating_add(name.len() as u64)
                .saturating_add(value.len() as u64)
                .saturating_add(4)
        },
    )
}

pub(crate) fn prune_native_memory_cache(state: &mut NativeMemoryCacheState, max_bytes: u64) {
    let now = Instant::now();
    let expired = state
        .objects
        .iter()
        .filter_map(|(key, entry)| {
            let stale_until = [
                entry.stale_while_revalidate_until,
                entry.stale_if_error_until,
            ]
            .into_iter()
            .flatten()
            .max()
            .unwrap_or(entry.expires_at);
            (stale_until <= now).then_some(key.clone())
        })
        .collect::<Vec<_>>();
    let expired_bytes = expired
        .iter()
        .filter_map(|key| remove_native_memory_cache_entry(state, key))
        .fold(0_u64, |total, entry| total.saturating_add(entry.weight));
    state.bytes = state.bytes.saturating_sub(expired_bytes);

    if state.bytes > max_bytes {
        let mut by_age = state
            .objects
            .iter()
            .map(|(key, entry)| (entry.stored_at, key.clone()))
            .collect::<Vec<_>>();
        by_age.sort_unstable_by_key(|(stored_at, _)| *stored_at);
        for (_, key) in by_age {
            if state.bytes <= max_bytes {
                break;
            }
            if let Some(entry) = remove_native_memory_cache_entry(state, &key) {
                state.bytes = state.bytes.saturating_sub(entry.weight);
            }
        }
        if state.objects.is_empty() && state.bytes > max_bytes {
            state.bytes = 0;
        } else {
            let actual_bytes = state
                .objects
                .values()
                .fold(0_u64, |total, entry| total.saturating_add(entry.weight));
            state.bytes = state.bytes.min(actual_bytes);
        }
    }
}

pub(crate) fn remove_native_memory_cache_entry(
    state: &mut NativeMemoryCacheState,
    key: &str,
) -> Option<NativeMemoryCacheEntry> {
    let removed = state.objects.remove(key);
    if removed.is_some() {
        state.purge_index.remove_combined(key);
        prune_native_memory_cache_variants_for_key(state, key);
    }
    removed
}

pub(crate) fn remove_native_memory_cache_variants(
    state: &mut NativeMemoryCacheState,
    base_key: &str,
) -> u64 {
    let Some(variants) = state.variants.remove(base_key) else {
        return 0;
    };
    variants.into_iter().fold(0_u64, |removed_bytes, variant| {
        let Some(entry) = state.objects.remove(&variant.key) else {
            return removed_bytes;
        };
        state.purge_index.remove_combined(&variant.key);
        removed_bytes.saturating_add(entry.weight)
    })
}

fn prune_native_memory_cache_variants_for_key(state: &mut NativeMemoryCacheState, key: &str) {
    state.variants.retain(|_, variants| {
        variants.retain(|variant| variant.key != key);
        !variants.is_empty()
    });
}

pub(crate) fn with_native_cache_status(
    mut response: NativeHttp1Response,
    cache: &CacheConfig,
    status: &str,
    reason: Option<&str>,
    age_secs: Option<u64>,
) -> NativeHttp1Response {
    if let Some(header) = &cache.status_header {
        response.push_header(header.clone(), status.to_owned());
    }
    if let (Some(header), Some(reason)) = (&cache.status_reason_header, reason) {
        response.push_header(header.clone(), reason.to_owned());
    }
    if let Some(age_secs) = age_secs {
        response.remove_header("age");
        response.push_header("age", age_secs.to_string());
    }
    response
}
