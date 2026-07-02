use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Instant, SystemTime};

use fluxheim_cache::purge_index::{
    CacheIndexedPurgeResult, CachePurgeIndexEntry, CacheStalePurgeResult,
};
use fluxheim_cache::{
    CacheObjectFreshnessState, DiskCacheObjectKey, SerializedCacheObject, StorageBinFileSet,
    StorageBinFreeMap, StorageBinIndexEntry, StorageBinLayoutPlan, StorageBinObjectLocation,
    encode_disk_cache_object, parse_disk_cache_object, read_storage_bin_index,
    write_storage_bin_index,
};
use fluxheim_config::{CacheConfig, CacheDiskBackend, CacheDiskEncryptionProvider};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

#[path = "native_http1_cache_backend.rs"]
mod native_http1_cache_backend;
#[path = "native_http1_cache_disk_path.rs"]
mod native_http1_cache_disk_path;
#[path = "native_http1_cache_encryption.rs"]
mod native_http1_cache_encryption;
#[path = "native_http1_cache_memory.rs"]
mod native_http1_cache_memory;
#[path = "native_http1_cache_meta.rs"]
mod native_http1_cache_meta;
#[path = "native_http1_cache_purge.rs"]
mod native_http1_cache_purge;

pub(crate) use native_http1_cache_backend::NativeDiskCacheStoreKey;
use native_http1_cache_backend::{
    NativeDiskCacheBackend, NativeDiskCacheLocation, NativeDiskCacheRecord, NativeDiskCacheState,
};
use native_http1_cache_disk_path::{
    NativeSafeDiskCachePath, create_native_cache_dir_all, native_cache_path_contains_symlink,
    native_disk_cache_read_limit, read_native_disk_cache_file,
};
use native_http1_cache_encryption::{
    NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1, NativeDiskCacheEncryption,
};
pub(crate) use native_http1_cache_memory::{
    NativeMemoryCacheCounter, NativeMemoryCacheEntry, NativeMemoryCacheFill,
    NativeMemoryCacheState, NativeMemoryCacheVariant, lock_native_memory_cache,
    native_cache_entry_weight, native_cache_ttl, native_peer_fill_cache_ttl,
    native_response_header_map, prune_native_memory_cache, remove_native_memory_cache_entry,
    remove_native_memory_cache_variants, with_native_cache_status,
};
use native_http1_cache_meta::{
    NativeDiskCacheMeta, native_disk_response_header_bytes, native_instant_to_unix_secs,
    native_memory_entry_from_disk_object,
};
pub(crate) use native_http1_cache_purge::register_native_disk_cache_purge_handle;
pub use native_http1_cache_purge::{
    inspect_native_disk_cache_object, purge_native_disk_cache_path_exact,
    purge_native_disk_cache_path_pattern, purge_native_disk_cache_path_prefix,
    purge_native_disk_cache_primary, purge_native_disk_cache_stale,
    purge_native_disk_cache_stale_all, purge_native_disk_cache_tag,
    purge_native_disk_cache_user_tag,
};

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

#[derive(Debug)]
pub(crate) struct NativeDiskCache {
    root: PathBuf,
    max_bytes: u64,
    max_object_bytes: fluxheim_config::ByteSize,
    backend: NativeDiskCacheBackend,
    encryption: Option<NativeDiskCacheEncryption>,
    state: Mutex<NativeDiskCacheState>,
    mutation_locks: Box<[Mutex<()>]>,
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
            mutation_locks: native_disk_cache_mutation_locks(),
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
            purge_index_entries: self.with_state(|state| state.purge_index.len() as u64),
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
            user_tag: key.user_tag.clone(),
            index_path: key.index_path.clone(),
            cache_tags: key.cache_tags.clone(),
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
        loop {
            if !self.evict_until_admissible(&key.combined, encoded_len)? {
                return Ok(());
            }
            let _mutation = self.lock_key_mutation(&key.combined);
            if !self.key_admissible(&key.combined, encoded_len) {
                continue;
            }
            self.remove_combined_locked(&key.combined);
            let Some(location) = self.write_encoded_object(&key.combined, &encoded)? else {
                return Ok(());
            };
            self.with_state_mut(|state| {
                let combined = key.combined.clone();
                let primary = key.primary.clone();
                let user_tag = key.user_tag.clone();
                let index_path = key.index_path.clone();
                let cache_tags = key.cache_tags.clone();
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
                        fields: key.vary_fields.clone(),
                        key: key.combined.clone(),
                    });
                }
                state
                    .purge_index
                    .insert_with_path_and_tags(combined, primary, user_tag, index_path, cache_tags);
                state.bytes = state.bytes.saturating_add(encoded_len);
            });
            break;
        }
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
        let mut evicted = false;
        loop {
            if self.key_admissible(incoming_key, incoming_weight) {
                if evicted {
                    self.persist_storage_bin_index();
                }
                return Ok(true);
            }
            if !self.evict_oldest()? {
                return Ok(false);
            }
            evicted = true;
        }
    }

    fn key_admissible(&self, incoming_key: &str, incoming_weight: u64) -> bool {
        self.with_state(|state| {
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
        })
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
        let root = NativeSafeDiskCachePath::from_path(self.root.clone());
        for shard_path in root.child_paths()? {
            if !shard_path.is_dir() || native_cache_path_contains_symlink(&self.root, &shard_path)?
            {
                continue;
            }
            let shard = NativeSafeDiskCachePath::from_path(shard_path);
            for path in shard.child_paths()? {
                if path.is_dir()
                    || path.extension().and_then(|value| value.to_str()) != Some("fhc")
                    || native_cache_path_contains_symlink(&self.root, &path)?
                {
                    continue;
                }
                let bytes = match read_native_disk_cache_file(
                    &path,
                    native_disk_cache_read_limit(self.max_object_bytes),
                ) {
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
                    state.variants.entry(primary.clone()).or_default().push(
                        NativeMemoryCacheVariant {
                            fields: meta.vary_fields,
                            key: combined.clone(),
                        },
                    );
                }
                if let Some(user_tag) = parsed.user_tag {
                    state.purge_index.insert_with_path_and_tags(
                        combined,
                        primary,
                        user_tag,
                        parsed.index_path,
                        parsed.cache_tags,
                    );
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
                    .entry(primary.clone())
                    .or_default()
                    .push(NativeMemoryCacheVariant {
                        fields: meta.vary_fields,
                        key: combined.clone(),
                    });
            }
            if let Some(user_tag) = parsed.user_tag {
                state.purge_index.insert_with_path_and_tags(
                    combined,
                    primary,
                    user_tag,
                    parsed.index_path,
                    parsed.cache_tags,
                );
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
                read_native_disk_cache_file(
                    path,
                    native_disk_cache_read_limit(self.max_object_bytes),
                )?
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

    fn decrypt_if_needed(&self, bytes: &[u8]) -> std::io::Result<Zeroizing<Vec<u8>>> {
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
                Ok(Zeroizing::new(bytes.to_vec()))
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

    fn purge_user_tag(&self, user_tag: &str, limit: usize, soft: bool) -> CacheIndexedPurgeResult {
        let entries =
            self.with_state(|state| state.purge_index.entries_for_user_tag(user_tag, limit));
        self.purge_indexed_entries(entries, soft)
    }

    fn purge_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
        soft: bool,
    ) -> CacheIndexedPurgeResult {
        let entries = self.with_state(|state| {
            state
                .purge_index
                .entries_for_user_tag_path_prefix(user_tag, path_prefix, limit)
        });
        self.purge_indexed_entries(entries, soft)
    }

    fn purge_path_exact(
        &self,
        user_tag: &str,
        path_exact: &str,
        limit: usize,
        soft: bool,
    ) -> CacheIndexedPurgeResult {
        let entries = self.with_state(|state| {
            state
                .purge_index
                .entries_for_user_tag_path_exact(user_tag, path_exact, limit)
        });
        self.purge_indexed_entries(entries, soft)
    }

    fn purge_cache_tag(
        &self,
        user_tag: &str,
        cache_tag: &str,
        limit: usize,
        soft: bool,
    ) -> CacheIndexedPurgeResult {
        let entries = self.with_state(|state| {
            state
                .purge_index
                .entries_for_user_tag_cache_tag(user_tag, cache_tag, limit)
        });
        self.purge_indexed_entries(entries, soft)
    }

    fn purge_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
        soft: bool,
    ) -> CacheIndexedPurgeResult {
        let entries = self.with_state(|state| {
            state
                .purge_index
                .entries_for_user_tag_path_pattern(user_tag, path_pattern, limit)
        });
        self.purge_indexed_entries(entries, soft)
    }

    fn purge_stale(&self, user_tag: &str, limit: usize, dry_run: bool) -> CacheStalePurgeResult {
        let entries =
            self.with_state(|state| state.purge_index.entries_for_user_tag(user_tag, limit));
        self.purge_stale_entries(entries, dry_run)
    }

    fn purge_indexed_entries(
        &self,
        entries: Vec<CachePurgeIndexEntry>,
        soft: bool,
    ) -> CacheIndexedPurgeResult {
        let now = Instant::now();
        let mut purged = 0_usize;
        for entry in &entries {
            if soft {
                let Some(record) =
                    self.with_state(|state| state.objects.get(&entry.combined_key).cloned())
                else {
                    self.with_state(|state| {
                        state.purge_index.remove_combined(&entry.combined_key);
                    });
                    continue;
                };
                if matches!(record.location, NativeDiskCacheLocation::StorageBin(_)) {
                    if self.remove_combined(&entry.combined_key) {
                        purged = purged.saturating_add(1);
                    }
                    continue;
                }
                let softened = self.soft_purge_filesystem_record(entry, &record, now);
                if softened {
                    purged = purged.saturating_add(1);
                }
                continue;
            }
            if self.remove_combined(&entry.combined_key) {
                purged = purged.saturating_add(1);
            }
        }
        CacheIndexedPurgeResult {
            matched: entries.len(),
            purged,
            truncated: false,
        }
    }

    fn soft_purge_filesystem_record(
        &self,
        entry: &CachePurgeIndexEntry,
        record: &NativeDiskCacheRecord,
        now: Instant,
    ) -> bool {
        let Ok(mut object) = self.read_record(record) else {
            return false;
        };
        let Some(mut memory_entry) = native_memory_entry_from_disk_object(&object) else {
            return false;
        };
        memory_entry.expires_at = now;
        let meta = NativeDiskCacheMeta::from_entry(
            &memory_entry,
            NativeDiskCacheMeta::decode(&object.internal_meta)
                .map(|meta| meta.vary_fields)
                .unwrap_or_default(),
        );
        object.internal_meta = meta.encode();
        let Ok(encoded) = encode_disk_cache_object(
            &DiskCacheObjectKey {
                combined: entry.combined_key.clone(),
                primary: entry.primary_key.clone(),
                user_tag: entry.user_tag.clone(),
                index_path: entry.path.clone(),
                cache_tags: entry.cache_tags.clone(),
            },
            &object.internal_meta,
            &object.response_header,
            &object.body,
        ) else {
            return false;
        };
        let encoded = if let Some(encryption) = &self.encryption {
            match encryption.encrypt(&entry.combined_key, &encoded) {
                Ok(encoded) => encoded,
                Err(_) => return false,
            }
        } else {
            encoded
        };
        let NativeDiskCacheLocation::Filesystem(path) = &record.location else {
            return false;
        };
        self.write_object_atomically(path, &encoded).is_ok()
    }

    fn purge_stale_entries(
        &self,
        entries: Vec<CachePurgeIndexEntry>,
        dry_run: bool,
    ) -> CacheStalePurgeResult {
        let now = Instant::now();
        let mut scanned = 0_usize;
        let mut stale = 0_usize;
        let mut purged = 0_usize;
        for entry in &entries {
            let Some(object) = self.get_combined(&entry.combined_key) else {
                self.with_state(|state| {
                    state.purge_index.remove_combined(&entry.combined_key);
                });
                continue;
            };
            scanned = scanned.saturating_add(1);
            if object.expires_at > now {
                continue;
            }
            stale = stale.saturating_add(1);
            if !dry_run && self.remove_combined(&entry.combined_key) {
                purged = purged.saturating_add(1);
            }
        }
        CacheStalePurgeResult {
            scanned,
            stale,
            purged,
            truncated: false,
        }
    }

    fn remove_combined(&self, combined_key: &str) -> bool {
        let _mutation = self.lock_key_mutation(combined_key);
        self.remove_combined_locked(combined_key)
    }

    fn remove_combined_locked(&self, combined_key: &str) -> bool {
        let removed = self.with_state_mut(|state| {
            let removed = state.objects.remove(combined_key);
            if let Some(record) = &removed {
                state.bytes = state.bytes.saturating_sub(record.weight);
                state.purge_index.remove_combined(combined_key);
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
        let Some(key) = self.with_state(|state| {
            state
                .objects
                .iter()
                .min_by_key(|(key, record)| (record.accessed_at, (*key).clone()))
                .map(|(key, _)| key.clone())
        }) else {
            return Ok(false);
        };
        Ok(self.remove_combined(&key))
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

    fn lock_key_mutation(&self, combined_key: &str) -> MutexGuard<'_, ()> {
        let stripe = native_disk_cache_mutation_lock_stripe(combined_key);
        match self.mutation_locks[stripe].lock() {
            Ok(guard) => guard,
            Err(error) => {
                log::error!(
                    target: "fluxheim::native_http1",
                    "native disk cache mutation lock poisoned: {error}"
                );
                std::process::abort();
            }
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

fn native_disk_cache_mutation_locks() -> Box<[Mutex<()>]> {
    (0..NATIVE_DISK_CACHE_MUTATION_LOCKS)
        .map(|_| Mutex::new(()))
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

fn native_disk_cache_mutation_lock_stripe(combined_key: &str) -> usize {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in combined_key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (hash as usize) % NATIVE_DISK_CACHE_MUTATION_LOCKS
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

const NATIVE_DISK_CACHE_MUTATION_LOCKS: usize = 128;

#[cfg(test)]
#[path = "native_http1_cache_tests.rs"]
mod tests;
