use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use fluxheim_cache::{
    CacheObjectFreshnessState, DiskCacheObjectKey, SerializedCacheObject, encode_disk_cache_object,
    parse_disk_cache_object,
};
use fluxheim_config::{CacheConfig, CacheDiskBackend, CacheDiskEncryptionProvider};
use zeroize::Zeroizing;

#[path = "native_http1_cache_backend.rs"]
mod native_http1_cache_backend;
#[path = "native_http1_cache_disk_path.rs"]
mod native_http1_cache_disk_path;
#[path = "native_http1_cache_encryption.rs"]
mod native_http1_cache_encryption;
#[path = "native_http1_cache_filesystem.rs"]
mod native_http1_cache_filesystem;
#[path = "native_http1_cache_inspect.rs"]
mod native_http1_cache_inspect;
#[path = "native_http1_cache_memory.rs"]
mod native_http1_cache_memory;
#[path = "native_http1_cache_meta.rs"]
mod native_http1_cache_meta;
#[path = "native_http1_cache_purge.rs"]
mod native_http1_cache_purge;
#[path = "native_http1_cache_state.rs"]
mod native_http1_cache_state;
#[path = "native_http1_cache_storage_bin.rs"]
mod native_http1_cache_storage_bin;

pub(crate) use native_http1_cache_backend::NativeDiskCacheStoreKey;
use native_http1_cache_backend::{
    NativeDiskCacheBackend, NativeDiskCacheLocation, NativeDiskCacheRecord, NativeDiskCacheState,
};
use native_http1_cache_disk_path::{
    native_cache_path_contains_symlink, native_disk_cache_read_limit, read_native_disk_cache_file,
};
use native_http1_cache_encryption::{
    NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1, NativeDiskCacheEncryption,
};
pub use native_http1_cache_inspect::inspect_native_disk_cache_object;
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
    purge_native_disk_cache_path_exact, purge_native_disk_cache_path_pattern,
    purge_native_disk_cache_path_prefix, purge_native_disk_cache_primary,
    purge_native_disk_cache_stale, purge_native_disk_cache_stale_all, purge_native_disk_cache_tag,
    purge_native_disk_cache_user_tag,
};
use native_http1_cache_state::native_disk_cache_mutation_locks;

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
            NativeDiskCacheBackend::Filesystem => self
                .write_filesystem_encoded_object(combined_key, encoded)
                .map(Some),
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
            NativeDiskCacheBackend::StorageBin(_) => {
                self.rebuild_storage_bin_backend(&mut state)?
            }
        }
        self.state = Mutex::new(state);
        self.prune();
        Ok(())
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

#[cfg(test)]
#[path = "native_http1_cache_tests.rs"]
mod tests;
