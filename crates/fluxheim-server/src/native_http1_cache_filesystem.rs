use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use fluxheim_cache::{
    CachePurgeIndexEntry, DiskCacheObjectKey, encode_disk_cache_object, parse_disk_cache_object,
};
use sha2::{Digest as _, Sha256};

use super::native_http1_cache_disk_path::{
    NativeSafeDiskCachePath, create_native_cache_dir_all, native_cache_path_contains_symlink,
    native_disk_cache_read_limit, read_native_disk_cache_file,
};
use super::native_http1_cache_meta::{NativeDiskCacheMeta, native_memory_entry_from_disk_object};
use super::{
    NativeDiskCache, NativeDiskCacheLocation, NativeDiskCacheRecord, NativeDiskCacheState,
    NativeMemoryCacheVariant,
};

impl NativeDiskCache {
    pub(super) fn rebuild_filesystem_index(
        &self,
        state: &mut NativeDiskCacheState,
    ) -> std::io::Result<()> {
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

    pub(super) fn write_filesystem_encoded_object(
        &self,
        combined_key: &str,
        encoded: &[u8],
    ) -> std::io::Result<NativeDiskCacheLocation> {
        let path = self.path_for_combined_key(combined_key);
        if let Some(parent) = path.parent() {
            create_native_cache_dir_all(parent)?;
        }
        self.write_object_atomically(&path, encoded)?;
        Ok(NativeDiskCacheLocation::Filesystem(path))
    }

    pub(super) fn soft_purge_filesystem_record(
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
}
