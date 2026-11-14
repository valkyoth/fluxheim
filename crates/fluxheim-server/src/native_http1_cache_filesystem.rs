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
    native_disk_cache_read_limit, read_native_disk_cache_file, validate_single_link_file,
};
use super::native_http1_cache_meta::{NativeDiskCacheMeta, native_memory_entry_from_disk_object};
use super::native_http1_cache_recovery::{
    FILESYSTEM_OBJECT_LIMIT, RECOVERY_ENTRY_LIMIT, RECOVERY_READ_LIMIT, RecoveryBudget,
    RecoveryReport, lowercase_hex, object_name, old_temp, recognizable_file, temp_name,
};
use super::{
    NativeDiskCache, NativeDiskCacheLocation, NativeDiskCacheRecord, NativeDiskCacheState,
    NativeMemoryCacheVariant,
};

impl NativeDiskCache {
    pub(super) fn rebuild_filesystem_index(
        &self,
        state: &mut NativeDiskCacheState,
    ) -> std::io::Result<()> {
        let read_limit = self.max_bytes.saturating_mul(2).max(RECOVERY_READ_LIMIT);
        let result = self.recover_filesystem(state, RECOVERY_ENTRY_LIMIT, read_limit);
        match &result {
            Ok(report) => log::info!(target: "fluxheim::native_http1",
                "filesystem cache recovery: removed_files={} removed_bytes={} retained_files={} retained_bytes={} unknown_entries={} failed_removals={} cleanup_exclusive={}",
                report.removed_files, report.removed_bytes, report.retained_files, report.retained_bytes,
                report.unknown_entries, report.failed_removals, self.filesystem_cleanup_allowed()),
            Err(_) => {
                log::error!(target: "fluxheim::native_http1", "filesystem cache recovery incomplete; initialization rejected")
            }
        }
        result.map(|report| {
            // Existing unindexed files consume real directory entries too.
            // Reserve their slots in addition to the fixed operational margin.
            let retained = report.retained_files.saturating_add(report.unknown_entries);
            state.filesystem_object_limit = Some(
                FILESYSTEM_OBJECT_LIMIT
                    .saturating_sub(usize::try_from(retained).unwrap_or(usize::MAX)),
            );
        })
    }

    pub(super) fn recover_filesystem(
        &self,
        state: &mut NativeDiskCacheState,
        entries: usize,
        bytes: u64,
    ) -> std::io::Result<RecoveryReport> {
        let mut budget = RecoveryBudget::new(entries, bytes);
        let mut report = RecoveryReport::default();
        for shard_path in budget.children(&self.root)? {
            let Some(shard_name) = shard_path.file_name().and_then(|name| name.to_str()) else {
                report.unknown_entries += 1;
                continue;
            };
            if !lowercase_hex(shard_name, 2)
                || !std::fs::symlink_metadata(&shard_path)?.is_dir()
                || native_cache_path_contains_symlink(&self.root, &shard_path)?
            {
                // Do not recurse into operator files or encryption state.
                report.unknown_entries += 1;
                continue;
            }
            for path in budget.children(&shard_path)? {
                budget.charge_read(0)?;
                let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                    report.unknown_entries += 1;
                    continue;
                };
                if !metadata.is_file() || native_cache_path_contains_symlink(&self.root, &path)? {
                    report.unknown_entries += 1;
                    continue;
                }
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                let temporary = temp_name(name);
                if !temporary && !object_name(name, shard_name) {
                    report.retain(metadata.len());
                    continue;
                }
                let safe = NativeSafeDiskCachePath::from_path(path.clone());
                let Ok(mut file) = safe.open_existing_file() else {
                    report.retain(metadata.len());
                    continue;
                };
                if validate_single_link_file(&file).is_err() {
                    report.retain(metadata.len());
                    continue;
                }
                let metadata = file.metadata()?;
                budget.charge_read(22)?;
                let recognizable = recognizable_file(&mut file).unwrap_or(false);
                drop(file);
                if temporary {
                    report.remove_or_retain(
                        &path,
                        metadata.len(),
                        recognizable
                            && old_temp(&metadata, SystemTime::now())
                            && self.filesystem_cleanup_allowed(),
                    );
                    continue;
                }
                if !recognizable {
                    report.retain(metadata.len());
                    continue;
                }
                if metadata.len() > native_disk_cache_read_limit(self.max_object_bytes) {
                    report.remove_or_retain(
                        &path,
                        metadata.len(),
                        self.filesystem_cleanup_allowed(),
                    );
                    continue;
                }
                budget.charge_read(metadata.len().saturating_add(1))?;
                // A shared inspection can race an atomic replacement. Do not
                // read more than the length charged to this scan's budget.
                let bytes = match read_native_disk_cache_file(&path, metadata.len()) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        report.retain(metadata.len());
                        continue;
                    }
                };
                if bytes.starts_with(super::NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1) {
                    report.remove_or_retain(
                        &path,
                        metadata.len(),
                        self.filesystem_cleanup_allowed(),
                    );
                    continue;
                }
                let bytes = match self.decrypt_if_needed(&bytes) {
                    Ok(bytes) => bytes,
                    // A missing/wrong key is not proof that ciphertext is garbage.
                    Err(_) => {
                        report.retain(metadata.len());
                        continue;
                    }
                };
                let parsed = match parse_disk_cache_object(&bytes, self.max_object_bytes) {
                    Ok(parsed) => parsed,
                    Err(_) => {
                        report.remove_or_retain(
                            &path,
                            metadata.len(),
                            self.filesystem_cleanup_allowed(),
                        );
                        continue;
                    }
                };
                let Some(combined) = parsed.combined_key.clone() else {
                    report.remove_or_retain(
                        &path,
                        metadata.len(),
                        self.filesystem_cleanup_allowed(),
                    );
                    continue;
                };
                let Some(primary) = parsed.primary_key.clone() else {
                    report.remove_or_retain(
                        &path,
                        metadata.len(),
                        self.filesystem_cleanup_allowed(),
                    );
                    continue;
                };
                let Some(meta) = NativeDiskCacheMeta::decode(&parsed.internal_meta) else {
                    report.remove_or_retain(
                        &path,
                        metadata.len(),
                        self.filesystem_cleanup_allowed(),
                    );
                    continue;
                };
                if native_memory_entry_from_disk_object(&parsed).is_none() {
                    report.remove_or_retain(
                        &path,
                        metadata.len(),
                        self.filesystem_cleanup_allowed(),
                    );
                    continue;
                }
                if state.objects.contains_key(&combined) {
                    report.retain(metadata.len());
                    continue;
                }
                let weight = bytes.len() as u64;
                state.bytes = state.bytes.saturating_add(weight);
                let path = if self.filesystem_cleanup_allowed() {
                    self.migrate_filesystem_identity_path(&path, &combined)?
                } else {
                    path
                };
                state.insert_object(
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
        Ok(report)
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
        if self.with_state(|state| state.filesystem_writes_blocked) {
            return Err(std::io::Error::other(
                "filesystem cache write admission is paused",
            ));
        }
        let mut last_error = None;
        for _ in 0..4 {
            let tmp_path = self.temp_path_for(path)?;
            match write_new_temporary(path, tmp_path, bytes) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    last_error = Some(error);
                }
                Err(error) => {
                    // A failed write may leave a temporary that could not be
                    // removed. Stop admission until recovery accounts for it.
                    self.pause_filesystem_writes();
                    return Err(error);
                }
            }
        }
        self.pause_filesystem_writes();
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
        let encoded = self.encryption.as_ref().map_or_else(
            || {
                let digest = Sha256::digest(key.as_bytes());
                let mut encoded = String::with_capacity(digest.len() * 2);
                for byte in digest {
                    let _ = write!(&mut encoded, "{byte:02x}");
                }
                encoded
            },
            |encryption| encryption.confidential_index_identity(key),
        );
        self.root.join(&encoded[..2]).join(format!("{encoded}.fhc"))
    }

    fn migrate_filesystem_identity_path(
        &self,
        current: &Path,
        combined_key: &str,
    ) -> std::io::Result<PathBuf> {
        let expected = self.path_for_combined_key(combined_key);
        if current == expected {
            return Ok(expected);
        }
        if let Some(parent) = expected.parent() {
            create_native_cache_dir_all(parent)?;
        }
        NativeSafeDiskCachePath::from_path(expected.clone())
            .rename_from(&NativeSafeDiskCachePath::from_path(current.to_path_buf()))?;
        Ok(expected)
    }

    pub(super) fn purge_legacy_encrypted_filesystem(&self) -> std::io::Result<()> {
        let mut budget = RecoveryBudget::new(RECOVERY_ENTRY_LIMIT, RECOVERY_READ_LIMIT);
        for shard_path in budget.children(&self.root)? {
            let shard_name = shard_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            if !lowercase_hex(shard_name, 2)
                || !std::fs::symlink_metadata(&shard_path)?.is_dir()
                || native_cache_path_contains_symlink(&self.root, &shard_path)?
            {
                continue;
            }
            for path in budget.children(&shard_path)? {
                if !object_name(
                    path.file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or_default(),
                    shard_name,
                ) || native_cache_path_contains_symlink(&self.root, &path)?
                {
                    continue;
                }
                let safe = NativeSafeDiskCachePath::from_path(path);
                let Ok(mut file) = safe.open_existing_file() else {
                    continue;
                };
                if validate_single_link_file(&file).is_err() {
                    continue;
                }
                budget.charge_read(22)?;
                let recognizable = recognizable_file(&mut file)?;
                drop(file);
                if recognizable {
                    safe.remove_file()?;
                }
            }
        }
        Ok(())
    }
}

fn write_new_temporary(path: &Path, temporary: PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    let tmp_safe = NativeSafeDiskCachePath::from_path(temporary);
    let destination = NativeSafeDiskCachePath::from_path(path.to_path_buf());
    // A failed exclusive create confers no ownership and must not unlink.
    let mut file = tmp_safe.create_new_file()?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        destination.rename_from(&tmp_safe)?;
        destination.sync_parent_dir()
    })();
    drop(file);
    if result.is_err() {
        let _ = tmp_safe.remove_file();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temporary_collision_preserves_existing_file_and_destination() {
        let directory = tempfile::tempdir().unwrap();
        let temporary = directory.path().join("occupied.tmp");
        let destination = directory.path().join("object.fhc");
        std::fs::write(&temporary, b"another writer").unwrap();
        std::fs::write(&destination, b"previous object").unwrap();
        assert!(write_new_temporary(&destination, temporary.clone(), b"replacement").is_err());
        assert_eq!(std::fs::read(temporary).unwrap(), b"another writer");
        assert_eq!(std::fs::read(destination).unwrap(), b"previous object");
    }

    #[test]
    fn failed_rename_removes_only_our_created_temporary() {
        let directory = tempfile::tempdir().unwrap();
        let temporary = directory.path().join("created.tmp");
        let destination = directory.path().join("directory");
        std::fs::create_dir(&destination).unwrap();
        assert!(write_new_temporary(&destination, temporary.clone(), b"replacement").is_err());
        assert!(!temporary.exists());
        assert!(destination.is_dir());
    }
}
