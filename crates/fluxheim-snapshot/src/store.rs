use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fluxheim_config::{Config, ConfigLoadError};

use crate::integrity::{SnapshotIntegrityKey, SnapshotIntegrityManifest};
use crate::metadata::{
    SnapshotMetadata, snapshot_message, validate_snapshot_id, validate_snapshot_metadata,
};
pub(crate) use crate::model::{
    ConfigSnapshot, SnapshotEntryStatus, SnapshotError, SnapshotIntegrityStatus, SnapshotListEntry,
};
use crate::store_fs::{
    MAX_CURRENT_SNAPSHOT_POINTER_BYTES, canonical_directory, ensure_real_directory, is_symlink,
    open_private_lock_file, optional_symlink_metadata, path_exists_without_following_symlinks,
    read_optional_regular_file_to_string, read_regular_file_to_string_with_limit,
    regular_snapshot_file_exists, snapshot_parent_path_contains_symlink, write_atomically,
    write_atomically_new,
};
use crate::store_support::{SnapshotTransaction, new_snapshot_id, unix_duration};

pub(crate) const MAX_SNAPSHOT_STORE_ENTRIES: usize = 1024;

#[derive(Debug, Clone)]
pub struct SnapshotStore {
    root: PathBuf,
    pub(crate) integrity: Option<Arc<SnapshotIntegrityKey>>,
}

impl SnapshotStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            integrity: None,
        }
    }

    pub fn with_integrity_key_file(
        root: impl Into<PathBuf>,
        key_file: &Path,
    ) -> Result<Self, SnapshotError> {
        Ok(Self {
            root: root.into(),
            integrity: Some(Arc::new(SnapshotIntegrityKey::load(key_file)?)),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn snapshot_config(
        &self,
        config: &Config,
        message: Option<&str>,
    ) -> Result<ConfigSnapshot, SnapshotError> {
        config
            .validate()
            .map_err(|error| SnapshotError::Config(ConfigLoadError::Validate(error)))?;
        let message = snapshot_message(message)?;
        self.with_store_lock(|| {
            self.ensure_store_capacity()?;
            let parent_id = self.current_id_unlocked()?;
            let generation = self.next_generation_unlocked()?;
            let created = unix_duration()?;
            let id = new_snapshot_id(created, generation);
            let config_path = self.config_path(&id);
            let metadata_path = self.metadata_path(&id);
            let integrity_path = self.integrity_path(&id);
            let metadata = SnapshotMetadata {
                id: id.clone(),
                created_unix_secs: created.as_secs(),
                parent_id,
                generation,
                message,
            };
            let raw_config = toml::to_string_pretty(config).map_err(SnapshotError::Encode)?;
            let raw_metadata = toml::to_string_pretty(&metadata).map_err(SnapshotError::Encode)?;

            let mut transaction = SnapshotTransaction::new();
            write_atomically_new(&config_path, raw_config.as_bytes())?;
            transaction.track(config_path.clone());
            write_atomically_new(&metadata_path, raw_metadata.as_bytes())?;
            transaction.track(metadata_path.clone());
            let integrity = if let Some(key) = self.integrity.as_deref() {
                let manifest = key.manifest(&id, raw_config.as_bytes(), raw_metadata.as_bytes());
                let raw_manifest =
                    toml::to_string_pretty(&manifest).map_err(SnapshotError::Encode)?;
                write_atomically_new(&integrity_path, raw_manifest.as_bytes())?;
                transaction.track(integrity_path);
                SnapshotIntegrityStatus::Authenticated
            } else {
                SnapshotIntegrityStatus::Unverified
            };
            self.set_current_unlocked(&id)?;
            transaction.commit();

            Ok(ConfigSnapshot {
                id,
                config_path,
                metadata_path,
                metadata,
                integrity,
            })
        })
    }

    pub fn list(&self) -> Result<Vec<ConfigSnapshot>, SnapshotError> {
        Ok(self
            .list_entries()?
            .into_iter()
            .filter_map(|entry| entry.snapshot)
            .collect())
    }

    pub fn list_entries(&self) -> Result<Vec<SnapshotListEntry>, SnapshotError> {
        self.validate_root()?;
        if !self.safe_existing_root()? {
            return Ok(Vec::new());
        }
        let configs_dir = self.configs_dir();
        if !self.safe_existing_configs_dir()? {
            return Ok(Vec::new());
        }

        let mut snapshots = Vec::new();
        for entry in fs::read_dir(configs_dir).map_err(SnapshotError::Io)? {
            let entry = entry.map_err(SnapshotError::Io)?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            if stem.ends_with(".meta") || stem.ends_with(".integrity") {
                continue;
            }
            if snapshots.len() >= MAX_SNAPSHOT_STORE_ENTRIES {
                snapshots.push(SnapshotListEntry {
                    id: stem.to_owned(),
                    snapshot: None,
                    status: SnapshotEntryStatus::Corrupt,
                    error: Some(format!(
                        "snapshot store contains more than {MAX_SNAPSHOT_STORE_ENTRIES} snapshots"
                    )),
                });
                break;
            }
            let entry = match self.load_snapshot(stem) {
                Ok(snapshot) => SnapshotListEntry {
                    id: stem.to_owned(),
                    status: match snapshot.integrity {
                        SnapshotIntegrityStatus::Authenticated => SnapshotEntryStatus::Healthy,
                        SnapshotIntegrityStatus::Unverified => SnapshotEntryStatus::Unverified,
                    },
                    snapshot: Some(snapshot),
                    error: None,
                },
                Err(error) => SnapshotListEntry {
                    id: stem.to_owned(),
                    snapshot: None,
                    status: SnapshotEntryStatus::Corrupt,
                    error: Some(error.to_string()),
                },
            };
            snapshots.push(entry);
        }

        snapshots.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(snapshots)
    }

    pub fn current_id(&self) -> Result<Option<String>, SnapshotError> {
        self.validate_root()?;
        self.current_id_unlocked()
    }

    fn current_id_unlocked(&self) -> Result<Option<String>, SnapshotError> {
        if !self.safe_existing_root()? {
            return Ok(None);
        }
        let path = self.current_path();
        if !path_exists_without_following_symlinks(&path)? {
            return Ok(None);
        }
        let id = read_regular_file_to_string_with_limit(&path, MAX_CURRENT_SNAPSHOT_POINTER_BYTES)?;
        let id = id.trim();
        if id.is_empty() {
            return Ok(None);
        }
        validate_snapshot_id(id)?;
        Ok(Some(id.to_owned()))
    }

    pub fn current_snapshot(&self) -> Result<Option<ConfigSnapshot>, SnapshotError> {
        let Some(id) = self.current_id()? else {
            return Ok(None);
        };

        self.load_snapshot(&id).map(Some)
    }

    pub fn snapshot(&self, id: &str) -> Result<ConfigSnapshot, SnapshotError> {
        self.validate_root()?;
        self.load_snapshot(id)
    }

    pub fn rollback_target(&self, target: Option<&str>) -> Result<ConfigSnapshot, SnapshotError> {
        self.with_store_lock(|| {
            let snapshot = self.rollback_candidate_unlocked(target)?;
            self.set_current_unlocked(&snapshot.id)?;
            Ok(snapshot)
        })
    }

    pub fn rollback_candidate(
        &self,
        target: Option<&str>,
    ) -> Result<ConfigSnapshot, SnapshotError> {
        self.validate_root()?;
        self.rollback_candidate_unlocked(target)
    }

    fn rollback_candidate_unlocked(
        &self,
        target: Option<&str>,
    ) -> Result<ConfigSnapshot, SnapshotError> {
        let id = match target {
            Some(id) => {
                validate_snapshot_id(id)?;
                id.to_owned()
            }
            None => self.previous_snapshot_id()?,
        };
        let snapshot = self.load_snapshot(&id)?;
        Config::load(Some(&snapshot.config_path)).map_err(SnapshotError::Config)?;
        Ok(snapshot)
    }

    pub fn set_current_snapshot(&self, id: &str) -> Result<(), SnapshotError> {
        self.with_store_lock(|| {
            self.load_snapshot(id)?;
            self.set_current_unlocked(id)
        })
    }

    fn previous_snapshot_id(&self) -> Result<String, SnapshotError> {
        let current = self
            .current_id_unlocked()?
            .ok_or(SnapshotError::CurrentMissing)?;
        let snapshot = self.load_snapshot(&current)?;
        snapshot
            .metadata
            .parent_id
            .ok_or(SnapshotError::NoPreviousSnapshot { current })
    }

    fn load_snapshot(&self, id: &str) -> Result<ConfigSnapshot, SnapshotError> {
        validate_snapshot_id(id)?;
        let config_path = self.config_path(id);
        if !regular_snapshot_file_exists(&config_path)? {
            return Err(SnapshotError::SnapshotNotFound { id: id.to_owned() });
        }

        let metadata_path = self.metadata_path(id);
        let raw_metadata = read_optional_regular_file_to_string(&metadata_path)?;
        let integrity = self.verify_integrity(id, raw_metadata.as_deref())?;
        let metadata = if let Some(raw) = raw_metadata {
            let metadata = toml::from_str(&raw).map_err(SnapshotError::Decode)?;
            validate_snapshot_metadata(&metadata, id)?;
            metadata
        } else {
            SnapshotMetadata {
                id: id.to_owned(),
                created_unix_secs: 0,
                parent_id: None,
                generation: 0,
                message: None,
            }
        };

        Ok(ConfigSnapshot {
            id: id.to_owned(),
            config_path,
            metadata_path,
            metadata,
            integrity,
        })
    }

    fn set_current_unlocked(&self, id: &str) -> Result<(), SnapshotError> {
        validate_snapshot_id(id)?;
        if !regular_snapshot_file_exists(&self.config_path(id))? {
            return Err(SnapshotError::SnapshotNotFound { id: id.to_owned() });
        }
        self.ensure_layout()?;
        write_atomically(&self.current_path(), format!("{id}\n").as_bytes())
    }

    fn ensure_layout(&self) -> Result<(), SnapshotError> {
        self.validate_root()?;
        ensure_real_directory(&self.root)?;

        let configs_dir = self.configs_dir();
        if is_symlink(&configs_dir)? {
            return Err(SnapshotError::UnsafeSnapshotPath { path: configs_dir });
        }
        ensure_real_directory(&configs_dir)?;
        self.ensure_configs_dir_under_root()?;
        Ok(())
    }

    fn ensure_store_capacity(&self) -> Result<(), SnapshotError> {
        if !self.safe_existing_root()? || !self.safe_existing_configs_dir()? {
            return Ok(());
        }

        let mut snapshots = 0_usize;
        for entry in fs::read_dir(self.configs_dir()).map_err(SnapshotError::Io)? {
            let entry = entry.map_err(SnapshotError::Io)?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            if stem.ends_with(".meta") || stem.ends_with(".integrity") {
                continue;
            }
            snapshots = snapshots.saturating_add(1);
            if snapshots >= MAX_SNAPSHOT_STORE_ENTRIES {
                return Err(SnapshotError::Io(io::Error::new(
                    io::ErrorKind::StorageFull,
                    format!(
                        "snapshot store {} reached the {} snapshot limit",
                        self.root.display(),
                        MAX_SNAPSHOT_STORE_ENTRIES
                    ),
                )));
            }
        }
        Ok(())
    }

    fn next_generation_unlocked(&self) -> Result<u64, SnapshotError> {
        let mut maximum = 0u64;
        if !self.safe_existing_configs_dir()? {
            return Ok(1);
        }
        for entry in fs::read_dir(self.configs_dir()).map_err(SnapshotError::Io)? {
            let path = entry.map_err(SnapshotError::Io)?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(id) = name.strip_suffix(".meta.toml") else {
                continue;
            };
            if let Ok(snapshot) = self.load_snapshot(id) {
                maximum = maximum.max(snapshot.metadata.generation);
            }
        }
        maximum.checked_add(1).ok_or_else(|| {
            SnapshotError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "snapshot generation counter overflowed",
            ))
        })
    }

    pub(crate) fn with_store_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, SnapshotError>,
    ) -> Result<T, SnapshotError> {
        self.validate_root()?;
        self.ensure_layout()?;
        let lock = open_private_lock_file(&self.root.join(".snapshot.lock"))?;
        lock.lock().map_err(SnapshotError::Io)?;
        let result = operation();
        let unlock = lock.unlock().map_err(SnapshotError::Io);
        match (result, unlock) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    fn validate_root(&self) -> Result<(), SnapshotError> {
        if self.root.as_os_str().is_empty()
            || self
                .root
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            || snapshot_parent_path_contains_symlink(&self.root).unwrap_or(true)
            || fluxheim_config::fs_trust::existing_path_or_parent_has_insecure_write_permissions(
                &self.root,
            )
            .unwrap_or(true)
        {
            return Err(SnapshotError::UnsafeStoreRoot {
                path: self.root.clone(),
            });
        }

        Ok(())
    }

    pub(crate) fn configs_dir(&self) -> PathBuf {
        self.root.join("configs")
    }

    fn current_path(&self) -> PathBuf {
        self.root.join("current")
    }

    pub(crate) fn config_path(&self, id: &str) -> PathBuf {
        self.configs_dir().join(format!("{id}.toml"))
    }

    pub(crate) fn metadata_path(&self, id: &str) -> PathBuf {
        self.configs_dir().join(format!("{id}.meta.toml"))
    }

    pub(crate) fn integrity_path(&self, id: &str) -> PathBuf {
        self.configs_dir().join(format!("{id}.integrity.toml"))
    }

    fn verify_integrity(
        &self,
        id: &str,
        raw_metadata: Option<&str>,
    ) -> Result<SnapshotIntegrityStatus, SnapshotError> {
        let Some(key) = self.integrity.as_deref() else {
            return Ok(SnapshotIntegrityStatus::Unverified);
        };
        let raw_metadata = raw_metadata
            .ok_or_else(|| SnapshotError::IntegrityManifestMissing { id: id.to_owned() })?;
        let raw_config = read_regular_file_to_string_with_limit(
            &self.config_path(id),
            crate::store_fs::MAX_SNAPSHOT_FILE_BYTES,
        )?;
        let raw_manifest = read_optional_regular_file_to_string(&self.integrity_path(id))?
            .ok_or_else(|| SnapshotError::IntegrityManifestMissing { id: id.to_owned() })?;
        let manifest: SnapshotIntegrityManifest =
            toml::from_str(&raw_manifest).map_err(SnapshotError::Decode)?;
        key.verify(
            id,
            raw_config.as_bytes(),
            raw_metadata.as_bytes(),
            &manifest,
        )?;
        Ok(SnapshotIntegrityStatus::Authenticated)
    }

    fn safe_existing_configs_dir(&self) -> Result<bool, SnapshotError> {
        let configs_dir = self.configs_dir();
        let Some(metadata) = optional_symlink_metadata(&configs_dir)? else {
            return Ok(false);
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SnapshotError::UnsafeSnapshotPath { path: configs_dir });
        }
        self.ensure_configs_dir_under_root()?;
        Ok(true)
    }

    fn safe_existing_root(&self) -> Result<bool, SnapshotError> {
        let Some(metadata) = optional_symlink_metadata(&self.root)? else {
            return Ok(false);
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SnapshotError::UnsafeSnapshotPath {
                path: self.root.clone(),
            });
        }
        Ok(true)
    }

    fn ensure_configs_dir_under_root(&self) -> Result<(), SnapshotError> {
        let root = canonical_directory(&self.root)?;
        let configs_dir = self.configs_dir();
        let configs_dir = canonical_directory(&configs_dir)?;
        if !configs_dir.starts_with(&root) {
            return Err(SnapshotError::UnsafeSnapshotPath { path: configs_dir });
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "store_safety_tests.rs"]
mod store_safety_tests;
#[cfg(test)]
#[path = "store_tests.rs"]
mod store_tests;
