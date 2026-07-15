use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fluxheim_config::{Config, ConfigLoadError};

use crate::integrity::{SnapshotCryptoProvider, SnapshotIntegrityKey, SnapshotIntegrityManifest};
use crate::metadata::{
    SnapshotMetadata, safe_snapshot_label, snapshot_message, validate_snapshot_id,
    validate_snapshot_metadata,
};
pub(crate) use crate::model::{
    ConfigSnapshot, SnapshotEntryStatus, SnapshotError, SnapshotIntegrityStatus, SnapshotListEntry,
    VerifiedConfigSnapshot,
};
use crate::store_fs::{
    MAX_CURRENT_SNAPSHOT_POINTER_BYTES, MAX_SNAPSHOT_FILE_BYTES,
    path_exists_without_following_symlinks, read_optional_regular_file_to_string_with_limit,
    read_regular_file_to_string_with_limit, regular_snapshot_file_exists, write_atomically,
    write_atomically_new,
};
use crate::store_layout::validate_integrity_key_outside_store;
use crate::store_support::{SnapshotTransaction, new_snapshot_id, unix_duration};

#[cfg(test)]
std::thread_local! {
    static FAIL_CURRENT_UPDATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(crate) const MAX_SNAPSHOT_STORE_ENTRIES: usize = 1024;

#[derive(Debug, Clone)]
pub struct SnapshotStore {
    pub(crate) root: PathBuf,
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
        provider: Arc<dyn SnapshotCryptoProvider>,
    ) -> Result<Self, SnapshotError> {
        validate_integrity_key_outside_store(root.into(), key_file, provider)
    }

    pub(crate) fn with_integrity_key_file_validated(
        root: PathBuf,
        key_file: &Path,
        provider: Arc<dyn SnapshotCryptoProvider>,
    ) -> Result<Self, SnapshotError> {
        Ok(Self {
            root,
            integrity: Some(Arc::new(SnapshotIntegrityKey::load(key_file, provider)?)),
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
        let raw_config = toml::to_string_pretty(config).map_err(SnapshotError::Encode)?;
        self.snapshot_serialized_config(raw_config, message)
    }

    fn snapshot_serialized_config(
        &self,
        raw_config: String,
        message: Option<String>,
    ) -> Result<ConfigSnapshot, SnapshotError> {
        ensure_snapshot_size(&raw_config)?;
        self.with_store_lock(|| {
            self.ensure_store_capacity()?;
            let parent_id = self.current_id_unlocked()?;
            let generation = self.allocate_generation_unlocked()?;
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
            let raw_metadata = toml::to_string_pretty(&metadata).map_err(SnapshotError::Encode)?;

            let mut transaction = SnapshotTransaction::new();
            publish_transaction_file(&mut transaction, &config_path, raw_config.as_bytes())?;
            publish_transaction_file(&mut transaction, &metadata_path, raw_metadata.as_bytes())?;
            let integrity = if let Some(key) = self.integrity.as_deref() {
                let manifest = key.manifest(
                    &id,
                    raw_config.as_bytes(),
                    raw_metadata.as_bytes(),
                    metadata.generation,
                )?;
                let raw_manifest =
                    toml::to_string_pretty(&manifest).map_err(SnapshotError::Encode)?;
                publish_transaction_file(
                    &mut transaction,
                    &integrity_path,
                    raw_manifest.as_bytes(),
                )?;
                SnapshotIntegrityStatus::Authenticated
            } else {
                SnapshotIntegrityStatus::Unverified
            };
            transaction.commit();
            self.set_current_unlocked(&id).map_err(|_| {
                SnapshotError::SnapshotPublishedButCurrentUpdateFailed { id: id.clone() }
            })?;

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
            let safe_label = safe_snapshot_label(stem);
            if snapshots.len() >= MAX_SNAPSHOT_STORE_ENTRIES {
                snapshots.push(SnapshotListEntry {
                    id: safe_label,
                    snapshot: None,
                    status: SnapshotEntryStatus::Corrupt,
                    error: Some(format!(
                        "snapshot store contains more than {MAX_SNAPSHOT_STORE_ENTRIES} snapshots"
                    )),
                });
                break;
            }
            if validate_snapshot_id(stem).is_err() {
                snapshots.push(SnapshotListEntry {
                    id: safe_label,
                    snapshot: None,
                    status: SnapshotEntryStatus::Corrupt,
                    error: Some("snapshot filename is invalid".to_owned()),
                });
                continue;
            }
            let entry = match self.load_snapshot(stem) {
                Ok(snapshot) => SnapshotListEntry {
                    id: safe_label.clone(),
                    status: match snapshot.integrity {
                        SnapshotIntegrityStatus::Authenticated => SnapshotEntryStatus::Healthy,
                        SnapshotIntegrityStatus::Unverified => SnapshotEntryStatus::Unverified,
                    },
                    snapshot: Some(snapshot),
                    error: None,
                },
                Err(error) => SnapshotListEntry {
                    id: safe_label,
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
            let verified = self.rollback_candidate_unlocked(target)?;
            self.set_current_unlocked(&verified.snapshot.id)?;
            Ok(verified.snapshot)
        })
    }

    pub fn rollback_candidate(
        &self,
        target: Option<&str>,
    ) -> Result<VerifiedConfigSnapshot, SnapshotError> {
        self.validate_root()?;
        self.rollback_candidate_unlocked(target)
    }

    fn rollback_candidate_unlocked(
        &self,
        target: Option<&str>,
    ) -> Result<VerifiedConfigSnapshot, SnapshotError> {
        let id = match target {
            Some(id) => {
                validate_snapshot_id(id)?;
                id.to_owned()
            }
            None => self.previous_snapshot_id()?,
        };
        let (snapshot, raw_config) = self.load_snapshot_config_bytes(&id)?;
        let config = Config::load_snapshot_bytes(&raw_config).map_err(SnapshotError::Config)?;
        Ok(VerifiedConfigSnapshot { snapshot, config })
    }

    pub fn set_current_snapshot(&self, id: &str) -> Result<(), SnapshotError> {
        self.with_store_lock(|| {
            self.load_snapshot_config_bytes(id)?;
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
        let raw_metadata = read_optional_regular_file_to_string_with_limit(
            &metadata_path,
            crate::metadata::MAX_SNAPSHOT_METADATA_BYTES,
        )?;
        let integrity = self.verify_integrity(id, raw_metadata.as_deref())?;
        self.snapshot_from_metadata(id, config_path, metadata_path, raw_metadata, integrity)
    }

    pub(crate) fn load_snapshot_config_bytes(
        &self,
        id: &str,
    ) -> Result<(ConfigSnapshot, Vec<u8>), SnapshotError> {
        validate_snapshot_id(id)?;
        let config_path = self.config_path(id);
        if !regular_snapshot_file_exists(&config_path)? {
            return Err(SnapshotError::SnapshotNotFound { id: id.to_owned() });
        }
        let raw_config = read_regular_file_to_string_with_limit(
            &config_path,
            crate::store_fs::MAX_SNAPSHOT_FILE_BYTES,
        )?
        .into_bytes();
        let metadata_path = self.metadata_path(id);
        let raw_metadata = read_optional_regular_file_to_string_with_limit(
            &metadata_path,
            crate::metadata::MAX_SNAPSHOT_METADATA_BYTES,
        )?;
        let integrity = self.verify_integrity_bytes(id, &raw_config, raw_metadata.as_deref())?;
        let snapshot =
            self.snapshot_from_metadata(id, config_path, metadata_path, raw_metadata, integrity)?;
        Ok((snapshot, raw_config))
    }

    fn snapshot_from_metadata(
        &self,
        id: &str,
        config_path: PathBuf,
        metadata_path: PathBuf,
        raw_metadata: Option<String>,
        integrity: SnapshotIntegrityStatus,
    ) -> Result<ConfigSnapshot, SnapshotError> {
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
        #[cfg(test)]
        if FAIL_CURRENT_UPDATE.with(|failure| failure.replace(false)) {
            return Err(SnapshotError::Io(io::Error::other(
                "injected current pointer failure",
            )));
        }
        write_atomically(&self.current_path(), format!("{id}\n").as_bytes())
    }

    #[cfg(test)]
    pub(crate) fn fail_next_current_update() {
        FAIL_CURRENT_UPDATE.with(|failure| failure.set(true));
    }

    fn verify_integrity(
        &self,
        id: &str,
        raw_metadata: Option<&str>,
    ) -> Result<SnapshotIntegrityStatus, SnapshotError> {
        if self.integrity.is_none() {
            return Ok(SnapshotIntegrityStatus::Unverified);
        }
        let raw_metadata = raw_metadata
            .ok_or_else(|| SnapshotError::IntegrityManifestMissing { id: id.to_owned() })?;
        let raw_config = read_regular_file_to_string_with_limit(
            &self.config_path(id),
            crate::store_fs::MAX_SNAPSHOT_FILE_BYTES,
        )?;
        self.verify_integrity_bytes(id, raw_config.as_bytes(), Some(raw_metadata))
    }

    fn verify_integrity_bytes(
        &self,
        id: &str,
        raw_config: &[u8],
        raw_metadata: Option<&str>,
    ) -> Result<SnapshotIntegrityStatus, SnapshotError> {
        let Some(key) = self.integrity.as_deref() else {
            return Ok(SnapshotIntegrityStatus::Unverified);
        };
        let raw_metadata = raw_metadata
            .ok_or_else(|| SnapshotError::IntegrityManifestMissing { id: id.to_owned() })?;
        let raw_manifest = read_optional_regular_file_to_string_with_limit(
            &self.integrity_path(id),
            crate::integrity::MAX_INTEGRITY_MANIFEST_BYTES,
        )?
        .ok_or_else(|| SnapshotError::IntegrityManifestMissing { id: id.to_owned() })?;
        let manifest: SnapshotIntegrityManifest =
            toml::from_str(&raw_manifest).map_err(SnapshotError::Decode)?;
        let metadata: SnapshotMetadata =
            toml::from_str(raw_metadata).map_err(SnapshotError::Decode)?;
        validate_snapshot_metadata(&metadata, id)?;
        key.verify(
            id,
            raw_config,
            raw_metadata.as_bytes(),
            metadata.generation,
            &manifest,
        )?;
        Ok(SnapshotIntegrityStatus::Authenticated)
    }
}

fn ensure_snapshot_size(contents: &str) -> Result<(), SnapshotError> {
    let length = u64::try_from(contents.len()).map_err(|_| {
        SnapshotError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "serialized snapshot length overflowed",
        ))
    })?;
    if length > MAX_SNAPSHOT_FILE_BYTES {
        return Err(SnapshotError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("serialized snapshot exceeds {MAX_SNAPSHOT_FILE_BYTES} bytes"),
        )));
    }
    Ok(())
}

fn publish_transaction_file(
    transaction: &mut SnapshotTransaction,
    path: &Path,
    contents: &[u8],
) -> Result<(), SnapshotError> {
    match write_atomically_new(path, contents) {
        Ok(()) => {
            transaction.track(path.to_path_buf());
            Ok(())
        }
        Err(error @ SnapshotError::PublishedButNotDurable { .. }) => {
            transaction.track(path.to_path_buf());
            Err(error)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "store_safety_tests.rs"]
mod store_safety_tests;
#[cfg(test)]
#[path = "store_tests.rs"]
mod store_tests;
