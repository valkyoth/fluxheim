use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fluxheim_config::{Config, ConfigLoadError};

use crate::metadata::{
    MAX_SNAPSHOT_ID_BYTES, SnapshotMetadata, snapshot_message, validate_snapshot_id,
    validate_snapshot_metadata,
};
use crate::store_fs::{
    MAX_CURRENT_SNAPSHOT_POINTER_BYTES, canonical_directory, ensure_real_directory, is_symlink,
    optional_symlink_metadata, path_exists_without_following_symlinks,
    read_optional_regular_file_to_string, read_regular_file_to_string_with_limit,
    regular_snapshot_file_exists, snapshot_parent_path_contains_symlink, unique_sequence,
    write_atomically,
};

const MAX_SNAPSHOT_STORE_ENTRIES: usize = 1024;

#[derive(Debug, Clone)]
pub struct SnapshotStore {
    root: PathBuf,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConfigSnapshot {
    pub id: String,
    pub config_path: PathBuf,
    pub metadata_path: PathBuf,
    pub metadata: SnapshotMetadata,
}

#[derive(Debug)]
pub enum SnapshotError {
    Io(io::Error),
    Encode(toml::ser::Error),
    Decode(toml::de::Error),
    Config(ConfigLoadError),
    EmptyStore,
    CurrentMissing,
    NoPreviousSnapshot { current: String },
    InvalidSnapshotId { id: String },
    SnapshotNotFound { id: String },
    InvalidSnapshotMessage { max_bytes: usize },
    UnsafeStoreRoot { path: PathBuf },
    UnsafeSnapshotPath { path: PathBuf },
}

impl SnapshotStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn snapshot_config(
        &self,
        config: &Config,
        message: Option<&str>,
    ) -> Result<ConfigSnapshot, SnapshotError> {
        self.validate_root()?;
        self.ensure_store_capacity()?;
        config
            .validate()
            .map_err(|error| SnapshotError::Config(ConfigLoadError::Validate(error)))?;
        self.ensure_layout()?;

        let id = new_snapshot_id();
        let config_path = self.config_path(&id);
        let metadata_path = self.metadata_path(&id);
        let metadata = SnapshotMetadata {
            id: id.clone(),
            created_unix_secs: unix_secs(),
            message: snapshot_message(message)?,
        };

        let raw_config = toml::to_string_pretty(config).map_err(SnapshotError::Encode)?;
        write_atomically(&config_path, raw_config.as_bytes())?;

        let raw_metadata = toml::to_string_pretty(&metadata).map_err(SnapshotError::Encode)?;
        write_atomically(&metadata_path, raw_metadata.as_bytes())?;

        self.set_current(&id)?;

        Ok(ConfigSnapshot {
            id,
            config_path,
            metadata_path,
            metadata,
        })
    }

    pub fn list(&self) -> Result<Vec<ConfigSnapshot>, SnapshotError> {
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
            if stem.ends_with(".meta") {
                continue;
            }
            if snapshots.len() >= MAX_SNAPSHOT_STORE_ENTRIES {
                return Err(SnapshotError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "snapshot store {} contains more than {} snapshots",
                        self.root.display(),
                        MAX_SNAPSHOT_STORE_ENTRIES
                    ),
                )));
            }
            snapshots.push(self.load_snapshot(stem)?);
        }

        snapshots.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(snapshots)
    }

    pub fn current_id(&self) -> Result<Option<String>, SnapshotError> {
        self.validate_root()?;
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

    pub fn rollback_target(&self, target: Option<&str>) -> Result<ConfigSnapshot, SnapshotError> {
        let snapshot = self.rollback_candidate(target)?;
        self.set_current(&snapshot.id)?;
        Ok(snapshot)
    }

    pub fn rollback_candidate(
        &self,
        target: Option<&str>,
    ) -> Result<ConfigSnapshot, SnapshotError> {
        self.validate_root()?;
        let id = rollback_target_id(self, target)?;
        let snapshot = self.load_snapshot(&id)?;
        Config::load(Some(&snapshot.config_path)).map_err(SnapshotError::Config)?;
        Ok(snapshot)
    }

    pub fn set_current_snapshot(&self, id: &str) -> Result<(), SnapshotError> {
        self.validate_root()?;
        self.set_current(id)
    }

    fn previous_snapshot_id(&self) -> Result<String, SnapshotError> {
        let current = self.current_id()?.ok_or(SnapshotError::CurrentMissing)?;
        let snapshots = self.list()?;
        if snapshots.is_empty() {
            return Err(SnapshotError::EmptyStore);
        }

        let Some(position) = snapshots.iter().position(|snapshot| snapshot.id == current) else {
            return Err(SnapshotError::SnapshotNotFound { id: current });
        };
        if position == 0 {
            return Err(SnapshotError::NoPreviousSnapshot { current });
        }

        Ok(snapshots[position - 1].id.clone())
    }

    fn load_snapshot(&self, id: &str) -> Result<ConfigSnapshot, SnapshotError> {
        validate_snapshot_id(id)?;
        let config_path = self.config_path(id);
        if !regular_snapshot_file_exists(&config_path)? {
            return Err(SnapshotError::SnapshotNotFound { id: id.to_owned() });
        }

        let metadata_path = self.metadata_path(id);
        let metadata = if let Some(raw) = read_optional_regular_file_to_string(&metadata_path)? {
            let metadata = toml::from_str(&raw).map_err(SnapshotError::Decode)?;
            validate_snapshot_metadata(&metadata, id)?;
            metadata
        } else {
            SnapshotMetadata {
                id: id.to_owned(),
                created_unix_secs: 0,
                message: None,
            }
        };

        Ok(ConfigSnapshot {
            id: id.to_owned(),
            config_path,
            metadata_path,
            metadata,
        })
    }

    fn set_current(&self, id: &str) -> Result<(), SnapshotError> {
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
            if stem.ends_with(".meta") {
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

    fn configs_dir(&self) -> PathBuf {
        self.root.join("configs")
    }

    fn current_path(&self) -> PathBuf {
        self.root.join("current")
    }

    fn config_path(&self, id: &str) -> PathBuf {
        self.configs_dir().join(format!("{id}.toml"))
    }

    fn metadata_path(&self, id: &str) -> PathBuf {
        self.configs_dir().join(format!("{id}.meta.toml"))
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

fn rollback_target_id(
    store: &SnapshotStore,
    target: Option<&str>,
) -> Result<String, SnapshotError> {
    match target {
        Some(id) => {
            validate_snapshot_id(id)?;
            Ok(id.to_owned())
        }
        None => store.previous_snapshot_id(),
    }
}

impl Display for SnapshotError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "snapshot I/O error: {error}"),
            Self::Encode(error) => write!(formatter, "could not encode snapshot TOML: {error}"),
            Self::Decode(error) => write!(formatter, "could not decode snapshot metadata: {error}"),
            Self::Config(error) => write!(formatter, "snapshot config is invalid: {error}"),
            Self::EmptyStore => formatter.write_str("snapshot store is empty"),
            Self::CurrentMissing => formatter.write_str("snapshot store has no current pointer"),
            Self::NoPreviousSnapshot { current } => {
                write!(formatter, "snapshot {current} has no previous snapshot")
            }
            Self::InvalidSnapshotId { id } if id.len() > MAX_SNAPSHOT_ID_BYTES => write!(
                formatter,
                "invalid snapshot id: length {} exceeds {} bytes",
                id.len(),
                MAX_SNAPSHOT_ID_BYTES
            ),
            Self::InvalidSnapshotId { id } => write!(formatter, "invalid snapshot id: {id}"),
            Self::SnapshotNotFound { id } => write!(formatter, "snapshot not found: {id}"),
            Self::InvalidSnapshotMessage { max_bytes } => write!(
                formatter,
                "snapshot message must be non-control text no longer than {max_bytes} bytes"
            ),
            Self::UnsafeStoreRoot { path } => write!(
                formatter,
                "snapshot store root must not be empty, contain parent-directory traversal, sit below a symlinked directory, or use a group- or world-writable directory: {}",
                path.display()
            ),
            Self::UnsafeSnapshotPath { path } => write!(
                formatter,
                "snapshot store path must be a regular file or directory inside the snapshot store: {}",
                path.display()
            ),
        }
    }
}

impl Error for SnapshotError {}

fn new_snapshot_id() -> String {
    let now = unix_duration();
    format!(
        "s{}-{:09}-{}",
        now.as_secs(),
        now.subsec_nanos(),
        unique_sequence()
    )
}

fn unix_secs() -> u64 {
    unix_duration().as_secs()
}

fn unix_duration() -> Duration {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration,
        Err(error) => {
            log::error!(
                target: "fluxheim::security",
                "system clock is before Unix epoch; aborting because snapshot identifiers require monotonic Unix-time input: {error}"
            );
            std::process::abort();
        }
    }
}

#[cfg(test)]
#[path = "store_safety_tests.rs"]
mod store_safety_tests;
#[cfg(test)]
#[path = "store_tests.rs"]
mod store_tests;
