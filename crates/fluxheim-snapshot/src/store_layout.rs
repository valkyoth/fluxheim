use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::integrity::SnapshotCryptoProvider;
use crate::store::{MAX_SNAPSHOT_STORE_ENTRIES, SnapshotError, SnapshotStore};
use crate::store_fs::{
    canonical_directory, ensure_real_directory, is_symlink, open_private_lock_file,
    optional_symlink_metadata, snapshot_parent_path_contains_symlink,
};

impl SnapshotStore {
    pub(crate) fn ensure_layout(&self) -> Result<(), SnapshotError> {
        self.validate_root()?;
        ensure_real_directory(&self.root)?;
        let configs_dir = self.configs_dir();
        if is_symlink(&configs_dir)? {
            return Err(SnapshotError::UnsafeSnapshotPath { path: configs_dir });
        }
        ensure_real_directory(&configs_dir)?;
        self.ensure_configs_dir_under_root()
    }

    pub(crate) fn ensure_store_capacity(&self) -> Result<(), SnapshotError> {
        if !self.safe_existing_root()? || !self.safe_existing_configs_dir()? {
            return Ok(());
        }
        let mut snapshots = 0_usize;
        for entry in fs::read_dir(self.configs_dir()).map_err(SnapshotError::Io)? {
            let path = entry.map_err(SnapshotError::Io)?.path();
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

    pub(crate) fn validate_root(&self) -> Result<(), SnapshotError> {
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

    pub(crate) fn current_path(&self) -> PathBuf {
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

    pub(crate) fn safe_existing_configs_dir(&self) -> Result<bool, SnapshotError> {
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

    pub(crate) fn safe_existing_root(&self) -> Result<bool, SnapshotError> {
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
        let configs_dir = canonical_directory(&self.configs_dir())?;
        if !configs_dir.starts_with(&root) {
            return Err(SnapshotError::UnsafeSnapshotPath { path: configs_dir });
        }
        Ok(())
    }
}

pub(crate) fn validate_integrity_key_outside_store(
    root: PathBuf,
    key_file: &Path,
    provider: Arc<dyn SnapshotCryptoProvider>,
) -> Result<SnapshotStore, SnapshotError> {
    SnapshotStore::new(root.clone()).validate_root()?;
    let current_dir = std::env::current_dir().map_err(SnapshotError::Io)?;
    let root_absolute = if root.is_absolute() {
        root.clone()
    } else {
        current_dir.join(&root)
    };
    let key_absolute = if key_file.is_absolute() {
        key_file.to_path_buf()
    } else {
        current_dir.join(key_file)
    };
    let key_canonical = fs::canonicalize(&key_absolute).map_err(SnapshotError::Io)?;
    let root_boundary = if root_absolute.exists() {
        fs::canonicalize(&root_absolute).map_err(SnapshotError::Io)?
    } else {
        root_absolute
    };
    if key_canonical.starts_with(root_boundary) {
        return Err(SnapshotError::UnsafeIntegrityKey {
            path: key_file.to_path_buf(),
        });
    }
    SnapshotStore::with_integrity_key_file_validated(root, key_file, provider)
}
