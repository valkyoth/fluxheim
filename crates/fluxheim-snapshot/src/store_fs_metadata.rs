#[cfg(not(unix))]
use std::io;
use std::path::Path;

use crate::store::SnapshotError;
#[cfg(unix)]
use crate::store_fs_unix::optional_symlink_metadata as optional_symlink_metadata_unix;

#[derive(Clone, Copy)]
pub(crate) struct SnapshotPathMetadata {
    is_file: bool,
    is_directory: bool,
    is_symlink: bool,
    #[cfg(unix)]
    mode: rustix::fs::RawMode,
}

#[derive(Clone, Copy)]
pub(crate) struct SnapshotPathFileType {
    is_symlink: bool,
}

impl SnapshotPathMetadata {
    #[cfg(unix)]
    pub(crate) fn from_unix_stat(stat: &rustix::fs::Stat) -> Self {
        let file_type = rustix::fs::FileType::from_raw_mode(stat.st_mode);
        Self {
            is_file: file_type.is_file(),
            is_directory: file_type.is_dir(),
            is_symlink: file_type.is_symlink(),
            mode: stat.st_mode,
        }
    }

    pub(crate) fn file_type(self) -> SnapshotPathFileType {
        SnapshotPathFileType {
            is_symlink: self.is_symlink,
        }
    }

    pub(crate) fn is_file(self) -> bool {
        self.is_file
    }

    pub(crate) fn is_dir(self) -> bool {
        self.is_directory
    }
}

impl SnapshotPathFileType {
    pub(crate) fn is_symlink(self) -> bool {
        self.is_symlink
    }
}

pub(crate) fn optional_symlink_metadata(
    path: &Path,
) -> Result<Option<SnapshotPathMetadata>, SnapshotError> {
    #[cfg(unix)]
    {
        optional_symlink_metadata_unix(path)
    }

    #[cfg(not(unix))]
    {
        match path.symlink_metadata() {
            Ok(metadata) => Ok(Some(SnapshotPathMetadata {
                is_file: metadata.is_file(),
                is_directory: metadata.is_dir(),
                is_symlink: metadata.file_type().is_symlink(),
            })),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(SnapshotError::Io(error)),
        }
    }
}

pub(crate) fn path_exists_without_following_symlinks(path: &Path) -> Result<bool, SnapshotError> {
    optional_symlink_metadata(path).map(|metadata| metadata.is_some())
}

pub(crate) fn require_real_directory(path: &Path) -> Result<(), SnapshotError> {
    let Some(metadata) = optional_symlink_metadata(path)? else {
        return Err(SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        });
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

pub(crate) fn is_symlink(path: &Path) -> Result<bool, SnapshotError> {
    optional_symlink_metadata(path).map(|metadata| {
        metadata
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
    })
}

pub(crate) fn require_private_path_metadata(
    path: &Path,
    metadata: &SnapshotPathMetadata,
) -> Result<(), SnapshotError> {
    #[cfg(unix)]
    {
        if metadata.mode & 0o077 != 0 {
            return Err(SnapshotError::UnsafeSnapshotPath {
                path: path.to_path_buf(),
            });
        }
    }
    #[cfg(not(unix))]
    let _ = (path, metadata);
    Ok(())
}
