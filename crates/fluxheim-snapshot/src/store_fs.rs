use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::store::SnapshotError;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[cfg(any(target_os = "linux", target_os = "android"))]
const O_NOFOLLOW: i32 = 0o400000;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const O_NOFOLLOW: i32 = 0x0100;

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!(
    "O_NOFOLLOW is unknown on this Unix platform; audit symlink-safe file opening before building Fluxheim"
);

pub(crate) const MAX_CURRENT_SNAPSHOT_POINTER_BYTES: u64 = 4096;
pub(crate) const MAX_SNAPSHOT_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const SNAPSHOT_DIR_MODE: u32 = 0o700;
pub(crate) const SNAPSHOT_FILE_MODE: u32 = 0o600;

pub(crate) fn write_atomically(path: &Path, contents: &[u8]) -> Result<(), SnapshotError> {
    let parent = path.parent().ok_or_else(|| {
        SnapshotError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "snapshot path has no parent",
        ))
    })?;
    require_real_directory(parent)?;
    require_plain_write_destination(path)?;

    let temp_path = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("snapshot"),
        std::process::id(),
        unique_sequence()
    ));

    {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.custom_flags(O_NOFOLLOW).mode(SNAPSHOT_FILE_MODE);
        }

        let mut file = options.open(&temp_path).map_err(SnapshotError::Io)?;
        #[cfg(unix)]
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(SNAPSHOT_FILE_MODE))
            .map_err(SnapshotError::Io)?;
        file.write_all(contents).map_err(SnapshotError::Io)?;
        file.sync_all().map_err(SnapshotError::Io)?;
    }

    fs::rename(&temp_path, path).map_err(SnapshotError::Io)?;
    sync_directory(parent)?;
    Ok(())
}

pub(crate) fn unique_sequence() -> u64 {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn regular_snapshot_file_exists(path: &Path) -> Result<bool, SnapshotError> {
    let Some(metadata) = optional_symlink_metadata(path)? else {
        return Ok(false);
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        });
    }
    Ok(true)
}

pub(crate) fn read_optional_regular_file_to_string(
    path: &Path,
) -> Result<Option<String>, SnapshotError> {
    if !path_exists_without_following_symlinks(path)? {
        return Ok(None);
    }
    read_regular_file_to_string(path).map(Some)
}

pub(crate) fn read_regular_file_to_string_with_limit(
    path: &Path,
    max_bytes: u64,
) -> Result<String, SnapshotError> {
    let file = open_regular_file(path)?;
    let metadata = file.metadata().map_err(SnapshotError::Io)?;
    if metadata.len() > max_bytes {
        return Err(SnapshotError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "snapshot file {} exceeds {} bytes",
                path.display(),
                max_bytes
            ),
        )));
    }

    let mut contents = String::new();
    let mut limited = file.take(max_bytes.saturating_add(1));
    limited
        .read_to_string(&mut contents)
        .map_err(SnapshotError::Io)?;
    if contents.len() as u64 > max_bytes {
        return Err(SnapshotError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "snapshot file {} changed while reading and exceeded {} bytes",
                path.display(),
                max_bytes
            ),
        )));
    }
    Ok(contents)
}

pub(crate) fn optional_symlink_metadata(
    path: &Path,
) -> Result<Option<fs::Metadata>, SnapshotError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(SnapshotError::Io(error)),
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

pub(crate) fn ensure_real_directory(path: &Path) -> Result<(), SnapshotError> {
    match optional_symlink_metadata(path)? {
        Some(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(SnapshotError::UnsafeSnapshotPath {
                path: path.to_path_buf(),
            });
        }
        Some(_) => {
            set_private_directory_mode(path)?;
            return Ok(());
        }
        None => {}
    }

    fs::create_dir_all(path).map_err(SnapshotError::Io)?;
    set_private_directory_mode(path)?;
    let metadata = fs::symlink_metadata(path).map_err(SnapshotError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        });
    }

    Ok(())
}

pub(crate) fn canonical_directory(path: &Path) -> Result<PathBuf, SnapshotError> {
    let metadata = fs::symlink_metadata(path).map_err(SnapshotError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        });
    }
    fs::canonicalize(path).map_err(SnapshotError::Io)
}

pub(crate) fn snapshot_parent_path_contains_symlink(path: &Path) -> io::Result<bool> {
    let Some(parent) = path.parent() else {
        return Ok(false);
    };
    if parent.as_os_str().is_empty() {
        return Ok(false);
    }

    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }

    Ok(false)
}

fn read_regular_file_to_string(path: &Path) -> Result<String, SnapshotError> {
    read_regular_file_to_string_with_limit(path, MAX_SNAPSHOT_FILE_BYTES)
}

fn open_regular_file(path: &Path) -> Result<File, SnapshotError> {
    let metadata = fs::symlink_metadata(path).map_err(SnapshotError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        });
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(O_NOFOLLOW);

    let file = options.open(path).map_err(SnapshotError::Io)?;
    let metadata = file.metadata().map_err(SnapshotError::Io)?;
    if !metadata.is_file() {
        return Err(SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        });
    }
    Ok(file)
}

fn require_plain_write_destination(path: &Path) -> Result<(), SnapshotError> {
    let Some(metadata) = optional_symlink_metadata(path)? else {
        return Ok(());
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn set_private_directory_mode(path: &Path) -> Result<(), SnapshotError> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(SNAPSHOT_DIR_MODE))
        .map_err(SnapshotError::Io)?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), SnapshotError> {
    let directory = File::open(path).map_err(SnapshotError::Io)?;
    directory.sync_all().map_err(SnapshotError::Io)
}
