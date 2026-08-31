#[cfg(not(unix))]
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::fs::{self, File};
#[cfg(not(unix))]
use std::io::Write as _;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::store::SnapshotError;
use crate::store_fs_metadata::require_private_path_metadata;
pub(crate) use crate::store_fs_metadata::{
    is_symlink, optional_symlink_metadata, path_exists_without_following_symlinks,
    require_real_directory,
};
#[cfg(unix)]
use crate::store_fs_unix::{
    create_private_directory_in_parent, open_private_lock_file_in_directory,
    sync_directory as sync_directory_unix, write_atomically_in_directory,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub(crate) const MAX_CURRENT_SNAPSHOT_POINTER_BYTES: u64 = 4096;
pub(crate) const MAX_SNAPSHOT_FILE_BYTES: u64 = 16 * 1024 * 1024;
#[cfg(unix)]
pub(crate) const SNAPSHOT_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
pub(crate) const SNAPSHOT_FILE_MODE: u32 = 0o600;

pub(crate) fn write_atomically(path: &Path, contents: &[u8]) -> Result<(), SnapshotError> {
    write_atomically_with_mode(path, contents, false)
}

pub(crate) fn write_atomically_new(path: &Path, contents: &[u8]) -> Result<(), SnapshotError> {
    write_atomically_with_mode(path, contents, true)
}

fn write_atomically_with_mode(
    path: &Path,
    contents: &[u8],
    create_new: bool,
) -> Result<(), SnapshotError> {
    let parent = path.parent().ok_or_else(|| {
        SnapshotError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "snapshot path has no parent",
        ))
    })?;
    require_real_directory(parent)?;

    #[cfg(unix)]
    {
        write_atomically_in_directory(parent, path, contents, create_new)
    }

    #[cfg(not(unix))]
    {
        if create_new && path_exists_without_following_symlinks(path)? {
            return Err(SnapshotError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "snapshot destination already exists",
            )));
        }
        require_plain_write_destination(path)?;

        let temp_path = parent.join(format!(
            ".{}.tmp-{}-{}",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("snapshot"),
            std::process::id(),
            unique_sequence()
        ));

        let mut cleanup = TempPathGuard::new(temp_path.clone());
        {
            #[cfg(windows)]
            let mut file = fluxheim_config::fs_trust::create_confidential_file(&temp_path)
                .map_err(SnapshotError::Io)?;
            #[cfg(not(windows))]
            let mut file = {
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                options.open(&temp_path).map_err(SnapshotError::Io)?
            };
            #[cfg(unix)]
            fs::set_permissions(&temp_path, fs::Permissions::from_mode(SNAPSHOT_FILE_MODE))
                .map_err(SnapshotError::Io)?;
            file.write_all(contents).map_err(SnapshotError::Io)?;
            file.sync_all().map_err(SnapshotError::Io)?;
        }

        if create_new {
            fs::hard_link(&temp_path, path).map_err(SnapshotError::Io)?;
            fs::remove_file(&temp_path).map_err(|_| SnapshotError::PublishedButNotDurable {
                path: path.to_path_buf(),
            })?;
            cleanup.disarm();
        } else {
            fs::rename(&temp_path, path).map_err(SnapshotError::Io)?;
            cleanup.disarm();
        }
        sync_directory(parent).map_err(|error| {
            if create_new {
                SnapshotError::PublishedButNotDurable {
                    path: path.to_path_buf(),
                }
            } else {
                error
            }
        })?;
        Ok(())
    }
}

pub(crate) fn open_private_lock_file(path: &Path) -> Result<File, SnapshotError> {
    let parent = path.parent().ok_or_else(|| {
        SnapshotError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "snapshot lock path has no parent",
        ))
    })?;
    require_real_directory(parent)?;

    #[cfg(unix)]
    let file = open_private_lock_file_in_directory(parent, path)?;

    #[cfg(windows)]
    let file = fluxheim_config::fs_trust::open_or_create_confidential_file(path)
        .map_err(SnapshotError::Io)?;

    #[cfg(all(not(unix), not(windows)))]
    let file = {
        require_plain_write_destination(path)?;
        if path_exists_without_following_symlinks(path)? {
            require_private_regular_file(path)?;
        }

        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        options.open(path).map_err(SnapshotError::Io)?
    };
    let metadata = file.metadata().map_err(SnapshotError::Io)?;
    if !metadata.is_file() {
        return Err(SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        });
    }
    require_private_metadata(path, &metadata)?;
    Ok(file)
}

#[cfg(not(unix))]
struct TempPathGuard {
    path: Option<PathBuf>,
}

#[cfg(not(unix))]
impl TempPathGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

#[cfg(not(unix))]
impl Drop for TempPathGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
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
    require_private_path_metadata(path, &metadata)?;
    #[cfg(windows)]
    require_private_regular_file(path)?;
    Ok(true)
}

pub(crate) fn require_private_regular_file(path: &Path) -> Result<(), SnapshotError> {
    open_regular_file(path).map(drop)
}

pub(crate) fn read_optional_regular_file_to_string_with_limit(
    path: &Path,
    max_bytes: u64,
) -> Result<Option<String>, SnapshotError> {
    if !path_exists_without_following_symlinks(path)? {
        return Ok(None);
    }
    read_regular_file_to_string_with_limit(path, max_bytes).map(Some)
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

pub(crate) fn ensure_real_directory(path: &Path) -> Result<(), SnapshotError> {
    match optional_symlink_metadata(path)? {
        Some(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(SnapshotError::UnsafeSnapshotPath {
                path: path.to_path_buf(),
            });
        }
        Some(metadata) => {
            require_private_path_metadata(path, &metadata)?;
            #[cfg(windows)]
            if fluxheim_config::fs_trust::existing_path_or_parent_has_insecure_write_permissions(
                path,
            )
            .map_err(SnapshotError::Io)?
            {
                return Err(SnapshotError::UnsafeSnapshotPath {
                    path: path.to_path_buf(),
                });
            }
            #[cfg(windows)]
            set_private_directory_mode(path)?;
            return Ok(());
        }
        None => {}
    }

    #[cfg(windows)]
    let created = match fluxheim_config::fs_trust::create_private_directory_all(path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(SnapshotError::Io(error)),
    };
    #[cfg(not(windows))]
    let created = match create_private_directory(path) {
        Ok(()) => true,
        Err(SnapshotError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error),
    };
    if created {
        set_private_directory_mode(path)?;
    }
    let metadata =
        optional_symlink_metadata(path)?.ok_or_else(|| SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        });
    }
    require_private_path_metadata(path, &metadata)
}

#[cfg(unix)]
pub(crate) fn create_private_directory(path: &Path) -> Result<(), SnapshotError> {
    create_private_directory_in_parent(path)
}

#[cfg(all(not(unix), not(windows)))]
pub(crate) fn create_private_directory(path: &Path) -> Result<(), SnapshotError> {
    fs::create_dir(path).map_err(SnapshotError::Io)
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

    fluxheim_config::config_path::path_existing_prefix_contains_symlink(parent)
}

fn open_regular_file(path: &Path) -> Result<File, SnapshotError> {
    #[cfg(not(unix))]
    {
        let metadata = path.symlink_metadata().map_err(SnapshotError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(SnapshotError::UnsafeSnapshotPath {
                path: path.to_path_buf(),
            });
        }
        require_private_metadata(path, &metadata)?;
    }

    #[cfg(unix)]
    let file: File = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            return SnapshotError::UnsafeSnapshotPath {
                path: path.to_path_buf(),
            };
        }
        SnapshotError::Io(io::Error::from_raw_os_error(error.raw_os_error()))
    })?
    .into();
    #[cfg(not(unix))]
    let file = {
        #[cfg(windows)]
        {
            fluxheim_config::fs_trust::open_confidential_file(path).map_err(|_| {
                SnapshotError::UnsafeSnapshotPath {
                    path: path.to_path_buf(),
                }
            })?
        }
        #[cfg(not(windows))]
        {
            OpenOptions::new()
                .read(true)
                .open(path)
                .map_err(SnapshotError::Io)?
        }
    };
    let metadata = file.metadata().map_err(SnapshotError::Io)?;
    if !metadata.is_file() {
        return Err(SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        });
    }
    require_private_metadata(path, &metadata)?;
    Ok(file)
}

#[cfg(all(test, unix))]
pub(crate) fn set_open_private_file_mode_for_test(
    path: &Path,
    mode: u32,
) -> Result<(), SnapshotError> {
    let file = open_regular_file(path)?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(SnapshotError::Io)
}

fn require_private_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), SnapshotError> {
    #[cfg(unix)]
    {
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(SnapshotError::UnsafeSnapshotPath {
                path: path.to_path_buf(),
            });
        }
    }
    #[cfg(not(unix))]
    let _ = (path, metadata);
    Ok(())
}

#[cfg(not(unix))]
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
    #[cfg(windows)]
    fluxheim_config::fs_trust::harden_private_directory(path).map_err(SnapshotError::Io)?;
    #[cfg(not(any(unix, windows)))]
    let _ = path;
    Ok(())
}

pub(crate) fn sync_directory(path: &Path) -> Result<(), SnapshotError> {
    #[cfg(unix)]
    {
        sync_directory_unix(path)
    }

    #[cfg(windows)]
    {
        fluxheim_config::fs_trust::sync_directory(path).map_err(SnapshotError::Io)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let directory = File::open(path).map_err(SnapshotError::Io)?;
        directory.sync_all().map_err(SnapshotError::Io)
    }
}
