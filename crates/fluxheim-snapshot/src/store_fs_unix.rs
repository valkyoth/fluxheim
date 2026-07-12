use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path};

use crate::store::SnapshotError;
use crate::store_fs::{SNAPSHOT_FILE_MODE, unique_sequence};
use crate::store_fs_metadata::SnapshotPathMetadata;

pub(crate) fn write_atomically_in_directory(
    parent: &Path,
    path: &Path,
    contents: &[u8],
    create_new: bool,
) -> Result<(), SnapshotError> {
    let destination_name = snapshot_file_name_in_directory(parent, path)?;
    let directory = open_snapshot_directory(parent)?;
    if create_new && directory_entry_exists(&directory, destination_name)? {
        return Err(SnapshotError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "snapshot destination already exists",
        )));
    }
    require_plain_write_directory_entry(&directory, destination_name, path)?;

    let temp_name = OsString::from(format!(
        ".{}.tmp-{}-{}",
        destination_name.to_string_lossy(),
        std::process::id(),
        unique_sequence()
    ));
    let mut cleanup = TempDirectoryEntryGuard::new(directory, temp_name);
    let fd = rustix::fs::openat(
        cleanup.directory(),
        cleanup.name(),
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(rustix_snapshot_error)?;
    let mut file = File::from(fd);
    file.set_permissions(fs::Permissions::from_mode(SNAPSHOT_FILE_MODE))
        .map_err(SnapshotError::Io)?;
    file.write_all(contents).map_err(SnapshotError::Io)?;
    file.sync_all().map_err(SnapshotError::Io)?;
    drop(file);

    if create_new {
        rustix::fs::linkat(
            cleanup.directory(),
            cleanup.name(),
            cleanup.directory(),
            destination_name,
            rustix::fs::AtFlags::empty(),
        )
        .map_err(rustix_snapshot_error)?;
        rustix::fs::unlinkat(
            cleanup.directory(),
            cleanup.name(),
            rustix::fs::AtFlags::empty(),
        )
        .map_err(|_| SnapshotError::PublishedButNotDurable {
            path: path.to_path_buf(),
        })?;
    } else {
        rustix::fs::renameat(
            cleanup.directory(),
            cleanup.name(),
            cleanup.directory(),
            destination_name,
        )
        .map_err(rustix_snapshot_error)?;
    }
    cleanup.disarm();
    rustix::fs::fsync(cleanup.directory()).map_err(|error| {
        if create_new {
            SnapshotError::PublishedButNotDurable {
                path: path.to_path_buf(),
            }
        } else {
            rustix_snapshot_error(error)
        }
    })
}

pub(crate) fn open_private_lock_file_in_directory(
    parent: &Path,
    path: &Path,
) -> Result<File, SnapshotError> {
    let name = snapshot_file_name_in_directory(parent, path)?;
    let directory = open_snapshot_directory(parent)?;
    require_plain_write_directory_entry(&directory, name, path)?;
    let fd = rustix::fs::openat(
        &directory,
        name,
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(rustix_snapshot_error)?;
    Ok(File::from(fd))
}

pub(crate) fn optional_symlink_metadata(
    path: &Path,
) -> Result<Option<SnapshotPathMetadata>, SnapshotError> {
    match rustix::fs::statat(rustix::fs::CWD, path, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(SnapshotPathMetadata::from_unix_stat(&stat))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(rustix_snapshot_error(error)),
    }
}

pub(crate) fn sync_directory(path: &Path) -> Result<(), SnapshotError> {
    let directory = open_snapshot_directory(path)?;
    rustix::fs::fsync(directory).map_err(rustix_snapshot_error)
}

fn snapshot_file_name_in_directory<'a>(
    directory: &Path,
    path: &'a Path,
) -> Result<&'a OsStr, SnapshotError> {
    if path.parent() != Some(directory) {
        return Err(SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        });
    }
    path.file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        })
}

fn open_snapshot_directory(path: &Path) -> Result<File, SnapshotError> {
    #[cfg(target_os = "linux")]
    {
        match rustix::fs::openat2(
            rustix::fs::CWD,
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        ) {
            Ok(directory) => return Ok(directory.into()),
            Err(rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL) => {}
            Err(error) => return Err(rustix_snapshot_error(error)),
        }
    }

    open_snapshot_directory_componentwise(path)
}

fn open_snapshot_directory_componentwise(path: &Path) -> Result<File, SnapshotError> {
    let mut directory = rustix::fs::openat(
        rustix::fs::CWD,
        if path.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        },
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(rustix_snapshot_error)?;

    for component in path.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir | Component::Prefix(_) => {
                return Err(SnapshotError::UnsafeSnapshotPath {
                    path: path.to_path_buf(),
                });
            }
        };
        directory = rustix::fs::openat(
            &directory,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(rustix_snapshot_error)?;
    }
    Ok(directory)
}

fn directory_entry_exists(directory: &File, name: &OsStr) -> Result<bool, SnapshotError> {
    match rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(error) => Err(rustix_snapshot_error(error)),
    }
}

fn require_plain_write_directory_entry(
    directory: &File,
    name: &OsStr,
    path: &Path,
) -> Result<(), SnapshotError> {
    match rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file() => Ok(()),
        Ok(_) => Err(SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        }),
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => Err(rustix_snapshot_error(error)),
    }
}

fn rustix_snapshot_error(error: rustix::io::Errno) -> SnapshotError {
    SnapshotError::Io(io::Error::from_raw_os_error(error.raw_os_error()))
}

struct TempDirectoryEntryGuard {
    directory: File,
    name: OsString,
    armed: bool,
}

impl TempDirectoryEntryGuard {
    fn new(directory: File, name: OsString) -> Self {
        Self {
            directory,
            name,
            armed: true,
        }
    }

    fn directory(&self) -> &File {
        &self.directory
    }

    fn name(&self) -> &OsStr {
        &self.name
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempDirectoryEntryGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = rustix::fs::unlinkat(&self.directory, &self.name, rustix::fs::AtFlags::empty());
        }
    }
}
