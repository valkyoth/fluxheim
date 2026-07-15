use std::ffi::OsStr;
use std::io::Read as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

const NATIVE_DISK_CACHE_READ_OVERHEAD_BYTES: u64 = 1024 * 1024;

pub(super) fn prepare_native_disk_cache_root(root: &Path) -> std::io::Result<PathBuf> {
    if native_configured_cache_path_contains_symlink(root)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "native disk cache root must not cross symlinks",
        ));
    }
    create_native_cache_dir_all(root)?;
    if native_configured_cache_path_contains_symlink(root)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "native disk cache root must not cross symlinks",
        ));
    }
    root.canonicalize()
}

pub(super) fn create_native_cache_dir_all(path: &Path) -> std::io::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(
            component,
            std::path::Component::Prefix(_)
                | std::path::Component::RootDir
                | std::path::Component::CurDir
        ) {
            continue;
        }
        if matches!(component, std::path::Component::ParentDir) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "native disk cache directory must not contain parent traversal",
            ));
        }
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "native disk cache path component is not a real directory",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                rustix::fs::mkdir(
                    &current,
                    rustix::fs::Mode::RWXU | rustix::fs::Mode::RGRP | rustix::fs::Mode::XGRP,
                )
                .or_else(|error| {
                    if error == rustix::io::Errno::EXIST {
                        Ok(())
                    } else {
                        Err(error)
                    }
                })
                .map_err(native_rustix_to_io_error)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn native_configured_cache_path_contains_symlink(path: &Path) -> std::io::Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

pub(super) fn native_cache_path_contains_symlink(
    root: &Path,
    path: &Path,
) -> std::io::Result<bool> {
    let Ok(relative) = path.strip_prefix(root) else {
        return Ok(true);
    };
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Ok(true);
        }
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

pub(super) fn native_disk_cache_read_limit(max_object_bytes: fluxheim_config::ByteSize) -> u64 {
    max_object_bytes
        .as_u64()
        .saturating_add(NATIVE_DISK_CACHE_READ_OVERHEAD_BYTES)
}

pub(super) fn read_native_disk_cache_file(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    let mut file = NativeSafeDiskCachePath::from_path(path.to_path_buf()).open_existing_file()?;
    let len = file.metadata()?.len();
    if len > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native disk cache object exceeds read limit",
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[derive(Debug, Clone)]
pub(super) struct NativeSafeDiskCachePath {
    path: PathBuf,
}

impl NativeSafeDiskCachePath {
    pub(super) fn from_path(path: PathBuf) -> Self {
        Self { path }
    }

    fn parent_and_name(&self) -> std::io::Result<(&Path, &std::ffi::OsStr)> {
        let parent = self.path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "native disk cache path has no parent",
            )
        })?;
        let name = self.path.file_name().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "native disk cache path has no file name",
            )
        })?;
        Ok((parent, name))
    }

    fn open_parent_dir(&self) -> std::io::Result<std::fs::File> {
        let (parent, _) = self.parent_and_name()?;
        let fd = rustix::fs::open(
            parent,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .map_err(native_rustix_to_io_error)?;
        Ok(fd.into())
    }

    pub(super) fn create_new_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(native_rustix_to_io_error)?;
        Ok(fd.into())
    }

    pub(super) fn open_existing_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(native_rustix_to_io_error)?;
        Ok(fd.into())
    }

    pub(super) fn open_or_create_read_write_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(native_rustix_to_io_error)?;
        Ok(fd.into())
    }

    fn open_existing_dir(&self) -> std::io::Result<std::fs::File> {
        let fd = rustix::fs::open(
            &self.path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(native_rustix_to_io_error)?;
        Ok(fd.into())
    }

    pub(super) fn child_paths(&self) -> std::io::Result<Vec<PathBuf>> {
        let canonical = self.path.canonicalize()?;
        if canonical != self.path {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "native disk cache directory path is not canonical",
            ));
        }
        let dir_file = self.open_existing_dir()?;
        let mut dir = rustix::fs::Dir::read_from(&dir_file).map_err(native_rustix_to_io_error)?;
        let mut paths = Vec::new();
        for entry in &mut dir {
            let entry = entry.map_err(native_rustix_to_io_error)?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            paths.push(self.path.join(OsStr::from_bytes(name)));
        }
        Ok(paths)
    }

    pub(super) fn rename_from(&self, source: &Self) -> std::io::Result<()> {
        let (_, source_name) = source.parent_and_name()?;
        let (_, destination_name) = self.parent_and_name()?;
        let source_parent = source.open_parent_dir()?;
        let destination_parent = self.open_parent_dir()?;
        rustix::fs::renameat(
            &source_parent,
            source_name,
            &destination_parent,
            destination_name,
        )
        .map_err(native_rustix_to_io_error)
    }

    pub(super) fn sync_parent_dir(&self) -> std::io::Result<()> {
        self.open_parent_dir()?.sync_all()
    }

    pub(super) fn remove_file(&self) -> std::io::Result<()> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        rustix::fs::unlinkat(&parent, name, rustix::fs::AtFlags::empty())
            .map_err(native_rustix_to_io_error)
    }
}

fn native_rustix_to_io_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}
