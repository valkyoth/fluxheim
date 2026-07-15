use std::path::{Path, PathBuf};

pub(crate) fn prepare_storage_bin_data_dir(
    root: &Path,
    data_dir: &Path,
) -> std::io::Result<PathBuf> {
    if storage_bin_path_contains_symlink(root, data_dir)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin data directory contains symlink: {}",
                data_dir.display()
            ),
        ));
    }
    match storage_bin_path_file_type_no_follow(data_dir)? {
        Some(file_type) if file_type.is_symlink() || !file_type.is_dir() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "storage-bin data directory is not a real directory: {}",
                    data_dir.display()
                ),
            ));
        }
        Some(_) => {}
        None => {
            create_storage_bin_dir_all(data_dir)?;
        }
    }
    if storage_bin_path_contains_symlink(root, data_dir)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin data directory contains symlink: {}",
                data_dir.display()
            ),
        ));
    }
    let canonical = data_dir.canonicalize()?;
    if !canonical.starts_with(root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin data directory escaped root: {}",
                canonical.display()
            ),
        ));
    }
    Ok(canonical)
}

pub(crate) fn create_storage_bin_dir_all(path: &Path) -> std::io::Result<()> {
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
                format!(
                    "storage-bin directory path must not contain parent traversal: {}",
                    path.display()
                ),
            ));
        }

        match storage_bin_path_file_type_no_follow(&current)? {
            Some(file_type) if file_type.is_symlink() || !file_type.is_dir() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "storage-bin directory path is not a real directory: {}",
                        current.display()
                    ),
                ));
            }
            Some(_) => {}
            None => {
                let mode = rustix::fs::Mode::RWXU | rustix::fs::Mode::RGRP | rustix::fs::Mode::XGRP;
                match rustix::fs::mkdir(&current, mode) {
                    Ok(()) => {}
                    Err(error) if error == rustix::io::Errno::EXIST => {}
                    Err(error) => return Err(storage_bin_rustix_to_io_error(error)),
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn storage_bin_path_file_type_no_follow(
    path: &Path,
) -> std::io::Result<Option<rustix::fs::FileType>> {
    match rustix::fs::statat(rustix::fs::CWD, path, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(rustix::fs::FileType::from_raw_mode(stat.st_mode))),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(None),
        Err(error) => Err(storage_bin_rustix_to_io_error(error)),
    }
}

pub(crate) fn storage_bin_configured_path_contains_symlink(path: &Path) -> std::io::Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }

    Ok(false)
}

pub(crate) fn storage_bin_path_contains_symlink(root: &Path, path: &Path) -> std::io::Result<bool> {
    let Ok(relative) = path.strip_prefix(root) else {
        return Ok(true);
    };

    for component in relative.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Ok(true);
        }
    }

    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(std::io::Error::new(
                    error.kind(),
                    format!("inspect storage-bin path {}: {error}", current.display()),
                ));
            }
        }
    }

    Ok(false)
}

pub(crate) fn storage_bin_temp_path(parent: &Path, label: &str) -> std::io::Result<PathBuf> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|error| {
        std::io::Error::other(format!("generate storage-bin {label} temp nonce: {error}"))
    })?;
    let mut encoded = String::with_capacity(nonce.len() * 2);
    for byte in nonce {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    Ok(parent.join(format!(
        ".fluxheim-storage-bin-{label}.{}.{}.tmp",
        std::process::id(),
        encoded
    )))
}

#[derive(Debug, Clone)]
pub(crate) struct StorageBinSafePath {
    path: PathBuf,
}

impl StorageBinSafePath {
    pub(crate) fn from_path(path: PathBuf) -> Self {
        Self { path }
    }

    fn parent_and_name(&self) -> std::io::Result<(&Path, &std::ffi::OsStr)> {
        let parent = self.path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("storage-bin path has no parent: {}", self.path.display()),
            )
        })?;
        let name = self.path.file_name().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("storage-bin path has no file name: {}", self.path.display()),
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
        .map_err(storage_bin_rustix_to_io_error)?;
        Ok(fd.into())
    }

    pub(crate) fn create_new_file(&self) -> std::io::Result<std::fs::File> {
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
        .map_err(storage_bin_rustix_to_io_error)?;
        Ok(fd.into())
    }

    pub(crate) fn create_new_read_write_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(storage_bin_rustix_to_io_error)?;
        Ok(fd.into())
    }

    pub(crate) fn open_existing_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map_err(storage_bin_rustix_to_io_error)?;
        Ok(fd.into())
    }

    pub(crate) fn open_read_write_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(storage_bin_rustix_to_io_error)?;
        Ok(fd.into())
    }

    pub(crate) fn rename_from(&self, source: &StorageBinSafePath) -> std::io::Result<()> {
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
        .map_err(storage_bin_rustix_to_io_error)
    }

    pub(crate) fn remove_file(&self) -> std::io::Result<()> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        rustix::fs::unlinkat(&parent, name, rustix::fs::AtFlags::empty())
            .map_err(storage_bin_rustix_to_io_error)
    }
}

fn storage_bin_rustix_to_io_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}
