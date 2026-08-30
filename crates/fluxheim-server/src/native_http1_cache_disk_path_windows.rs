use std::io::Read as _;
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};

use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};

const NATIVE_DISK_CACHE_READ_OVERHEAD_BYTES: u64 = 1024 * 1024;

pub(super) fn prepare_native_disk_cache_root(root: &Path) -> std::io::Result<PathBuf> {
    if native_configured_cache_path_contains_symlink(root)? {
        return Err(unsafe_path_error(
            "native disk cache root must not cross reparse points",
        ));
    }
    create_native_cache_dir_all(root)?;
    if native_configured_cache_path_contains_symlink(root)? {
        return Err(unsafe_path_error(
            "native disk cache root must not cross reparse points",
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
            Component::Prefix(_) | Component::RootDir | Component::CurDir
        ) {
            continue;
        }
        if matches!(component, Component::ParentDir) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "native disk cache directory must not contain parent traversal",
            ));
        }
        match path_metadata_no_follow(&current)? {
            Some(metadata) if metadata_is_reparse_point(&metadata) || !metadata.is_dir() => {
                return Err(unsafe_path_error(
                    "native disk cache path component is not a real directory",
                ));
            }
            Some(_) => {}
            None => match std::fs::create_dir(&current) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let Some(metadata) = path_metadata_no_follow(&current)? else {
                        return Err(error);
                    };
                    if metadata_is_reparse_point(&metadata) || !metadata.is_dir() {
                        return Err(unsafe_path_error(
                            "native disk cache path component is not a real directory",
                        ));
                    }
                }
                Err(error) => return Err(error),
            },
        }
    }
    Ok(())
}

fn native_configured_cache_path_contains_symlink(path: &Path) -> std::io::Result<bool> {
    path_contains_reparse_point(path)
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
        let Component::Normal(name) = component else {
            return Ok(true);
        };
        current.push(name);
        match path_metadata_no_follow(&current)? {
            Some(metadata) if metadata_is_reparse_point(&metadata) => return Ok(true),
            Some(_) => {}
            None => return Ok(false),
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
    let file = NativeSafeDiskCachePath::from_path(path.to_path_buf()).open_existing_file()?;
    let len = file.metadata()?.len();
    if len > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native disk cache object exceeds read limit",
        ));
    }
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native disk cache object changed while reading and exceeds read limit",
        ));
    }
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

    fn parent(&self) -> std::io::Result<&Path> {
        self.path
            .parent()
            .ok_or_else(|| unsafe_path_error("native disk cache path has no parent"))
    }

    fn validate_parent(&self) -> std::io::Result<()> {
        let parent = self.parent()?;
        if fluxheim_config::fs_trust::existing_path_or_parent_has_insecure_write_permissions(
            parent,
        )? {
            return Err(unsafe_path_error(
                "native disk cache parent has an untrusted writable ACL",
            ));
        }
        if path_contains_reparse_point(parent)? {
            return Err(unsafe_path_error(
                "native disk cache parent contains a reparse point",
            ));
        }
        let metadata = std::fs::symlink_metadata(parent)?;
        if metadata_is_reparse_point(&metadata) || !metadata.is_dir() {
            return Err(unsafe_path_error(
                "native disk cache parent is not a real directory",
            ));
        }
        Ok(())
    }

    fn open(
        &self,
        read: bool,
        write: bool,
        create: bool,
        create_new: bool,
    ) -> std::io::Result<std::fs::File> {
        self.validate_parent()?;
        if !create_new {
            reject_existing_reparse_point_if_present(&self.path)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options
            .read(read)
            .write(write)
            .create(create)
            .create_new(create_new)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION);
        let file = options.open(&self.path)?;
        let metadata = file.metadata()?;
        if metadata_is_reparse_point(&metadata) || !metadata.is_file() {
            return Err(unsafe_path_error(
                "native disk cache path is not a real file",
            ));
        }
        ensure_opened_path_unchanged(&self.path, &file)?;
        Ok(file)
    }

    pub(super) fn open_existing_file(&self) -> std::io::Result<std::fs::File> {
        self.open(true, false, false, false)
    }

    pub(super) fn open_or_create_read_write_file(&self) -> std::io::Result<std::fs::File> {
        self.open(true, true, true, false)
    }

    pub(super) fn child_paths(&self) -> std::io::Result<Vec<PathBuf>> {
        if path_contains_reparse_point(&self.path)? {
            return Err(unsafe_path_error(
                "native disk cache directory contains a reparse point",
            ));
        }
        let canonical = self.path.canonicalize()?;
        if canonical != self.path {
            return Err(unsafe_path_error(
                "native disk cache directory path is not canonical",
            ));
        }
        std::fs::read_dir(&self.path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect()
    }

    pub(super) fn rename_from(&self, source: &Self) -> std::io::Result<()> {
        self.validate_parent()?;
        source.validate_parent()?;
        reject_existing_reparse_point(&source.path)?;
        reject_existing_reparse_point_if_present(&self.path)?;
        std::fs::rename(&source.path, &self.path)
    }

    pub(super) fn persist_tempfile(
        &self,
        temporary: tempfile::NamedTempFile,
    ) -> std::io::Result<()> {
        self.validate_parent()?;
        reject_existing_reparse_point_if_present(&self.path)?;
        let file = temporary.persist(&self.path).map_err(|error| error.error)?;
        file.sync_all()
    }

    pub(super) fn sync_parent_dir(&self) -> std::io::Result<()> {
        self.validate_parent()?;
        match self.open(true, true, false, false) {
            Ok(file) => file.sync_all(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(super) fn remove_file(&self) -> std::io::Result<()> {
        self.validate_parent()?;
        reject_existing_reparse_point(&self.path)?;
        std::fs::remove_file(&self.path)
    }
}

fn path_contains_reparse_point(path: &Path) -> std::io::Result<bool> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Ok(true);
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match component {
            Component::Prefix(_) | Component::CurDir => continue,
            Component::ParentDir => return Ok(true),
            Component::RootDir | Component::Normal(_) => {}
        }
        match path_metadata_no_follow(&current)? {
            Some(metadata) if metadata_is_reparse_point(&metadata) => return Ok(true),
            Some(_) => {}
            None => return Ok(false),
        }
    }
    Ok(false)
}

fn path_metadata_no_follow(path: &Path) -> std::io::Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn metadata_is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn reject_existing_reparse_point(path: &Path) -> std::io::Result<()> {
    match path_metadata_no_follow(path)? {
        Some(metadata) if metadata_is_reparse_point(&metadata) || !metadata.is_file() => Err(
            unsafe_path_error("native disk cache path is not a real file"),
        ),
        Some(_) => Ok(()),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "native disk cache path does not exist",
        )),
    }
}

fn reject_existing_reparse_point_if_present(path: &Path) -> std::io::Result<()> {
    match reject_existing_reparse_point(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn ensure_opened_path_unchanged(path: &Path, file: &std::fs::File) -> std::io::Result<()> {
    let path_handle = same_file::Handle::from_path(path)?;
    let opened_handle = same_file::Handle::from_file(file.try_clone()?)?;
    if path_handle == opened_handle {
        Ok(())
    } else {
        Err(unsafe_path_error(
            "native disk cache path changed during secure open",
        ))
    }
}

fn unsafe_path_error(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::{
        NativeSafeDiskCachePath, path_contains_reparse_point, prepare_native_disk_cache_root,
    };

    #[test]
    fn absolute_native_cache_root_skips_bare_windows_prefix() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("cache");

        let prepared = prepare_native_disk_cache_root(&root).unwrap();

        assert_eq!(prepared, root.canonicalize().unwrap());
        assert!(!path_contains_reparse_point(&prepared).unwrap());
    }

    #[test]
    fn parent_traversal_is_treated_as_unsafe() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("cache/../outside");

        assert!(path_contains_reparse_point(&path).unwrap());
    }

    #[test]
    fn persisted_tempfile_replaces_existing_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("state");
        std::fs::write(&destination, b"old").unwrap();
        let mut temporary = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        temporary.write_all(b"new").unwrap();
        temporary.as_file().sync_all().unwrap();

        NativeSafeDiskCachePath::from_path(destination.clone())
            .persist_tempfile(temporary)
            .unwrap();

        assert_eq!(std::fs::read(destination).unwrap(), b"new");
    }
}
