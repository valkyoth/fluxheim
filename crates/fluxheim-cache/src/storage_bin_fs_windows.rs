use std::os::windows::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

#[derive(Clone, Copy)]
pub(crate) struct StorageBinFileType {
    directory: bool,
    reparse_point: bool,
}

impl StorageBinFileType {
    pub(crate) fn is_dir(self) -> bool {
        self.directory
    }

    pub(crate) fn is_symlink(self) -> bool {
        self.reparse_point
    }
}

pub(crate) fn prepare_storage_bin_data_dir(
    root: &Path,
    data_dir: &Path,
) -> std::io::Result<PathBuf> {
    if storage_bin_path_contains_symlink(root, data_dir)? {
        return Err(unsafe_path_error(format!(
            "storage-bin data directory contains a reparse point: {}",
            data_dir.display()
        )));
    }
    match storage_bin_path_file_type_no_follow(data_dir)? {
        Some(file_type) if file_type.is_symlink() || !file_type.is_dir() => {
            return Err(unsafe_path_error(format!(
                "storage-bin data directory is not a real directory: {}",
                data_dir.display()
            )));
        }
        Some(_) => {}
        None => create_storage_bin_dir_all(data_dir)?,
    }
    if storage_bin_path_contains_symlink(root, data_dir)? {
        return Err(unsafe_path_error(format!(
            "storage-bin data directory contains a reparse point: {}",
            data_dir.display()
        )));
    }
    let canonical_root = root.canonicalize()?;
    let canonical = data_dir.canonicalize()?;
    if !canonical.starts_with(&canonical_root) {
        return Err(unsafe_path_error(format!(
            "storage-bin data directory escaped root: {}",
            canonical.display()
        )));
    }
    for trusted_path in [&canonical_root, &canonical] {
        if fluxheim_config::fs_trust::existing_path_or_parent_has_insecure_write_permissions(
            trusted_path,
        )? {
            return Err(unsafe_path_error(format!(
                "storage-bin directory has an untrusted writable ACL: {}",
                trusted_path.display()
            )));
        }
    }
    Ok(canonical)
}

pub(crate) fn create_storage_bin_dir_all(path: &Path) -> std::io::Result<()> {
    fluxheim_config::fs_trust::create_private_directory_all(path)
}

pub(crate) fn storage_bin_path_file_type_no_follow(
    path: &Path,
) -> std::io::Result<Option<StorageBinFileType>> {
    let absolute = absolute_path(path)?;
    let inspected = match fluxheim_windows_security::inspect_absolute_path(&absolute) {
        Ok(inspected) => inspected,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return Ok(Some(StorageBinFileType {
                directory: false,
                reparse_point: true,
            }));
        }
        Err(error) => return Err(error),
    };
    if !inspected.target_exists() {
        return Ok(None);
    }
    let metadata = inspected.target()?.metadata()?;
    Ok(Some(StorageBinFileType {
        directory: metadata.is_dir(),
        reparse_point: metadata_is_reparse_point(&metadata),
    }))
}

pub(crate) fn storage_bin_configured_path_contains_symlink(path: &Path) -> std::io::Result<bool> {
    path_contains_reparse_point(path)
}

pub(crate) fn storage_bin_path_contains_symlink(root: &Path, path: &Path) -> std::io::Result<bool> {
    let Ok(relative) = path.strip_prefix(root) else {
        return Ok(true);
    };
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Ok(true);
        }
    }
    path_contains_reparse_point(path)
}

fn path_contains_reparse_point(path: &Path) -> std::io::Result<bool> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Ok(true);
    }
    let absolute = absolute_path(path)?;
    match fluxheim_windows_security::inspect_absolute_path(&absolute) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(true),
        Err(error) => Err(error),
    }
}

fn absolute_path(path: &Path) -> std::io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "storage-bin path must not contain parent traversal",
                ));
            }
        }
    }
    Ok(normalized)
}

fn metadata_is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
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
            unsafe_path_error(format!(
                "storage-bin path has no parent: {}",
                self.path.display()
            ))
        })?;
        let name = self.path.file_name().ok_or_else(|| {
            unsafe_path_error(format!(
                "storage-bin path has no file name: {}",
                self.path.display()
            ))
        })?;
        Ok((parent, name))
    }

    fn validate_parent(&self) -> std::io::Result<()> {
        let (parent, _) = self.parent_and_name()?;
        if fluxheim_config::fs_trust::existing_path_or_parent_has_insecure_write_permissions(
            parent,
        )? {
            return Err(unsafe_path_error(format!(
                "storage-bin parent has an untrusted writable ACL: {}",
                parent.display()
            )));
        }
        if path_contains_reparse_point(parent)? {
            return Err(unsafe_path_error(format!(
                "storage-bin parent contains a reparse point: {}",
                parent.display()
            )));
        }
        let inspected = fluxheim_windows_security::inspect_absolute_path(&absolute_path(parent)?)?;
        let metadata = inspected.target()?.metadata()?;
        if metadata_is_reparse_point(&metadata) || !metadata.is_dir() {
            return Err(unsafe_path_error(format!(
                "storage-bin parent is not a real directory: {}",
                parent.display()
            )));
        }
        Ok(())
    }

    fn open(&self, read: bool, write: bool, create_new: bool) -> std::io::Result<std::fs::File> {
        self.validate_parent()?;
        let file = match (read, write, create_new) {
            (false, true, true) => {
                fluxheim_config::fs_trust::create_regular_file(&self.path, false)?
            }
            (true, true, true) => fluxheim_config::fs_trust::create_regular_file(&self.path, true)?,
            (true, false, false) => fluxheim_config::fs_trust::open_regular_file(&self.path)?,
            (true, true, false) => {
                fluxheim_config::fs_trust::open_regular_file_for_update(&self.path)?
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "unsupported storage-bin file open mode",
                ));
            }
        };
        let metadata = file.metadata()?;
        if metadata_is_reparse_point(&metadata) || !metadata.is_file() {
            return Err(unsafe_path_error(format!(
                "storage-bin path is not a real file: {}",
                self.path.display()
            )));
        }
        Ok(file)
    }

    pub(crate) fn create_new_file(&self) -> std::io::Result<std::fs::File> {
        self.open(false, true, true)
    }

    pub(crate) fn create_new_read_write_file(&self) -> std::io::Result<std::fs::File> {
        self.open(true, true, true)
    }

    pub(crate) fn open_existing_file(&self) -> std::io::Result<std::fs::File> {
        self.open(true, false, false)
    }

    pub(crate) fn open_read_write_file(&self) -> std::io::Result<std::fs::File> {
        self.open(true, true, false)
    }

    pub(crate) fn rename_from(&self, source: &StorageBinSafePath) -> std::io::Result<()> {
        self.validate_parent()?;
        source.validate_parent()?;
        reject_existing_reparse_point_if_present(&self.path)?;
        fluxheim_windows_security::rename_regular_file(&source.path, &self.path)
    }

    pub(crate) fn remove_file(&self) -> std::io::Result<()> {
        self.validate_parent()?;
        fluxheim_windows_security::remove_regular_file(&self.path)
    }

    pub(crate) fn sync_parent_directory(&self) -> std::io::Result<()> {
        let (parent, _) = self.parent_and_name()?;
        self.validate_parent()?;
        fluxheim_config::fs_trust::sync_directory(parent)
    }
}

fn reject_existing_reparse_point(path: &Path) -> std::io::Result<()> {
    let inspected = fluxheim_windows_security::inspect_absolute_path(&absolute_path(path)?)?;
    if !inspected.target_exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "storage-bin path does not exist",
        ));
    }
    let metadata = inspected.target()?.metadata()?;
    if metadata_is_reparse_point(&metadata) || !metadata.is_file() {
        return Err(unsafe_path_error(format!(
            "storage-bin path is not a real file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn reject_existing_reparse_point_if_present(path: &Path) -> std::io::Result<()> {
    match reject_existing_reparse_point(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn unsafe_path_error(message: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::{
        path_contains_reparse_point, prepare_storage_bin_data_dir,
        storage_bin_path_contains_symlink,
    };

    #[test]
    fn absolute_storage_bin_root_skips_bare_windows_prefix() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("cache");
        let data = root.join("bins");
        std::fs::create_dir(&root).unwrap();

        let prepared = prepare_storage_bin_data_dir(&root, &data).unwrap();

        assert_eq!(prepared, data.canonicalize().unwrap());
        assert!(!path_contains_reparse_point(&prepared).unwrap());
    }

    #[test]
    fn storage_bin_data_directory_must_remain_below_root() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("cache");
        let outside = temporary.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();

        let error = prepare_storage_bin_data_dir(&root, &outside).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn parent_traversal_is_treated_as_unsafe() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("cache/../outside");

        assert!(path_contains_reparse_point(&path).unwrap());
    }

    #[test]
    fn storage_bin_path_rejects_directory_junction_components() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let junction = root.path().join("junction");
        let status = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(dunce::simplified(&junction))
            .arg(dunce::simplified(outside.path()))
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "failed to create test directory junction");

        let rejected = storage_bin_path_contains_symlink(root.path(), &junction).unwrap();
        std::fs::remove_dir(&junction).unwrap();

        assert!(rejected);
    }
}
