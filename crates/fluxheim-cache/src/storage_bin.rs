use std::io::{Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};

pub use crate::storage_bin_alloc::{StorageBinFreeMap, StorageBinFreeRange};
use crate::storage_bin_fs::{
    StorageBinSafePath, create_storage_bin_dir_all, prepare_storage_bin_data_dir,
    storage_bin_configured_path_contains_symlink, storage_bin_path_contains_symlink,
    storage_bin_path_file_type_no_follow, storage_bin_temp_path,
};
pub use crate::storage_bin_index::{
    STORAGE_BIN_INDEX_FILENAME, StorageBinIndexEntry, read_storage_bin_index,
    storage_bin_index_path, write_storage_bin_index,
};
pub use crate::storage_bin_manifest::{
    STORAGE_BIN_DATA_DIR, STORAGE_BIN_MANIFEST_FILENAME, StorageBinLayoutPlan, StorageBinManifest,
    StorageBinObjectLocation,
};

const MAX_STORAGE_BIN_MANIFEST_BYTES: u64 = 4096;

#[derive(Debug, Clone)]
pub struct StorageBinFileSet {
    layout: StorageBinLayoutPlan,
}

impl StorageBinFileSet {
    pub fn new(layout: StorageBinLayoutPlan) -> Self {
        Self { layout }
    }

    pub fn write_object(
        &self,
        location: StorageBinObjectLocation,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        if bytes.len() as u64 != location.len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin write length does not match object location",
            ));
        }
        let location = location.validate(self.layout.bin_size_bytes)?;
        let mut file = self.open_bin_for_write(location.bin_id)?;
        write_storage_bin_range(&mut file, location.offset, bytes)
    }

    pub fn read_object(&self, location: StorageBinObjectLocation) -> std::io::Result<Vec<u8>> {
        let location = location.validate(self.layout.bin_size_bytes)?;
        let mut file = self.open_bin_for_read(location.bin_id)?;
        read_storage_bin_range(&mut file, location.offset, location.len)
    }

    pub fn remove_bin(&self, bin_id: u64) -> std::io::Result<()> {
        let path = self.safe_bin_path(bin_id)?;
        let safe_path = StorageBinSafePath::from_path(path);
        match safe_path.remove_file() {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn open_bin_for_write(&self, bin_id: u64) -> std::io::Result<std::fs::File> {
        let path = self.safe_bin_path(bin_id)?;
        if let Some(parent) = path.parent() {
            prepare_storage_bin_data_dir(&self.layout.root, parent)?;
        }
        let safe_path = StorageBinSafePath::from_path(path);
        match safe_path.open_read_write_file() {
            Ok(file) => Ok(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let file = safe_path.create_new_read_write_file()?;
                if self.layout.preallocate {
                    file.set_len(self.layout.bin_size_bytes.as_u64())?;
                    file.sync_all()?;
                }
                Ok(file)
            }
            Err(error) => Err(error),
        }
    }

    fn open_bin_for_read(&self, bin_id: u64) -> std::io::Result<std::fs::File> {
        let path = self.safe_bin_path(bin_id)?;
        StorageBinSafePath::from_path(path).open_existing_file()
    }

    fn safe_bin_path(&self, bin_id: u64) -> std::io::Result<PathBuf> {
        if bin_id >= self.layout.max_bins() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin id exceeds configured cache budget",
            ));
        }
        let path = self.layout.bin_path(bin_id);
        if !path.starts_with(&self.layout.root)
            || storage_bin_path_contains_symlink(&self.layout.root, &path)?
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("storage-bin path is unsafe: {}", path.display()),
            ));
        }
        Ok(path)
    }
}

pub fn prepare_storage_bin_layout(
    layout: &StorageBinLayoutPlan,
) -> std::io::Result<StorageBinManifest> {
    let root = prepare_storage_bin_root(&layout.root)?;
    let canonical_layout = StorageBinLayoutPlan {
        root: root.clone(),
        manifest_path: root.join(STORAGE_BIN_MANIFEST_FILENAME),
        data_dir: root.join(STORAGE_BIN_DATA_DIR),
        bin_size_bytes: layout.bin_size_bytes,
        max_size_bytes: layout.max_size_bytes,
        preallocate: layout.preallocate,
        max_open_bins: layout.max_open_bins,
    };

    prepare_storage_bin_data_dir(&root, &canonical_layout.data_dir)?;
    match read_storage_bin_manifest(&root, &canonical_layout.manifest_path)? {
        Some(manifest) => {
            manifest.ensure_matches_layout(&canonical_layout)?;
            Ok(manifest)
        }
        None => {
            let manifest = StorageBinManifest::from_layout(&canonical_layout);
            write_storage_bin_manifest(&root, &canonical_layout.manifest_path, &manifest)?;
            Ok(manifest)
        }
    }
}

fn prepare_storage_bin_root(root: &Path) -> std::io::Result<PathBuf> {
    if storage_bin_configured_path_contains_symlink(root)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin root contains symlink: {}", root.display()),
        ));
    }
    match storage_bin_path_file_type_no_follow(root)? {
        Some(file_type) if file_type.is_symlink() || !file_type.is_dir() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "storage-bin root is not a real directory: {}",
                    root.display()
                ),
            ));
        }
        Some(_) => {}
        None => {
            create_storage_bin_dir_all(root)?;
        }
    }
    if storage_bin_configured_path_contains_symlink(root)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin root contains symlink: {}", root.display()),
        ));
    }
    root.canonicalize()
}

fn read_storage_bin_manifest(
    root: &Path,
    path: &Path,
) -> std::io::Result<Option<StorageBinManifest>> {
    if storage_bin_path_contains_symlink(root, path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin manifest path contains symlink: {}",
                path.display()
            ),
        ));
    }
    let canonical = match path.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !canonical.starts_with(root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin manifest escaped root: {}", canonical.display()),
        ));
    }

    let file = StorageBinSafePath::from_path(canonical).open_existing_file()?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_STORAGE_BIN_MANIFEST_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "storage-bin manifest must be a bounded regular file",
        ));
    }
    let mut contents = String::new();
    file.take(MAX_STORAGE_BIN_MANIFEST_BYTES.saturating_add(1))
        .read_to_string(&mut contents)?;
    if contents.len() as u64 > MAX_STORAGE_BIN_MANIFEST_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "storage-bin manifest exceeds the supported file-size limit",
        ));
    }
    StorageBinManifest::decode(&contents).map(Some)
}

fn write_storage_bin_manifest(
    root: &Path,
    path: &Path,
    manifest: &StorageBinManifest,
) -> std::io::Result<()> {
    if !path.starts_with(root) || storage_bin_path_contains_symlink(root, path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin manifest path is unsafe: {}", path.display()),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin manifest path has no parent: {}",
                path.display()
            ),
        )
    })?;
    let temp_path = storage_bin_temp_path(parent, "manifest")?;
    let path = StorageBinSafePath::from_path(path.to_path_buf());
    let temp_path = StorageBinSafePath::from_path(temp_path);
    let write_result = (|| {
        let mut file = temp_path.create_new_file()?;
        file.write_all(manifest.encode().as_bytes())?;
        file.sync_all()?;
        path.rename_from(&temp_path)
    })();
    if write_result.is_err() {
        let _ = temp_path.remove_file();
    }
    write_result
}

fn write_storage_bin_range(
    file: &mut std::fs::File,
    offset: u64,
    bytes: &[u8],
) -> std::io::Result<()> {
    file.seek(std::io::SeekFrom::Start(offset))?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn read_storage_bin_range(
    file: &mut std::fs::File,
    offset: u64,
    len: u64,
) -> std::io::Result<Vec<u8>> {
    let capacity = usize::try_from(len).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "storage-bin object is too large for this platform",
        )
    })?;
    file.seek(std::io::SeekFrom::Start(offset))?;
    let mut bytes = vec![0; capacity];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}
