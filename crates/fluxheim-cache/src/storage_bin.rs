use std::io::{Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub use crate::storage_bin_alloc::{StorageBinFreeMap, StorageBinFreeRange};
use crate::storage_bin_fs::{
    StorageBinSafePath, create_storage_bin_dir_all, prepare_storage_bin_data_dir,
    storage_bin_configured_path_contains_symlink, storage_bin_path_contains_symlink,
    storage_bin_path_file_type_no_follow, storage_bin_temp_path,
};
pub use crate::storage_bin_manifest::{
    STORAGE_BIN_DATA_DIR, STORAGE_BIN_MANIFEST_FILENAME, StorageBinLayoutPlan, StorageBinManifest,
    StorageBinObjectLocation,
};

pub const STORAGE_BIN_INDEX_FILENAME: &str = ".fluxheim-storage-bin-index-v1";

const STORAGE_BIN_INDEX_MAGIC_V1: &str = "FLUXHEIM-STORAGE-BIN-INDEX-v1";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StorageBinIndexEntry {
    pub combined_key: String,
    pub location: StorageBinObjectLocation,
    pub accessed: SystemTime,
}

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

pub fn storage_bin_index_path(root: &Path) -> PathBuf {
    root.join(STORAGE_BIN_INDEX_FILENAME)
}

pub fn read_storage_bin_index(
    layout: &StorageBinLayoutPlan,
) -> std::io::Result<Vec<StorageBinIndexEntry>> {
    let path = storage_bin_index_path(&layout.root);
    if storage_bin_path_contains_symlink(&layout.root, &path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin index path contains symlink: {}",
                path.display()
            ),
        ));
    }
    let canonical = match path.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if !canonical.starts_with(&layout.root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin index escaped root: {}", canonical.display()),
        ));
    }

    let mut file = StorageBinSafePath::from_path(canonical).open_existing_file()?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    parse_storage_bin_index(layout, &contents)
}

pub fn write_storage_bin_index(
    layout: &StorageBinLayoutPlan,
    entries: &[StorageBinIndexEntry],
) -> std::io::Result<()> {
    let path = storage_bin_index_path(&layout.root);
    if !path.starts_with(&layout.root) || storage_bin_path_contains_symlink(&layout.root, &path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin index path is unsafe: {}", path.display()),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin index path has no parent: {}", path.display()),
        )
    })?;
    let temp_path = storage_bin_temp_path(parent, "index")?;
    let path = StorageBinSafePath::from_path(path);
    let temp_path = StorageBinSafePath::from_path(temp_path);
    let write_result = (|| {
        let mut file = temp_path.create_new_file()?;
        writeln!(file, "{STORAGE_BIN_INDEX_MAGIC_V1}")?;
        let mut entries = entries.to_vec();
        entries.sort_by(|left, right| left.combined_key.cmp(&right.combined_key));
        for entry in entries {
            entry.location.validate(layout.bin_size_bytes)?;
            writeln!(
                file,
                "{}\t{}\t{}\t{}\t{}",
                storage_bin_hex_encode(entry.combined_key.as_bytes()),
                entry.location.bin_id,
                entry.location.offset,
                entry.location.len,
                storage_bin_system_time_unix_secs(entry.accessed).unwrap_or(0)
            )?;
        }
        file.sync_all()?;
        path.rename_from(&temp_path)
    })();
    if write_result.is_err() {
        let _ = temp_path.remove_file();
    }
    write_result
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

    let mut file = StorageBinSafePath::from_path(canonical).open_existing_file()?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
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

fn parse_storage_bin_index(
    layout: &StorageBinLayoutPlan,
    contents: &str,
) -> std::io::Result<Vec<StorageBinIndexEntry>> {
    let mut lines = contents.lines();
    match lines.next() {
        Some(STORAGE_BIN_INDEX_MAGIC_V1) => {}
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid storage-bin index magic",
            ));
        }
    }
    let mut entries = Vec::new();
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 5 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid storage-bin index line",
            ));
        }
        let combined_key = storage_bin_hex_decode_string(fields[0])?;
        let location = StorageBinObjectLocation {
            bin_id: parse_storage_bin_index_u64(fields[1], "bin id")?,
            offset: parse_storage_bin_index_u64(fields[2], "offset")?,
            len: parse_storage_bin_index_u64(fields[3], "length")?,
        }
        .validate(layout.bin_size_bytes)?;
        entries.push(StorageBinIndexEntry {
            combined_key,
            location,
            accessed: storage_bin_unix_secs_system_time(parse_storage_bin_index_u64(
                fields[4], "accessed",
            )?),
        });
    }
    Ok(entries)
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

fn parse_storage_bin_index_u64(value: &str, field: &str) -> std::io::Result<u64> {
    value.parse::<u64>().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid storage-bin index {field}: {error}"),
        )
    })
}

fn storage_bin_hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn storage_bin_hex_decode_string(value: &str) -> std::io::Result<String> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid storage-bin index hex key",
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = storage_bin_hex_nibble(chunk[0]).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid storage-bin index hex key",
            )
        })?;
        let low = storage_bin_hex_nibble(chunk[1]).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid storage-bin index hex key",
            )
        })?;
        bytes.push((high << 4) | low);
    }
    String::from_utf8(bytes).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("storage-bin index key is not utf-8: {error}"),
        )
    })
}

fn storage_bin_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn storage_bin_system_time_unix_secs(time: SystemTime) -> Option<u64> {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn storage_bin_unix_secs_system_time(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(secs))
        .unwrap_or(SystemTime::UNIX_EPOCH)
}
