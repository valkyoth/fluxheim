use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::storage_bin::{StorageBinLayoutPlan, StorageBinObjectLocation};
use crate::storage_bin_fs::{
    StorageBinSafePath, storage_bin_path_contains_symlink, storage_bin_temp_path,
};

pub const STORAGE_BIN_INDEX_FILENAME: &str = ".fluxheim-storage-bin-index-v1";

const STORAGE_BIN_INDEX_MAGIC_V1: &str = "FLUXHEIM-STORAGE-BIN-INDEX-v1";
const MAX_STORAGE_BIN_INDEX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STORAGE_BIN_INDEX_ENTRIES: usize = 1_000_000;
const MAX_STORAGE_BIN_INDEX_KEY_HEX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StorageBinIndexEntry {
    pub combined_key: String,
    pub location: StorageBinObjectLocation,
    pub accessed: SystemTime,
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

    let file = StorageBinSafePath::from_path(canonical).open_existing_file()?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_STORAGE_BIN_INDEX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "storage-bin index exceeds the supported file-size limit",
        ));
    }
    let mut contents = String::new();
    file.take(MAX_STORAGE_BIN_INDEX_BYTES.saturating_add(1))
        .read_to_string(&mut contents)?;
    if contents.len() as u64 > MAX_STORAGE_BIN_INDEX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "storage-bin index exceeds the supported file-size limit",
        ));
    }
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

fn parse_storage_bin_index(
    layout: &StorageBinLayoutPlan,
    contents: &str,
) -> std::io::Result<Vec<StorageBinIndexEntry>> {
    let mut lines = contents.lines();
    if lines.next() != Some(STORAGE_BIN_INDEX_MAGIC_V1) {
        return Err(invalid_index("invalid storage-bin index magic"));
    }
    let mut entries = Vec::new();
    for line in lines {
        if entries.len() >= MAX_STORAGE_BIN_INDEX_ENTRIES {
            return Err(invalid_index(
                "storage-bin index exceeds the supported entry limit",
            ));
        }
        let mut fields = line.split('\t');
        let combined_key_hex = fields.next().unwrap_or_default();
        let bin_id = next_index_field(&mut fields)?;
        let offset = next_index_field(&mut fields)?;
        let len = next_index_field(&mut fields)?;
        let accessed = next_index_field(&mut fields)?;
        if fields.next().is_some() {
            return Err(invalid_index("invalid storage-bin index line"));
        }
        if combined_key_hex.len() > MAX_STORAGE_BIN_INDEX_KEY_HEX_BYTES {
            return Err(invalid_index(
                "storage-bin index key exceeds the supported length limit",
            ));
        }
        entries.try_reserve(1).map_err(|_| {
            invalid_index("storage-bin index allocation exceeds available capacity")
        })?;
        let combined_key = storage_bin_hex_decode_string(combined_key_hex)?;
        let location = StorageBinObjectLocation {
            bin_id: parse_storage_bin_index_u64(bin_id, "bin id")?,
            offset: parse_storage_bin_index_u64(offset, "offset")?,
            len: parse_storage_bin_index_u64(len, "length")?,
        }
        .validate(layout.bin_size_bytes)?;
        entries.push(StorageBinIndexEntry {
            combined_key,
            location,
            accessed: storage_bin_unix_secs_system_time(parse_storage_bin_index_u64(
                accessed, "accessed",
            )?),
        });
    }
    Ok(entries)
}

fn next_index_field<'a>(fields: &mut impl Iterator<Item = &'a str>) -> std::io::Result<&'a str> {
    fields
        .next()
        .ok_or_else(|| invalid_index("invalid storage-bin index line"))
}

fn parse_storage_bin_index_u64(value: &str, field: &str) -> std::io::Result<u64> {
    value
        .parse::<u64>()
        .map_err(|error| invalid_index(format!("invalid storage-bin index {field}: {error}")))
}

fn storage_bin_hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn storage_bin_hex_decode_string(value: &str) -> std::io::Result<String> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_index("invalid storage-bin index hex key"));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(value.len() / 2).map_err(|_| {
        invalid_index("storage-bin index key allocation exceeds available capacity")
    })?;
    for chunk in value.as_bytes().as_chunks::<2>().0 {
        let high = storage_bin_hex_nibble(chunk[0])
            .ok_or_else(|| invalid_index("invalid storage-bin index hex key"))?;
        let low = storage_bin_hex_nibble(chunk[1])
            .ok_or_else(|| invalid_index("invalid storage-bin index hex key"))?;
        bytes.push((high << 4) | low);
    }
    String::from_utf8(bytes)
        .map_err(|error| invalid_index(format!("storage-bin index key is not utf-8: {error}")))
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

fn invalid_index(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}
