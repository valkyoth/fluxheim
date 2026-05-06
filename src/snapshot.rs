use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::Config;

#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400000;

const MAX_CURRENT_SNAPSHOT_POINTER_BYTES: u64 = 4096;
const MAX_SNAPSHOT_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SNAPSHOT_STORE_ENTRIES: usize = 1024;
const MAX_SNAPSHOT_ID_BYTES: usize = 128;
pub const MAX_SNAPSHOT_MESSAGE_BYTES: usize = 4096;

#[derive(Debug, Clone)]
pub struct SnapshotStore {
    root: PathBuf,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConfigSnapshot {
    pub id: String,
    pub config_path: PathBuf,
    pub metadata_path: PathBuf,
    pub metadata: SnapshotMetadata,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotMetadata {
    pub id: String,
    pub created_unix_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug)]
pub enum SnapshotError {
    Io(io::Error),
    Encode(toml::ser::Error),
    Decode(toml::de::Error),
    Config(crate::config::ConfigLoadError),
    EmptyStore,
    CurrentMissing,
    NoPreviousSnapshot { current: String },
    InvalidSnapshotId { id: String },
    SnapshotNotFound { id: String },
    InvalidSnapshotMessage { max_bytes: usize },
    UnsafeStoreRoot { path: PathBuf },
    UnsafeSnapshotPath { path: PathBuf },
}

impl SnapshotStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn snapshot_config(
        &self,
        config: &Config,
        message: Option<&str>,
    ) -> Result<ConfigSnapshot, SnapshotError> {
        self.validate_root()?;
        config.validate().map_err(|error| {
            SnapshotError::Config(crate::config::ConfigLoadError::Validate(error))
        })?;
        self.ensure_layout()?;

        let id = new_snapshot_id();
        let config_path = self.config_path(&id);
        let metadata_path = self.metadata_path(&id);
        let metadata = SnapshotMetadata {
            id: id.clone(),
            created_unix_secs: unix_secs(),
            message: snapshot_message(message)?,
        };

        let raw_config = toml::to_string_pretty(config).map_err(SnapshotError::Encode)?;
        write_atomically(&config_path, raw_config.as_bytes())?;

        let raw_metadata = toml::to_string_pretty(&metadata).map_err(SnapshotError::Encode)?;
        write_atomically(&metadata_path, raw_metadata.as_bytes())?;

        self.set_current(&id)?;

        Ok(ConfigSnapshot {
            id,
            config_path,
            metadata_path,
            metadata,
        })
    }

    pub fn list(&self) -> Result<Vec<ConfigSnapshot>, SnapshotError> {
        self.validate_root()?;
        if !self.safe_existing_root()? {
            return Ok(Vec::new());
        }
        let configs_dir = self.configs_dir();
        if !self.safe_existing_configs_dir()? {
            return Ok(Vec::new());
        }

        let mut snapshots = Vec::new();
        for entry in fs::read_dir(configs_dir).map_err(SnapshotError::Io)? {
            let entry = entry.map_err(SnapshotError::Io)?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            if stem.ends_with(".meta") {
                continue;
            }
            if snapshots.len() >= MAX_SNAPSHOT_STORE_ENTRIES {
                return Err(SnapshotError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "snapshot store {} contains more than {} snapshots",
                        self.root.display(),
                        MAX_SNAPSHOT_STORE_ENTRIES
                    ),
                )));
            }
            snapshots.push(self.load_snapshot(stem)?);
        }

        snapshots.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(snapshots)
    }

    pub fn current_id(&self) -> Result<Option<String>, SnapshotError> {
        self.validate_root()?;
        if !self.safe_existing_root()? {
            return Ok(None);
        }
        let path = self.current_path();
        if !path_exists_without_following_symlinks(&path)? {
            return Ok(None);
        }
        let id = read_regular_file_to_string_with_limit(&path, MAX_CURRENT_SNAPSHOT_POINTER_BYTES)?;
        let id = id.trim();
        if id.is_empty() {
            return Ok(None);
        }
        validate_snapshot_id(id)?;
        Ok(Some(id.to_owned()))
    }

    pub fn current_snapshot(&self) -> Result<Option<ConfigSnapshot>, SnapshotError> {
        let Some(id) = self.current_id()? else {
            return Ok(None);
        };

        self.load_snapshot(&id).map(Some)
    }

    pub fn rollback_target(&self, target: Option<&str>) -> Result<ConfigSnapshot, SnapshotError> {
        let snapshot = self.rollback_candidate(target)?;
        self.set_current(&snapshot.id)?;
        Ok(snapshot)
    }

    pub fn rollback_candidate(
        &self,
        target: Option<&str>,
    ) -> Result<ConfigSnapshot, SnapshotError> {
        self.validate_root()?;
        let id = rollback_target_id(self, target)?;
        let snapshot = self.load_snapshot(&id)?;
        Config::load(Some(&snapshot.config_path)).map_err(SnapshotError::Config)?;
        Ok(snapshot)
    }

    pub fn set_current_snapshot(&self, id: &str) -> Result<(), SnapshotError> {
        self.validate_root()?;
        self.set_current(id)
    }

    fn previous_snapshot_id(&self) -> Result<String, SnapshotError> {
        let current = self.current_id()?.ok_or(SnapshotError::CurrentMissing)?;
        let snapshots = self.list()?;
        if snapshots.is_empty() {
            return Err(SnapshotError::EmptyStore);
        }

        let Some(position) = snapshots.iter().position(|snapshot| snapshot.id == current) else {
            return Err(SnapshotError::SnapshotNotFound { id: current });
        };
        if position == 0 {
            return Err(SnapshotError::NoPreviousSnapshot { current });
        }

        Ok(snapshots[position - 1].id.clone())
    }

    fn load_snapshot(&self, id: &str) -> Result<ConfigSnapshot, SnapshotError> {
        validate_snapshot_id(id)?;
        let config_path = self.config_path(id);
        if !regular_snapshot_file_exists(&config_path)? {
            return Err(SnapshotError::SnapshotNotFound { id: id.to_owned() });
        }

        let metadata_path = self.metadata_path(id);
        let metadata = if let Some(raw) = read_optional_regular_file_to_string(&metadata_path)? {
            let metadata = toml::from_str(&raw).map_err(SnapshotError::Decode)?;
            validate_snapshot_metadata(&metadata, id)?;
            metadata
        } else {
            SnapshotMetadata {
                id: id.to_owned(),
                created_unix_secs: 0,
                message: None,
            }
        };

        Ok(ConfigSnapshot {
            id: id.to_owned(),
            config_path,
            metadata_path,
            metadata,
        })
    }

    fn set_current(&self, id: &str) -> Result<(), SnapshotError> {
        validate_snapshot_id(id)?;
        if !regular_snapshot_file_exists(&self.config_path(id))? {
            return Err(SnapshotError::SnapshotNotFound { id: id.to_owned() });
        }
        self.ensure_layout()?;
        write_atomically(&self.current_path(), format!("{id}\n").as_bytes())
    }

    fn ensure_layout(&self) -> Result<(), SnapshotError> {
        self.validate_root()?;
        ensure_real_directory(&self.root)?;

        let configs_dir = self.configs_dir();
        if is_symlink(&configs_dir)? {
            return Err(SnapshotError::UnsafeSnapshotPath { path: configs_dir });
        }
        ensure_real_directory(&configs_dir)?;
        self.ensure_configs_dir_under_root()?;
        Ok(())
    }

    fn validate_root(&self) -> Result<(), SnapshotError> {
        if self.root.as_os_str().is_empty()
            || self
                .root
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            || snapshot_parent_path_contains_symlink(&self.root).unwrap_or(true)
            || snapshot_root_or_parent_is_world_writable(&self.root).unwrap_or(true)
        {
            return Err(SnapshotError::UnsafeStoreRoot {
                path: self.root.clone(),
            });
        }

        Ok(())
    }

    fn configs_dir(&self) -> PathBuf {
        self.root.join("configs")
    }

    fn current_path(&self) -> PathBuf {
        self.root.join("current")
    }

    fn config_path(&self, id: &str) -> PathBuf {
        self.configs_dir().join(format!("{id}.toml"))
    }

    fn metadata_path(&self, id: &str) -> PathBuf {
        self.configs_dir().join(format!("{id}.meta.toml"))
    }

    fn safe_existing_configs_dir(&self) -> Result<bool, SnapshotError> {
        let configs_dir = self.configs_dir();
        let Some(metadata) = optional_symlink_metadata(&configs_dir)? else {
            return Ok(false);
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SnapshotError::UnsafeSnapshotPath { path: configs_dir });
        }
        self.ensure_configs_dir_under_root()?;
        Ok(true)
    }

    fn safe_existing_root(&self) -> Result<bool, SnapshotError> {
        let Some(metadata) = optional_symlink_metadata(&self.root)? else {
            return Ok(false);
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SnapshotError::UnsafeSnapshotPath {
                path: self.root.clone(),
            });
        }
        Ok(true)
    }

    fn ensure_configs_dir_under_root(&self) -> Result<(), SnapshotError> {
        let root = canonical_directory(&self.root)?;
        let configs_dir = self.configs_dir();
        let configs_dir = canonical_directory(&configs_dir)?;
        if !configs_dir.starts_with(&root) {
            return Err(SnapshotError::UnsafeSnapshotPath { path: configs_dir });
        }
        Ok(())
    }
}

fn rollback_target_id(
    store: &SnapshotStore,
    target: Option<&str>,
) -> Result<String, SnapshotError> {
    match target {
        Some(id) => {
            validate_snapshot_id(id)?;
            Ok(id.to_owned())
        }
        None => store.previous_snapshot_id(),
    }
}

impl Display for SnapshotError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "snapshot I/O error: {error}"),
            Self::Encode(error) => write!(formatter, "could not encode snapshot TOML: {error}"),
            Self::Decode(error) => write!(formatter, "could not decode snapshot metadata: {error}"),
            Self::Config(error) => write!(formatter, "snapshot config is invalid: {error}"),
            Self::EmptyStore => formatter.write_str("snapshot store is empty"),
            Self::CurrentMissing => formatter.write_str("snapshot store has no current pointer"),
            Self::NoPreviousSnapshot { current } => {
                write!(formatter, "snapshot {current} has no previous snapshot")
            }
            Self::InvalidSnapshotId { id } if id.len() > MAX_SNAPSHOT_ID_BYTES => write!(
                formatter,
                "invalid snapshot id: length {} exceeds {} bytes",
                id.len(),
                MAX_SNAPSHOT_ID_BYTES
            ),
            Self::InvalidSnapshotId { id } => write!(formatter, "invalid snapshot id: {id}"),
            Self::SnapshotNotFound { id } => write!(formatter, "snapshot not found: {id}"),
            Self::InvalidSnapshotMessage { max_bytes } => write!(
                formatter,
                "snapshot message must be non-control text no longer than {max_bytes} bytes"
            ),
            Self::UnsafeStoreRoot { path } => write!(
                formatter,
                "snapshot store root must not be empty, contain parent-directory traversal, sit below a symlinked directory, or use a world-writable directory: {}",
                path.display()
            ),
            Self::UnsafeSnapshotPath { path } => write!(
                formatter,
                "snapshot store path must be a regular file or directory inside the snapshot store: {}",
                path.display()
            ),
        }
    }
}

impl Error for SnapshotError {}

fn new_snapshot_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch for snapshot ids");
    format!(
        "s{}-{:09}-{}-{}",
        now.as_secs(),
        now.subsec_nanos(),
        std::process::id(),
        unique_sequence()
    )
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch for snapshot metadata")
        .as_secs()
}

fn snapshot_message(message: Option<&str>) -> Result<Option<String>, SnapshotError> {
    match message {
        Some(message) => valid_snapshot_message(message),
        None => Ok(None),
    }
}

fn valid_snapshot_message(message: &str) -> Result<Option<String>, SnapshotError> {
    let message = message.trim();
    if message.is_empty() {
        Ok(None)
    } else if message.len() > MAX_SNAPSHOT_MESSAGE_BYTES || message.chars().any(char::is_control) {
        Err(SnapshotError::InvalidSnapshotMessage {
            max_bytes: MAX_SNAPSHOT_MESSAGE_BYTES,
        })
    } else {
        Ok(Some(message.to_owned()))
    }
}

fn validate_snapshot_metadata(
    metadata: &SnapshotMetadata,
    expected_id: &str,
) -> Result<(), SnapshotError> {
    validate_snapshot_id(&metadata.id)?;
    if metadata.id != expected_id {
        return Err(SnapshotError::InvalidSnapshotId {
            id: metadata.id.clone(),
        });
    }
    if let Some(message) = metadata.message.as_deref() {
        valid_snapshot_message(message)?;
    }
    Ok(())
}

fn validate_snapshot_id(id: &str) -> Result<(), SnapshotError> {
    if id.is_empty()
        || id.len() > MAX_SNAPSHOT_ID_BYTES
        || id
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_')
    {
        return Err(SnapshotError::InvalidSnapshotId { id: id.to_owned() });
    }

    Ok(())
}

fn write_atomically(path: &Path, contents: &[u8]) -> Result<(), SnapshotError> {
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
        #[cfg(target_os = "linux")]
        options.custom_flags(O_NOFOLLOW);

        let mut file = options.open(&temp_path).map_err(SnapshotError::Io)?;
        file.write_all(contents).map_err(SnapshotError::Io)?;
        file.sync_all().map_err(SnapshotError::Io)?;
    }

    fs::rename(&temp_path, path).map_err(SnapshotError::Io)?;
    sync_directory(parent)?;
    Ok(())
}

fn unique_sequence() -> u64 {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

fn sync_directory(path: &Path) -> Result<(), SnapshotError> {
    let directory = File::open(path).map_err(SnapshotError::Io)?;
    directory.sync_all().map_err(SnapshotError::Io)
}

fn regular_snapshot_file_exists(path: &Path) -> Result<bool, SnapshotError> {
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

fn read_optional_regular_file_to_string(path: &Path) -> Result<Option<String>, SnapshotError> {
    if !path_exists_without_following_symlinks(path)? {
        return Ok(None);
    }
    read_regular_file_to_string(path).map(Some)
}

fn read_regular_file_to_string(path: &Path) -> Result<String, SnapshotError> {
    read_regular_file_to_string_with_limit(path, MAX_SNAPSHOT_FILE_BYTES)
}

fn read_regular_file_to_string_with_limit(
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

fn open_regular_file(path: &Path) -> Result<File, SnapshotError> {
    let metadata = fs::symlink_metadata(path).map_err(SnapshotError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        });
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
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

fn optional_symlink_metadata(path: &Path) -> Result<Option<fs::Metadata>, SnapshotError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(SnapshotError::Io(error)),
    }
}

fn path_exists_without_following_symlinks(path: &Path) -> Result<bool, SnapshotError> {
    optional_symlink_metadata(path).map(|metadata| metadata.is_some())
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

fn require_real_directory(path: &Path) -> Result<(), SnapshotError> {
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

fn is_symlink(path: &Path) -> Result<bool, SnapshotError> {
    optional_symlink_metadata(path).map(|metadata| {
        metadata
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
    })
}

fn ensure_real_directory(path: &Path) -> Result<(), SnapshotError> {
    match optional_symlink_metadata(path)? {
        Some(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(SnapshotError::UnsafeSnapshotPath {
                path: path.to_path_buf(),
            });
        }
        Some(_) => return Ok(()),
        None => {}
    }

    fs::create_dir_all(path).map_err(SnapshotError::Io)?;
    let metadata = fs::symlink_metadata(path).map_err(SnapshotError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        });
    }

    Ok(())
}

fn canonical_directory(path: &Path) -> Result<PathBuf, SnapshotError> {
    let metadata = fs::symlink_metadata(path).map_err(SnapshotError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SnapshotError::UnsafeSnapshotPath {
            path: path.to_path_buf(),
        });
    }
    fs::canonicalize(path).map_err(SnapshotError::Io)
}

fn snapshot_parent_path_contains_symlink(path: &Path) -> io::Result<bool> {
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

#[cfg(unix)]
fn snapshot_root_or_parent_is_world_writable(path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;

    let mut current = path.to_path_buf();

    loop {
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(false),
            Ok(metadata) => return Ok(metadata.permissions().mode() & 0o002 != 0),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !current.pop() {
                    return Ok(false);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(not(unix))]
fn snapshot_root_or_parent_is_world_writable(_path: &Path) -> io::Result<bool> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::{SnapshotError, SnapshotStore, write_atomically};
    use crate::config::{Config, ProxyConfig};
    use crate::test_support::unique_temp_path;

    #[test]
    fn snapshots_validated_config_and_sets_current() {
        let dir = TestDir::new("snapshot-current");
        let store = SnapshotStore::new(dir.path());
        let snapshot = store
            .snapshot_config(&Config::default(), Some("initial config"))
            .unwrap();

        assert!(snapshot.config_path.is_file());
        assert!(snapshot.metadata_path.is_file());
        assert_eq!(store.current_id().unwrap(), Some(snapshot.id.clone()));
        assert_eq!(
            store.list().unwrap()[0].metadata.message.as_deref(),
            Some("initial config")
        );
        assert!(snapshot.config_path.starts_with(store.root()));
    }

    #[test]
    fn rejects_oversized_snapshot_message() {
        let dir = TestDir::new("snapshot-message-oversized");
        let store = SnapshotStore::new(dir.path());

        let error = store
            .snapshot_config(
                &Config::default(),
                Some(&"a".repeat(super::MAX_SNAPSHOT_MESSAGE_BYTES + 1)),
            )
            .unwrap_err();

        assert!(matches!(
            error,
            SnapshotError::InvalidSnapshotMessage { .. }
        ));
        assert_eq!(store.list().unwrap().len(), 0);
    }

    #[test]
    fn rejects_snapshot_message_with_control_character() {
        let dir = TestDir::new("snapshot-message-control");
        let store = SnapshotStore::new(dir.path());

        let error = store
            .snapshot_config(&Config::default(), Some("line one\nline two"))
            .unwrap_err();

        assert!(matches!(
            error,
            SnapshotError::InvalidSnapshotMessage { .. }
        ));
    }

    #[test]
    fn rejects_snapshot_store_with_too_many_entries() {
        let dir = TestDir::new("snapshot-too-many-entries");
        let store = SnapshotStore::new(dir.path());
        std::fs::create_dir(dir.path().join("configs")).unwrap();
        for index in 0..=super::MAX_SNAPSHOT_STORE_ENTRIES {
            std::fs::write(
                dir.path().join("configs").join(format!("s{index:04}.toml")),
                b"",
            )
            .unwrap();
        }

        let error = store.list().unwrap_err();

        assert!(
            matches!(error, SnapshotError::Io(error) if error.kind() == std::io::ErrorKind::InvalidData)
        );
    }

    #[test]
    fn current_snapshot_loads_current_pointer() {
        let dir = TestDir::new("snapshot-current-load");
        let store = SnapshotStore::new(dir.path());
        assert!(store.current_snapshot().unwrap().is_none());

        let snapshot = store
            .snapshot_config(&Config::default(), Some("first"))
            .unwrap();

        assert_eq!(store.current_snapshot().unwrap().unwrap().id, snapshot.id);
    }

    #[test]
    fn rollback_without_target_selects_previous_snapshot() {
        let dir = TestDir::new("snapshot-rollback");
        let store = SnapshotStore::new(dir.path());
        let first = store
            .snapshot_config(&Config::default(), Some("first"))
            .unwrap();
        let second_config = Config {
            proxy: ProxyConfig {
                upstream: Some("127.0.0.1:4000".to_owned()),
                ..ProxyConfig::default()
            },
            ..Config::default()
        };
        let second = store
            .snapshot_config(&second_config, Some("second"))
            .unwrap();
        assert_eq!(store.current_id().unwrap(), Some(second.id));

        let rollback = store.rollback_target(None).unwrap();

        assert_eq!(rollback.id, first.id);
        assert_eq!(store.current_id().unwrap(), Some(first.id));
    }

    #[test]
    fn rollback_candidate_does_not_move_current_pointer() {
        let dir = TestDir::new("snapshot-rollback-candidate");
        let store = SnapshotStore::new(dir.path());
        let first = store
            .snapshot_config(&Config::default(), Some("first"))
            .unwrap();
        let second = store
            .snapshot_config(&Config::default(), Some("second"))
            .unwrap();

        let candidate = store.rollback_candidate(None).unwrap();

        assert_eq!(candidate.id, first.id);
        assert_eq!(store.current_id().unwrap(), Some(second.id));
    }

    #[test]
    fn rollback_rejects_invalid_snapshot_id() {
        let dir = TestDir::new("snapshot-invalid-id");
        let store = SnapshotStore::new(dir.path());

        let error = store.rollback_target(Some("../bad")).unwrap_err();

        assert!(matches!(error, SnapshotError::InvalidSnapshotId { .. }));
    }

    #[test]
    fn rollback_rejects_oversized_snapshot_id_without_reflecting_it() {
        let dir = TestDir::new("snapshot-oversized-id");
        let store = SnapshotStore::new(dir.path());
        let id = "a".repeat(super::MAX_SNAPSHOT_ID_BYTES + 1);

        let error = store.rollback_target(Some(&id)).unwrap_err();
        let message = error.to_string();

        assert!(matches!(error, SnapshotError::InvalidSnapshotId { .. }));
        assert!(message.contains("length 129 exceeds 128 bytes"));
        assert!(!message.contains(&id));
    }

    #[test]
    fn rejects_snapshot_store_root_with_parent_traversal() {
        let store = SnapshotStore::new("../fluxheim-snapshots");

        let error = store.list().unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeStoreRoot { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_snapshot_store_root() {
        let target = TestDir::new("snapshot-root-target");
        let root = unique_temp_path("snapshot-root-symlink");
        std::os::unix::fs::symlink(target.path(), &root).unwrap();
        let store = SnapshotStore::new(&root);

        let error = store.list().unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeSnapshotPath { .. }));
        let _ = std::fs::remove_file(root);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_snapshot_store_root_below_symlinked_directory() {
        let dir = TestDir::new("snapshot-root-parent-symlink");
        let real_parent = dir.path().join("real-parent");
        let linked_parent = dir.path().join("linked-parent");
        std::fs::create_dir(&real_parent).unwrap();
        std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();
        let store = SnapshotStore::new(linked_parent.join("snapshots"));

        let error = store
            .snapshot_config(&Config::default(), Some("initial"))
            .unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeStoreRoot { .. }));
        assert!(!real_parent.join("snapshots").exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_snapshot_store_root_below_world_writable_directory() {
        let root = unique_temp_path("snapshot-root-world-writable");
        let store = SnapshotStore::new(&root);

        let error = store
            .snapshot_config(&Config::default(), Some("initial"))
            .unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeStoreRoot { .. }));
        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_current_pointer() {
        let dir = TestDir::new("snapshot-current-symlink");
        let store = SnapshotStore::new(dir.path());
        let snapshot = store
            .snapshot_config(&Config::default(), Some("initial"))
            .unwrap();

        let outside = dir.path().join("outside-current");
        std::fs::write(&outside, format!("{}\n", snapshot.id)).unwrap();
        std::fs::remove_file(store.current_path()).unwrap();
        std::os::unix::fs::symlink(&outside, store.current_path()).unwrap();

        let error = store.current_id().unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeSnapshotPath { .. }));
    }

    #[test]
    fn rejects_oversized_current_pointer() {
        let dir = TestDir::new("snapshot-current-oversized");
        let store = SnapshotStore::new(dir.path());
        store
            .snapshot_config(&Config::default(), Some("initial"))
            .unwrap();
        std::fs::write(
            store.current_path(),
            vec![b'a'; (super::MAX_CURRENT_SNAPSHOT_POINTER_BYTES + 1) as usize],
        )
        .unwrap();

        let error = store.current_id().unwrap_err();

        assert!(
            matches!(error, SnapshotError::Io(error) if error.kind() == std::io::ErrorKind::InvalidData)
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_snapshot_config() {
        let dir = TestDir::new("snapshot-config-symlink");
        let store = SnapshotStore::new(dir.path());
        let snapshot = store
            .snapshot_config(&Config::default(), Some("initial"))
            .unwrap();
        let outside = dir.path().join("outside.toml");
        std::fs::write(
            &outside,
            toml::to_string_pretty(&Config::default()).unwrap(),
        )
        .unwrap();
        std::fs::remove_file(&snapshot.config_path).unwrap();
        std::os::unix::fs::symlink(&outside, &snapshot.config_path).unwrap();

        let error = store.rollback_candidate(Some(&snapshot.id)).unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeSnapshotPath { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_snapshot_metadata() {
        let dir = TestDir::new("snapshot-metadata-symlink");
        let store = SnapshotStore::new(dir.path());
        let snapshot = store
            .snapshot_config(&Config::default(), Some("initial"))
            .unwrap();
        let outside = dir.path().join("outside.meta.toml");
        std::fs::write(
            &outside,
            format!(
                "id = \"{}\"\ncreated_unix_secs = 1\nmessage = \"outside\"\n",
                snapshot.id
            ),
        )
        .unwrap();
        std::fs::remove_file(&snapshot.metadata_path).unwrap();
        std::os::unix::fs::symlink(&outside, &snapshot.metadata_path).unwrap();

        let error = store.list().unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeSnapshotPath { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_configs_directory() {
        let dir = TestDir::new("snapshot-configs-dir-symlink");
        let outside = TestDir::new("snapshot-configs-outside");
        let configs_dir = dir.path().join("configs");
        std::os::unix::fs::symlink(outside.path(), &configs_dir).unwrap();
        let store = SnapshotStore::new(dir.path());

        let error = store.list().unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeSnapshotPath { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_atomic_write_below_symlinked_parent() {
        let dir = TestDir::new("snapshot-write-parent-symlink");
        let outside = TestDir::new("snapshot-write-parent-outside");
        let symlinked_parent = dir.path().join("linked-parent");
        std::os::unix::fs::symlink(outside.path(), &symlinked_parent).unwrap();

        let error = write_atomically(&symlinked_parent.join("current"), b"snapshot\n").unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeSnapshotPath { .. }));
        let _ = std::fs::remove_file(symlinked_parent);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_atomic_write_to_symlinked_destination() {
        let dir = TestDir::new("snapshot-write-destination-symlink");
        let outside = dir.path().join("outside-current");
        let destination = dir.path().join("current");
        std::fs::write(&outside, "old\n").unwrap();
        std::os::unix::fs::symlink(&outside, &destination).unwrap();

        let error = write_atomically(&destination, b"new\n").unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeSnapshotPath { .. }));
        assert_eq!(std::fs::read_to_string(outside).unwrap(), "old\n");
    }

    struct TestDir {
        path: std::path::PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let path = unique_temp_path(name);
            std::fs::create_dir(&path).expect("create test directory");
            Self { path }
        }

        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
