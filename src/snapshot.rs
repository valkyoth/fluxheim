use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::Config;

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
            message: message.and_then(non_empty_message),
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
        let configs_dir = self.configs_dir();
        if !configs_dir.exists() {
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
            snapshots.push(self.load_snapshot(stem)?);
        }

        snapshots.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(snapshots)
    }

    pub fn current_id(&self) -> Result<Option<String>, SnapshotError> {
        let path = self.current_path();
        if !path.exists() {
            return Ok(None);
        }
        let id = fs::read_to_string(path).map_err(SnapshotError::Io)?;
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
        let id = rollback_target_id(self, target)?;
        let snapshot = self.load_snapshot(&id)?;
        Config::load(Some(&snapshot.config_path)).map_err(SnapshotError::Config)?;
        Ok(snapshot)
    }

    pub fn set_current_snapshot(&self, id: &str) -> Result<(), SnapshotError> {
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
        if !config_path.is_file() {
            return Err(SnapshotError::SnapshotNotFound { id: id.to_owned() });
        }

        let metadata_path = self.metadata_path(id);
        let metadata = if metadata_path.is_file() {
            let raw = fs::read_to_string(&metadata_path).map_err(SnapshotError::Io)?;
            toml::from_str(&raw).map_err(SnapshotError::Decode)?
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
        if !self.config_path(id).is_file() {
            return Err(SnapshotError::SnapshotNotFound { id: id.to_owned() });
        }
        self.ensure_layout()?;
        write_atomically(&self.current_path(), format!("{id}\n").as_bytes())
    }

    fn ensure_layout(&self) -> Result<(), SnapshotError> {
        fs::create_dir_all(self.configs_dir()).map_err(SnapshotError::Io)
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
            Self::InvalidSnapshotId { id } => write!(formatter, "invalid snapshot id: {id}"),
            Self::SnapshotNotFound { id } => write!(formatter, "snapshot not found: {id}"),
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

fn non_empty_message(message: &str) -> Option<String> {
    let message = message.trim();
    if message.is_empty() {
        None
    } else {
        Some(message.to_owned())
    }
}

fn validate_snapshot_id(id: &str) -> Result<(), SnapshotError> {
    if id.is_empty()
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
    fs::create_dir_all(parent).map_err(SnapshotError::Io)?;

    let temp_path = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("snapshot"),
        std::process::id(),
        unique_sequence()
    ));

    {
        let mut file = File::create(&temp_path).map_err(SnapshotError::Io)?;
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{SnapshotError, SnapshotStore};
    use crate::config::{Config, ProxyConfig};

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
                upstream: "127.0.0.1:4000".to_owned(),
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

    struct TestDir {
        path: std::path::PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "fluxheim-{name}-{nonce}-{}",
                unique_test_sequence()
            ));
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

    fn unique_test_sequence() -> u64 {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    }
}
