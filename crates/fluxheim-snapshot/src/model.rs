use std::io;
use std::path::PathBuf;

use fluxheim_config::ConfigLoadError;

use crate::metadata::SnapshotMetadata;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConfigSnapshot {
    pub id: String,
    pub config_path: PathBuf,
    pub metadata_path: PathBuf,
    pub metadata: SnapshotMetadata,
    pub integrity: SnapshotIntegrityStatus,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SnapshotIntegrityStatus {
    Authenticated,
    Unverified,
}

impl SnapshotIntegrityStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authenticated => "authenticated",
            Self::Unverified => "unverified",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SnapshotEntryStatus {
    Healthy,
    Unverified,
    Corrupt,
}

impl SnapshotEntryStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Unverified => "unverified",
            Self::Corrupt => "corrupt",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotListEntry {
    pub id: String,
    pub snapshot: Option<ConfigSnapshot>,
    pub status: SnapshotEntryStatus,
    pub error: Option<String>,
}

#[derive(Debug)]
pub enum SnapshotError {
    Io(io::Error),
    Encode(toml::ser::Error),
    Decode(toml::de::Error),
    Config(ConfigLoadError),
    EmptyStore,
    CurrentMissing,
    NoPreviousSnapshot { current: String },
    InvalidSnapshotId { id: String },
    SnapshotNotFound { id: String },
    InvalidSnapshotMessage { max_bytes: usize },
    UnsafeStoreRoot { path: PathBuf },
    UnsafeSnapshotPath { path: PathBuf },
    InvalidSystemClock,
    InvalidIntegrityKey,
    UnsafeIntegrityKey { path: PathBuf },
    IntegrityManifestMissing { id: String },
    IntegrityVerificationFailed { id: String },
    InvalidPrunePolicy,
    RuntimeStateIntegrityFailed,
}
