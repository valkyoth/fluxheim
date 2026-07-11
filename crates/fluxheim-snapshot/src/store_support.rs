use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::metadata::MAX_SNAPSHOT_ID_BYTES;
use crate::store::SnapshotError;
use crate::store_fs::unique_sequence;

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
            Self::InvalidSnapshotId { id } => write!(
                formatter,
                "invalid snapshot id: {} bytes; expected 1..={} ASCII letters, digits, '-' or '_'",
                id.len(),
                MAX_SNAPSHOT_ID_BYTES
            ),
            Self::SnapshotNotFound { id } => write!(formatter, "snapshot not found: {id}"),
            Self::InvalidSnapshotMessage { max_bytes } => write!(
                formatter,
                "snapshot message must be non-control text no longer than {max_bytes} bytes"
            ),
            Self::UnsafeStoreRoot { path } => write!(
                formatter,
                "snapshot store root must be private and must not contain traversal or symlinks: {}",
                path.display()
            ),
            Self::UnsafeSnapshotPath { path } => write!(
                formatter,
                "snapshot path must remain a regular file or directory inside the store: {}",
                path.display()
            ),
            Self::InvalidSystemClock => {
                formatter.write_str("system clock is before the Unix epoch")
            }
            Self::InvalidIntegrityKey => formatter.write_str(
                "snapshot integrity key must be a regular file containing 32..=4096 bytes",
            ),
            Self::UnsafeIntegrityKey { path } => write!(
                formatter,
                "snapshot integrity key has an untrusted path: {}",
                path.display()
            ),
            Self::IntegrityManifestMissing { id } => {
                write!(
                    formatter,
                    "snapshot {id} has no authenticated integrity manifest"
                )
            }
            Self::IntegrityVerificationFailed { id } => {
                write!(formatter, "snapshot {id} failed integrity verification")
            }
            Self::InvalidPrunePolicy => {
                formatter.write_str("snapshot prune requires --keep or --older-than")
            }
            Self::RuntimeStateIntegrityFailed => {
                formatter.write_str("snapshot self-healing state failed integrity verification")
            }
            Self::PublishedButNotDurable { path } => write!(
                formatter,
                "snapshot file was published but final durability failed: {}",
                path.display()
            ),
            Self::SnapshotPublishedButCurrentUpdateFailed { id } => write!(
                formatter,
                "snapshot {id} was published but the current pointer update failed"
            ),
            Self::GenerationExhausted => {
                formatter.write_str("snapshot generation counter is exhausted")
            }
            Self::GenerationStateInvalid => {
                formatter.write_str("snapshot generation state failed validation")
            }
            Self::PruneBoundaryInvalid => {
                formatter.write_str("snapshot pruning boundary state failed validation")
            }
            Self::CryptoProvider(error) => {
                write!(formatter, "snapshot cryptographic provider failed: {error}")
            }
        }
    }
}

impl Error for SnapshotError {}

pub(crate) fn new_snapshot_id(now: Duration, generation: u64) -> String {
    format!(
        "s{}-{:09}-{generation:020}-{:020}",
        now.as_secs(),
        now.subsec_nanos(),
        unique_sequence()
    )
}

pub(crate) fn unix_duration() -> Result<Duration, SnapshotError> {
    unix_duration_from(SystemTime::now())
}

fn unix_duration_from(now: SystemTime) -> Result<Duration, SnapshotError> {
    now.duration_since(UNIX_EPOCH)
        .map_err(|_| SnapshotError::InvalidSystemClock)
}

pub(crate) struct SnapshotTransaction {
    paths: Vec<PathBuf>,
    committed: bool,
}

impl SnapshotTransaction {
    pub(crate) fn new() -> Self {
        Self {
            paths: Vec::new(),
            committed: false,
        }
    }

    pub(crate) fn track(&mut self, path: PathBuf) {
        self.paths.push(path);
    }

    pub(crate) fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for SnapshotTransaction {
    fn drop(&mut self) {
        if !self.committed {
            for path in self.paths.iter().rev() {
                let _ = fs::remove_file(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_epoch_clock_returns_typed_error() {
        let before_epoch = UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            unix_duration_from(before_epoch),
            Err(SnapshotError::InvalidSystemClock)
        ));
    }
}
