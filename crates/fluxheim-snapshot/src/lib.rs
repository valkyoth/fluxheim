#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

mod metadata;
mod state;
mod store;
mod store_fs;

pub use metadata::{MAX_SNAPSHOT_MESSAGE_BYTES, SnapshotMetadata};
pub use state::{
    PendingValidation, SnapshotApplyMode, SnapshotHealthSignalOutcome, SnapshotRollbackReason,
    SnapshotRuntimeState, ValidationMetrics,
};
pub use store::{ConfigSnapshot, SnapshotError, SnapshotStore};
