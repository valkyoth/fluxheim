#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

mod state;
mod store;

pub use state::{
    PendingValidation, SnapshotApplyMode, SnapshotHealthSignalOutcome, SnapshotRollbackReason,
    SnapshotRuntimeState, ValidationMetrics,
};
pub use store::{
    ConfigSnapshot, MAX_SNAPSHOT_MESSAGE_BYTES, SnapshotError, SnapshotMetadata, SnapshotStore,
};
