#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

mod integrity;
mod metadata;
mod model;
mod operations;
mod recovery;
mod state;
mod store;
mod store_fs;
mod store_support;

#[cfg(test)]
mod operations_tests;

pub use metadata::{MAX_SNAPSHOT_MESSAGE_BYTES, SnapshotMetadata};
pub use model::{
    ConfigSnapshot, SnapshotEntryStatus, SnapshotError, SnapshotIntegrityStatus, SnapshotListEntry,
};
pub use operations::{
    SnapshotDiff, SnapshotDoctorReport, SnapshotPruneOptions, SnapshotPruneReport,
};
pub use state::{
    PendingValidation, SnapshotApplyMode, SnapshotHealthSignalOutcome, SnapshotRollbackReason,
    SnapshotRuntimeState, ValidationMetrics,
};
pub use store::SnapshotStore;
