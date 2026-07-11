#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

mod generation;
mod integrity;
mod metadata;
mod model;
mod operations;
mod prune_boundary;
mod recovery;
mod state;
mod store;
mod store_fs;
mod store_layout;
mod store_support;

#[cfg(test)]
mod operations_tests;
#[cfg(test)]
mod snapshot_hardening_tests;

pub use integrity::SnapshotCryptoProvider;
pub use metadata::{MAX_SNAPSHOT_MESSAGE_BYTES, SnapshotMetadata};
pub use model::{
    ConfigSnapshot, SnapshotEntryStatus, SnapshotError, SnapshotIntegrityStatus, SnapshotListEntry,
    VerifiedConfigSnapshot,
};
pub use operations::{
    SnapshotDiff, SnapshotDoctorReport, SnapshotPruneOptions, SnapshotPruneReport,
};
pub use state::{
    PendingValidation, SnapshotApplyMode, SnapshotHealthSignalOutcome, SnapshotRollbackReason,
    SnapshotRuntimeState, ValidationMetrics,
};
pub use store::SnapshotStore;
