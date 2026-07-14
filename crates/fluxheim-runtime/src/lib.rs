#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

mod background;
pub mod policy;

pub use background::{
    BackgroundTaskKind, BackgroundTaskSpawner, BackgroundTaskSpec, CriticalBackgroundJoinHandle,
    FluxBackgroundReady, FluxBackgroundService, FluxBackgroundTask, FluxShutdown,
    NativeBackgroundJoinHandle, NativeBackgroundSupervisor, ShutdownReason, ShutdownState,
    ShutdownView, background_service, background_service_with_kind,
};
pub use policy::{
    PolicyEpoch, PolicyProof, RuntimeDecision, RuntimeDecisionKind, RuntimeDecisionReason,
    RuntimeFact, RuntimeFactKind, RuntimeFactVisibility,
};
