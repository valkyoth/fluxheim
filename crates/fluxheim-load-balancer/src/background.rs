pub use fluxheim_runtime::{
    BackgroundTaskKind, FluxBackgroundReady, FluxBackgroundService, FluxShutdown,
};

pub(crate) fn background_service_with_kind<T>(
    name: impl Into<String>,
    kind: BackgroundTaskKind,
    task: T,
) -> FluxBackgroundService<T> {
    FluxBackgroundService::with_kind(name, kind, task)
}
