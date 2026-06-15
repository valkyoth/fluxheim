pub use fluxheim_runtime::{FluxBackgroundReady, FluxBackgroundService, FluxShutdown};

pub(crate) fn background_service<T>(name: impl Into<String>, task: T) -> FluxBackgroundService<T> {
    FluxBackgroundService::new(name, task)
}
