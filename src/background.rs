pub(crate) use fluxheim_runtime::{
    BackgroundTaskKind, BackgroundTaskSpec, FluxBackgroundReady, FluxBackgroundTask, FluxShutdown,
};

pub(crate) struct FluxBackgroundService<T>
where
    T: FluxBackgroundTask,
{
    inner: fluxheim_runtime::FluxBackgroundService<T>,
}

impl<T> FluxBackgroundService<T>
where
    T: FluxBackgroundTask,
{
    #[cfg(any(feature = "metrics", feature = "stream-proxy", feature = "udp-proxy"))]
    pub(crate) fn new(name: impl Into<String>, task: T) -> Self {
        Self {
            inner: fluxheim_runtime::background_service(name, task),
        }
    }

    pub(crate) fn with_kind(name: impl Into<String>, kind: BackgroundTaskKind, task: T) -> Self {
        Self {
            inner: fluxheim_runtime::background_service_with_kind(name, kind, task),
        }
    }

    pub(crate) fn into_native(self) -> fluxheim_runtime::FluxBackgroundService<T> {
        self.inner
    }
}

pub(crate) fn background_service_for_spec<T>(
    spec: BackgroundTaskSpec,
    task: T,
) -> FluxBackgroundService<T>
where
    T: FluxBackgroundTask,
{
    FluxBackgroundService::with_kind(spec.name(), spec.kind(), task)
}
