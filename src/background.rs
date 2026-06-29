#[cfg(any())]
use async_trait::async_trait;
#[cfg(all(any(), unix))]
use pingora::server::ListenFds;
#[cfg(any())]
use pingora::server::ShutdownWatch;
#[cfg(any())]
use pingora::services::{ServiceReadyNotifier, ServiceWithDependents};

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

#[cfg(any())]
#[async_trait]
impl<T> ServiceWithDependents for FluxBackgroundService<T>
where
    T: FluxBackgroundTask,
{
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<ListenFds>,
        shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
        ready: ServiceReadyNotifier,
    ) {
        self.inner
            .task()
            .start(
                fluxheim_runtime::FluxShutdown::new(shutdown),
                fluxheim_runtime::FluxBackgroundReady::new(move || ready.notify_ready()),
            )
            .await;
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    #[allow(deprecated)]
    fn threads(&self) -> Option<usize> {
        self.inner.threads()
    }
}
