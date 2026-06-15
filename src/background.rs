use async_trait::async_trait;
#[cfg(unix)]
use pingora::server::ListenFds;
use pingora::server::ShutdownWatch;
use pingora::services::{ServiceReadyNotifier, ServiceWithDependents};

pub(crate) use fluxheim_runtime::{FluxBackgroundReady, FluxBackgroundTask, FluxShutdown};

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
    pub(crate) fn new(name: impl Into<String>, task: T) -> Self {
        Self {
            inner: fluxheim_runtime::background_service(name, task),
        }
    }
}

pub(crate) fn background_service<T>(name: impl Into<String>, task: T) -> FluxBackgroundService<T>
where
    T: FluxBackgroundTask,
{
    FluxBackgroundService::new(name, task)
}

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

    fn threads(&self) -> Option<usize> {
        self.inner.threads()
    }
}
