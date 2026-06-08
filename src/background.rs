use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
#[cfg(unix)]
use pingora::server::ListenFds;
use pingora::server::ShutdownWatch;
use pingora::services::{ServiceReadyNotifier, ServiceWithDependents};

pub(crate) struct FluxShutdown {
    inner: ShutdownWatch,
}

impl FluxShutdown {
    fn new(inner: ShutdownWatch) -> Self {
        Self { inner }
    }

    pub(crate) fn is_shutdown(&self) -> bool {
        *self.inner.borrow()
    }

    pub(crate) async fn sleep_or_shutdown(&mut self, delay: Duration) -> bool {
        match tokio::time::timeout(delay, self.inner.changed()).await {
            Ok(Ok(())) => self.is_shutdown(),
            Ok(Err(_closed)) => true,
            Err(_elapsed) => false,
        }
    }
}

pub(crate) struct FluxBackgroundReady {
    inner: Option<ServiceReadyNotifier>,
}

impl FluxBackgroundReady {
    fn new(inner: ServiceReadyNotifier) -> Self {
        Self { inner: Some(inner) }
    }

    pub(crate) fn notify_ready(&mut self) {
        if let Some(ready) = self.inner.take() {
            ServiceReadyNotifier::notify_ready(ready);
        }
    }
}

#[async_trait]
pub(crate) trait FluxBackgroundTask: Send + Sync + 'static {
    async fn start(&self, shutdown: FluxShutdown, ready: FluxBackgroundReady);
}

pub(crate) struct FluxBackgroundService<T>
where
    T: FluxBackgroundTask,
{
    name: String,
    task: Arc<T>,
}

impl<T> FluxBackgroundService<T>
where
    T: FluxBackgroundTask,
{
    pub(crate) fn new(name: impl Into<String>, task: T) -> Self {
        Self {
            name: name.into(),
            task: Arc::new(task),
        }
    }

    #[cfg(feature = "load-balancer")]
    pub(crate) fn task(&self) -> Arc<T> {
        self.task.clone()
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
        self.task
            .start(FluxShutdown::new(shutdown), FluxBackgroundReady::new(ready))
            .await;
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}
