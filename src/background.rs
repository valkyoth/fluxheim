use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
#[cfg(unix)]
use pingora::server::ListenFds;
use pingora::server::ShutdownWatch;
use pingora::services::{ServiceReadyNotifier, ServiceWithDependents};
use tokio::sync::watch;

pub(crate) struct FluxShutdown {
    inner: watch::Receiver<bool>,
}

impl FluxShutdown {
    fn new(inner: watch::Receiver<bool>) -> Self {
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
    inner: Option<Box<dyn FnOnce() + Send + 'static>>,
}

impl FluxBackgroundReady {
    fn new(notify: impl FnOnce() + Send + 'static) -> Self {
        Self {
            inner: Some(Box::new(notify)),
        }
    }

    pub(crate) fn notify_ready(&mut self) {
        if let Some(notify) = self.inner.take() {
            notify();
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
            .start(
                FluxShutdown::new(shutdown),
                FluxBackgroundReady::new(move || ready.notify_ready()),
            )
            .await;
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}

#[cfg(test)]
mod tests {
    use super::{FluxBackgroundReady, FluxShutdown};
    use std::time::Duration;
    use tokio::sync::watch;

    #[tokio::test]
    async fn flux_shutdown_reports_shutdown_signal() {
        let (sender, receiver) = watch::channel(false);
        let mut shutdown = FluxShutdown::new(receiver);

        assert!(!shutdown.is_shutdown());
        sender.send(true).unwrap();

        assert!(shutdown.sleep_or_shutdown(Duration::from_secs(10)).await);
        assert!(shutdown.is_shutdown());
    }

    #[tokio::test]
    async fn flux_shutdown_treats_closed_sender_as_shutdown() {
        let (sender, receiver) = watch::channel(false);
        let mut shutdown = FluxShutdown::new(receiver);

        drop(sender);

        assert!(shutdown.sleep_or_shutdown(Duration::from_secs(10)).await);
    }

    #[tokio::test]
    async fn flux_shutdown_sleep_returns_false_when_delay_elapses() {
        let (_sender, receiver) = watch::channel(false);
        let mut shutdown = FluxShutdown::new(receiver);

        assert!(!shutdown.sleep_or_shutdown(Duration::from_millis(1)).await);
    }

    #[test]
    fn flux_background_ready_notifies_once() {
        let (sender, receiver) = watch::channel(false);
        let mut ready = FluxBackgroundReady::new(move || {
            let _ = sender.send(true);
        });

        ready.notify_ready();
        ready.notify_ready();

        assert!(*receiver.borrow());
    }
}
