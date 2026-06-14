use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

pub struct FluxShutdown {
    inner: watch::Receiver<bool>,
}

impl FluxShutdown {
    pub fn new(inner: watch::Receiver<bool>) -> Self {
        Self { inner }
    }

    pub fn is_shutdown(&self) -> bool {
        *self.inner.borrow()
    }

    pub async fn sleep_or_shutdown(&mut self, delay: Duration) -> bool {
        match tokio::time::timeout(delay, self.inner.changed()).await {
            Ok(Ok(())) => self.is_shutdown(),
            Ok(Err(_closed)) => true,
            Err(_elapsed) => false,
        }
    }
}

pub struct FluxBackgroundReady {
    inner: Option<Box<dyn FnOnce() + Send + 'static>>,
}

impl FluxBackgroundReady {
    pub fn new(notify: impl FnOnce() + Send + 'static) -> Self {
        Self {
            inner: Some(Box::new(notify)),
        }
    }

    pub fn notify_ready(&mut self) {
        if let Some(notify) = self.inner.take() {
            notify();
        }
    }
}

pub struct FluxBackgroundService<T> {
    name: String,
    task: Arc<T>,
}

impl<T> FluxBackgroundService<T> {
    pub(crate) fn new(name: impl Into<String>, task: T) -> Self {
        Self {
            name: name.into(),
            task: Arc::new(task),
        }
    }

    pub(crate) fn task(&self) -> Arc<T> {
        self.task.clone()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn threads(&self) -> Option<usize> {
        Some(1)
    }
}

pub(crate) fn background_service<T>(name: impl Into<String>, task: T) -> FluxBackgroundService<T> {
    FluxBackgroundService::new(name, task)
}
