use std::error::Error;
use std::time::Duration;

pub(super) struct NativeRuntimeTasks {
    proxy: Option<fluxheim_server::NativeHttp1ProxyRuntimeHandle>,
    admin: super::runtime_admin::NativeAdminListenerTasks,
    background: Vec<fluxheim_runtime::NativeBackgroundJoinHandle>,
    watchdog: Option<fluxheim_runtime::NativeBackgroundJoinHandle>,
}

impl NativeRuntimeTasks {
    pub(super) fn new(
        proxy: Option<fluxheim_server::NativeHttp1ProxyRuntimeHandle>,
        admin: super::runtime_admin::NativeAdminListenerTasks,
        background: Vec<fluxheim_runtime::NativeBackgroundJoinHandle>,
        watchdog: fluxheim_runtime::NativeBackgroundJoinHandle,
    ) -> Self {
        Self {
            proxy,
            admin,
            background,
            watchdog: Some(watchdog),
        }
    }

    pub(super) async fn drain(
        &mut self,
        timeout: Duration,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let result = tokio::time::timeout(timeout, self.join()).await;
        match result {
            Ok(result) => result?,
            Err(_) => {
                self.abort_all();
                log::warn!(
                    target: "fluxheim::native_runtime",
                    "native runtime graceful drain timed out after {}s; remaining work aborted",
                    timeout.as_secs()
                );
            }
        }
        if let Some(watchdog) = self.watchdog.take() {
            watchdog.abort();
            let _ = watchdog.join().await;
        }
        Ok(())
    }

    fn abort_all(&mut self) {
        if let Some(proxy) = &self.proxy {
            proxy.abort_all();
        }
        self.admin.abort_all();
        for handle in &self.background {
            handle.abort();
        }
    }

    async fn join(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Some(proxy) = self.proxy.take() {
            for result in proxy.join().await {
                result?;
            }
        }
        self.admin.join().await?;
        while let Some(handle) = self.background.pop() {
            handle.join().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    struct Dropped(Arc<AtomicBool>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn drain_timeout_aborts_outstanding_listener_tasks() {
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = dropped.clone();
        let mut admin = super::super::runtime_admin::NativeAdminListenerTasks::new();
        admin.spawn(async move {
            let _dropped = Dropped(task_dropped);
            std::future::pending::<()>().await;
            Ok(())
        });
        let supervisor = fluxheim_runtime::NativeBackgroundSupervisor::new();
        let watchdog = supervisor.spawn_critical_watchdog(Vec::new());
        let mut tasks = NativeRuntimeTasks::new(None, admin, Vec::new(), watchdog);

        tasks.drain(Duration::from_millis(10)).await.unwrap();
        tokio::task::yield_now().await;

        assert!(dropped.load(Ordering::Acquire));
    }
}
