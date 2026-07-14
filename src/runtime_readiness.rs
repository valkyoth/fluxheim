use std::io;

use futures::stream::{FuturesUnordered, StreamExt as _};
use tokio::sync::oneshot;

pub(super) struct BackgroundReadiness {
    waiters: Vec<(String, oneshot::Receiver<()>)>,
}

impl BackgroundReadiness {
    pub(super) const fn new() -> Self {
        Self {
            waiters: Vec::new(),
        }
    }

    pub(super) fn spawn<T>(
        &mut self,
        supervisor: &fluxheim_runtime::NativeBackgroundSupervisor,
        service: fluxheim_runtime::FluxBackgroundService<T>,
    ) -> fluxheim_runtime::NativeBackgroundJoinHandle
    where
        T: fluxheim_runtime::FluxBackgroundTask,
    {
        let name = service.name().to_owned();
        let (ready_tx, ready_rx) = oneshot::channel();
        self.waiters.push((name, ready_rx));
        supervisor.spawn_service_with_ready(service, move || {
            let _ = ready_tx.send(());
        })
    }

    pub(super) async fn wait(
        self,
        supervisor: &fluxheim_runtime::NativeBackgroundSupervisor,
    ) -> io::Result<()> {
        let mut waiters = FuturesUnordered::new();
        for (name, ready_rx) in self.waiters {
            waiters.push(async move {
                ready_rx.await.map_err(|_| {
                    io::Error::other(format!(
                        "background service {name} exited before reporting readiness"
                    ))
                })
            });
        }

        let mut shutdown = supervisor.shutdown_view();
        while !waiters.is_empty() {
            tokio::select! {
                result = waiters.next() => {
                    if let Some(result) = result {
                        result?;
                    }
                }
                _ = shutdown.wait_for_shutdown() => {
                    return Err(io::Error::other(
                        "native runtime shutdown was requested before startup completed",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(super) fn notify_ready() -> io::Result<()> {
    notify(&[
        libsystemd::daemon::NotifyState::Ready,
        libsystemd::daemon::NotifyState::Status("Fluxheim native runtime ready".to_owned()),
    ])
}

#[cfg(not(target_os = "linux"))]
pub(super) fn notify_ready() -> io::Result<()> {
    Ok(())
}

pub(super) fn notify_stopping() {
    if let Err(error) = notify_stopping_inner() {
        log::warn!(
            target: "fluxheim::native_runtime",
            "failed to notify service manager that Fluxheim is stopping: {error}"
        );
    }
}

#[cfg(target_os = "linux")]
fn notify_stopping_inner() -> io::Result<()> {
    notify(&[
        libsystemd::daemon::NotifyState::Stopping,
        libsystemd::daemon::NotifyState::Status("Fluxheim native runtime draining".to_owned()),
    ])
}

#[cfg(not(target_os = "linux"))]
fn notify_stopping_inner() -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn notify(states: &[libsystemd::daemon::NotifyState]) -> io::Result<()> {
    let configured = std::env::var_os("NOTIFY_SOCKET");
    if let Some(value) = configured.as_ref()
        && value.to_str().is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET is not valid Unicode",
        ));
    }
    let sent = libsystemd::daemon::notify(false, states)
        .map_err(|error| io::Error::other(error.to_string()))?;
    if configured.is_some() && !sent {
        return Err(io::Error::other(
            "NOTIFY_SOCKET was configured but no readiness datagram was sent",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ReadyTask;

    #[async_trait::async_trait]
    impl fluxheim_runtime::FluxBackgroundTask for ReadyTask {
        async fn start(
            &self,
            mut shutdown: fluxheim_runtime::FluxShutdown,
            mut ready: fluxheim_runtime::FluxBackgroundReady,
        ) {
            ready.notify_ready();
            let _ = shutdown.wait_for_shutdown().await;
        }
    }

    struct ExitsBeforeReadyTask;

    #[async_trait::async_trait]
    impl fluxheim_runtime::FluxBackgroundTask for ExitsBeforeReadyTask {
        async fn start(
            &self,
            _shutdown: fluxheim_runtime::FluxShutdown,
            _ready: fluxheim_runtime::FluxBackgroundReady,
        ) {
        }
    }

    #[tokio::test]
    async fn waits_for_background_service_readiness() {
        let supervisor = fluxheim_runtime::NativeBackgroundSupervisor::new();
        let mut readiness = BackgroundReadiness::new();
        let handle = readiness.spawn(
            &supervisor,
            fluxheim_runtime::FluxBackgroundService::new("ready-task", ReadyTask),
        );

        readiness.wait(&supervisor).await.unwrap();
        assert!(supervisor.shutdown());
        handle.join().await.unwrap();
    }

    #[tokio::test]
    async fn rejects_service_exit_before_readiness() {
        let supervisor = fluxheim_runtime::NativeBackgroundSupervisor::new();
        let mut readiness = BackgroundReadiness::new();
        let handle = readiness.spawn(
            &supervisor,
            fluxheim_runtime::FluxBackgroundService::new("not-ready-task", ExitsBeforeReadyTask),
        );

        let error = readiness.wait(&supervisor).await.unwrap_err();
        assert!(error.to_string().contains("not-ready-task exited"));
        handle.join().await.unwrap();
    }
}
