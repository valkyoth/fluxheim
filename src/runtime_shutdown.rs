use std::time::Duration;

const DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS: u64 = 30;

pub(super) fn native_runtime_shutdown_grace(
    process: &fluxheim_server::ProcessSpec,
) -> Option<Duration> {
    process.grace_period_seconds().map(Duration::from_secs)
}

pub(super) fn native_runtime_shutdown_timeout(process: &fluxheim_server::ProcessSpec) -> Duration {
    Duration::from_secs(
        process
            .graceful_shutdown_timeout_seconds()
            .unwrap_or(DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS),
    )
}

pub(super) async fn wait_native_runtime_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = signal(SignalKind::terminate()).ok();
        let mut quit = signal(SignalKind::quit()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                if let Some(signal) = &mut terminate {
                    let _ = signal.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
            _ = async {
                if let Some(signal) = &mut quit {
                    let _ = signal.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
        }
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows::{ctrl_break, ctrl_c};

        let mut interrupt = ctrl_c().map_or_else(
            |error| {
                log::warn!("failed to register Windows CTRL_C shutdown handler: {error}");
                None
            },
            Some,
        );
        let mut terminate = ctrl_break().map_or_else(
            |error| {
                log::warn!("failed to register Windows CTRL_BREAK shutdown handler: {error}");
                None
            },
            Some,
        );
        tokio::select! {
            _ = async {
                if let Some(signal) = &mut interrupt {
                    let _ = signal.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
            _ = async {
                if let Some(signal) = &mut terminate {
                    let _ = signal.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
