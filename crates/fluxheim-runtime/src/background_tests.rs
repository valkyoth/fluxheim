use super::*;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};

#[derive(Clone, Copy)]
struct StaticShutdown(ShutdownState);

impl ShutdownView for StaticShutdown {
    fn shutdown_state(&self) -> ShutdownState {
        self.0
    }
}

#[test]
fn shutdown_state_reports_running_and_requested() {
    assert!(!ShutdownState::running().is_requested());
    let requested = ShutdownState::requested(ShutdownReason::Signal);
    assert!(requested.is_requested());
    assert_eq!(requested.reason(), Some(ShutdownReason::Signal));
}

#[test]
fn shutdown_view_default_uses_state() {
    let view = StaticShutdown(ShutdownState::requested(ShutdownReason::Supervisor));
    assert!(view.is_shutdown_requested());
}

#[test]
fn background_task_spec_preserves_kind_name_and_criticality() {
    let spec = BackgroundTaskSpec::new(
        "load-balancer-refresh",
        BackgroundTaskKind::LoadBalancerRefresh,
    )
    .critical(true);

    assert_eq!(spec.name(), "load-balancer-refresh");
    assert_eq!(spec.kind(), BackgroundTaskKind::LoadBalancerRefresh);
    assert!(spec.is_critical());
}

#[test]
fn background_service_preserves_task_kind() {
    struct Task;

    let service = FluxBackgroundService::with_kind("cache", BackgroundTaskKind::CacheMetrics, Task);

    assert_eq!(service.name(), "cache");
    assert_eq!(service.kind(), Some(BackgroundTaskKind::CacheMetrics));
    assert!(!service.is_critical());
}

#[tokio::test]
async fn native_background_supervisor_runs_service_until_shutdown() {
    struct ShutdownAwareTask {
        finished: mpsc::Sender<bool>,
    }

    #[async_trait]
    impl FluxBackgroundTask for ShutdownAwareTask {
        async fn start(&self, mut shutdown: FluxShutdown, mut ready: FluxBackgroundReady) {
            ready.notify_ready();
            let stopped_by_shutdown = shutdown.sleep_or_shutdown(Duration::from_secs(10)).await;
            self.finished.send(stopped_by_shutdown).await.unwrap();
        }
    }

    let supervisor = NativeBackgroundSupervisor::new();
    let (ready_tx, mut ready_rx) = watch::channel(false);
    let (finished_tx, mut finished_rx) = mpsc::channel(1);
    let service = FluxBackgroundService::from_spec(
        BackgroundTaskSpec::new("test-task", BackgroundTaskKind::MetricsExport),
        ShutdownAwareTask {
            finished: finished_tx,
        },
    );

    let handle = supervisor.spawn_service_with_ready(service, move || {
        let _ = ready_tx.send(true);
    });

    assert_eq!(handle.name(), "test-task");
    assert_eq!(handle.kind(), Some(BackgroundTaskKind::MetricsExport));
    ready_rx.changed().await.unwrap();
    assert!(*ready_rx.borrow());
    assert!(supervisor.shutdown());
    assert!(finished_rx.recv().await.unwrap());
    handle.join().await.unwrap();
}

#[tokio::test]
async fn native_background_supervisor_preserves_untyped_service_metadata() {
    struct ReadyTask;

    #[async_trait]
    impl FluxBackgroundTask for ReadyTask {
        async fn start(&self, _shutdown: FluxShutdown, mut ready: FluxBackgroundReady) {
            ready.notify_ready();
        }
    }

    let supervisor = NativeBackgroundSupervisor::new();
    let (ready_tx, mut ready_rx) = watch::channel(false);
    let service = FluxBackgroundService::new("untyped-task", ReadyTask);

    let handle = supervisor.spawn_service_with_ready(service, move || {
        let _ = ready_tx.send(true);
    });

    assert_eq!(handle.name(), "untyped-task");
    assert_eq!(handle.kind(), None);
    ready_rx.changed().await.unwrap();
    assert!(*ready_rx.borrow());
    handle.join().await.unwrap();
}

#[tokio::test]
async fn native_background_supervisor_spawns_raw_background_future() {
    let supervisor = NativeBackgroundSupervisor::new();
    let (sender, mut receiver) = mpsc::channel(1);
    let spec = BackgroundTaskSpec::new("raw-task", BackgroundTaskKind::CacheMetrics).critical(true);

    let handle = supervisor.spawn_background(spec, async move {
        sender.send(7_u8).await.unwrap();
    });

    assert_eq!(handle.name(), "raw-task");
    assert_eq!(handle.kind(), Some(BackgroundTaskKind::CacheMetrics));
    assert!(handle.is_critical());
    assert_eq!(receiver.recv().await, Some(7));
    handle.join().await.unwrap();
}

#[tokio::test]
async fn native_background_join_handle_aborts_task_on_drop() {
    struct DropNotify(Option<oneshot::Sender<()>>);

    impl Drop for DropNotify {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    let supervisor = NativeBackgroundSupervisor::new();
    let (ready_tx, ready_rx) = oneshot::channel();
    let (drop_tx, drop_rx) = oneshot::channel();
    let handle = supervisor.spawn_background(
        BackgroundTaskSpec::new("detached-task", BackgroundTaskKind::CacheMetrics),
        async move {
            let _drop_notify = DropNotify(Some(drop_tx));
            let _ = ready_tx.send(());
            std::future::pending::<()>().await;
        },
    );

    ready_rx
        .await
        .expect("task should start before handle drop");
    drop(handle);

    tokio::time::timeout(Duration::from_secs(10), drop_rx)
        .await
        .expect("dropped handle should abort task")
        .expect("task drop notifier should send");
}

#[tokio::test]
async fn native_background_join_handle_aborts_task_when_join_future_is_cancelled() {
    struct DropNotify(Option<oneshot::Sender<()>>);

    impl Drop for DropNotify {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    let supervisor = NativeBackgroundSupervisor::new();
    let (ready_tx, ready_rx) = oneshot::channel();
    let (drop_tx, drop_rx) = oneshot::channel();
    let handle = supervisor.spawn_background(
        BackgroundTaskSpec::new("joined-task", BackgroundTaskKind::CacheMetrics),
        async move {
            let _drop_notify = DropNotify(Some(drop_tx));
            let _ = ready_tx.send(());
            std::future::pending::<()>().await;
        },
    );

    ready_rx
        .await
        .expect("task should start before join future cancellation");
    let join_task = tokio::spawn(handle.join());
    join_task.abort();

    tokio::time::timeout(Duration::from_secs(10), drop_rx)
        .await
        .expect("cancelled join future should abort task")
        .expect("task drop notifier should send");
}

#[tokio::test]
async fn native_background_supervisor_pre_spawn_shutdown_reaches_new_views() {
    let supervisor = NativeBackgroundSupervisor::new();

    assert!(supervisor.shutdown());
    let mut shutdown = supervisor.shutdown_view();

    assert!(shutdown.wait_for_shutdown().await);
    assert!(shutdown.is_shutdown());
}

#[tokio::test]
async fn native_background_supervisor_shutdown_waiter_observes_shutdown() {
    let supervisor = NativeBackgroundSupervisor::new();
    let mut shutdown = supervisor.shutdown_view();
    let waiter = tokio::spawn(async move { shutdown.wait_for_shutdown().await });

    assert!(supervisor.shutdown());
    assert!(waiter.await.unwrap());

    let mut shutdown = supervisor.shutdown_view();
    assert!(shutdown.sleep_or_shutdown(Duration::from_secs(10)).await);
    assert!(shutdown.is_shutdown());
}

#[tokio::test]
async fn native_background_supervisor_last_drop_requests_shutdown() {
    let supervisor = NativeBackgroundSupervisor::new();
    let mut shutdown = supervisor.shutdown_view();

    drop(supervisor);

    assert!(shutdown.sleep_or_shutdown(Duration::from_secs(10)).await);
    assert!(shutdown.is_shutdown());
}

#[tokio::test]
async fn native_background_supervisor_clone_drop_does_not_request_shutdown() {
    let supervisor = NativeBackgroundSupervisor::new();
    let mut shutdown = supervisor.shutdown_view();

    drop(supervisor.clone());

    assert!(!shutdown.sleep_or_shutdown(Duration::from_millis(1)).await);
    assert!(!shutdown.is_shutdown());
}

#[tokio::test]
async fn native_background_supervisor_watchdog_shutdowns_on_critical_exit() {
    let supervisor = NativeBackgroundSupervisor::new();
    let shutdown = supervisor.shutdown_view();
    let critical = supervisor.spawn_background(
        BackgroundTaskSpec::new("critical-task", BackgroundTaskKind::MetricsExport).critical(true),
        async {},
    );

    let watchdog = supervisor.spawn_critical_watchdog(vec![critical]);

    watchdog.join().await.unwrap();
    assert!(shutdown.is_shutdown());
}

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
