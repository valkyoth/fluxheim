#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub mod policy;

pub use policy::{
    PolicyEpoch, PolicyProof, RuntimeDecision, RuntimeDecisionKind, RuntimeDecisionReason,
    RuntimeFact, RuntimeFactKind, RuntimeFactVisibility,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownReason {
    Signal,
    Supervisor,
    Fatal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownState {
    requested: bool,
    reason: Option<ShutdownReason>,
}

impl ShutdownState {
    pub const fn running() -> Self {
        Self {
            requested: false,
            reason: None,
        }
    }

    pub const fn requested(reason: ShutdownReason) -> Self {
        Self {
            requested: true,
            reason: Some(reason),
        }
    }

    pub const fn is_requested(self) -> bool {
        self.requested
    }

    pub const fn reason(self) -> Option<ShutdownReason> {
        self.reason
    }
}

pub trait ShutdownView {
    fn shutdown_state(&self) -> ShutdownState;

    fn is_shutdown_requested(&self) -> bool {
        self.shutdown_state().is_requested()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackgroundTaskKind {
    AcmeRenewal,
    CacheMetrics,
    CacheStalePurge,
    CertificateReload,
    LoadBalancerRefresh,
    MetricsExport,
    RuntimeWatchdog,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackgroundTaskSpec {
    name: &'static str,
    kind: BackgroundTaskKind,
    critical: bool,
}

impl BackgroundTaskSpec {
    pub const fn new(name: &'static str, kind: BackgroundTaskKind) -> Self {
        Self {
            name,
            kind,
            critical: false,
        }
    }

    pub const fn critical(mut self, critical: bool) -> Self {
        self.critical = critical;
        self
    }

    pub const fn name(self) -> &'static str {
        self.name
    }

    pub const fn kind(self) -> BackgroundTaskKind {
        self.kind
    }

    pub const fn is_critical(self) -> bool {
        self.critical
    }
}

pub trait BackgroundTaskSpawner {
    type JoinHandle;

    fn spawn_background<F>(&self, spec: BackgroundTaskSpec, task: F) -> Self::JoinHandle
    where
        F: Future<Output = ()> + Send + 'static;
}

#[derive(Debug)]
pub struct NativeBackgroundJoinHandle {
    name: String,
    kind: Option<BackgroundTaskKind>,
    critical: bool,
    handle: Option<JoinHandle<()>>,
}

impl NativeBackgroundJoinHandle {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn kind(&self) -> Option<BackgroundTaskKind> {
        self.kind
    }

    pub const fn is_critical(&self) -> bool {
        self.critical
    }

    pub fn is_finished(&self) -> bool {
        self.handle.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// Abort the underlying task.
    ///
    /// # Warning
    ///
    /// If this handle is critical and has been registered with
    /// [`NativeBackgroundSupervisor::spawn_critical_watchdog`], aborting the
    /// task causes the watchdog to request process-wide shutdown. Prefer
    /// graceful shutdown through [`NativeBackgroundSupervisor::shutdown`] unless
    /// local cancellation is explicitly intended.
    pub fn abort(&self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }

    pub async fn join(mut self) -> Result<(), tokio::task::JoinError> {
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        AbortOnCancelJoin::new(handle).await
    }
}

impl Drop for NativeBackgroundJoinHandle {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

struct AbortOnCancelJoin {
    handle: Option<JoinHandle<()>>,
}

impl AbortOnCancelJoin {
    fn new(handle: JoinHandle<()>) -> Self {
        Self {
            handle: Some(handle),
        }
    }
}

impl Future for AbortOnCancelJoin {
    type Output = Result<(), tokio::task::JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(handle) = self.handle.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let result = std::task::ready!(Pin::new(handle).poll(cx));
        self.handle.take();
        Poll::Ready(result)
    }
}

impl Drop for AbortOnCancelJoin {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

#[derive(Clone)]
pub struct NativeBackgroundSupervisor {
    inner: Arc<NativeBackgroundSupervisorInner>,
}

struct NativeBackgroundSupervisorInner {
    shutdown_tx: watch::Sender<bool>,
}

impl Drop for NativeBackgroundSupervisorInner {
    fn drop(&mut self) {
        self.shutdown_tx.send_replace(true);
    }
}

impl NativeBackgroundSupervisor {
    pub fn new() -> Self {
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        Self {
            inner: Arc::new(NativeBackgroundSupervisorInner { shutdown_tx }),
        }
    }

    #[must_use = "returns false if shutdown was already in progress; true if this call initiated it"]
    pub fn shutdown(&self) -> bool {
        !self.inner.shutdown_tx.send_replace(true)
    }

    pub fn shutdown_view(&self) -> FluxShutdown {
        FluxShutdown::new(self.inner.shutdown_tx.subscribe())
    }

    pub fn spawn_service<T>(&self, service: FluxBackgroundService<T>) -> NativeBackgroundJoinHandle
    where
        T: FluxBackgroundTask,
    {
        self.spawn_service_with_ready(service, || {})
    }

    pub fn spawn_service_with_ready<T>(
        &self,
        service: FluxBackgroundService<T>,
        ready: impl FnOnce() + Send + 'static,
    ) -> NativeBackgroundJoinHandle
    where
        T: FluxBackgroundTask,
    {
        let name = service.name().to_owned();
        let kind = service.kind();
        let critical = service.is_critical();
        let task = service.task();
        let shutdown = self.shutdown_view();
        let handle = tokio::spawn(async move {
            task.start(shutdown, FluxBackgroundReady::new(ready)).await;
        });

        NativeBackgroundJoinHandle {
            name,
            kind,
            critical,
            handle: Some(handle),
        }
    }

    /// Spawn a watchdog task that requests shutdown when any critical task exits.
    ///
    /// The returned handle represents the watchdog task itself. Do not register
    /// that handle with another watchdog: its exit only means all watched tasks
    /// have exited, not that an independent service failed.
    pub fn spawn_critical_watchdog<I>(&self, handles: I) -> NativeBackgroundJoinHandle
    where
        I: IntoIterator<Item = NativeBackgroundJoinHandle>,
    {
        let watchers = handles
            .into_iter()
            .filter(|handle| handle.is_critical())
            .map(|handle| {
                let supervisor = self.clone();
                tokio::spawn(async move {
                    let _ = handle.join().await;
                    let _ = supervisor.shutdown();
                })
            })
            .collect::<Vec<_>>();
        let handle = tokio::spawn(async move {
            for watcher in watchers {
                let _ = watcher.await;
            }
        });

        NativeBackgroundJoinHandle {
            name: "critical-background-watchdog".to_owned(),
            kind: Some(BackgroundTaskKind::RuntimeWatchdog),
            critical: true,
            handle: Some(handle),
        }
    }
}

impl Default for NativeBackgroundSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl BackgroundTaskSpawner for NativeBackgroundSupervisor {
    type JoinHandle = NativeBackgroundJoinHandle;

    fn spawn_background<F>(&self, spec: BackgroundTaskSpec, task: F) -> Self::JoinHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        NativeBackgroundJoinHandle {
            name: spec.name().to_owned(),
            kind: Some(spec.kind()),
            critical: spec.is_critical(),
            handle: Some(tokio::spawn(task)),
        }
    }
}

#[derive(Clone)]
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

    /// Wait until shutdown is requested.
    ///
    /// This method is cancellation-safe for use inside `tokio::select!`: if a
    /// caller drops the wait future after a notification is delivered, the next
    /// call still observes the latest state before waiting again.
    pub async fn wait_for_shutdown(&mut self) -> bool {
        loop {
            if *self.inner.borrow_and_update() {
                return true;
            }
            if self.inner.changed().await.is_err() {
                return true;
            }
        }
    }

    pub async fn sleep_or_shutdown(&mut self, delay: Duration) -> bool {
        if self.is_shutdown() {
            return true;
        }
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

#[async_trait]
pub trait FluxBackgroundTask: Send + Sync + 'static {
    async fn start(&self, shutdown: FluxShutdown, ready: FluxBackgroundReady);
}

pub struct FluxBackgroundService<T> {
    name: String,
    kind: Option<BackgroundTaskKind>,
    critical: bool,
    task: Arc<T>,
}

impl<T> FluxBackgroundService<T> {
    pub fn new(name: impl Into<String>, task: T) -> Self {
        Self {
            name: name.into(),
            kind: None,
            critical: false,
            task: Arc::new(task),
        }
    }

    pub fn from_spec(spec: BackgroundTaskSpec, task: T) -> Self {
        Self {
            name: spec.name().to_owned(),
            kind: Some(spec.kind()),
            critical: spec.is_critical(),
            task: Arc::new(task),
        }
    }

    pub fn with_kind(name: impl Into<String>, kind: BackgroundTaskKind, task: T) -> Self {
        Self {
            name: name.into(),
            kind: Some(kind),
            critical: false,
            task: Arc::new(task),
        }
    }

    pub fn task(&self) -> Arc<T> {
        self.task.clone()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> Option<BackgroundTaskKind> {
        self.kind
    }

    pub fn is_critical(&self) -> bool {
        self.critical
    }

    /// Pingora compatibility only. The native `NativeBackgroundSupervisor`
    /// ignores this value; remove it after the `1.6.24` Pingora exit.
    #[deprecated(
        since = "1.6.21",
        note = "Pingora compatibility only; native supervisor ignores thread count"
    )]
    pub fn threads(&self) -> Option<usize> {
        Some(1)
    }
}

pub fn background_service<T>(name: impl Into<String>, task: T) -> FluxBackgroundService<T> {
    FluxBackgroundService::new(name, task)
}

pub fn background_service_with_kind<T>(
    name: impl Into<String>,
    kind: BackgroundTaskKind,
    task: T,
) -> FluxBackgroundService<T> {
    FluxBackgroundService::with_kind(name, kind, task)
}

#[cfg(test)]
mod tests {
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

        let service =
            FluxBackgroundService::with_kind("cache", BackgroundTaskKind::CacheMetrics, Task);

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
        let spec =
            BackgroundTaskSpec::new("raw-task", BackgroundTaskKind::CacheMetrics).critical(true);

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
            BackgroundTaskSpec::new("critical-task", BackgroundTaskKind::MetricsExport)
                .critical(true),
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
}
