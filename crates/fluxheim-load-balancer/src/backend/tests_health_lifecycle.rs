use super::*;
use crate::backend::FluxHealthCheck;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

struct Check {
    active: Arc<AtomicUsize>,
    members: Arc<Mutex<Vec<std::net::SocketAddr>>>,
    closed: Arc<AtomicUsize>,
}

struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl FluxHealthCheck for Check {
    async fn check(&self, _: &FluxBackend) -> FluxResult<()> {
        self.active.fetch_add(1, Ordering::SeqCst);
        let _active = Active(Arc::clone(&self.active));
        std::future::pending().await
    }
    fn health_threshold(&self, _: bool) -> usize {
        1
    }
    fn update_backends(&self, backends: &std::collections::BTreeSet<FluxBackend>) {
        *self.members.lock().unwrap() = backends.iter().map(|backend| backend.addr).collect();
    }
    fn close_connections(&self) {
        self.closed.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn health_membership_hooks_cover_discovery_add_remove_and_retarget() {
    let first = FluxBackend::new("127.0.0.1:3000").unwrap();
    let second = FluxBackend::new("127.0.0.1:3001").unwrap();
    let third = FluxBackend::new("127.0.0.1:3002").unwrap();
    let mut set = FluxBackendSet::default();
    set.insert(first.clone());
    let discovery = TestDiscovery::new(set);
    let discovered = Arc::clone(&discovery.backends);
    let members = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = FluxLoadBalancerRuntime::new(Box::new(discovery));
    runtime.set_health_check(Box::new(Check {
        active: Arc::default(),
        members: Arc::clone(&members),
        closed: Arc::default(),
    }));
    runtime.update().await.unwrap();
    assert_eq!(*members.lock().unwrap(), vec![first.addr]);
    runtime.add_runtime_backend(second.clone()).unwrap();
    assert_eq!(*members.lock().unwrap(), vec![first.addr, second.addr]);
    runtime.remove_runtime_backend(&first).unwrap();
    assert_eq!(*members.lock().unwrap(), vec![second.addr]);
    runtime
        .update_runtime_backend(&second, third.clone())
        .unwrap();
    assert_eq!(*members.lock().unwrap(), vec![third.addr]);
    let mut replacement = FluxBackendSet::default();
    replacement.insert(first.clone());
    *discovered.lock().unwrap() = replacement;
    runtime.update().await.unwrap();
    assert_eq!(*members.lock().unwrap(), vec![first.addr]);
}

#[tokio::test]
async fn cancelling_parallel_health_sweep_does_not_detach_probes() {
    let mut set = FluxBackendSet::default();
    for port in [3000, 3001] {
        set.insert(FluxBackend::new(&format!("127.0.0.1:{port}")).unwrap());
    }
    let active = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let mut runtime = FluxLoadBalancerRuntime::new(Box::new(TestDiscovery::new(set)));
    runtime.set_health_check(Box::new(Check {
        active: Arc::clone(&active),
        members: Arc::default(),
        closed: Arc::clone(&closed),
    }));
    runtime.update().await.unwrap();
    let runtime = Arc::new(runtime);
    let cloned = Arc::clone(&runtime);
    let task = tokio::spawn(async move { cloned.run_health_check(true).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while active.load(Ordering::SeqCst) != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(active.load(Ordering::SeqCst), 0);
    drop(crate::backend::CloseHealthConnections(
        &runtime.health_check,
    ));
    assert_eq!(closed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn shutdown_cancels_inflight_probes_and_closes_health_pool() {
    let mut set = FluxBackendSet::default();
    set.insert(FluxBackend::new("127.0.0.1:3000").unwrap());
    let active = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let mut runtime = FluxLoadBalancerRuntime::new(Box::new(TestDiscovery::new(set)));
    runtime.set_health_check(Box::new(Check {
        active: Arc::clone(&active),
        members: Arc::default(),
        closed: Arc::clone(&closed),
    }));
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        runtime
            .run(
                crate::background::FluxShutdown::new(receiver),
                crate::background::FluxBackgroundReady::new(|| {}),
            )
            .await;
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while active.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(closed.load(Ordering::SeqCst), 1);
}
