use std::io;
use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;

use super::{
    FluxBackend, FluxBackendDiscovery, FluxBackendSet, FluxLoadBalancerRuntime,
    MAX_RUNTIME_BACKEND_COUNT,
};
use crate::key::backend_key;
use fluxheim_common::{FluxError, FluxResult};

struct TestDiscovery {
    backends: Mutex<FluxBackendSet>,
    fail: Arc<Mutex<bool>>,
}

impl TestDiscovery {
    fn new(backends: FluxBackendSet) -> Self {
        Self {
            backends: Mutex::new(backends),
            fail: Arc::new(Mutex::new(false)),
        }
    }
}

#[async_trait]
impl FluxBackendDiscovery for TestDiscovery {
    async fn discover_flux_backends(&self) -> FluxResult<FluxBackendSet> {
        if *self
            .fail
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
        {
            return Err(FluxError::invalid_input("test discovery failure"));
        }
        Ok(self
            .backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone())
    }
}

#[tokio::test]
async fn update_publishes_backend_and_health_as_one_snapshot() {
    let backend = FluxBackend::new("127.0.0.1:3000").unwrap();
    let mut set = FluxBackendSet::default();
    set.insert(backend.clone());
    set.set_ready(&backend, false);
    let runtime = FluxLoadBalancerRuntime::new(Box::new(TestDiscovery::new(set)));

    runtime.update().await.unwrap();

    let snapshot = runtime.snapshot.load();
    let key = backend_key(&backend);
    assert!(snapshot.backends.contains(&backend));
    assert!(snapshot.health.contains_key(&key));
    assert!(!snapshot.health.get(&key).unwrap().ready());
}

#[tokio::test]
async fn runtime_retarget_starts_with_fresh_health_state() {
    let backend = FluxBackend::new("127.0.0.1:3000").unwrap();
    let updated = FluxBackend::new("127.0.0.1:3001").unwrap();
    let mut set = FluxBackendSet::default();
    set.insert(backend.clone());
    let runtime = FluxLoadBalancerRuntime::new(Box::new(TestDiscovery::new(set)));

    runtime.update().await.unwrap();
    runtime.set_enable(&backend, false);

    runtime
        .update_runtime_backend(&backend, updated.clone())
        .unwrap();

    let snapshot = runtime.snapshot.load();
    let current_key = backend_key(&backend);
    let updated_key = backend_key(&updated);
    assert!(!snapshot.backends.contains(&backend));
    assert!(snapshot.backends.contains(&updated));
    assert!(!snapshot.health.contains_key(&current_key));
    assert!(snapshot.health.get(&updated_key).unwrap().ready());
}

#[tokio::test]
async fn update_records_discovery_success_and_failure_status() {
    let backend = FluxBackend::new("127.0.0.1:3000").unwrap();
    let mut set = FluxBackendSet::default();
    set.insert(backend);
    let discovery = TestDiscovery::new(set);
    let fail = discovery.fail.clone();
    let runtime = FluxLoadBalancerRuntime::new(Box::new(discovery));

    runtime.update().await.unwrap();
    let success = runtime.discovery_runtime_status();
    assert!(!success.refresh_enabled);
    assert_eq!(success.success_count, 1);
    assert_eq!(success.failure_count, 0);
    assert!(success.last_success_unix_secs.is_some());
    assert!(success.last_error.is_none());

    *fail.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
    let error = runtime.update().await.unwrap_err();
    assert!(error.to_string().contains("test discovery failure"));
    let failure = runtime.discovery_runtime_status();
    assert_eq!(failure.success_count, 1);
    assert_eq!(failure.failure_count, 1);
    assert!(failure.last_failure_unix_secs.is_some());
    assert_eq!(
        failure.last_error.as_deref(),
        Some("test discovery failure")
    );
}

#[tokio::test]
async fn runtime_remove_rejects_last_backend_inside_mutation_lock() {
    let backend = FluxBackend::new("127.0.0.1:3000").unwrap();
    let mut set = FluxBackendSet::default();
    set.insert(backend.clone());
    let runtime = FluxLoadBalancerRuntime::new(Box::new(TestDiscovery::new(set)));

    runtime.update().await.unwrap();
    let error = runtime.remove_runtime_backend(&backend).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("at least one backend"));
    assert_eq!(runtime.snapshot.load().backends.len(), 1);
}

#[tokio::test]
async fn runtime_add_rejects_backend_set_over_limit() {
    let mut set = FluxBackendSet::default();
    for port in 10_000..10_000 + MAX_RUNTIME_BACKEND_COUNT {
        set.insert(FluxBackend::new(&format!("127.0.0.1:{port}")).unwrap());
    }
    let runtime = FluxLoadBalancerRuntime::new(Box::new(TestDiscovery::new(set)));

    runtime.update().await.unwrap();
    let extra = FluxBackend::new("127.0.0.1:20000").unwrap();
    let error = runtime.add_runtime_backend(extra).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("size limit"));
    assert_eq!(
        runtime.snapshot.load().backends.len(),
        MAX_RUNTIME_BACKEND_COUNT
    );
}
