use std::collections::{BTreeSet, HashMap};
use std::io;
use std::process;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use super::LoadBalancerMetricLabels;
pub(crate) use super::backend_model::BackendIdentity;
pub(super) use super::backend_model::{FluxBackend, FluxBackendSet};
use super::key::backend_key;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use fluxheim_common::{FluxError, FluxResult};
use futures::future;

pub type RuntimeBackend = FluxBackend;

pub(super) const MAX_RUNTIME_BACKEND_COUNT: usize = 256;
const MAX_DISCOVERY_ERROR_BYTES: usize = 256;

#[async_trait]
pub(super) trait FluxBackendDiscovery: Send + Sync + 'static {
    async fn discover_flux_backends(&self) -> FluxResult<FluxBackendSet>;
}

#[async_trait]
pub(super) trait FluxHealthCheck: Send + Sync + 'static {
    async fn check(&self, target: &RuntimeBackend) -> FluxResult<()>;

    fn health_threshold(&self, success: bool) -> usize;

    async fn health_status_change(&self, _target: &RuntimeBackend, _healthy: bool) {}

    fn backend_summary(&self, target: &RuntimeBackend) -> String {
        format!("{target:?}")
    }
}

struct FluxBackendHealthInner {
    healthy: bool,
    enabled: bool,
    consecutive_counter: usize,
}

#[derive(Clone)]
struct FluxBackendHealth(Arc<Mutex<FluxBackendHealthInner>>);

impl Default for FluxBackendHealth {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(FluxBackendHealthInner {
            healthy: true,
            enabled: true,
            consecutive_counter: 0,
        })))
    }
}

impl FluxBackendHealth {
    fn lock(&self) -> std::sync::MutexGuard<'_, FluxBackendHealthInner> {
        self.0.lock().unwrap_or_else(|_| process::abort())
    }

    fn ready(&self) -> bool {
        let health = self.lock();
        health.healthy && health.enabled
    }

    fn enable(&self, enabled: bool) {
        self.lock().enabled = enabled;
    }

    fn observe(&self, healthy: bool, flip_threshold: usize) -> bool {
        let mut health = self.lock();
        if health.healthy != healthy {
            health.consecutive_counter = health.consecutive_counter.saturating_add(1);
            if health.consecutive_counter >= flip_threshold {
                health.healthy = healthy;
                health.consecutive_counter = 0;
                return true;
            }
        } else {
            health.consecutive_counter = 0;
        }
        false
    }
}

#[derive(Default)]
struct FluxBackendSnapshot {
    backends: Arc<BTreeSet<RuntimeBackend>>,
    health: Arc<HashMap<u64, FluxBackendHealth>>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct FluxBackendDiscoveryRuntimeStatus {
    pub(super) refresh_enabled: bool,
    pub(super) update_frequency_secs: Option<u64>,
    pub(super) success_count: u64,
    pub(super) failure_count: u64,
    pub(super) last_success_unix_secs: Option<u64>,
    pub(super) last_failure_unix_secs: Option<u64>,
    pub(super) last_error: Option<String>,
}

#[derive(Default)]
struct FluxBackendDiscoveryRuntimeState {
    success_count: u64,
    failure_count: u64,
    last_success_unix_secs: Option<u64>,
    last_failure_unix_secs: Option<u64>,
    last_error: Option<String>,
}

pub struct FluxLoadBalancerRuntime {
    discovery: Arc<dyn FluxBackendDiscovery>,
    health_check: Option<Arc<dyn FluxHealthCheck>>,
    snapshot: ArcSwap<FluxBackendSnapshot>,
    discovery_state: Mutex<FluxBackendDiscoveryRuntimeState>,
    metric_labels: Option<LoadBalancerMetricLabels>,
    mutation_lock: Mutex<()>,
    update_frequency: Option<Duration>,
    health_check_frequency: Option<Duration>,
    parallel_health_check: bool,
}

impl FluxLoadBalancerRuntime {
    pub(super) fn new(discovery: Box<dyn FluxBackendDiscovery>) -> Self {
        Self {
            discovery: discovery.into(),
            health_check: None,
            snapshot: Default::default(),
            discovery_state: Mutex::new(FluxBackendDiscoveryRuntimeState::default()),
            metric_labels: None,
            mutation_lock: Mutex::new(()),
            update_frequency: None,
            health_check_frequency: None,
            parallel_health_check: false,
        }
    }

    pub(super) fn set_update_frequency(&mut self, frequency: Option<Duration>) {
        self.update_frequency = frequency;
    }

    pub(super) fn set_health_check(&mut self, health_check: Box<dyn FluxHealthCheck>) {
        self.health_check = Some(health_check.into());
    }

    pub(super) fn set_health_check_frequency(&mut self, frequency: Option<Duration>) {
        self.health_check_frequency = frequency;
    }

    pub(super) fn set_parallel_health_check(&mut self, parallel: bool) {
        self.parallel_health_check = parallel;
    }

    pub(super) fn set_metric_labels(&mut self, labels: LoadBalancerMetricLabels) {
        self.metric_labels = Some(labels);
    }

    pub(super) async fn update(&self) -> FluxResult<()> {
        let result = self.update_inner().await;
        self.record_discovery_result(&result);
        result
    }

    async fn update_inner(&self) -> FluxResult<()> {
        let discovered = self.discovery.discover_flux_backends().await?;
        let (new_backends, enablement) = discovered.into_parts();
        let snapshot = self.snapshot.load();
        if *snapshot.backends != new_backends {
            let old_health = Arc::clone(&snapshot.health);
            let mut next_health = HashMap::with_capacity(new_backends.len());
            for backend in &new_backends {
                let key = backend_key(backend);
                let backend_health = old_health.get(&key).cloned().unwrap_or_default();
                if let Some(enabled) = enablement.get(&key) {
                    backend_health.enable(*enabled);
                }
                next_health.insert(key, backend_health);
            }
            self.snapshot.store(Arc::new(FluxBackendSnapshot {
                backends: Arc::new(new_backends),
                health: Arc::new(next_health),
            }));
        } else {
            for (key, enabled) in enablement {
                if let Some(backend_health) = snapshot.health.get(&key) {
                    backend_health.enable(enabled);
                }
            }
        }
        Ok(())
    }

    fn record_discovery_result(&self, result: &FluxResult<()>) {
        let now = unix_timestamp_secs();
        let event = {
            let mut state = self
                .discovery_state
                .lock()
                .unwrap_or_else(|_| process::abort());
            match result {
                Ok(()) => {
                    state.success_count = state.success_count.saturating_add(1);
                    state.last_success_unix_secs = Some(now);
                    state.last_error = None;
                    "discovery_success"
                }
                Err(error) => {
                    state.failure_count = state.failure_count.saturating_add(1);
                    state.last_failure_unix_secs = Some(now);
                    state.last_error = Some(bounded_discovery_error(error));
                    "discovery_failure"
                }
            }
        };
        self.record_discovery_metric(event);
    }

    fn record_discovery_metric(&self, event: &str) {
        #[cfg(feature = "metrics")]
        if let Some(labels) = &self.metric_labels {
            crate::metrics::record_load_balancer_event(labels.vhost(), labels.route(), None, event);
        }
        #[cfg(not(feature = "metrics"))]
        {
            if let Some(labels) = &self.metric_labels {
                let _ = (&labels.vhost, &labels.route);
            }
            let _ = event;
        }
    }

    pub(super) fn discovery_runtime_status(&self) -> FluxBackendDiscoveryRuntimeStatus {
        let state = self
            .discovery_state
            .lock()
            .unwrap_or_else(|_| process::abort());
        FluxBackendDiscoveryRuntimeStatus {
            refresh_enabled: self.update_frequency.is_some(),
            update_frequency_secs: self.update_frequency.map(|frequency| frequency.as_secs()),
            success_count: state.success_count,
            failure_count: state.failure_count,
            last_success_unix_secs: state.last_success_unix_secs,
            last_failure_unix_secs: state.last_failure_unix_secs,
            last_error: state.last_error.clone(),
        }
    }

    pub(super) fn set_enable(&self, backend: &RuntimeBackend, enabled: bool) {
        if let Some(backend_health) = self.snapshot.load().health.get(&backend_key(backend)) {
            backend_health.enable(enabled);
        }
    }

    pub(super) fn runtime_backend_set_mutable(&self) -> bool {
        self.update_frequency.is_none()
    }

    pub(super) fn add_runtime_backend(&self, backend: RuntimeBackend) -> io::Result<usize> {
        if !self.runtime_backend_set_mutable() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime backend-set mutation is available only for static upstream pools",
            ));
        }
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let snapshot = self.snapshot.load_full();
        let key = backend_key(&backend);
        if snapshot
            .backends
            .iter()
            .any(|existing| backend_key(existing) == key)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "load balancer member is already configured in this pool",
            ));
        }
        if snapshot.backends.len() >= MAX_RUNTIME_BACKEND_COUNT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "load balancer backend-set size limit reached; remove a member before adding another",
            ));
        }

        let mut next_backends = (*snapshot.backends).clone();
        next_backends.insert(backend);
        let mut next_health = (*snapshot.health).clone();
        next_health.entry(key).or_default();
        let backend_count = next_backends.len();
        self.snapshot.store(Arc::new(FluxBackendSnapshot {
            backends: Arc::new(next_backends),
            health: Arc::new(next_health),
        }));
        Ok(backend_count)
    }

    pub(super) fn remove_runtime_backend(&self, backend: &RuntimeBackend) -> io::Result<usize> {
        if !self.runtime_backend_set_mutable() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime backend-set mutation is available only for static upstream pools",
            ));
        }
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let snapshot = self.snapshot.load_full();
        let key = backend_key(backend);
        if snapshot.backends.len() <= 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "load balancer member cannot be removed because at least one backend must remain",
            ));
        }
        if !snapshot
            .backends
            .iter()
            .any(|existing| backend_key(existing) == key)
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "load balancer member is not configured in this pool",
            ));
        }

        let mut next_backends = (*snapshot.backends).clone();
        next_backends.retain(|existing| backend_key(existing) != key);
        let mut next_health = (*snapshot.health).clone();
        next_health.remove(&key);
        let backend_count = next_backends.len();
        self.snapshot.store(Arc::new(FluxBackendSnapshot {
            backends: Arc::new(next_backends),
            health: Arc::new(next_health),
        }));
        Ok(backend_count)
    }

    pub(super) fn update_runtime_backend(
        &self,
        current: &RuntimeBackend,
        updated: RuntimeBackend,
    ) -> io::Result<usize> {
        if !self.runtime_backend_set_mutable() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime backend-set mutation is available only for static upstream pools",
            ));
        }
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let snapshot = self.snapshot.load_full();
        let current_key = backend_key(current);
        let updated_key = backend_key(&updated);
        if !snapshot
            .backends
            .iter()
            .any(|existing| backend_key(existing) == current_key)
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "load balancer member is not configured in this pool",
            ));
        }
        if current_key != updated_key
            && snapshot
                .backends
                .iter()
                .any(|existing| backend_key(existing) == updated_key)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "updated load balancer member address is already configured in this pool",
            ));
        }

        let mut next_backends = (*snapshot.backends).clone();
        next_backends.retain(|existing| backend_key(existing) != current_key);
        next_backends.insert(updated);
        let mut next_health = (*snapshot.health).clone();
        if current_key != updated_key {
            next_health.remove(&current_key);
            next_health.entry(updated_key).or_default();
        } else {
            next_health.entry(updated_key).or_default();
        }
        let backend_count = next_backends.len();
        self.snapshot.store(Arc::new(FluxBackendSnapshot {
            backends: Arc::new(next_backends),
            health: Arc::new(next_health),
        }));
        Ok(backend_count)
    }

    pub(super) async fn run(
        &self,
        mut shutdown: crate::background::FluxShutdown,
        mut ready: crate::background::FluxBackgroundReady,
    ) {
        const NEVER: Duration = Duration::from_secs(u32::MAX as u64);
        let mut now = Instant::now();
        let mut next_update = now;
        let mut next_health_check = now;

        loop {
            if shutdown.is_shutdown() {
                return;
            }

            if next_update <= now {
                if let Err(error) = self.update().await {
                    log::warn!("load-balancer discovery update failed: {error}");
                }
                next_update = checked_next_wake(now, self.update_frequency.unwrap_or(NEVER));
            }

            ready.notify_ready();

            if next_health_check <= now {
                self.run_health_check(self.parallel_health_check).await;
                next_health_check =
                    checked_next_wake(now, self.health_check_frequency.unwrap_or(NEVER));
            }

            if self.update_frequency.is_none() && self.health_check_frequency.is_none() {
                return;
            }

            let wake_at = std::cmp::min(next_update, next_health_check);
            if sleep_until_or_shutdown(&mut shutdown, wake_at).await {
                return;
            }
            now = Instant::now();
        }
    }

    pub(super) fn health_check_frequency(&self) -> Option<Duration> {
        self.health_check_frequency
    }

    pub(super) fn parallel_health_check(&self) -> bool {
        self.parallel_health_check
    }

    pub(super) async fn run_health_check(&self, parallel: bool) {
        async fn check_one(
            backend: RuntimeBackend,
            check: Arc<dyn FluxHealthCheck>,
            health: Arc<HashMap<u64, FluxBackendHealth>>,
        ) {
            let error = check.check(&backend).await.err();
            if let Some(backend_health) = health.get(&backend_key(&backend)) {
                let healthy = error.is_none();
                let flipped = backend_health.observe(healthy, check.health_threshold(healthy));
                if flipped {
                    check.health_status_change(&backend, healthy).await;
                    let summary = check.backend_summary(&backend);
                    if let Some(error) = error {
                        log::warn!("{summary} becomes unhealthy, {error}");
                    } else {
                        log::info!("{summary} becomes healthy");
                    }
                }
            }
        }

        let Some(health_check) = self.health_check.as_ref() else {
            return;
        };

        let snapshot = self.snapshot.load_full();
        if parallel {
            let jobs = snapshot.backends.iter().cloned().map(|backend| {
                tokio::spawn(check_one(
                    backend,
                    health_check.clone(),
                    Arc::clone(&snapshot.health),
                ))
            });
            let _ = future::join_all(jobs).await;
        } else {
            for backend in snapshot.backends.iter().cloned() {
                check_one(backend, health_check.clone(), Arc::clone(&snapshot.health)).await;
            }
        }
    }
}

async fn sleep_until_or_shutdown(
    shutdown: &mut crate::background::FluxShutdown,
    wake_at: Instant,
) -> bool {
    let now = Instant::now();
    if wake_at <= now {
        return false;
    }
    shutdown
        .sleep_or_shutdown(wake_at.duration_since(now))
        .await
}

fn checked_next_wake(now: Instant, delay: Duration) -> Instant {
    now.checked_add(delay)
        .unwrap_or_else(|| now + Duration::from_secs(3600))
}

fn bounded_discovery_error(error: &FluxError) -> String {
    let mut message = error.to_string();
    if message.len() <= MAX_DISCOVERY_ERROR_BYTES {
        return message;
    }
    let mut truncate_at = MAX_DISCOVERY_ERROR_BYTES;
    while !message.is_char_boundary(truncate_at) {
        truncate_at -= 1;
    }
    message.truncate(truncate_at);
    message
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) trait BackendContainer {
    fn backend_snapshot(&self) -> BackendContainerSnapshot;
}

impl BackendContainer for FluxLoadBalancerRuntime {
    fn backend_snapshot(&self) -> BackendContainerSnapshot {
        BackendContainerSnapshot {
            snapshot: self.snapshot.load_full(),
            health_check_enabled: self.health_check.is_some(),
        }
    }
}

impl<T> BackendContainer for Arc<T>
where
    T: BackendContainer + ?Sized,
{
    fn backend_snapshot(&self) -> BackendContainerSnapshot {
        (**self).backend_snapshot()
    }
}

pub(super) struct BackendContainerSnapshot {
    snapshot: Arc<FluxBackendSnapshot>,
    health_check_enabled: bool,
}

impl BackendContainerSnapshot {
    pub(super) fn backends(&self) -> &BTreeSet<RuntimeBackend> {
        &self.snapshot.backends
    }

    pub(super) fn ready(&self, backend: &RuntimeBackend) -> bool {
        self.snapshot
            .health
            .get(&backend_key(backend))
            .map_or(!self.health_check_enabled, FluxBackendHealth::ready)
    }
}

pub(super) fn backend_container_snapshot(
    container: &impl BackendContainer,
) -> BackendContainerSnapshot {
    container.backend_snapshot()
}

#[cfg(test)]
mod tests {
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
}
