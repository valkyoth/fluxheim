use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::SocketAddr;
use std::process;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use super::key::{backend_authority_key, backend_key};
use crate::flux_error::{FluxError, FluxResult};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use futures::future;
use pingora::lb::Backend;
use pingora::server::ShutdownWatch;
use pingora::services::ServiceReadyNotifier;

pub(super) type RuntimeBackend = Backend;

#[async_trait]
pub(super) trait FluxBackendDiscovery: Send + Sync + 'static {
    async fn discover_flux_backends(&self) -> FluxResult<FluxBackendSet>;
}

#[async_trait]
pub(super) trait FluxHealthCheck: Send + Sync + 'static {
    async fn check(&self, target: &Backend) -> FluxResult<()>;

    fn health_threshold(&self, success: bool) -> usize;

    async fn health_status_change(&self, _target: &Backend, _healthy: bool) {}

    fn backend_summary(&self, target: &Backend) -> String {
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
    backends: Arc<BTreeSet<Backend>>,
    health: Arc<HashMap<u64, FluxBackendHealth>>,
}

pub(super) struct FluxLoadBalancerRuntime {
    discovery: Arc<dyn FluxBackendDiscovery>,
    health_check: Option<Arc<dyn FluxHealthCheck>>,
    snapshot: ArcSwap<FluxBackendSnapshot>,
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

    pub(super) async fn update(&self) -> FluxResult<()> {
        let discovered = self.discovery.discover_flux_backends().await?;
        let (new_backends, enablement) = discovered.into_pingora_parts()?;
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

    pub(super) fn set_enable(&self, backend: &Backend, enabled: bool) {
        if let Some(backend_health) = self.snapshot.load().health.get(&backend_key(backend)) {
            backend_health.enable(enabled);
        }
    }

    pub(super) async fn run(
        &self,
        shutdown: ShutdownWatch,
        mut ready: Option<ServiceReadyNotifier>,
    ) {
        const NEVER: Duration = Duration::from_secs(u32::MAX as u64);
        let mut now = Instant::now();
        let mut next_update = now;
        let mut next_health_check = now;

        loop {
            if *shutdown.borrow() {
                return;
            }

            if next_update <= now {
                if let Err(error) = self.update().await {
                    log::warn!("load-balancer discovery update failed: {error}");
                }
                next_update = checked_next_wake(now, self.update_frequency.unwrap_or(NEVER));
            }

            if let Some(ready) = ready.take() {
                ServiceReadyNotifier::notify_ready(ready);
            }

            if next_health_check <= now {
                self.run_health_check(self.parallel_health_check).await;
                next_health_check =
                    checked_next_wake(now, self.health_check_frequency.unwrap_or(NEVER));
            }

            if self.update_frequency.is_none() && self.health_check_frequency.is_none() {
                return;
            }

            let wake_at = std::cmp::min(next_update, next_health_check);
            tokio::time::sleep_until(wake_at.into()).await;
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
            backend: Backend,
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

fn checked_next_wake(now: Instant, delay: Duration) -> Instant {
    now.checked_add(delay)
        .unwrap_or_else(|| now + Duration::from_secs(3600))
}

pub(crate) trait BackendIdentity {
    fn authority(&self) -> String;

    fn weight(&self) -> usize;

    fn key(&self) -> u64 {
        backend_authority_key(&self.authority())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct FluxBackend {
    address: SocketAddr,
    weight: usize,
}

impl FluxBackend {
    pub(super) fn new(authority: &str) -> FluxResult<Self> {
        Self::new_with_weight(authority, 1)
    }

    pub(super) fn new_with_weight(authority: &str, weight: usize) -> FluxResult<Self> {
        let address = authority.parse::<SocketAddr>().map_err(|error| {
            FluxError::io(
                "load-balancer backend authority is not a socket address",
                io::Error::new(io::ErrorKind::InvalidInput, error),
            )
        })?;
        Ok(Self { address, weight })
    }

    pub(super) fn to_pingora_backend(&self) -> FluxResult<Backend> {
        Backend::new_with_weight(&self.authority(), self.weight).map_err(|error| {
            FluxError::io(
                "load-balancer backend cannot be adapted to Pingora",
                io::Error::other(error.to_string()),
            )
        })
    }
}

impl BackendIdentity for FluxBackend {
    fn authority(&self) -> String {
        self.address.to_string()
    }

    fn weight(&self) -> usize {
        self.weight
    }
}

impl BackendIdentity for Backend {
    fn authority(&self) -> String {
        self.addr.to_string()
    }

    fn weight(&self) -> usize {
        self.weight
    }
}

impl<T> BackendIdentity for &T
where
    T: BackendIdentity + ?Sized,
{
    fn authority(&self) -> String {
        (*self).authority()
    }

    fn weight(&self) -> usize {
        (*self).weight()
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct FluxBackendSet {
    backends: BTreeSet<FluxBackend>,
    ready: HashMap<u64, bool>,
}

impl FluxBackendSet {
    pub(super) fn insert(&mut self, backend: FluxBackend) {
        self.backends.insert(backend);
    }

    pub(super) fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &FluxBackend> {
        self.backends.iter()
    }

    #[cfg(test)]
    pub(super) fn set_ready(&mut self, backend: &FluxBackend, ready: bool) {
        self.ready.insert(backend.key(), ready);
    }

    pub(super) fn into_pingora_parts(self) -> FluxResult<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let mut backends = BTreeSet::new();
        for backend in self.backends {
            backends.insert(backend.to_pingora_backend()?);
        }
        Ok((backends, self.ready))
    }
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
    pub(super) fn backends(&self) -> &BTreeSet<Backend> {
        &self.snapshot.backends
    }

    pub(super) fn ready(&self, backend: &Backend) -> bool {
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
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::{
        BackendIdentity, FluxBackend, FluxBackendDiscovery, FluxBackendSet, FluxLoadBalancerRuntime,
    };
    use crate::flux_error::FluxResult;

    struct TestDiscovery {
        backends: Mutex<FluxBackendSet>,
    }

    impl TestDiscovery {
        fn new(backends: FluxBackendSet) -> Self {
            Self {
                backends: Mutex::new(backends),
            }
        }
    }

    #[async_trait]
    impl FluxBackendDiscovery for TestDiscovery {
        async fn discover_flux_backends(&self) -> FluxResult<FluxBackendSet> {
            Ok(self
                .backends
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone())
        }
    }

    #[test]
    fn flux_backend_preserves_authority_weight_and_key() {
        let backend = FluxBackend::new_with_weight("127.0.0.1:3000", 7).unwrap();

        assert_eq!(backend.authority(), "127.0.0.1:3000");
        assert_eq!(backend.weight(), 7);
        assert_eq!(
            backend.key(),
            crate::load_balancer::backend_authority_key("127.0.0.1:3000")
        );
    }

    #[test]
    fn flux_backend_set_adapts_to_pingora_parts() {
        let backend = FluxBackend::new("127.0.0.1:3000").unwrap();
        let mut set = FluxBackendSet::default();
        set.insert(backend.clone());
        set.set_ready(&backend, false);

        let (backends, ready) = set.into_pingora_parts().unwrap();
        assert_eq!(backends.len(), 1);
        assert_eq!(ready.get(&backend.key()), Some(&false));
        assert_eq!(
            backends.iter().next().unwrap().addr.to_string(),
            "127.0.0.1:3000"
        );
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
        let pingora_backend = backend.to_pingora_backend().unwrap();
        let key = crate::load_balancer::backend_key(&pingora_backend);
        assert!(snapshot.backends.contains(&pingora_backend));
        assert!(snapshot.health.contains_key(&key));
        assert!(!snapshot.health.get(&key).unwrap().ready());
    }
}
