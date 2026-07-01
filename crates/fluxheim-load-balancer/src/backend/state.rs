use std::collections::{BTreeSet, HashMap};
use std::process;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use fluxheim_common::FluxError;

use super::FluxLoadBalancerRuntime;
use super::RuntimeBackend;
use crate::key::backend_key;

const MAX_DISCOVERY_ERROR_BYTES: usize = 256;

struct FluxBackendHealthInner {
    healthy: bool,
    enabled: bool,
    consecutive_counter: usize,
}

#[derive(Clone)]
pub(super) struct FluxBackendHealth(Arc<Mutex<FluxBackendHealthInner>>);

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

    pub(super) fn ready(&self) -> bool {
        let health = self.lock();
        health.healthy && health.enabled
    }

    pub(super) fn enable(&self, enabled: bool) {
        self.lock().enabled = enabled;
    }

    pub(super) fn observe(&self, healthy: bool, flip_threshold: usize) -> bool {
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
pub(super) struct FluxBackendSnapshot {
    pub(super) backends: Arc<BTreeSet<RuntimeBackend>>,
    pub(super) health: Arc<HashMap<u64, FluxBackendHealth>>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct FluxBackendDiscoveryRuntimeStatus {
    pub(crate) refresh_enabled: bool,
    pub(crate) update_frequency_secs: Option<u64>,
    pub(crate) success_count: u64,
    pub(crate) failure_count: u64,
    pub(crate) last_success_unix_secs: Option<u64>,
    pub(crate) last_failure_unix_secs: Option<u64>,
    pub(crate) last_error: Option<String>,
}

#[derive(Default)]
pub(super) struct FluxBackendDiscoveryRuntimeState {
    pub(super) success_count: u64,
    pub(super) failure_count: u64,
    pub(super) last_success_unix_secs: Option<u64>,
    pub(super) last_failure_unix_secs: Option<u64>,
    pub(super) last_error: Option<String>,
}

pub(super) fn bounded_discovery_error(error: &FluxError) -> String {
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

pub(super) fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) trait BackendContainer {
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

pub(crate) struct BackendContainerSnapshot {
    snapshot: Arc<FluxBackendSnapshot>,
    health_check_enabled: bool,
}

impl BackendContainerSnapshot {
    pub(crate) fn backends(&self) -> &BTreeSet<RuntimeBackend> {
        &self.snapshot.backends
    }

    pub(crate) fn ready(&self, backend: &RuntimeBackend) -> bool {
        self.snapshot
            .health
            .get(&backend_key(backend))
            .map_or(!self.health_check_enabled, FluxBackendHealth::ready)
    }
}

pub(crate) fn backend_container_snapshot(
    container: &impl BackendContainer,
) -> BackendContainerSnapshot {
    container.backend_snapshot()
}
