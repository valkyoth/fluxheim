use std::collections::hash_map::DefaultHasher;
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures::FutureExt;
use pingora::http::RequestHeader;
use pingora::lb::Backend;
use pingora::lb::Backends;
use pingora::lb::discovery::Static;
use pingora::lb::health_check::TcpHealthCheck;
use pingora::lb::prelude::LoadBalancer;
use pingora::lb::selection::{
    BackendIter, BackendSelection, Consistent, FNVHash, Random, RoundRobin,
};
use pingora::services::ServiceWithDependents;
use pingora::services::background::{BackgroundService, GenBackgroundService};

use crate::config::{
    LoadBalancePassiveHealthConfig, LoadBalanceSelection, LoadBalanceSlowStartConfig, ProxyConfig,
};

pub type UpstreamLoadBalancerService = Box<dyn ServiceWithDependents>;

#[derive(Clone)]
pub struct UpstreamLoadBalancer {
    inner: UpstreamLoadBalancerInner,
    key_source: LoadBalanceKeySource,
    passive_health: Option<Arc<PassiveHealthState>>,
    slow_start: Option<Arc<SlowStartState>>,
    backend_policy: BackendSelectionPolicy,
    max_iterations: usize,
}

pub struct SelectedUpstream {
    pub backend: Backend,
    pub permit: Option<LoadBalancedConnectionPermit>,
    pub reporter: Option<LoadBalancedUpstreamReporter>,
}

#[derive(Debug)]
pub struct LoadBalancedConnectionPermit {
    counter: Arc<AtomicUsize>,
}

#[derive(Clone)]
pub struct LoadBalancedUpstreamReporter {
    backend_key: u64,
    passive_health: Arc<PassiveHealthState>,
    slow_start: Option<Arc<SlowStartState>>,
}

impl Debug for LoadBalancedUpstreamReporter {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoadBalancedUpstreamReporter")
            .field("backend_key", &self.backend_key)
            .finish_non_exhaustive()
    }
}

impl Drop for LoadBalancedConnectionPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Debug for UpstreamLoadBalancer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UpstreamLoadBalancer")
            .field("max_iterations", &self.max_iterations)
            .finish_non_exhaustive()
    }
}

impl UpstreamLoadBalancer {
    pub fn from_proxy_config(config: &ProxyConfig) -> io::Result<Option<Self>> {
        match config.load_balance.selection {
            LoadBalanceSelection::RoundRobin => {
                let Some(inner) = configured_load_balancer::<RoundRobin>(config)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::RoundRobin(Arc::new(inner)),
                    config,
                )))
            }
            LoadBalanceSelection::LeastConnections => {
                let Some(inner) = configured_load_balancer::<RoundRobin>(config)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::LeastConnections {
                        inner: Arc::new(inner),
                        counters: Arc::new(BackendConnectionCounters::default()),
                    },
                    config,
                )))
            }
            LoadBalanceSelection::PowerOfTwo => {
                let Some(inner) = configured_load_balancer::<Random>(config)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::PowerOfTwo {
                        inner: Arc::new(inner),
                        counters: Arc::new(BackendConnectionCounters::default()),
                    },
                    config,
                )))
            }
            LoadBalanceSelection::SourceHash
            | LoadBalanceSelection::UriHash
            | LoadBalanceSelection::HeaderHash
            | LoadBalanceSelection::CookieHash => {
                let Some(inner) = configured_load_balancer::<FNVHash>(config)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::FnvHash(Arc::new(inner)),
                    config,
                )))
            }
            LoadBalanceSelection::ConsistentSourceHash
            | LoadBalanceSelection::ConsistentUriHash
            | LoadBalanceSelection::ConsistentHeaderHash
            | LoadBalanceSelection::ConsistentCookieHash => {
                let Some(inner) = configured_load_balancer::<Consistent>(config)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::ConsistentHash(Arc::new(inner)),
                    config,
                )))
            }
        }
    }

    pub fn background_service_from_proxy_config(
        name: &str,
        config: &ProxyConfig,
    ) -> io::Result<Option<(Self, UpstreamLoadBalancerService)>> {
        match config.load_balance.selection {
            LoadBalanceSelection::RoundRobin => background_service_for::<RoundRobin>(
                name,
                config,
                UpstreamLoadBalancerInner::RoundRobin,
            ),
            LoadBalanceSelection::LeastConnections => {
                background_service_for::<RoundRobin>(name, config, |inner| {
                    UpstreamLoadBalancerInner::LeastConnections {
                        inner,
                        counters: Arc::new(BackendConnectionCounters::default()),
                    }
                })
            }
            LoadBalanceSelection::PowerOfTwo => {
                background_service_for::<Random>(name, config, |inner| {
                    UpstreamLoadBalancerInner::PowerOfTwo {
                        inner,
                        counters: Arc::new(BackendConnectionCounters::default()),
                    }
                })
            }
            LoadBalanceSelection::SourceHash
            | LoadBalanceSelection::UriHash
            | LoadBalanceSelection::HeaderHash
            | LoadBalanceSelection::CookieHash => {
                background_service_for::<FNVHash>(name, config, UpstreamLoadBalancerInner::FnvHash)
            }
            LoadBalanceSelection::ConsistentSourceHash
            | LoadBalanceSelection::ConsistentUriHash
            | LoadBalanceSelection::ConsistentHeaderHash
            | LoadBalanceSelection::ConsistentCookieHash => background_service_for::<Consistent>(
                name,
                config,
                UpstreamLoadBalancerInner::ConsistentHash,
            ),
        }
    }

    pub fn select(
        &self,
        request: &RequestHeader,
        client_ip: Option<IpAddr>,
    ) -> Option<SelectedUpstream> {
        let key = self.key_source.request_key(request, client_ip);
        let mut selected = self.inner.select(
            key.as_deref(),
            self.max_iterations,
            self.passive_health.as_deref(),
            self.slow_start.as_deref(),
            &self.backend_policy,
        )?;
        selected.reporter =
            self.passive_health
                .as_ref()
                .map(|passive_health| LoadBalancedUpstreamReporter {
                    backend_key: backend_connection_key(&selected.backend),
                    passive_health: passive_health.clone(),
                    slow_start: self.slow_start.clone(),
                });
        Some(selected)
    }

    fn from_inner(inner: UpstreamLoadBalancerInner, config: &ProxyConfig) -> Self {
        Self {
            inner,
            key_source: LoadBalanceKeySource::from_config(config),
            passive_health: config.load_balance.passive_health.enabled.then(|| {
                Arc::new(PassiveHealthState::from_config(
                    &config.load_balance.passive_health,
                ))
            }),
            slow_start: config
                .load_balance
                .slow_start
                .enabled
                .then(|| Arc::new(SlowStartState::from_config(&config.load_balance.slow_start))),
            backend_policy: BackendSelectionPolicy::from_config(config),
            max_iterations: config.load_balance.max_iterations,
        }
    }

    #[cfg(test)]
    fn backend_count(&self) -> usize {
        self.inner.backend_count()
    }

    #[cfg(test)]
    fn backend_weights(&self) -> Vec<usize> {
        self.inner.backend_weights()
    }

    #[cfg(test)]
    fn health_check_frequency(&self) -> Option<Duration> {
        self.inner.health_check_frequency()
    }

    #[cfg(test)]
    fn parallel_health_check(&self) -> bool {
        self.inner.parallel_health_check()
    }
}

#[derive(Clone)]
enum UpstreamLoadBalancerInner {
    RoundRobin(Arc<LoadBalancer<RoundRobin>>),
    LeastConnections {
        inner: Arc<LoadBalancer<RoundRobin>>,
        counters: Arc<BackendConnectionCounters>,
    },
    PowerOfTwo {
        inner: Arc<LoadBalancer<Random>>,
        counters: Arc<BackendConnectionCounters>,
    },
    FnvHash(Arc<LoadBalancer<FNVHash>>),
    ConsistentHash(Arc<LoadBalancer<Consistent>>),
}

impl UpstreamLoadBalancerInner {
    fn select(
        &self,
        key: Option<&[u8]>,
        max_iterations: usize,
        passive_health: Option<&PassiveHealthState>,
        slow_start: Option<&SlowStartState>,
        backend_policy: &BackendSelectionPolicy,
    ) -> Option<SelectedUpstream> {
        match self {
            Self::RoundRobin(inner) => select_pingora(
                inner,
                b"",
                max_iterations,
                passive_health,
                slow_start,
                backend_policy,
            )
            .map(SelectedUpstream::new),
            Self::LeastConnections { inner, counters } => select_least_connections(
                inner,
                counters,
                passive_health,
                slow_start,
                backend_policy,
            ),
            Self::PowerOfTwo { inner, counters } => select_power_of_two(
                inner,
                counters,
                max_iterations,
                passive_health,
                slow_start,
                backend_policy,
            ),
            Self::FnvHash(inner) => select_pingora(
                inner,
                key.unwrap_or_default(),
                max_iterations,
                passive_health,
                slow_start,
                backend_policy,
            )
            .map(SelectedUpstream::new),
            Self::ConsistentHash(inner) => select_pingora(
                inner,
                key.unwrap_or_default(),
                max_iterations,
                passive_health,
                slow_start,
                backend_policy,
            )
            .map(SelectedUpstream::new),
        }
    }

    #[cfg(test)]
    fn backend_count(&self) -> usize {
        match self {
            Self::RoundRobin(inner) => inner.backends().get_backend().len(),
            Self::LeastConnections { inner, .. } => inner.backends().get_backend().len(),
            Self::PowerOfTwo { inner, .. } => inner.backends().get_backend().len(),
            Self::FnvHash(inner) => inner.backends().get_backend().len(),
            Self::ConsistentHash(inner) => inner.backends().get_backend().len(),
        }
    }

    #[cfg(test)]
    fn backend_weights(&self) -> Vec<usize> {
        match self {
            Self::RoundRobin(inner) => backend_weights(inner),
            Self::LeastConnections { inner, .. } => backend_weights(inner),
            Self::PowerOfTwo { inner, .. } => backend_weights(inner),
            Self::FnvHash(inner) => backend_weights(inner),
            Self::ConsistentHash(inner) => backend_weights(inner),
        }
    }

    #[cfg(test)]
    fn health_check_frequency(&self) -> Option<Duration> {
        match self {
            Self::RoundRobin(inner) => inner.health_check_frequency,
            Self::LeastConnections { inner, .. } => inner.health_check_frequency,
            Self::PowerOfTwo { inner, .. } => inner.health_check_frequency,
            Self::FnvHash(inner) => inner.health_check_frequency,
            Self::ConsistentHash(inner) => inner.health_check_frequency,
        }
    }

    #[cfg(test)]
    fn parallel_health_check(&self) -> bool {
        match self {
            Self::RoundRobin(inner) => inner.parallel_health_check,
            Self::LeastConnections { inner, .. } => inner.parallel_health_check,
            Self::PowerOfTwo { inner, .. } => inner.parallel_health_check,
            Self::FnvHash(inner) => inner.parallel_health_check,
            Self::ConsistentHash(inner) => inner.parallel_health_check,
        }
    }
}

impl SelectedUpstream {
    fn new(backend: Backend) -> Self {
        Self {
            backend,
            permit: None,
            reporter: None,
        }
    }
}

impl LoadBalancedUpstreamReporter {
    pub fn record_status(&self, status: u16) {
        if let Some(restart_at) = self.passive_health.record_status(self.backend_key, status) {
            self.reset_slow_start(restart_at);
        }
    }

    pub fn record_failure(&self) {
        if let Some(restart_at) = self.passive_health.record_failure(self.backend_key) {
            self.reset_slow_start(restart_at);
        }
    }

    fn reset_slow_start(&self, restart_at: Instant) {
        if let Some(slow_start) = &self.slow_start {
            slow_start.reset_at(self.backend_key, restart_at);
        }
    }
}

struct PassiveHealthState {
    consecutive_failure: usize,
    ejection: Duration,
    failure_statuses: Arc<[u16]>,
    backends: Arc<Mutex<std::collections::HashMap<u64, PassiveBackendHealth>>>,
}

#[derive(Clone, Copy, Debug, Default)]
struct PassiveBackendHealth {
    consecutive_failures: usize,
    ejected_until: Option<Instant>,
}

impl PassiveHealthState {
    fn from_config(config: &LoadBalancePassiveHealthConfig) -> Self {
        Self {
            consecutive_failure: config.consecutive_failure,
            ejection: Duration::from_secs(config.ejection_secs),
            failure_statuses: config.failure_statuses.clone().into(),
            backends: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    fn is_ejected(&self, backend: &Backend) -> bool {
        let key = backend_connection_key(backend);
        let mut backends = self
            .backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(state) = backends.get_mut(&key) else {
            return false;
        };
        if state
            .ejected_until
            .is_some_and(|until| Instant::now() < until)
        {
            return true;
        }
        state.ejected_until = None;
        false
    }

    fn record_status(&self, key: u64, status: u16) -> Option<Instant> {
        if self.failure_status(status) {
            self.record_failure(key)
        } else {
            self.record_success(key);
            None
        }
    }

    fn record_failure(&self, key: u64) -> Option<Instant> {
        let mut backends = self
            .backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = backends.entry(key).or_default();
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= self.consecutive_failure {
            state.consecutive_failures = 0;
            let ejected_until = Instant::now() + self.ejection;
            state.ejected_until = Some(ejected_until);
            return Some(ejected_until);
        }
        None
    }

    fn record_success(&self, key: u64) {
        let mut backends = self
            .backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(state) = backends.get_mut(&key) {
            state.consecutive_failures = 0;
            state.ejected_until = None;
        }
    }

    fn failure_status(&self, status: u16) -> bool {
        if self.failure_statuses.is_empty() {
            return (500..=599).contains(&status);
        }
        self.failure_statuses.contains(&status)
    }
}

#[derive(Debug)]
struct SlowStartState {
    duration: Duration,
    backends: Mutex<std::collections::HashMap<u64, Instant>>,
}

impl SlowStartState {
    fn from_config(config: &LoadBalanceSlowStartConfig) -> Self {
        Self {
            duration: Duration::from_secs(config.duration_secs),
            backends: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn permits(&self, backend: &Backend) -> bool {
        let now = Instant::now();
        let key = backend_connection_key(backend);
        let mut backends = self
            .backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let started_at = *backends.entry(key).or_insert(now);
        let elapsed = now.saturating_duration_since(started_at);
        if elapsed >= self.duration {
            return true;
        }

        let progress_per_mille =
            ((elapsed.as_millis() * 1000) / self.duration.as_millis()).clamp(1, 1000) as u64;
        (key % 1000) < progress_per_mille
    }

    fn reset_at(&self, key: u64, restart_at: Instant) {
        self.backends
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key, restart_at);
    }
}

#[derive(Default)]
struct BackendConnectionCounters {
    counters: Mutex<std::collections::HashMap<u64, Arc<AtomicUsize>>>,
}

impl BackendConnectionCounters {
    fn count(&self, backend: &Backend) -> usize {
        self.counter(backend).load(Ordering::Acquire)
    }

    fn permit(&self, backend: &Backend) -> Option<LoadBalancedConnectionPermit> {
        let counter = self.counter(backend);
        let mut current = counter.load(Ordering::Acquire);
        loop {
            let next = current.checked_add(1)?;
            match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Some(LoadBalancedConnectionPermit { counter }),
                Err(observed) => current = observed,
            }
        }
    }

    fn counter(&self, backend: &Backend) -> Arc<AtomicUsize> {
        let mut counters = self
            .counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        counters
            .entry(backend_connection_key(backend))
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone()
    }
}

fn backend_connection_key(backend: &Backend) -> u64 {
    let mut hasher = DefaultHasher::new();
    backend.hash(&mut hasher);
    hasher.finish()
}

#[derive(Clone, Debug, Default)]
struct BackendSelectionPolicy {
    backup: Arc<std::collections::HashSet<u64>>,
    drain: Arc<std::collections::HashSet<u64>>,
}

impl BackendSelectionPolicy {
    fn from_config(config: &ProxyConfig) -> Self {
        Self {
            backup: backend_policy_keys(&config.backup_upstreams).into(),
            drain: backend_policy_keys(&config.drain_upstreams).into(),
        }
    }

    fn permits(&self, backend: &Backend, allow_backup: bool) -> bool {
        let key = backend_policy_key(backend);
        !self.drain.contains(&key) && (allow_backup || !self.backup.contains(&key))
    }
}

fn backend_policy_keys(upstreams: &[String]) -> std::collections::HashSet<u64> {
    upstreams
        .iter()
        .filter_map(|upstream| Backend::new(upstream).ok())
        .map(|backend| backend_policy_key(&backend))
        .collect()
}

fn backend_policy_key(backend: &Backend) -> u64 {
    let mut hasher = DefaultHasher::new();
    backend.addr.hash(&mut hasher);
    hasher.finish()
}

fn select_pingora<S>(
    inner: &LoadBalancer<S>,
    key: &[u8],
    max_iterations: usize,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
) -> Option<Backend>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    select_pingora_with_backup_policy(
        inner,
        key,
        max_iterations,
        passive_health,
        slow_start,
        backend_policy,
        SelectionPass {
            allow_backup: false,
            ignore_slow_start: false,
        },
    )
    .or_else(|| {
        select_pingora_with_backup_policy(
            inner,
            key,
            max_iterations,
            passive_health,
            slow_start,
            backend_policy,
            SelectionPass {
                allow_backup: true,
                ignore_slow_start: false,
            },
        )
    })
    .or_else(|| {
        select_pingora_with_backup_policy(
            inner,
            key,
            max_iterations,
            passive_health,
            slow_start,
            backend_policy,
            SelectionPass {
                allow_backup: false,
                ignore_slow_start: true,
            },
        )
    })
}

#[derive(Clone, Copy)]
struct SelectionPass {
    allow_backup: bool,
    ignore_slow_start: bool,
}

fn select_pingora_with_backup_policy<S>(
    inner: &LoadBalancer<S>,
    key: &[u8],
    max_iterations: usize,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
    pass: SelectionPass,
) -> Option<Backend>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    inner.select_with(key, max_iterations, |backend, ready| {
        ready
            && backend_policy.permits(backend, pass.allow_backup)
            && passive_health.is_none_or(|health| !health.is_ejected(backend))
            && (pass.ignore_slow_start || slow_start.is_none_or(|state| state.permits(backend)))
    })
}

fn select_least_connections(
    inner: &LoadBalancer<RoundRobin>,
    counters: &BackendConnectionCounters,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
) -> Option<SelectedUpstream> {
    select_least_connections_with_backup_policy(
        inner,
        counters,
        passive_health,
        slow_start,
        backend_policy,
        false,
        false,
    )
    .or_else(|| {
        select_least_connections_with_backup_policy(
            inner,
            counters,
            passive_health,
            slow_start,
            backend_policy,
            true,
            false,
        )
    })
    .or_else(|| {
        select_least_connections_with_backup_policy(
            inner,
            counters,
            passive_health,
            slow_start,
            backend_policy,
            false,
            true,
        )
    })
}

fn select_least_connections_with_backup_policy(
    inner: &LoadBalancer<RoundRobin>,
    counters: &BackendConnectionCounters,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
    allow_backup: bool,
    ignore_slow_start: bool,
) -> Option<SelectedUpstream> {
    let mut selected = None;
    for backend in inner.backends().get_backend().iter() {
        if !inner.backends().ready(backend)
            || !backend_policy.permits(backend, allow_backup)
            || passive_health.is_some_and(|health| health.is_ejected(backend))
            || (!ignore_slow_start && slow_start.is_some_and(|state| !state.permits(backend)))
        {
            continue;
        }
        let connections = counters.count(backend);
        if selected
            .as_ref()
            .is_none_or(|(_, selected_connections)| connections < *selected_connections)
        {
            selected = Some((backend.clone(), connections));
        }
    }
    let backend = selected.map(|(backend, _)| backend)?;
    let permit = counters.permit(&backend)?;
    Some(SelectedUpstream {
        permit: Some(permit),
        backend,
        reporter: None,
    })
}

fn select_power_of_two(
    inner: &LoadBalancer<Random>,
    counters: &BackendConnectionCounters,
    max_iterations: usize,
    passive_health: Option<&PassiveHealthState>,
    slow_start: Option<&SlowStartState>,
    backend_policy: &BackendSelectionPolicy,
) -> Option<SelectedUpstream> {
    let first = select_pingora(
        inner,
        b"",
        max_iterations,
        passive_health,
        slow_start,
        backend_policy,
    )?;
    let first_key = backend_connection_key(&first);
    let second = (0..max_iterations)
        .filter_map(|_| {
            select_pingora(
                inner,
                b"",
                max_iterations,
                passive_health,
                slow_start,
                backend_policy,
            )
        })
        .find(|backend| backend_connection_key(backend) != first_key)
        .unwrap_or_else(|| first.clone());
    let selected = if counters.count(&second) < counters.count(&first) {
        second
    } else {
        first
    };
    let permit = counters.permit(&selected)?;
    Some(SelectedUpstream {
        permit: Some(permit),
        backend: selected,
        reporter: None,
    })
}

#[derive(Clone, Debug)]
enum LoadBalanceKeySource {
    None,
    SourceIp,
    Uri,
    Header(String),
    Cookie(String),
}

impl LoadBalanceKeySource {
    fn from_config(config: &ProxyConfig) -> Self {
        match config.load_balance.selection {
            LoadBalanceSelection::RoundRobin => Self::None,
            LoadBalanceSelection::LeastConnections => Self::None,
            LoadBalanceSelection::PowerOfTwo => Self::None,
            LoadBalanceSelection::SourceHash | LoadBalanceSelection::ConsistentSourceHash => {
                Self::SourceIp
            }
            LoadBalanceSelection::UriHash | LoadBalanceSelection::ConsistentUriHash => Self::Uri,
            LoadBalanceSelection::HeaderHash | LoadBalanceSelection::ConsistentHeaderHash => config
                .load_balance
                .hash_header
                .clone()
                .map(Self::Header)
                .unwrap_or(Self::None),
            LoadBalanceSelection::CookieHash | LoadBalanceSelection::ConsistentCookieHash => config
                .load_balance
                .hash_cookie
                .clone()
                .map(Self::Cookie)
                .unwrap_or(Self::None),
        }
    }

    fn request_key(&self, request: &RequestHeader, client_ip: Option<IpAddr>) -> Option<Vec<u8>> {
        match self {
            Self::None => None,
            Self::SourceIp => client_ip.map(|ip| ip.to_string().into_bytes()),
            Self::Uri => Some(request.uri.to_string().into_bytes()),
            Self::Header(name) => {
                let mut key = Vec::new();
                for value in request.headers.get_all(name.as_str()) {
                    let bytes = value.as_bytes();
                    key.extend_from_slice(&bytes.len().to_le_bytes());
                    key.extend_from_slice(bytes);
                }
                (!key.is_empty()).then_some(key)
            }
            Self::Cookie(name) => cookie_key(request, name),
        }
    }
}

fn cookie_key(request: &RequestHeader, name: &str) -> Option<Vec<u8>> {
    for header in request.headers.get_all("cookie") {
        let Ok(header) = header.to_str() else {
            continue;
        };
        for part in header.split(';') {
            let Some((candidate, value)) = part.trim().split_once('=') else {
                continue;
            };
            if candidate.trim() == name {
                return Some(value.trim().as_bytes().to_vec());
            }
        }
    }
    None
}

fn configured_load_balancer<S>(config: &ProxyConfig) -> io::Result<Option<LoadBalancer<S>>>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    if config.upstreams.len() < 2 {
        return Ok(None);
    }

    let backends = configured_backends(config)?;
    let mut load_balancer = LoadBalancer::from_backends(Backends::new(Static::new(backends)));
    load_balancer
        .update()
        .now_or_never()
        .ok_or_else(|| io::Error::other("static load balancer update blocked unexpectedly"))?
        .map_err(|error| io::Error::other(error.to_string()))?;
    if config.load_balance.health_check.enabled {
        let mut health_check = if config.upstream_tls {
            TcpHealthCheck::new_tls(&config.upstream_sni())
        } else {
            TcpHealthCheck::new()
        };
        health_check.consecutive_success = config.load_balance.health_check.consecutive_success;
        health_check.consecutive_failure = config.load_balance.health_check.consecutive_failure;
        load_balancer.set_health_check(health_check);
        load_balancer.health_check_frequency = Some(Duration::from_secs(
            config.load_balance.health_check.interval_secs,
        ));
        load_balancer.parallel_health_check = config.load_balance.health_check.parallel;
    }

    Ok(Some(load_balancer))
}

fn background_service_for<S>(
    name: &str,
    config: &ProxyConfig,
    wrap: fn(Arc<LoadBalancer<S>>) -> UpstreamLoadBalancerInner,
) -> io::Result<Option<(UpstreamLoadBalancer, UpstreamLoadBalancerService)>>
where
    S: BackendSelection + Send + Sync + 'static,
    S::Iter: BackendIter,
    LoadBalancer<S>: BackgroundService,
{
    let Some(inner) = configured_load_balancer::<S>(config)? else {
        return Ok(None);
    };

    let service = GenBackgroundService::new(format!("LB {name}"), Arc::new(inner));
    let load_balancer = UpstreamLoadBalancer::from_inner(wrap(service.task()), config);
    Ok(Some((load_balancer, Box::new(service))))
}

fn configured_backends(config: &ProxyConfig) -> io::Result<std::collections::BTreeSet<Backend>> {
    let mut backends = std::collections::BTreeSet::new();
    for (index, upstream) in config.upstreams.iter().enumerate() {
        let weight = config.upstream_weights.get(index).copied().unwrap_or(1);
        let backend = Backend::new_with_weight(upstream, weight)
            .map_err(|error| io::Error::other(error.to_string()))?;
        backends.insert(backend);
    }
    Ok(backends)
}

#[cfg(test)]
fn backend_weights<S>(inner: &LoadBalancer<S>) -> Vec<usize>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    inner
        .backends()
        .get_backend()
        .iter()
        .map(|backend| backend.weight)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use pingora::http::RequestHeader;
    use pingora::lb::Backend;

    use crate::config::{
        LoadBalanceConfig, LoadBalanceHealthCheckConfig, LoadBalancePassiveHealthConfig,
        LoadBalanceSelection, LoadBalanceSlowStartConfig, ProxyConfig,
    };

    use super::{
        LoadBalancedUpstreamReporter, PassiveHealthState, SlowStartState, UpstreamLoadBalancer,
        backend_connection_key,
    };

    fn install_test_crypto_provider() {
        #[cfg(feature = "tls-rustls-backend")]
        let _ = crate::tls::install_rustls_crypto_provider();
    }

    fn request() -> RequestHeader {
        RequestHeader::build("GET", b"/app?id=42", None).unwrap()
    }

    #[test]
    fn builds_round_robin_from_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(balancer.backend_count(), 2);
        assert!(balancer.select(&request(), None).is_some());
    }

    #[test]
    fn builds_weighted_round_robin_from_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_weights: vec![1, 4],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(balancer.backend_count(), 2);
        assert_eq!(balancer.backend_weights(), [1, 4]);
        assert!(balancer.select(&request(), None).is_some());
    }

    #[test]
    fn builds_hash_selection_from_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::SourceHash,
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let client_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let first = balancer.select(&request(), Some(client_ip)).unwrap();
        let second = balancer.select(&request(), Some(client_ip)).unwrap();
        assert_eq!(first.backend.addr, second.backend.addr);
    }

    #[test]
    fn builds_consistent_header_hash_selection_from_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::ConsistentHeaderHash,
                hash_header: Some("x-session".to_owned()),
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let mut request = request();
        request.insert_header("x-session", "abc").unwrap();
        let first = balancer.select(&request, None).unwrap();
        let second = balancer.select(&request, None).unwrap();
        assert_eq!(first.backend.addr, second.backend.addr);
    }

    #[test]
    fn builds_cookie_hash_selection_from_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::CookieHash,
                hash_cookie: Some("session".to_owned()),
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let mut request = request();
        request
            .insert_header("cookie", "other=1; session=abc; theme=dark")
            .unwrap();
        let first = balancer.select(&request, None).unwrap();
        let second = balancer.select(&request, None).unwrap();
        assert_eq!(first.backend.addr, second.backend.addr);
    }

    #[test]
    fn least_connections_tracks_held_permits() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::LeastConnections,
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let first = balancer.select(&request(), None).unwrap();
        let first_addr = first.backend.addr.clone();
        let second = balancer.select(&request(), None).unwrap();
        assert_ne!(&first_addr, &second.backend.addr);
        drop(first);
        let third = balancer.select(&request(), None).unwrap();
        assert_eq!(third.backend.addr, first_addr);
    }

    #[test]
    fn builds_power_of_two_selection_from_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::PowerOfTwo,
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let selected = balancer.select(&request(), None).unwrap();
        assert!(selected.permit.is_some());
    }

    #[test]
    fn slow_start_gates_new_backends_until_warmed() {
        let state = SlowStartState::from_config(&LoadBalanceSlowStartConfig {
            enabled: true,
            duration_secs: 60,
        });
        let backend = (3000..4000)
            .filter_map(|port| Backend::new(&format!("127.0.0.1:{port}")).ok())
            .find(|backend| backend_connection_key(backend) % 1000 > 900)
            .expect("test backend with high slow-start gate");

        assert!(!state.permits(&backend));
        state.backends.lock().unwrap().insert(
            backend_connection_key(&backend),
            Instant::now() - Duration::from_secs(61),
        );
        assert!(state.permits(&backend));
    }

    #[test]
    fn slow_start_does_not_outage_all_warming_backends() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                slow_start: LoadBalanceSlowStartConfig {
                    enabled: true,
                    duration_secs: 60,
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        assert!(balancer.select(&request(), None).is_some());
    }

    #[test]
    fn passive_recovery_restarts_slow_start_window() {
        let slow_start = Arc::new(SlowStartState::from_config(&LoadBalanceSlowStartConfig {
            enabled: true,
            duration_secs: 60,
        }));
        let backend = (3000..4000)
            .filter_map(|port| Backend::new(&format!("127.0.0.1:{port}")).ok())
            .find(|backend| backend_connection_key(backend) % 1000 > 900)
            .expect("test backend with high slow-start gate");
        let key = backend_connection_key(&backend);
        slow_start
            .backends
            .lock()
            .unwrap()
            .insert(key, Instant::now() - Duration::from_secs(61));
        assert!(slow_start.permits(&backend));

        let reporter = LoadBalancedUpstreamReporter {
            backend_key: key,
            passive_health: Arc::new(PassiveHealthState::from_config(
                &LoadBalancePassiveHealthConfig {
                    enabled: true,
                    consecutive_failure: 1,
                    ejection_secs: 1,
                    ..LoadBalancePassiveHealthConfig::default()
                },
            )),
            slow_start: Some(slow_start.clone()),
        };
        reporter.record_failure();

        assert!(!slow_start.permits(&backend));
    }

    #[test]
    fn passive_health_ejects_failed_backend() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                passive_health: LoadBalancePassiveHealthConfig {
                    enabled: true,
                    consecutive_failure: 1,
                    ejection_secs: 60,
                    failure_statuses: Vec::new(),
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let failed = balancer.select(&request(), None).unwrap();
        let failed_addr = failed.backend.addr.clone();
        failed.reporter.unwrap().record_status(503);
        let next = balancer.select(&request(), None).unwrap();
        assert_ne!(failed_addr, next.backend.addr);
    }

    #[test]
    fn backup_upstreams_are_used_after_primary_ejection() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            backup_upstreams: vec!["127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                passive_health: LoadBalancePassiveHealthConfig {
                    enabled: true,
                    consecutive_failure: 1,
                    ejection_secs: 60,
                    failure_statuses: Vec::new(),
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let primary = balancer.select(&request(), None).unwrap();
        assert_eq!(primary.backend.addr.to_string(), "127.0.0.1:3000");
        primary.reporter.unwrap().record_failure();
        let backup = balancer.select(&request(), None).unwrap();
        assert_eq!(backup.backend.addr.to_string(), "127.0.0.1:3001");
    }

    #[test]
    fn drained_upstreams_do_not_receive_new_selections() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            drain_upstreams: vec!["127.0.0.1:3000".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        for _ in 0..4 {
            let selected = balancer.select(&request(), None).unwrap();
            assert_eq!(selected.backend.addr.to_string(), "127.0.0.1:3001");
        }
    }

    #[test]
    fn configures_pingora_tcp_health_check() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                health_check: LoadBalanceHealthCheckConfig {
                    enabled: true,
                    interval_secs: 3,
                    consecutive_success: 2,
                    consecutive_failure: 4,
                    parallel: true,
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(
            balancer.health_check_frequency(),
            Some(Duration::from_secs(3))
        );
        assert!(balancer.parallel_health_check());
    }

    #[test]
    fn builds_background_service_and_shared_selector() {
        install_test_crypto_provider();
        let (balancer, _service) = UpstreamLoadBalancer::background_service_from_proxy_config(
            "test",
            &ProxyConfig {
                upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
                ..ProxyConfig::default()
            },
        )
        .unwrap()
        .unwrap();

        assert_eq!(balancer.backend_count(), 2);
        assert!(balancer.select(&request(), None).is_some());
    }

    #[test]
    fn stays_disabled_without_load_balanced_upstreams() {
        let without_upstreams =
            UpstreamLoadBalancer::from_proxy_config(&ProxyConfig::default()).unwrap();
        let single_upstream = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["missing-container.test:3000".to_owned()],
            ..ProxyConfig::default()
        })
        .unwrap();

        assert!(without_upstreams.is_none());
        assert!(single_upstream.is_none());
    }
}
