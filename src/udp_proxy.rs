use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
#[cfg(unix)]
use pingora::server::ListenFds;
use pingora::server::ShutdownWatch;
use pingora::services::{ServiceReadyNotifier, ServiceWithDependents};
use tokio::net::UdpSocket;

use crate::config::{Config, UdpRouteConfig, UdpRouteMode};
use crate::flux_error::{FluxError, FluxResult};

const UDP_RECEIVE_BUFFER_BYTES: usize = 65_507;
const UDP_DROP_LOG_INTERVAL_MILLIS: u64 = 1_000;
const UDP_RESPONSE_RATE_TRACKED_SOURCES_FLOOR: usize = 4_096;

type UdpSourceSessions = Arc<Mutex<HashMap<IpAddr, usize>>>;
type UdpResponseRateWindows = Arc<Mutex<UdpResponseRateState>>;

pub(crate) fn udp_services_from_config(config: &Config) -> io::Result<Vec<UdpProxyService>> {
    if !config.udp.enabled {
        return Ok(Vec::new());
    }

    config
        .udp
        .routes
        .iter()
        .map(UdpProxyService::from_config)
        .collect()
}

pub(crate) struct UdpProxyService {
    name: String,
    listen: Arc<[String]>,
    app: Arc<UdpProxyApp>,
}

impl UdpProxyService {
    fn from_config(route: &UdpRouteConfig) -> io::Result<Self> {
        let app = UdpProxyApp::from_config(route).map_err(FluxError::into_io)?;
        Ok(Self {
            name: format!("UDP proxy {}", route.name),
            listen: route.listen.clone().into(),
            app: Arc::new(app),
        })
    }

    async fn run_listener(
        app: Arc<UdpProxyApp>,
        socket: Arc<UdpSocket>,
        listen: String,
        mut shutdown: ShutdownWatch,
    ) {
        let listener_local = match socket.local_addr() {
            Ok(address) => address,
            Err(error) => {
                log::error!(
                    target: "fluxheim::udp",
                    "UDP listener {listen} has no local address: {error}"
                );
                return;
            }
        };
        let mut buffer = vec![0u8; UDP_RECEIVE_BUFFER_BYTES];
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                received = socket.recv_from(&mut buffer) => {
                    match received {
                        Ok((len, source)) => {
                            if len > app.max_datagram_bytes {
                                app.record_drop("oversized_downstream");
                                app.log_dropped_datagram(
                                    source,
                                    "oversized downstream datagram",
                                    format_args!("{} bytes > {}", len, app.max_datagram_bytes),
                                );
                                continue;
                            }
                            let slot = match app.acquire_session_slot(source.ip()) {
                                Ok(slot) => slot,
                                Err(UdpAcquireError::RouteLimit) => {
                                    app.record_drop("max_sessions");
                                    app.log_dropped_datagram(
                                        source,
                                        "max_sessions exceeded",
                                        format_args!("active session cap is {}", app.max_sessions),
                                    );
                                    continue;
                                }
                                Err(UdpAcquireError::SourceLimit) => {
                                    app.record_drop("max_sessions_per_source");
                                    app.log_dropped_datagram(
                                        source,
                                        "max_sessions_per_source exceeded",
                                        format_args!(
                                            "per-source active session cap is {}",
                                            app.max_sessions_per_source
                                        ),
                                    );
                                    continue;
                                }
                            };
                            app.record_datagram("downstream", "accepted");
                            let payload = buffer[..len].to_vec();
                            let app = app.clone();
                            let socket = socket.clone();
                            tokio::spawn(async move {
                                let _slot = slot;
                                app.process_datagram(socket, listener_local, source, payload).await;
                            });
                        }
                        Err(error) => {
                            log::warn!(
                                target: "fluxheim::udp",
                                "UDP listener {listen} failed to receive datagram: {error}"
                            );
                        }
                    }
                }
            }
        }
        log::info!(target: "fluxheim::udp", "UDP listener {listen} stopped");
    }
}

#[async_trait]
impl ServiceWithDependents for UdpProxyService {
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<ListenFds>,
        mut shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
        ready_notifier: ServiceReadyNotifier,
    ) {
        let mut listeners = Vec::with_capacity(self.listen.len());
        for listen in self.listen.iter() {
            match UdpSocket::bind(listen).await {
                Ok(socket) => listeners.push((listen.clone(), Arc::new(socket))),
                Err(error) => {
                    log::error!(
                        target: "fluxheim::udp",
                        "failed to bind UDP listener {listen}: {error}"
                    );
                    process::exit(1);
                }
            }
        }
        ready_notifier.notify_ready();
        if listeners.is_empty() {
            let _ = shutdown.changed().await;
            return;
        }
        let mut tasks = Vec::with_capacity(listeners.len());
        for (listen, socket) in listeners {
            tasks.push(tokio::spawn(Self::run_listener(
                self.app.clone(),
                socket,
                listen,
                shutdown.clone(),
            )));
        }
        let _ = shutdown.changed().await;
        for task in tasks {
            task.abort();
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}

struct UdpProxyApp {
    name: Arc<str>,
    mode: UdpRouteMode,
    upstreams: Arc<[RuntimeUdpUpstream]>,
    weight_total: usize,
    response_timeout: Duration,
    passive_health_ejection: Duration,
    max_datagram_bytes: usize,
    max_sessions: usize,
    max_sessions_per_source: usize,
    max_responses_per_source_per_second: usize,
    passive_health_enabled: bool,
    passive_health_failures: usize,
    response_rate_tracked_sources: usize,
    active_sessions: Arc<AtomicUsize>,
    source_sessions: UdpSourceSessions,
    response_rate_windows: UdpResponseRateWindows,
    datagrams_total: AtomicU64,
    responses_total: AtomicU64,
    drops_total: AtomicU64,
    next_upstream: AtomicUsize,
    last_drop_log_millis: AtomicU64,
    suppressed_drop_logs: AtomicUsize,
}

impl UdpProxyApp {
    fn from_config(route: &UdpRouteConfig) -> FluxResult<Self> {
        if matches!(
            route.mode,
            UdpRouteMode::QuicPassThrough | UdpRouteMode::GameProxy
        ) {
            return Err(FluxError::InvalidInput(
                "UDP route mode requires session-affinity runtime support",
            ));
        }
        let upstreams = runtime_udp_upstreams(route);
        if upstreams.is_empty() {
            return Err(FluxError::InvalidInput(
                "UDP route requires at least one upstream",
            ));
        }
        let weight_total = upstreams
            .iter()
            .try_fold(0usize, |sum, upstream| sum.checked_add(upstream.weight))
            .ok_or(FluxError::InvalidInput(
                "UDP upstream weight total overflow",
            ))?;
        if weight_total == 0 {
            return Err(FluxError::InvalidInput(
                "UDP route requires at least one selectable upstream",
            ));
        }

        let max_sessions = route.max_sessions;
        let max_sessions_per_source = route.max_sessions_per_source;
        let response_rate_tracked_sources = max_sessions
            .max(max_sessions_per_source)
            .max(UDP_RESPONSE_RATE_TRACKED_SOURCES_FLOOR);

        if route
            .listen
            .iter()
            .filter_map(|listen| listen.parse::<SocketAddr>().ok())
            .any(|listen| !listen.ip().is_loopback())
        {
            log::warn!(
                target: "fluxheim::security",
                "UDP route {} ({:?} mode) listens on a non-loopback address; verify ingress filtering and response-rate limits before public exposure",
                route.name,
                route.mode
            );
        }

        Ok(Self {
            name: Arc::from(route.name.as_str()),
            mode: route.mode,
            upstreams: upstreams.into(),
            weight_total,
            response_timeout: Duration::from_secs(route.response_timeout_secs),
            passive_health_ejection: Duration::from_secs(route.passive_health_ejection_secs),
            max_datagram_bytes: route.max_datagram_bytes,
            max_sessions,
            max_sessions_per_source,
            max_responses_per_source_per_second: route.max_responses_per_source_per_second,
            passive_health_enabled: route.passive_health_enabled,
            passive_health_failures: route.passive_health_failures,
            response_rate_tracked_sources,
            active_sessions: Arc::new(AtomicUsize::new(0)),
            source_sessions: Arc::new(Mutex::new(HashMap::new())),
            response_rate_windows: Arc::new(Mutex::new(UdpResponseRateState::default())),
            datagrams_total: AtomicU64::new(0),
            responses_total: AtomicU64::new(0),
            drops_total: AtomicU64::new(0),
            next_upstream: AtomicUsize::new(0),
            last_drop_log_millis: AtomicU64::new(0),
            suppressed_drop_logs: AtomicUsize::new(0),
        })
    }

    fn acquire_session_slot(&self, source: IpAddr) -> Result<UdpSessionSlot, UdpAcquireError> {
        let route_counter = if self.max_sessions == 0 {
            None
        } else {
            match self.active_sessions.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |current| (current < self.max_sessions).then_some(current + 1),
            ) {
                Ok(_) => Some(self.active_sessions.clone()),
                Err(_) => return Err(UdpAcquireError::RouteLimit),
            }
        };

        let source_counter = if self.max_sessions_per_source == 0 {
            None
        } else {
            let mut sessions = self.lock_source_sessions();
            let current = sessions.get(&source).copied().unwrap_or(0);
            if current >= self.max_sessions_per_source {
                if let Some(counter) = &route_counter {
                    counter.fetch_sub(1, Ordering::AcqRel);
                }
                return Err(UdpAcquireError::SourceLimit);
            }
            sessions.insert(source, current + 1);
            Some((self.source_sessions.clone(), source))
        };

        self.set_active_session_metric();
        Ok(UdpSessionSlot {
            route_counter,
            source_counter,
            route_name: self.name.clone(),
        })
    }

    async fn process_datagram(
        &self,
        downstream: Arc<UdpSocket>,
        listener_local: SocketAddr,
        source: SocketAddr,
        payload: Vec<u8>,
    ) {
        let upstream = self.select_upstream();
        let result = match self.mode {
            UdpRouteMode::DnsLoadBalance => {
                self.forward_request_response(
                    &downstream,
                    listener_local,
                    source,
                    &payload,
                    upstream,
                )
                .await
            }
            UdpRouteMode::SyslogForward => {
                self.forward_one_way(listener_local, &payload, upstream)
                    .await
            }
            UdpRouteMode::QuicPassThrough | UdpRouteMode::GameProxy => {
                Err(io::Error::other("unsupported UDP route mode"))
            }
        };
        match result {
            Ok(()) => upstream.record_success(),
            Err(error) => {
                self.record_datagram("upstream", "error");
                self.record_upstream_failure(upstream);
                log::debug!(
                    target: "fluxheim::udp",
                    "UDP route {} failed to forward datagram via {}: {error}",
                    self.name,
                    upstream.alias.as_deref().unwrap_or(upstream.authority.as_str())
                );
            }
        }
    }

    fn select_upstream(&self) -> &RuntimeUdpUpstream {
        let start = self.next_upstream.fetch_add(1, Ordering::Relaxed) % self.weight_total;
        let now = udp_log_millis();
        let start_index = self.upstream_index_for_weight_slot(start);
        for offset in 0..self.upstreams.len() {
            let index = (start_index + offset) % self.upstreams.len();
            if self.upstreams[index].ready(now) {
                return &self.upstreams[index];
            }
        }
        self.upstream_for_weight_slot(start)
    }

    fn upstream_for_weight_slot(&self, slot: usize) -> &RuntimeUdpUpstream {
        &self.upstreams[self.upstream_index_for_weight_slot(slot)]
    }

    fn upstream_index_for_weight_slot(&self, mut slot: usize) -> usize {
        for (index, upstream) in self.upstreams.iter().enumerate() {
            if slot < upstream.weight {
                return index;
            }
            slot -= upstream.weight;
        }
        0
    }

    async fn forward_request_response(
        &self,
        downstream: &UdpSocket,
        listener_local: SocketAddr,
        source: SocketAddr,
        payload: &[u8],
        upstream: &RuntimeUdpUpstream,
    ) -> io::Result<()> {
        let upstream_socket = self
            .connected_upstream_socket(listener_local, upstream)
            .await?;
        upstream_socket.send(payload).await?;
        self.record_datagram("upstream", "sent");
        let mut response = vec![0u8; self.max_datagram_bytes.saturating_add(1)];
        let response_timeout = self.response_timeout();
        let len = tokio::time::timeout(response_timeout, upstream_socket.recv(&mut response))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "UDP upstream response timed out")
            })??;
        if len > self.max_datagram_bytes {
            self.record_drop("oversized_upstream");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP upstream response exceeded route datagram cap",
            ));
        }
        if !self.allow_response_to_source(source.ip()) {
            self.record_drop("response_rate_limited");
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "UDP response rate limit exceeded",
            ));
        }
        downstream.send_to(&response[..len], source).await?;
        self.responses_total.fetch_add(1, Ordering::Relaxed);
        self.record_datagram("downstream", "sent");
        Ok(())
    }

    async fn forward_one_way(
        &self,
        listener_local: SocketAddr,
        payload: &[u8],
        upstream: &RuntimeUdpUpstream,
    ) -> io::Result<()> {
        let upstream_socket = self
            .connected_upstream_socket(listener_local, upstream)
            .await?;
        upstream_socket.send(payload).await?;
        self.record_datagram("upstream", "sent");
        Ok(())
    }

    async fn connected_upstream_socket(
        &self,
        listener_local: SocketAddr,
        upstream: &RuntimeUdpUpstream,
    ) -> io::Result<UdpSocket> {
        let bind_addr = upstream_bind_addr(&upstream.authority, listener_local);
        let socket = UdpSocket::bind(bind_addr).await?;
        let connect_timeout = self.response_timeout();
        tokio::time::timeout(connect_timeout, socket.connect(upstream.authority.as_str()))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "UDP upstream connect timed out")
            })??;
        Ok(socket)
    }

    fn response_timeout(&self) -> Duration {
        self.response_timeout
    }

    fn allow_response_to_source(&self, source: IpAddr) -> bool {
        if self.max_responses_per_source_per_second == 0 {
            return true;
        }
        let now_secs = udp_log_millis() / 1_000;
        let mut state = self.lock_response_rate_windows();
        if state.window_secs != now_secs {
            state.window_secs = now_secs;
            state.windows.clear();
        }
        if !state.windows.contains_key(&source)
            && state.windows.len() >= self.response_rate_tracked_sources
        {
            return false;
        }
        let window = state
            .windows
            .entry(source)
            .or_insert(UdpResponseRateWindow { count: 0 });
        if window.count >= self.max_responses_per_source_per_second {
            return false;
        }
        window.count += 1;
        true
    }

    fn record_upstream_failure(&self, upstream: &RuntimeUdpUpstream) {
        if !self.passive_health_enabled {
            return;
        }
        let failures = upstream.failures.fetch_add(1, Ordering::AcqRel) + 1;
        if failures < self.passive_health_failures {
            return;
        }
        upstream.failures.store(0, Ordering::Release);
        let ejected_until = udp_log_millis().saturating_add(
            self.passive_health_ejection
                .as_millis()
                .min(u128::from(u64::MAX)) as u64,
        );
        upstream
            .ejected_until_millis
            .store(ejected_until, Ordering::Release);
        log::warn!(
            target: "fluxheim::udp",
            "UDP route {} passively ejected upstream {} after {} consecutive failures for {} seconds",
            self.name,
            upstream.alias.as_deref().unwrap_or(upstream.authority.as_str()),
            self.passive_health_failures,
            self.passive_health_ejection.as_secs()
        );
    }

    fn lock_source_sessions(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, usize>> {
        // Poisoning would mean per-source UDP accounting is no longer
        // trustworthy. Keep this critical section free of panic-capable work.
        match self.source_sessions.lock() {
            Ok(guard) => guard,
            Err(_) => {
                log::error!(
                    target: "fluxheim::security",
                    "UDP route {} source session lock poisoned; aborting to avoid inconsistent per-source accounting",
                    self.name
                );
                process::abort();
            }
        }
    }

    fn lock_response_rate_windows(&self) -> std::sync::MutexGuard<'_, UdpResponseRateState> {
        // Poisoning would mean UDP response-rate accounting is no longer
        // trustworthy. Keep this critical section free of panic-capable work.
        match self.response_rate_windows.lock() {
            Ok(guard) => guard,
            Err(_) => {
                log::error!(
                    target: "fluxheim::security",
                    "UDP route {} response-rate lock poisoned; aborting to avoid inconsistent UDP rate limiting",
                    self.name
                );
                process::abort();
            }
        }
    }

    fn record_datagram(&self, direction: &'static str, outcome: &'static str) {
        self.datagrams_total.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "metrics")]
        crate::metrics::record_udp_datagram(
            &self.name,
            udp_mode_label(self.mode),
            direction,
            outcome,
        );
        #[cfg(not(feature = "metrics"))]
        let _ = (direction, outcome);
    }

    fn record_drop(&self, reason: &'static str) {
        self.drops_total.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "metrics")]
        crate::metrics::record_udp_drop(&self.name, reason);
        #[cfg(not(feature = "metrics"))]
        let _ = reason;
    }

    fn set_active_session_metric(&self) {
        #[cfg(feature = "metrics")]
        crate::metrics::set_udp_active_sessions(
            &self.name,
            self.active_sessions.load(Ordering::Acquire),
        );
    }

    fn log_dropped_datagram(
        &self,
        source: SocketAddr,
        reason: &'static str,
        detail: impl std::fmt::Display,
    ) {
        let now = udp_log_millis();
        let last = self.last_drop_log_millis.load(Ordering::Relaxed);
        if now.saturating_sub(last) < UDP_DROP_LOG_INTERVAL_MILLIS {
            self.suppressed_drop_logs.fetch_add(1, Ordering::Relaxed);
            return;
        }

        if self
            .last_drop_log_millis
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            self.suppressed_drop_logs.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let suppressed = self.suppressed_drop_logs.swap(0, Ordering::AcqRel);
        log::warn!(
            target: "fluxheim::udp",
            "UDP route {} dropped datagram from {source}: {reason}; {detail}; suppressed_since_last={suppressed}",
            self.name
        );
    }
}

struct RuntimeUdpUpstream {
    authority: String,
    alias: Option<String>,
    weight: usize,
    failures: AtomicUsize,
    ejected_until_millis: AtomicU64,
}

impl RuntimeUdpUpstream {
    fn ready(&self, now_millis: u64) -> bool {
        self.ejected_until_millis.load(Ordering::Acquire) <= now_millis
    }

    fn record_success(&self) {
        self.failures.store(0, Ordering::Release);
        self.ejected_until_millis.store(0, Ordering::Release);
    }
}

#[derive(Debug, Default)]
struct UdpResponseRateState {
    window_secs: u64,
    windows: HashMap<IpAddr, UdpResponseRateWindow>,
}

#[derive(Debug, Clone, Copy)]
struct UdpResponseRateWindow {
    count: usize,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum UdpAcquireError {
    RouteLimit,
    SourceLimit,
}

struct UdpSessionSlot {
    route_counter: Option<Arc<AtomicUsize>>,
    source_counter: Option<(UdpSourceSessions, IpAddr)>,
    route_name: Arc<str>,
}

impl Drop for UdpSessionSlot {
    fn drop(&mut self) {
        if let Some(counter) = &self.route_counter {
            counter.fetch_sub(1, Ordering::AcqRel);
            #[cfg(feature = "metrics")]
            crate::metrics::set_udp_active_sessions(
                &self.route_name,
                counter.load(Ordering::Acquire),
            );
        }
        if let Some((sessions, source)) = &self.source_counter {
            // Poisoning would mean per-source UDP accounting is no longer
            // trustworthy. Keep this critical section free of panic-capable work.
            let mut sessions = match sessions.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    log::error!(
                        target: "fluxheim::security",
                        "UDP route {} source session lock poisoned during release; aborting to avoid inconsistent per-source accounting",
                        self.route_name
                    );
                    process::abort();
                }
            };
            match sessions.get_mut(source) {
                Some(count) if *count > 1 => *count -= 1,
                Some(_) => {
                    sessions.remove(source);
                }
                None => {}
            }
        }
    }
}

#[cfg(feature = "metrics")]
fn udp_mode_label(mode: UdpRouteMode) -> &'static str {
    match mode {
        UdpRouteMode::DnsLoadBalance => "dns_load_balance",
        UdpRouteMode::SyslogForward => "syslog_forward",
        UdpRouteMode::QuicPassThrough => "quic_pass_through",
        UdpRouteMode::GameProxy => "game_proxy",
    }
}

fn runtime_udp_upstreams(route: &UdpRouteConfig) -> Vec<RuntimeUdpUpstream> {
    route
        .upstreams()
        .enumerate()
        .map(|(index, authority)| RuntimeUdpUpstream {
            authority: authority.to_owned(),
            alias: route.upstream_aliases.get(index).cloned(),
            weight: route.upstream_weights.get(index).copied().unwrap_or(1),
            failures: AtomicUsize::new(0),
            ejected_until_millis: AtomicU64::new(0),
        })
        .collect()
}

fn upstream_bind_addr(authority: &str, listener_local: SocketAddr) -> SocketAddr {
    authority
        .parse::<SocketAddr>()
        .map(|address| unspecified_bind_addr(address.ip()))
        .unwrap_or_else(|_| unspecified_bind_addr(listener_local.ip()))
}

fn unspecified_bind_addr(ip: IpAddr) -> SocketAddr {
    match ip {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn udp_log_millis() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    millis.min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::{UdpAcquireError, UdpProxyApp, unspecified_bind_addr};
    use crate::config::{UdpRouteConfig, UdpRouteMode};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use tokio::net::UdpSocket;

    fn route(upstream: String, mode: UdpRouteMode) -> UdpRouteConfig {
        UdpRouteConfig {
            name: "udp-test".to_owned(),
            mode,
            listen: vec!["127.0.0.1:5353".to_owned()],
            upstream: Some(upstream),
            upstreams: Vec::new(),
            upstream_weights: Vec::new(),
            upstream_aliases: Vec::new(),
            idle_timeout_secs: 1,
            response_timeout_secs: 1,
            max_datagram_bytes: 512,
            max_sessions: 1,
            max_sessions_per_source: 1,
            max_responses_per_source_per_second: 256,
            passive_health_enabled: true,
            passive_health_failures: 3,
            passive_health_ejection_secs: 10,
        }
    }

    #[tokio::test]
    async fn udp_dns_mode_forwards_response_to_downstream() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let mut buf = [0u8; 32];
            let (len, peer) = upstream.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], b"query");
            upstream.send_to(b"answer", peer).await.unwrap();
        });

        let app = UdpProxyApp::from_config(&route(
            upstream_addr.to_string(),
            UdpRouteMode::DnsLoadBalance,
        ))
        .unwrap();
        let downstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        app.process_datagram(
            downstream.clone(),
            downstream.local_addr().unwrap(),
            client.local_addr().unwrap(),
            b"query".to_vec(),
        )
        .await;

        let mut response = [0u8; 32];
        let (len, _peer) = client.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..len], b"answer");
        upstream_task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_dns_mode_drops_oversized_upstream_response() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let mut buf = [0u8; 32];
            let (_len, peer) = upstream.recv_from(&mut buf).await.unwrap();
            let oversized = vec![b'x'; 513];
            upstream.send_to(&oversized, peer).await.unwrap();
        });

        let app = UdpProxyApp::from_config(&route(
            upstream_addr.to_string(),
            UdpRouteMode::DnsLoadBalance,
        ))
        .unwrap();
        let downstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        app.process_datagram(
            downstream.clone(),
            downstream.local_addr().unwrap(),
            client.local_addr().unwrap(),
            b"query".to_vec(),
        )
        .await;

        let mut response = [0u8; 32];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                client.recv_from(&mut response)
            )
            .await
            .is_err()
        );
        upstream_task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_syslog_mode_forwards_without_response() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let app = UdpProxyApp::from_config(&route(
            upstream_addr.to_string(),
            UdpRouteMode::SyslogForward,
        ))
        .unwrap();
        let downstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        app.process_datagram(
            downstream.clone(),
            downstream.local_addr().unwrap(),
            client.local_addr().unwrap(),
            b"<13>message".to_vec(),
        )
        .await;

        let mut received = [0u8; 32];
        let (len, _peer) = upstream.recv_from(&mut received).await.unwrap();
        assert_eq!(&received[..len], b"<13>message");
    }

    #[test]
    fn udp_session_slot_releases_counted_counter() {
        let app = UdpProxyApp::from_config(&route(
            "127.0.0.1:53".to_owned(),
            UdpRouteMode::DnsLoadBalance,
        ))
        .unwrap();
        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let slot = app.acquire_session_slot(source).unwrap();
        assert!(matches!(
            app.acquire_session_slot(source),
            Err(UdpAcquireError::RouteLimit)
        ));
        drop(slot);
        assert!(app.acquire_session_slot(source).is_ok());
    }

    #[test]
    fn udp_session_slot_enforces_per_source_limit() {
        let mut route = route("127.0.0.1:53".to_owned(), UdpRouteMode::DnsLoadBalance);
        route.max_sessions = 2;
        route.max_sessions_per_source = 1;
        let app = UdpProxyApp::from_config(&route).unwrap();
        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let other = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

        let slot = app.acquire_session_slot(source).unwrap();
        assert!(matches!(
            app.acquire_session_slot(source),
            Err(UdpAcquireError::SourceLimit)
        ));
        assert!(app.acquire_session_slot(other).is_ok());
        drop(slot);
        assert!(app.acquire_session_slot(source).is_ok());
    }

    #[test]
    fn udp_response_rate_limit_is_per_source_per_second() {
        let mut route = route("127.0.0.1:53".to_owned(), UdpRouteMode::DnsLoadBalance);
        route.max_responses_per_source_per_second = 1;
        let app = UdpProxyApp::from_config(&route).unwrap();
        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);

        assert!(app.allow_response_to_source(source));
        assert!(!app.allow_response_to_source(source));
    }

    #[test]
    fn udp_response_rate_limit_rolls_generation_without_per_packet_scan() {
        let mut route = route("127.0.0.1:53".to_owned(), UdpRouteMode::DnsLoadBalance);
        route.max_responses_per_source_per_second = 2;
        let app = UdpProxyApp::from_config(&route).unwrap();
        let old_source = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let new_source = IpAddr::V4(Ipv4Addr::LOCALHOST);

        {
            let mut state = app.lock_response_rate_windows();
            state.window_secs = (super::udp_log_millis() / 1_000).saturating_sub(1);
            state
                .windows
                .insert(old_source, super::UdpResponseRateWindow { count: 2 });
        }

        assert!(app.allow_response_to_source(new_source));
        let state = app.lock_response_rate_windows();
        assert_eq!(state.windows.len(), 1);
        assert!(state.windows.contains_key(&new_source));
        assert!(!state.windows.contains_key(&old_source));
    }

    #[test]
    fn udp_selection_skips_passively_ejected_upstream() {
        let mut route = route("127.0.0.1:53".to_owned(), UdpRouteMode::DnsLoadBalance);
        route.upstream = None;
        route.upstreams = vec!["127.0.0.1:53".to_owned(), "127.0.0.1:54".to_owned()];
        route.upstream_weights = vec![1, 1];
        route.upstream_aliases = vec!["bad".to_owned(), "good".to_owned()];
        let app = UdpProxyApp::from_config(&route).unwrap();

        app.upstreams[0].ejected_until_millis.store(
            super::udp_log_millis().saturating_add(10_000),
            Ordering::Release,
        );

        let selected = app.select_upstream();
        assert_eq!(selected.alias.as_deref(), Some("good"));
    }

    #[test]
    fn udp_passive_health_ejects_and_success_restores_upstream() {
        let mut route = route("127.0.0.1:53".to_owned(), UdpRouteMode::DnsLoadBalance);
        route.passive_health_failures = 1;
        let app = UdpProxyApp::from_config(&route).unwrap();
        let upstream = &app.upstreams[0];

        app.record_upstream_failure(upstream);
        assert!(upstream.ejected_until_millis.load(Ordering::Acquire) > super::udp_log_millis());

        upstream.record_success();
        assert_eq!(upstream.failures.load(Ordering::Acquire), 0);
        assert_eq!(upstream.ejected_until_millis.load(Ordering::Acquire), 0);
    }

    #[test]
    fn udp_unspecified_bind_addr_matches_address_family() {
        assert_eq!(
            unspecified_bind_addr(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "0.0.0.0:0".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            unspecified_bind_addr(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            "[::]:0".parse::<SocketAddr>().unwrap()
        );
    }
}
