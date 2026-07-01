use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::process;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::config::{UdpRouteConfig, UdpRouteMode};
use fluxheim_common::{FluxError, FluxResult};

const UDP_DROP_LOG_INTERVAL_MILLIS: u64 = 1_000;
const UDP_EJECTION_LOG_INTERVAL_MILLIS: u64 = 1_000;
const UDP_RESPONSE_RATE_TRACKED_SOURCES_FLOOR: usize = 4_096;

mod service;
pub(crate) use service::udp_background_services_from_config;
mod state;
#[cfg(feature = "metrics")]
use state::udp_mode_label;
#[cfg(test)]
use state::unspecified_bind_addr;
use state::{
    RuntimeUdpUpstream, UdpAcquireError, UdpResponseRateState, UdpResponseRateWindow,
    UdpResponseRateWindows, UdpSessionSlot, UdpSourceSessions, runtime_udp_upstreams,
    udp_error_counts_for_passive_health, udp_log_millis, upstream_bind_addr,
};

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
    last_ejection_log_millis: AtomicU64,
    suppressed_ejection_logs: AtomicUsize,
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
            last_ejection_log_millis: AtomicU64::new(0),
            suppressed_ejection_logs: AtomicUsize::new(0),
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
                if udp_error_counts_for_passive_health(&error) {
                    self.record_upstream_failure(upstream);
                }
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
        self.log_passive_ejection(upstream);
    }

    fn log_passive_ejection(&self, upstream: &RuntimeUdpUpstream) {
        let now = udp_log_millis();
        let last = self.last_ejection_log_millis.load(Ordering::Relaxed);
        if now.saturating_sub(last) < UDP_EJECTION_LOG_INTERVAL_MILLIS {
            self.suppressed_ejection_logs
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        if self
            .last_ejection_log_millis
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            self.suppressed_ejection_logs
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        let suppressed = self.suppressed_ejection_logs.swap(0, Ordering::AcqRel);
        log::warn!(
            target: "fluxheim::udp",
            "UDP route {} passively ejected upstream {} after {} consecutive failures for {} seconds; suppressed_since_last={suppressed}",
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

#[cfg(test)]
mod tests;
