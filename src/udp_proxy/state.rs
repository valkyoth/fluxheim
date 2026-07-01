use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::UdpRouteConfig;
#[cfg(feature = "metrics")]
use crate::config::UdpRouteMode;

pub(super) type UdpSourceSessions = Arc<Mutex<HashMap<IpAddr, usize>>>;
pub(super) type UdpResponseRateWindows = Arc<Mutex<UdpResponseRateState>>;

pub(super) fn udp_error_counts_for_passive_health(error: &std::io::Error) -> bool {
    !matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::InvalidData
    )
}

pub(super) struct RuntimeUdpUpstream {
    pub(super) authority: String,
    pub(super) alias: Option<String>,
    pub(super) weight: usize,
    pub(super) failures: AtomicUsize,
    pub(super) ejected_until_millis: AtomicU64,
}

impl RuntimeUdpUpstream {
    pub(super) fn ready(&self, now_millis: u64) -> bool {
        self.ejected_until_millis.load(Ordering::Acquire) <= now_millis
    }

    pub(super) fn record_success(&self) {
        self.failures.store(0, Ordering::Release);
        self.ejected_until_millis.store(0, Ordering::Release);
    }
}

#[derive(Debug, Default)]
pub(super) struct UdpResponseRateState {
    pub(super) window_secs: u64,
    pub(super) windows: HashMap<IpAddr, UdpResponseRateWindow>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct UdpResponseRateWindow {
    pub(super) count: usize,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum UdpAcquireError {
    RouteLimit,
    SourceLimit,
}

pub(super) struct UdpSessionSlot {
    pub(super) route_counter: Option<Arc<AtomicUsize>>,
    pub(super) source_counter: Option<(UdpSourceSessions, IpAddr)>,
    pub(super) route_name: Arc<str>,
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
pub(super) fn udp_mode_label(mode: UdpRouteMode) -> &'static str {
    match mode {
        UdpRouteMode::DnsLoadBalance => "dns_load_balance",
        UdpRouteMode::SyslogForward => "syslog_forward",
        UdpRouteMode::QuicPassThrough => "quic_pass_through",
        UdpRouteMode::GameProxy => "game_proxy",
    }
}

pub(super) fn runtime_udp_upstreams(route: &UdpRouteConfig) -> Vec<RuntimeUdpUpstream> {
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

pub(super) fn upstream_bind_addr(authority: &str, listener_local: SocketAddr) -> SocketAddr {
    authority
        .parse::<SocketAddr>()
        .map(|address| unspecified_bind_addr(address.ip()))
        .unwrap_or_else(|_| unspecified_bind_addr(listener_local.ip()))
}

pub(super) fn unspecified_bind_addr(ip: IpAddr) -> SocketAddr {
    match ip {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

pub(super) fn udp_log_millis() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    millis.min(u128::from(u64::MAX)) as u64
}
