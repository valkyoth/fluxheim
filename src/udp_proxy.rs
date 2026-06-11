use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
                                app.log_dropped_datagram(
                                    source,
                                    "oversized downstream datagram",
                                    format_args!("{} bytes > {}", len, app.max_datagram_bytes),
                                );
                                continue;
                            }
                            let Some(slot) = app.acquire_session_slot() else {
                                app.log_dropped_datagram(
                                    source,
                                    "max_sessions exceeded",
                                    format_args!("active session cap is {}", app.max_sessions),
                                );
                                continue;
                            };
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
    max_datagram_bytes: usize,
    max_sessions: usize,
    active_sessions: Arc<AtomicUsize>,
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

        Ok(Self {
            name: Arc::from(route.name.as_str()),
            mode: route.mode,
            upstreams: upstreams.into(),
            weight_total,
            response_timeout: Duration::from_secs(route.response_timeout_secs),
            max_datagram_bytes: route.max_datagram_bytes,
            max_sessions: route.max_sessions,
            active_sessions: Arc::new(AtomicUsize::new(0)),
            next_upstream: AtomicUsize::new(0),
            last_drop_log_millis: AtomicU64::new(0),
            suppressed_drop_logs: AtomicUsize::new(0),
        })
    }

    fn acquire_session_slot(&self) -> Option<UdpSessionSlot> {
        if self.max_sessions == 0 {
            return Some(UdpSessionSlot::unlimited());
        }
        match self
            .active_sessions
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < self.max_sessions).then_some(current + 1)
            }) {
            Ok(_) => Some(UdpSessionSlot::counted(self.active_sessions.clone())),
            Err(_) => None,
        }
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
        if let Err(error) = result {
            log::debug!(
                target: "fluxheim::udp",
                "UDP route {} failed to forward datagram via {}: {error}",
                self.name,
                upstream.alias.as_deref().unwrap_or(upstream.authority.as_str())
            );
        }
    }

    fn select_upstream(&self) -> &RuntimeUdpUpstream {
        let mut slot = self.next_upstream.fetch_add(1, Ordering::Relaxed) % self.weight_total;
        for upstream in self.upstreams.iter() {
            if slot < upstream.weight {
                return upstream;
            }
            slot -= upstream.weight;
        }
        &self.upstreams[0]
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
        let mut response = vec![0u8; self.max_datagram_bytes.saturating_add(1)];
        let response_timeout = self.response_timeout();
        let len = tokio::time::timeout(response_timeout, upstream_socket.recv(&mut response))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "UDP upstream response timed out")
            })??;
        if len > self.max_datagram_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP upstream response exceeded route datagram cap",
            ));
        }
        downstream.send_to(&response[..len], source).await?;
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
}

struct UdpSessionSlot {
    counter: Option<Arc<AtomicUsize>>,
}

impl UdpSessionSlot {
    fn counted(counter: Arc<AtomicUsize>) -> Self {
        Self {
            counter: Some(counter),
        }
    }

    fn unlimited() -> Self {
        Self { counter: None }
    }
}

impl Drop for UdpSessionSlot {
    fn drop(&mut self) {
        if let Some(counter) = &self.counter {
            counter.fetch_sub(1, Ordering::AcqRel);
        }
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
    use super::{UdpProxyApp, UdpSessionSlot, unspecified_bind_addr};
    use crate::config::{UdpRouteConfig, UdpRouteMode};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
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
            max_session_secs: Some(1),
            max_datagram_bytes: 512,
            max_sessions: 1,
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
        let slot = app.acquire_session_slot().unwrap();
        assert!(matches!(slot, UdpSessionSlot { counter: Some(_) }));
        assert!(app.acquire_session_slot().is_none());
        drop(slot);
        assert!(app.acquire_session_slot().is_some());
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
