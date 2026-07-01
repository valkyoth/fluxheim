use std::io;
use std::process;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::background::{FluxBackgroundReady, FluxBackgroundTask, FluxShutdown};
use crate::config::{Config, UdpRouteConfig};
use fluxheim_common::FluxError;

use super::{UdpAcquireError, UdpProxyApp};

const UDP_RECEIVE_BUFFER_BYTES: usize = 65_507;

pub(crate) fn udp_background_services_from_config(
    config: &Config,
) -> io::Result<Vec<crate::background::FluxBackgroundService<UdpProxyTask>>> {
    if !config.udp.enabled {
        return Ok(Vec::new());
    }

    config
        .udp
        .routes
        .iter()
        .map(udp_background_service_from_route)
        .collect()
}

fn udp_background_service_from_route(
    route: &UdpRouteConfig,
) -> io::Result<crate::background::FluxBackgroundService<UdpProxyTask>> {
    UdpProxyService::from_config(route).map(UdpProxyService::into_background_service)
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

    fn into_background_service(self) -> crate::background::FluxBackgroundService<UdpProxyTask> {
        crate::background::FluxBackgroundService::new(
            self.name,
            UdpProxyTask {
                listen: self.listen,
                app: self.app,
            },
        )
    }
}

pub(crate) struct UdpProxyTask {
    listen: Arc<[String]>,
    app: Arc<UdpProxyApp>,
}

impl UdpProxyTask {
    async fn run_listener(
        app: Arc<UdpProxyApp>,
        socket: Arc<UdpSocket>,
        listen: String,
        mut shutdown: FluxShutdown,
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
            if shutdown.is_shutdown() {
                break;
            }
            tokio::select! {
                requested = shutdown.wait_for_shutdown() => {
                    if requested {
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
impl FluxBackgroundTask for UdpProxyTask {
    async fn start(&self, shutdown: FluxShutdown, mut ready: FluxBackgroundReady) {
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
        ready.notify_ready();
        if listeners.is_empty() {
            let mut shutdown = shutdown;
            let _ = shutdown.wait_for_shutdown().await;
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
        let mut shutdown = shutdown;
        let _ = shutdown.wait_for_shutdown().await;
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
    }
}
