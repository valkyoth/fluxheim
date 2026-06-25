use std::error::Error;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use fluxheim_config::Config;
use fluxheim_runtime::{FluxShutdown, NativeBackgroundSupervisor};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::{
    ListenerProtocol, NativeHttp1Error, NativeHttp1HostRouter, NativeHttp1HostRouterConfigError,
    NativeRuntimeLaunchPlan, NativeRuntimeLaunchPlanError, ServerPlan, ServiceKind,
    serve_native_http1_listener,
};

pub struct NativeHttp1ProxyRuntime {
    policy: crate::DownstreamHttp1Policy,
    router: Arc<NativeHttp1HostRouter>,
    listeners: Vec<NativeHttp1ProxyRuntimeListener>,
}

struct NativeHttp1ProxyRuntimeListener {
    planned_addr: SocketAddr,
    local_addr: SocketAddr,
    listener: TcpListener,
}

#[derive(Debug)]
pub struct NativeHttp1ProxyRuntimeHandle {
    listeners: Vec<NativeHttp1ProxyListenerHandle>,
}

#[derive(Debug)]
struct NativeHttp1ProxyListenerHandle {
    local_addr: SocketAddr,
    handle: Option<JoinHandle<Result<(), NativeHttp1Error>>>,
}

#[derive(Debug)]
pub enum NativeHttp1ProxyRuntimeError {
    Bind {
        addr: SocketAddr,
        source: io::Error,
    },
    LaunchPlan(NativeRuntimeLaunchPlanError),
    MissingProxyHttpListener,
    ProxyProtocol {
        addr: SocketAddr,
    },
    Router(NativeHttp1HostRouterConfigError),
    UnsupportedListener {
        protocol: ListenerProtocol,
        addr: SocketAddr,
    },
}

impl fmt::Display for NativeHttp1ProxyRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind { addr, source } => {
                write!(
                    formatter,
                    "failed to bind native HTTP/1 proxy listener {addr}: {source}"
                )
            }
            Self::LaunchPlan(error) => {
                write!(formatter, "native HTTP/1 proxy launch plan: {error}")
            }
            Self::MissingProxyHttpListener => {
                formatter.write_str("native HTTP/1 proxy runtime requires a proxy HTTP listener")
            }
            Self::ProxyProtocol { addr } => write!(
                formatter,
                "native HTTP/1 proxy listener {addr} requires downstream PROXY protocol support"
            ),
            Self::Router(error) => write!(formatter, "native HTTP/1 host router: {error}"),
            Self::UnsupportedListener { protocol, addr } => write!(
                formatter,
                "native HTTP/1 proxy listener {addr} uses unsupported protocol {protocol:?}"
            ),
        }
    }
}

impl Error for NativeHttp1ProxyRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Bind { source, .. } => Some(source),
            Self::LaunchPlan(error) => Some(error),
            Self::Router(error) => Some(error),
            Self::MissingProxyHttpListener
            | Self::ProxyProtocol { .. }
            | Self::UnsupportedListener { .. } => None,
        }
    }
}

impl NativeHttp1ProxyRuntime {
    pub async fn bind_from_config(
        config: &Config,
        plan: &ServerPlan,
    ) -> Result<Self, NativeHttp1ProxyRuntimeError> {
        let launch_plan = plan
            .native_runtime_launch_plan()
            .map_err(NativeHttp1ProxyRuntimeError::LaunchPlan)?;
        Self::bind_from_launch_plan(config, &launch_plan).await
    }

    pub async fn bind_from_launch_plan(
        config: &Config,
        launch_plan: &NativeRuntimeLaunchPlan,
    ) -> Result<Self, NativeHttp1ProxyRuntimeError> {
        let router = Arc::new(
            NativeHttp1HostRouter::from_config(
                config,
                launch_plan.downstream_http1(),
                launch_plan.process().upstream_keepalive_pool_size(),
            )
            .map_err(NativeHttp1ProxyRuntimeError::Router)?,
        );
        let mut listeners = Vec::new();
        for planned in launch_plan
            .listeners()
            .iter()
            .filter(|listener| listener.service_kind() == ServiceKind::ProxyHttp)
        {
            if planned.proxy_protocol_enabled() {
                return Err(NativeHttp1ProxyRuntimeError::ProxyProtocol {
                    addr: planned.listener_addr(),
                });
            }
            if planned.listener_protocol() != ListenerProtocol::Http {
                return Err(NativeHttp1ProxyRuntimeError::UnsupportedListener {
                    protocol: planned.listener_protocol(),
                    addr: planned.listener_addr(),
                });
            }
            let listener = TcpListener::bind(planned.listener_addr())
                .await
                .map_err(|source| NativeHttp1ProxyRuntimeError::Bind {
                    addr: planned.listener_addr(),
                    source,
                })?;
            let local_addr =
                listener
                    .local_addr()
                    .map_err(|source| NativeHttp1ProxyRuntimeError::Bind {
                        addr: planned.listener_addr(),
                        source,
                    })?;
            listeners.push(NativeHttp1ProxyRuntimeListener {
                planned_addr: planned.listener_addr(),
                local_addr,
                listener,
            });
        }
        if listeners.is_empty() {
            return Err(NativeHttp1ProxyRuntimeError::MissingProxyHttpListener);
        }
        Ok(Self {
            policy: launch_plan.downstream_http1(),
            router,
            listeners,
        })
    }

    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .map(|listener| listener.local_addr)
            .collect()
    }

    pub fn planned_addrs(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .map(|listener| listener.planned_addr)
            .collect()
    }

    pub fn start(self, supervisor: &NativeBackgroundSupervisor) -> NativeHttp1ProxyRuntimeHandle {
        let mut handles = Vec::with_capacity(self.listeners.len());
        for listener in self.listeners {
            let local_addr = listener.local_addr;
            let policy = self.policy;
            let router = self.router.clone();
            let shutdown = supervisor.shutdown_view();
            let handle = tokio::spawn(async move {
                serve_native_http1_listener(
                    listener.listener,
                    policy,
                    router,
                    shutdown_wait(shutdown),
                )
                .await
            });
            handles.push(NativeHttp1ProxyListenerHandle {
                local_addr,
                handle: Some(handle),
            });
        }
        NativeHttp1ProxyRuntimeHandle { listeners: handles }
    }
}

impl NativeHttp1ProxyRuntimeHandle {
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .map(|listener| listener.local_addr)
            .collect()
    }

    pub async fn join(mut self) -> Vec<Result<(), NativeHttp1Error>> {
        let listeners = std::mem::take(&mut self.listeners);
        let mut results = Vec::with_capacity(listeners.len());
        for mut listener in listeners {
            let Some(handle) = listener.handle.take() else {
                continue;
            };
            match handle.await {
                Ok(result) => results.push(result),
                Err(error) if error.is_cancelled() => {}
                Err(error) => results.push(Err(NativeHttp1Error::Io(io::Error::other(error)))),
            }
        }
        results
    }
}

impl Drop for NativeHttp1ProxyRuntimeHandle {
    fn drop(&mut self) {
        for listener in &mut self.listeners {
            if let Some(handle) = &listener.handle {
                handle.abort();
            }
        }
    }
}

async fn shutdown_wait(mut shutdown: FluxShutdown) {
    let _ = shutdown.wait_for_shutdown().await;
}
