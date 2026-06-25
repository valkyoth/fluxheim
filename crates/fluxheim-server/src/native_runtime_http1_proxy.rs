use std::error::Error;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use fluxheim_config::{Config, TlsAlpnPolicy};
use fluxheim_runtime::{FluxShutdown, NativeBackgroundSupervisor};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[cfg(feature = "tls-rustls-backend")]
use crate::serve_native_http1_rustls_listener;
use crate::{
    ListenerProtocol, NativeHttp1Error, NativeHttp1HostRouter, NativeHttp1HostRouterConfigError,
    NativeRuntimeLaunchPlan, NativeRuntimeLaunchPlanError, ServerPlan, ServiceKind,
    serve_native_http1_listener, serve_native_http1_listener_with_proxy_protocol,
};

#[cfg(feature = "tls-rustls-backend")]
const ACME_TLS_ALPN_PROTOCOL: &[u8] = b"acme-tls/1";

pub struct NativeHttp1ProxyRuntime {
    policy: crate::DownstreamHttp1Policy,
    proxy_protocol: crate::ProxyProtocolPolicy,
    router: Arc<NativeHttp1HostRouter>,
    listeners: Vec<NativeHttp1ProxyRuntimeListener>,
    #[cfg(feature = "tls-rustls-backend")]
    rustls_config: Option<Arc<rustls::ServerConfig>>,
}

struct NativeHttp1ProxyRuntimeListener {
    protocol: ListenerProtocol,
    proxy_protocol_enabled: bool,
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
    Router(NativeHttp1HostRouterConfigError),
    #[cfg(feature = "tls-rustls-backend")]
    RustlsCertificate(fluxheim_tls::RustlsDownstreamCertificateError),
    #[cfg(feature = "tls-rustls-backend")]
    RustlsServerConfig(fluxheim_tls::RustlsDownstreamServerConfigError),
    #[cfg(feature = "tls-rustls-backend")]
    TlsPlan(fluxheim_tls::DownstreamTlsPlanError),
    UnsupportedTlsAlpn {
        policy: TlsAlpnPolicy,
    },
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
            Self::Router(error) => write!(formatter, "native HTTP/1 host router: {error}"),
            #[cfg(feature = "tls-rustls-backend")]
            Self::RustlsCertificate(error) => {
                write!(
                    formatter,
                    "native HTTP/1 rustls certificate resolver: {error}"
                )
            }
            #[cfg(feature = "tls-rustls-backend")]
            Self::RustlsServerConfig(error) => {
                write!(formatter, "native HTTP/1 rustls server config: {error}")
            }
            #[cfg(feature = "tls-rustls-backend")]
            Self::TlsPlan(error) => write!(formatter, "native HTTP/1 TLS listener plan: {error}"),
            Self::UnsupportedTlsAlpn { policy } => write!(
                formatter,
                "native HTTP/1 proxy HTTPS listener requires tls.alpn = \"http1\", got {policy:?}"
            ),
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
            #[cfg(feature = "tls-rustls-backend")]
            Self::RustlsCertificate(error) => Some(error),
            #[cfg(feature = "tls-rustls-backend")]
            Self::RustlsServerConfig(error) => Some(error),
            #[cfg(feature = "tls-rustls-backend")]
            Self::TlsPlan(error) => Some(error),
            Self::MissingProxyHttpListener
            | Self::UnsupportedTlsAlpn { .. }
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
        let has_https_listener = launch_plan.listeners().iter().any(|listener| {
            listener.service_kind() == ServiceKind::ProxyHttp
                && listener.listener_protocol() == ListenerProtocol::Https
        });
        #[cfg(feature = "tls-rustls-backend")]
        let rustls_config = if has_https_listener {
            Some(native_rustls_server_config(config)?)
        } else {
            None
        };
        #[cfg(not(feature = "tls-rustls-backend"))]
        if has_https_listener {
            let listener = launch_plan
                .listeners()
                .iter()
                .find(|listener| {
                    listener.service_kind() == ServiceKind::ProxyHttp
                        && listener.listener_protocol() == ListenerProtocol::Https
                })
                .ok_or(NativeHttp1ProxyRuntimeError::MissingProxyHttpListener)?;
            return Err(NativeHttp1ProxyRuntimeError::UnsupportedListener {
                protocol: listener.listener_protocol(),
                addr: listener.listener_addr(),
            });
        }
        let mut listeners = Vec::new();
        for planned in launch_plan
            .listeners()
            .iter()
            .filter(|listener| listener.service_kind() == ServiceKind::ProxyHttp)
        {
            if !matches!(
                planned.listener_protocol(),
                ListenerProtocol::Http | ListenerProtocol::Https
            ) {
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
                protocol: planned.listener_protocol(),
                proxy_protocol_enabled: planned.proxy_protocol_enabled(),
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
            proxy_protocol: launch_plan.proxy_protocol().clone(),
            router,
            listeners,
            #[cfg(feature = "tls-rustls-backend")]
            rustls_config,
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
            let proxy_protocol = self.proxy_protocol.clone();
            let router = self.router.clone();
            let shutdown = supervisor.shutdown_view();
            #[cfg(feature = "tls-rustls-backend")]
            let rustls_config = self.rustls_config.clone();
            let handle = tokio::spawn(async move {
                match listener.protocol {
                    ListenerProtocol::Http if listener.proxy_protocol_enabled => {
                        serve_native_http1_listener_with_proxy_protocol(
                            listener.listener,
                            policy,
                            proxy_protocol,
                            router,
                            shutdown_wait(shutdown),
                        )
                        .await
                    }
                    ListenerProtocol::Http => {
                        serve_native_http1_listener(
                            listener.listener,
                            policy,
                            router,
                            shutdown_wait(shutdown),
                        )
                        .await
                    }
                    #[cfg(feature = "tls-rustls-backend")]
                    ListenerProtocol::Https => {
                        let Some(rustls_config) = rustls_config else {
                            return Err(NativeHttp1Error::Io(io::Error::other(
                                "missing rustls config for native HTTPS listener",
                            )));
                        };
                        serve_native_http1_rustls_listener(
                            listener.listener,
                            policy,
                            rustls_config,
                            router,
                            shutdown_wait(shutdown),
                        )
                        .await
                    }
                    #[cfg(not(feature = "tls-rustls-backend"))]
                    ListenerProtocol::Https => Err(NativeHttp1Error::Io(io::Error::other(
                        "native HTTPS listener requires tls-rustls-backend",
                    ))),
                    ListenerProtocol::AdminHttp
                    | ListenerProtocol::MetricsHttp
                    | ListenerProtocol::StreamTcp
                    | ListenerProtocol::Udp => Err(NativeHttp1Error::Io(io::Error::other(
                        "unsupported native HTTP/1 proxy listener protocol",
                    ))),
                }
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

#[cfg(feature = "tls-rustls-backend")]
fn native_rustls_server_config(
    config: &Config,
) -> Result<Arc<rustls::ServerConfig>, NativeHttp1ProxyRuntimeError> {
    if config.tls.effective_alpn() != TlsAlpnPolicy::Http1 {
        return Err(NativeHttp1ProxyRuntimeError::UnsupportedTlsAlpn {
            policy: config.tls.effective_alpn(),
        });
    }
    let plan = fluxheim_tls::DownstreamTlsListenerPlan::from_config(config)
        .map_err(NativeHttp1ProxyRuntimeError::TlsPlan)?
        .ok_or(NativeHttp1ProxyRuntimeError::MissingProxyHttpListener)?;
    let resolver = Arc::new(
        fluxheim_tls::RustlsDownstreamCertificateResolver::new(plan.selector())
            .map_err(NativeHttp1ProxyRuntimeError::RustlsCertificate)?,
    );
    let acme_tls_alpn_protocol = plan
        .acme_tls_alpn_enabled()
        .then_some(ACME_TLS_ALPN_PROTOCOL);
    fluxheim_tls::build_rustls_downstream_server_config(
        &config.tls,
        resolver,
        acme_tls_alpn_protocol,
    )
    .map(Arc::new)
    .map_err(NativeHttp1ProxyRuntimeError::RustlsServerConfig)
}
