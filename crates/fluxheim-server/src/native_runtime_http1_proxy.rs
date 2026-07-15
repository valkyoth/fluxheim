use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use fluxheim_config::{Config, TlsAlpnPolicy};
use fluxheim_runtime::{FluxShutdown, NativeBackgroundSupervisor};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[cfg(any(
    feature = "tls-rustls-backend",
    all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
))]
use crate::DownstreamHttp2Policy;
#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
use crate::native_http1::{NativeTlsHttp2Dispatch, serve_native_http1_and_http2_openssl_listener};
#[cfg(feature = "tls-rustls-backend")]
use crate::native_http1::{NativeTlsHttp2Dispatch, serve_native_http1_and_http2_rustls_listener};
#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
use crate::serve_native_http1_openssl_listener;
#[cfg(feature = "tls-rustls-backend")]
use crate::serve_native_http1_rustls_listener;
use crate::{
    ListenerProtocol, NativeHttp1Error, NativeHttp1HostRouter, NativeHttp1HostRouterConfigError,
    NativeHttp1ReloadableRouter, NativeHttp1RouterReloadHandle, NativeRequestBodyBudget,
    NativeRuntimeLaunchPlan, NativeRuntimeLaunchPlanError, ServerPlan, ServiceKind,
    serve_native_http1_listener, serve_native_http1_listener_with_proxy_protocol,
};

#[path = "native_runtime_http1_proxy_error.rs"]
mod runtime_error;
#[path = "native_runtime_http1_proxy_handle.rs"]
mod runtime_handle;
#[path = "native_runtime_http1_proxy_listener.rs"]
mod runtime_listener;
#[path = "native_runtime_http1_proxy_tls.rs"]
mod runtime_tls;

#[cfg(all(test, target_os = "linux"))]
pub(crate) use runtime_listener::inherited_socket_is_listening;
use runtime_listener::native_proxy_runtime_listeners;

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
use runtime_tls::native_openssl_acceptor;
#[cfg(feature = "tls-rustls-backend")]
use runtime_tls::native_rustls_server_config;
#[cfg(any(
    feature = "tls-rustls-backend",
    all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
))]
use runtime_tls::native_tls_alpn_protocols;

pub struct NativeHttp1ProxyRuntime {
    policy: crate::DownstreamHttp1Policy,
    #[cfg(any(
        feature = "tls-rustls-backend",
        all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
    ))]
    http2_policy: DownstreamHttp2Policy,
    proxy_protocol: crate::ProxyProtocolPolicy,
    router: Arc<NativeHttp1ReloadableRouter>,
    router_reloader: NativeHttp1RouterReloadHandle,
    listeners: Vec<NativeHttp1ProxyRuntimeListener>,
    #[cfg(feature = "load-balancer")]
    load_balancer_services: Vec<fluxheim_load_balancer::UpstreamLoadBalancerService>,
    #[cfg(feature = "load-balancer")]
    load_balancer_admin_pools: Vec<crate::NativeLoadBalancerAdminPool>,
    #[cfg(feature = "tls-rustls-backend")]
    rustls_config: Option<Arc<rustls::ServerConfig>>,
    #[cfg(feature = "tls-rustls-backend")]
    rustls_certificate_resolver: Option<Arc<fluxheim_tls::RustlsDownstreamCertificateResolver>>,
    #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
    openssl_acceptor: Option<Arc<openssl::ssl::SslAcceptor>>,
    #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
    openssl_certificate_store: Option<Arc<fluxheim_tls::OpenSslDownstreamCertificateStore>>,
    #[cfg(any(
        feature = "tls-rustls-backend",
        all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
    ))]
    tls_alpn_policy: TlsAlpnPolicy,
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
    DuplicateInheritedListener {
        addr: SocketAddr,
    },
    InheritedListenerCount {
        expected: usize,
        actual: usize,
    },
    InheritedListenerInspect {
        source: io::Error,
    },
    InheritedListenerNotListening {
        addr: SocketAddr,
    },
    InheritedListenerSetup {
        addr: SocketAddr,
        source: io::Error,
    },
    MissingProxyHttpListener,
    MissingInheritedListener {
        addr: SocketAddr,
    },
    Router(NativeHttp1HostRouterConfigError),
    #[cfg(feature = "tls-rustls-backend")]
    RustlsCertificate(fluxheim_tls::RustlsDownstreamCertificateError),
    #[cfg(feature = "tls-rustls-backend")]
    RustlsServerConfig(fluxheim_tls::RustlsDownstreamServerConfigError),
    #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
    OpenSslAcceptor(fluxheim_tls::OpenSslDownstreamAcceptorError),
    #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
    OpenSslCertificateStore(fluxheim_tls::OpenSslDownstreamCertificateStoreError),
    #[cfg(any(
        feature = "tls-rustls-backend",
        all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
    ))]
    TlsPlan(fluxheim_tls::DownstreamTlsPlanError),
    UnsupportedTlsAlpn {
        policy: TlsAlpnPolicy,
    },
    UnsupportedListener {
        protocol: ListenerProtocol,
        addr: SocketAddr,
    },
    UnexpectedInheritedListener {
        addr: SocketAddr,
    },
}

impl NativeHttp1ProxyRuntime {
    pub async fn bind_from_config(
        config: &Config,
        plan: &ServerPlan,
    ) -> Result<Self, NativeHttp1ProxyRuntimeError> {
        let launch_plan = plan
            .native_runtime_launch_plan()
            .map_err(NativeHttp1ProxyRuntimeError::LaunchPlan)?;
        Self::bind_from_launch_plan_with_listeners(config, &launch_plan, None).await
    }

    pub async fn bind_from_config_with_inherited_listeners(
        config: &Config,
        plan: &ServerPlan,
        listeners: Vec<std::net::TcpListener>,
    ) -> Result<Self, NativeHttp1ProxyRuntimeError> {
        let launch_plan = plan
            .native_runtime_launch_plan()
            .map_err(NativeHttp1ProxyRuntimeError::LaunchPlan)?;
        Self::bind_from_launch_plan_with_listeners(config, &launch_plan, Some(listeners)).await
    }

    pub async fn bind_from_launch_plan(
        config: &Config,
        launch_plan: &NativeRuntimeLaunchPlan,
    ) -> Result<Self, NativeHttp1ProxyRuntimeError> {
        Self::bind_from_launch_plan_with_listeners(config, launch_plan, None).await
    }

    async fn bind_from_launch_plan_with_listeners(
        config: &Config,
        launch_plan: &NativeRuntimeLaunchPlan,
        inherited_listeners: Option<Vec<std::net::TcpListener>>,
    ) -> Result<Self, NativeHttp1ProxyRuntimeError> {
        #[cfg(feature = "load-balancer")]
        let (router, load_balancer_services, load_balancer_admin_pools) =
            NativeHttp1HostRouter::from_config_with_native_load_balancer_services(
                config,
                launch_plan.downstream_http1(),
                launch_plan.process().upstream_keepalive_pool_size(),
            )
            .map_err(NativeHttp1ProxyRuntimeError::Router)?;
        #[cfg(not(feature = "load-balancer"))]
        let router = NativeHttp1HostRouter::from_config(
            config,
            launch_plan.downstream_http1(),
            launch_plan.process().upstream_keepalive_pool_size(),
        )
        .map_err(NativeHttp1ProxyRuntimeError::Router)?;
        #[cfg(feature = "load-balancer")]
        let background_load_balancer_services = !load_balancer_services.is_empty();
        #[cfg(not(feature = "load-balancer"))]
        let background_load_balancer_services = false;
        let (router, router_reloader) = NativeHttp1ReloadableRouter::new(
            router,
            launch_plan.downstream_http1(),
            launch_plan.process().upstream_keepalive_pool_size(),
            background_load_balancer_services,
            NativeRequestBodyBudget::new(
                config
                    .server
                    .limits
                    .max_buffered_request_body_bytes
                    .as_usize(),
            ),
        );
        let router = Arc::new(router);
        let has_https_listener = launch_plan.listeners().iter().any(|listener| {
            listener.service_kind() == ServiceKind::ProxyHttp
                && listener.listener_protocol() == ListenerProtocol::Https
        });
        #[cfg(feature = "tls-rustls-backend")]
        let (rustls_config, rustls_certificate_resolver) = if has_https_listener {
            let (config, resolver) = native_rustls_server_config(config)?;
            (Some(config), Some(resolver))
        } else {
            (None, None)
        };
        #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
        let (openssl_acceptor, openssl_certificate_store) = if has_https_listener {
            let (acceptor, store) = native_openssl_acceptor(config)?;
            (Some(acceptor), store)
        } else {
            (None, None)
        };
        #[cfg(all(
            not(feature = "tls-rustls-backend"),
            not(feature = "tls-openssl-backend")
        ))]
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
        let listeners = native_proxy_runtime_listeners(launch_plan, inherited_listeners).await?;
        Ok(Self {
            policy: launch_plan.downstream_http1(),
            #[cfg(any(
                feature = "tls-rustls-backend",
                all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
            ))]
            http2_policy: launch_plan.downstream_http2(),
            proxy_protocol: launch_plan.proxy_protocol().clone(),
            router,
            router_reloader,
            listeners,
            #[cfg(feature = "load-balancer")]
            load_balancer_services,
            #[cfg(feature = "load-balancer")]
            load_balancer_admin_pools,
            #[cfg(feature = "tls-rustls-backend")]
            rustls_config,
            #[cfg(feature = "tls-rustls-backend")]
            rustls_certificate_resolver,
            #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
            openssl_acceptor,
            #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
            openssl_certificate_store,
            #[cfg(any(
                feature = "tls-rustls-backend",
                all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
            ))]
            tls_alpn_policy: config.tls.effective_alpn(),
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

    pub fn router_reloader(&self) -> NativeHttp1RouterReloadHandle {
        self.router_reloader.clone()
    }

    #[cfg(feature = "load-balancer")]
    pub fn take_load_balancer_services(
        &mut self,
    ) -> Vec<fluxheim_load_balancer::UpstreamLoadBalancerService> {
        std::mem::take(&mut self.load_balancer_services)
    }

    #[cfg(feature = "load-balancer")]
    pub fn load_balancer_admin_pools(&self) -> Vec<crate::NativeLoadBalancerAdminPool> {
        self.load_balancer_admin_pools.clone()
    }

    #[cfg(feature = "tls-rustls-backend")]
    pub fn rustls_certificate_resolver(
        &self,
    ) -> Option<Arc<fluxheim_tls::RustlsDownstreamCertificateResolver>> {
        self.rustls_certificate_resolver.clone()
    }

    #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
    pub fn openssl_certificate_store(
        &self,
    ) -> Option<Arc<fluxheim_tls::OpenSslDownstreamCertificateStore>> {
        self.openssl_certificate_store.clone()
    }

    pub fn start(self, supervisor: &NativeBackgroundSupervisor) -> NativeHttp1ProxyRuntimeHandle {
        let mut handles = Vec::with_capacity(self.listeners.len());
        for listener in self.listeners {
            let local_addr = listener.local_addr;
            let policy = self.policy;
            #[cfg(any(
                feature = "tls-rustls-backend",
                all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
            ))]
            let http2_policy = self.http2_policy;
            let proxy_protocol = self.proxy_protocol.clone();
            let router = self.router.clone();
            let shutdown = supervisor.shutdown_view();
            #[cfg(any(
                feature = "tls-rustls-backend",
                all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend")
            ))]
            let tls_alpn_policy = self.tls_alpn_policy;
            #[cfg(feature = "tls-rustls-backend")]
            let rustls_config = self.rustls_config.clone();
            #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
            let openssl_acceptor = self.openssl_acceptor.clone();
            let handle = tokio::spawn(async move {
                let result = match listener.protocol {
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
                        let (http1_allowed, http2_allowed) =
                            native_tls_alpn_protocols(tls_alpn_policy);
                        if http2_allowed {
                            let h2_dispatch = NativeTlsHttp2Dispatch {
                                policy: http2_policy,
                                http1_allowed,
                                http2_allowed,
                            };
                            serve_native_http1_and_http2_rustls_listener(
                                listener.listener,
                                policy,
                                rustls_config,
                                h2_dispatch,
                                router,
                                shutdown_wait(shutdown),
                            )
                            .await
                        } else {
                            serve_native_http1_rustls_listener(
                                listener.listener,
                                policy,
                                rustls_config,
                                router,
                                shutdown_wait(shutdown),
                            )
                            .await
                        }
                    }
                    #[cfg(all(
                        not(feature = "tls-rustls-backend"),
                        feature = "tls-openssl-backend"
                    ))]
                    ListenerProtocol::Https => {
                        let Some(openssl_acceptor) = openssl_acceptor else {
                            return Err(NativeHttp1Error::Io(io::Error::other(
                                "missing OpenSSL acceptor for native HTTPS listener",
                            )));
                        };
                        let (http1_allowed, http2_allowed) =
                            native_tls_alpn_protocols(tls_alpn_policy);
                        if http2_allowed {
                            let h2_dispatch = NativeTlsHttp2Dispatch {
                                policy: http2_policy,
                                http1_allowed,
                                http2_allowed,
                            };
                            serve_native_http1_and_http2_openssl_listener(
                                listener.listener,
                                policy,
                                openssl_acceptor,
                                h2_dispatch,
                                router,
                                shutdown_wait(shutdown),
                            )
                            .await
                        } else {
                            serve_native_http1_openssl_listener(
                                listener.listener,
                                policy,
                                openssl_acceptor,
                                router,
                                shutdown_wait(shutdown),
                            )
                            .await
                        }
                    }
                    #[cfg(all(
                        not(feature = "tls-rustls-backend"),
                        not(feature = "tls-openssl-backend")
                    ))]
                    ListenerProtocol::Https => Err(NativeHttp1Error::Io(io::Error::other(
                        "native HTTPS listener requires tls-rustls-backend",
                    ))),
                    ListenerProtocol::AdminHttp
                    | ListenerProtocol::MetricsHttp
                    | ListenerProtocol::StreamTcp
                    | ListenerProtocol::Udp => Err(NativeHttp1Error::Io(io::Error::other(
                        "unsupported native HTTP/1 proxy listener protocol",
                    ))),
                };
                if let Err(error) = &result {
                    log::error!(
                        target: "fluxheim::native_runtime",
                        "native HTTP/1 proxy listener {local_addr} exited unexpectedly: {error}"
                    );
                    std::process::exit(1);
                }
                result
            });
            handles.push(NativeHttp1ProxyListenerHandle {
                local_addr,
                handle: Some(handle),
            });
        }
        NativeHttp1ProxyRuntimeHandle { listeners: handles }
    }
}

async fn shutdown_wait(mut shutdown: FluxShutdown) {
    let _ = shutdown.wait_for_shutdown().await;
}
