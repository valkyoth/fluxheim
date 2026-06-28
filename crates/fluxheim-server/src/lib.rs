#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use fluxheim_runtime::ShutdownView;

mod background;
mod control;
mod http1;
mod http2;
mod listener;
mod native_http1;
#[cfg(feature = "acme")]
mod native_http1_acme;
mod native_http1_cache;
mod native_http1_client;
mod native_http1_forwarded;
mod native_http1_host_router;
#[cfg(feature = "php-fpm")]
mod native_http1_php;
mod native_http1_plan;
mod native_http1_proxy;
mod native_http1_route_proxy;
mod native_http1_static_web;
#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
mod native_http1_tls;
mod native_http1_upstream_response;
mod native_http2;
mod native_http2_client;
mod native_http2_route_adapter;
mod native_http2_stack;
mod native_runtime_http1_proxy;
mod native_runtime_launch_plan;
mod native_runtime_manifest;
mod plan;
mod process;
mod proxy_protocol;
mod service;
#[cfg(unix)]
mod unix_listener;

pub use control::CertificateReloadControlPlan;
pub use http1::DownstreamHttp1Policy;
pub use http2::DownstreamHttp2Policy;
pub use listener::{ListenerProtocol, ListenerSpec};
#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
pub use native_http1::serve_native_http1_openssl_listener;
#[cfg(feature = "tls-rustls-backend")]
pub use native_http1::serve_native_http1_rustls_listener;
#[cfg(unix)]
pub use native_http1::serve_native_http1_unix_listener;
pub use native_http1::{
    NativeHttp1ConnectionStream, NativeHttp1Error, NativeHttp1GeoContext, NativeHttp1Handler,
    NativeHttp1Request, NativeHttp1RequestContext, NativeHttp1Response,
    NativeHttp1ResponseWritePolicy, NativeHttp1TlsClientIdentity, serve_native_http1_connection,
    serve_native_http1_listener, serve_native_http1_listener_with_proxy_protocol,
};
#[cfg(feature = "acme")]
pub use native_http1_acme::NativeHttp1AcmeHttp01Store;
pub use native_http1_client::{NativeHttp1Upstream, NativeTcpKeepalivePolicy};
pub use native_http1_host_router::{NativeHttp1HostRouter, NativeHttp1HostRouterConfigError};
pub use native_http1_plan::{
    NativeHttp1ProxyCandidate, NativeHttp1ProxyCutoverStatus, NativeHttp1ProxyCutoverSummary,
};
pub use native_http1_proxy::{NativeHttp1Proxy, NativeHttp1ProxyConfigError};
pub use native_http1_route_proxy::{
    NativeHttp1RouteProxy, NativeHttp1RouteProxyConfigError, NativeHttp1RouteProxyRoute,
};
pub use native_http1_static_web::NativeHttp1StaticWeb;
#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
pub use native_http1_tls::NativeHttp1UpstreamTls;
pub use native_http2::{
    NativeHttp2Preview, NativeHttp2SafetyHook, NativeHttp2SafetyReport, NativeHttp2SafetyStatus,
};
pub use native_http2_client::{
    NativeHttp2UpstreamRequest, NativeHttp2UpstreamResponse, send_native_http2_upstream_on_io,
};
pub use native_http2_route_adapter::NativeHttp2RouteAdapter;
pub use native_http2_stack::{
    NativeHttp2Handler, NativeHttp2Request, NativeHttp2Response, NativeHttp2StackError,
    native_http2_stack_probe, native_http2_stack_probe_with_response,
    serve_native_http2_connection,
};
pub use native_runtime_http1_proxy::{
    NativeHttp1ProxyRuntime, NativeHttp1ProxyRuntimeError, NativeHttp1ProxyRuntimeHandle,
};
pub use native_runtime_launch_plan::{
    NativeRuntimeLaunchBackgroundTask, NativeRuntimeLaunchListener, NativeRuntimeLaunchPlan,
    NativeRuntimeLaunchPlanError, NativeRuntimeListenerTransport,
};
pub use native_runtime_manifest::{
    NativeRuntimeManifest, NativeRuntimeManifestError, NativeRuntimeServiceManifest,
};
pub use plan::{
    NativeRuntimeCutoverBlocker, NativeRuntimeCutoverSummary, RuntimeAdapterKind, ServerPlan,
};
pub use process::ProcessSpec;
pub use proxy_protocol::{ProxyProtocolPolicy, ProxyProtocolTrustedSource};
pub use service::{AdminOpsSocketPlan, ServiceKind, ServiceSpec};
#[cfg(unix)]
pub use unix_listener::replace_private_unix_listener;

pub trait ServerRunner {
    type Error;

    fn run(&self, plan: ServerPlan, shutdown: &dyn ShutdownView) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerPlanError {
    InvalidListenerAddress { address: String },
    InvalidProxyProtocolTrustedSource { source: String, reason: String },
}

impl std::fmt::Display for ServerPlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidListenerAddress { address } => {
                write!(formatter, "invalid listener address {address:?}")
            }
            Self::InvalidProxyProtocolTrustedSource { source, reason } => {
                write!(
                    formatter,
                    "invalid PROXY protocol trusted source {source:?}: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for ServerPlanError {}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

#[cfg(test)]
mod native_http1_test_utils;

#[cfg(test)]
#[path = "native_http1_tests.rs"]
mod native_http1_tests;

#[cfg(test)]
#[path = "native_http1_client_tests.rs"]
mod native_http1_client_tests;

#[cfg(test)]
#[path = "native_http1_host_router_tests.rs"]
mod native_http1_host_router_tests;

#[cfg(test)]
#[path = "native_http1_proxy_tests.rs"]
mod native_http1_proxy_tests;

#[cfg(test)]
#[path = "native_http1_route_proxy_tests.rs"]
mod native_http1_route_proxy_tests;

#[cfg(test)]
#[path = "native_http1_route_static_web_tests.rs"]
mod native_http1_route_static_web_tests;

#[cfg(all(
    test,
    any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")
))]
#[path = "native_http1_proxy_tls_tests.rs"]
mod native_http1_proxy_tls_tests;

#[cfg(all(
    test,
    any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")
))]
#[path = "native_http1_proxy_tls_policy_tests.rs"]
mod native_http1_proxy_tls_policy_tests;

#[cfg(test)]
#[path = "native_http1_plan_tests.rs"]
mod native_http1_plan_tests;

#[cfg(test)]
#[path = "native_runtime_http1_proxy_tests.rs"]
mod native_runtime_http1_proxy_tests;

#[cfg(test)]
#[path = "native_http2_tests.rs"]
mod native_http2_tests;

#[cfg(test)]
#[path = "native_http2_upstream_tests.rs"]
mod native_http2_upstream_tests;

#[cfg(test)]
#[path = "server_background_tests.rs"]
mod background_tests;

#[cfg(all(test, unix))]
#[path = "server_unix_tests.rs"]
mod unix_tests;
