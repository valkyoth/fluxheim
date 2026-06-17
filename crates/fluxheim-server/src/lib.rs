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
mod native_http1_client;
mod native_http1_plan;
mod native_http1_proxy;
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
pub use native_http1::{
    NativeHttp1Error, NativeHttp1Handler, NativeHttp1Request, NativeHttp1Response,
    serve_native_http1_connection, serve_native_http1_listener,
};
pub use native_http1_client::NativeHttp1Upstream;
pub use native_http1_plan::NativeHttp1ProxyCandidate;
pub use native_http1_proxy::{NativeHttp1Proxy, NativeHttp1ProxyConfigError};
pub use plan::{RuntimeAdapterKind, ServerPlan};
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
#[path = "native_http1_tests.rs"]
mod native_http1_tests;

#[cfg(test)]
#[path = "native_http1_client_tests.rs"]
mod native_http1_client_tests;

#[cfg(test)]
#[path = "native_http1_proxy_tests.rs"]
mod native_http1_proxy_tests;

#[cfg(test)]
#[path = "native_http1_plan_tests.rs"]
mod native_http1_plan_tests;

#[cfg(test)]
#[path = "server_background_tests.rs"]
mod background_tests;

#[cfg(all(test, unix))]
#[path = "server_unix_tests.rs"]
mod unix_tests;
