#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

#[cfg(feature = "acme")]
pub mod acme;
pub mod acme_companion;
#[cfg(feature = "proxy")]
pub mod admin;
#[cfg(feature = "proxy")]
mod background;
pub mod cli;
pub mod config {
    #[allow(unused_imports)]
    pub use fluxheim_config::*;
}
pub mod config_tester;
mod config_tester_profiles;
mod config_tester_runtime;
mod config_tester_upstreams;
#[cfg(feature = "ingress")]
mod http_types;
pub mod internal_crypto;
#[cfg(feature = "metrics")]
pub mod metrics;
#[cfg(feature = "metrics")]
mod metrics_native;
#[cfg(feature = "metrics-otlp")]
pub mod metrics_otlp;
#[cfg(feature = "metrics")]
mod metrics_secret;
#[cfg(all(feature = "web", feature = "proxy"))]
mod native_http1_static;
#[cfg(feature = "proxy")]
pub mod native_proxy;
#[cfg(feature = "security")]
pub mod security;
#[cfg(feature = "stream-proxy")]
mod stream_proxy;
#[cfg(all(
    feature = "stream-proxy",
    any(feature = "tls-rustls-backend", feature = "tls-openssl")
))]
mod stream_tls;
#[cfg(all(feature = "stream-proxy", feature = "tls-openssl"))]
mod stream_tls_openssl;
#[cfg(all(feature = "stream-proxy", feature = "tls-rustls-backend"))]
mod stream_tls_rustls;
#[cfg(any(
    feature = "tls",
    feature = "tls-rustls-backend",
    feature = "tls-openssl"
))]
pub mod tls;
#[cfg(feature = "udp-proxy")]
mod udp_proxy;
#[cfg(all(
    feature = "stream-proxy",
    any(feature = "tls-rustls-backend", feature = "tls-openssl")
))]
mod upstream_tls;
#[cfg(feature = "web")]
pub mod web;

pub mod runtime;

#[cfg(any(
    all(feature = "tls-rustls", feature = "tls-rustls-fips"),
    all(feature = "tls-rustls-backend", feature = "tls-openssl"),
))]
compile_error!(
    "select only one Fluxheim TLS backend feature: tls-rustls, tls-rustls-fips, or tls-openssl"
);

#[cfg(all(feature = "privacy-mode", feature = "geoip"))]
compile_error!("privacy-mode builds do not include GeoIP lookup or Geo-Context metadata");

#[cfg(all(
    feature = "tls-rustls-backend",
    not(any(feature = "tls-rustls", feature = "tls-rustls-fips"))
))]
compile_error!("tls-rustls-backend is an internal feature; select tls-rustls or tls-rustls-fips");

#[cfg(all(feature = "privacy-mode", feature = "cache"))]
compile_error!(
    "privacy-mode cannot be combined with the cache feature; build with --no-default-features --features profile-privacy or select proxy,web,tls-*,privacy-mode explicitly"
);

#[cfg(all(feature = "privacy-mode", feature = "compression"))]
compile_error!(
    "privacy-mode cannot be combined with compression; zero-retention builds must not transform response bodies"
);

#[cfg(all(feature = "privacy-mode", feature = "metrics"))]
compile_error!(
    "privacy-mode cannot be combined with metrics; zero-retention builds must not compile request metrics"
);

#[cfg(all(feature = "privacy-mode", feature = "metrics-otlp"))]
compile_error!(
    "privacy-mode cannot be combined with metrics-otlp; zero-retention builds must not compile metrics export"
);

#[cfg(all(feature = "privacy-mode", feature = "otel-tracing"))]
compile_error!(
    "privacy-mode cannot be combined with otel-tracing; zero-retention builds must not compile trace context propagation"
);

#[cfg(all(feature = "privacy-mode", feature = "otel-otlp"))]
compile_error!(
    "privacy-mode cannot be combined with otel-otlp; zero-retention builds must not compile trace export"
);

pub fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    cli::run_from_env()
}
