#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

#[cfg(feature = "acme")]
pub mod acme;
#[cfg(feature = "proxy")]
pub mod admin;
#[cfg(feature = "cache")]
pub mod cache;
pub mod cache_headers;
pub mod cli;
pub mod config;
mod fs_trust;
#[cfg(feature = "proxy")]
pub mod headers;
#[cfg(feature = "load-balancer")]
pub mod load_balancer;
#[cfg(feature = "metrics")]
pub mod metrics;
#[cfg(feature = "metrics-otlp")]
pub mod metrics_otlp;
#[cfg(feature = "otel-otlp")]
pub mod otel_otlp;
#[cfg(feature = "proxy")]
pub mod proxy;
pub mod reload;
#[cfg(feature = "security")]
pub mod security;
pub mod snapshot;
#[cfg(any(
    feature = "tls",
    feature = "tls-rustls",
    feature = "tls-openssl",
    feature = "tls-boringssl",
    feature = "tls-s2n"
))]
pub mod tls;
#[cfg(feature = "otel-tracing")]
pub mod trace_context;
#[cfg(feature = "web")]
pub mod web;

pub mod runtime;

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(any(
    all(feature = "tls-rustls", feature = "tls-openssl"),
    all(feature = "tls-rustls", feature = "tls-boringssl"),
    all(feature = "tls-rustls", feature = "tls-s2n"),
    all(feature = "tls-openssl", feature = "tls-boringssl"),
    all(feature = "tls-openssl", feature = "tls-s2n"),
    all(feature = "tls-boringssl", feature = "tls-s2n"),
))]
compile_error!(
    "select only one Fluxheim TLS backend feature: tls-rustls, tls-openssl, tls-boringssl, or tls-s2n"
);

#[cfg(all(feature = "privacy-mode", feature = "cache"))]
compile_error!(
    "privacy-mode cannot be combined with the cache feature; build with --no-default-features --features profile-privacy or select proxy,web,tls-*,privacy-mode explicitly"
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

#[cfg(any(
    all(feature = "php-fpm", feature = "php-turbine"),
    all(feature = "php-fpm", feature = "php-phprs"),
    all(feature = "php-turbine", feature = "php-phprs"),
))]
compile_error!("select only one Fluxheim PHP runtime feature: php-fpm, php-turbine, or php-phprs");

pub fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    cli::run_from_env()
}
