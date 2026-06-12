#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

pub mod config;
pub mod config_access;
pub mod config_acme;
pub mod config_admin;
pub mod config_cache;
pub mod config_compression;
pub mod config_geoip;
pub mod config_header;
pub mod config_http;
pub mod config_load_balance;
pub mod config_loader;
pub mod config_logging;
pub mod config_net;
pub mod config_observability;
pub mod config_path;
pub mod config_php;
pub mod config_proxy;
pub mod config_route;
pub mod config_server;
pub mod config_stream;
pub mod config_tls;
pub mod config_types;
pub mod config_udp;
pub mod config_web;
mod fs_trust;
mod internal_crypto;
#[cfg(any(feature = "metrics-otlp", feature = "otel-otlp"))]
mod otlp_http;

#[cfg(test)]
mod test_support {
    pub use fluxheim_common::test_support::*;
}

pub use config::*;
