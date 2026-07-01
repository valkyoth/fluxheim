#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

pub mod config;
pub mod config_access;
pub mod config_acme;
pub mod config_acme_challenge;
pub mod config_acme_issuer;
pub mod config_admin;
pub mod config_admin_health;
pub mod config_admin_socket;
pub mod config_admin_transport;
pub mod config_cache;
pub mod config_compression;
pub mod config_geoip;
pub mod config_header;
pub mod config_header_response;
pub mod config_header_validation;
pub mod config_http;
pub mod config_load_balance;
pub mod config_load_balance_health;
mod config_load_balance_health_validate;
pub mod config_load_balance_passive_health;
pub mod config_load_balance_persistence;
pub mod config_load_balance_queue;
pub mod config_load_balance_retry;
pub mod config_load_balance_slow_start;
pub mod config_loader;
pub mod config_logging;
pub mod config_metrics_summary;
pub mod config_net;
pub mod config_observability;
pub mod config_path;
pub mod config_php;
pub mod config_proxy;
pub mod config_proxy_auth;
pub mod config_proxy_traffic_mirror;
pub mod config_route;
pub mod config_server;
pub mod config_stream;
pub mod config_stream_slots;
#[cfg(all(test, feature = "stream-proxy"))]
mod config_stream_tests;
pub mod config_stream_tls;
pub mod config_tls;
pub mod config_types;
pub mod config_udp;
pub mod config_web;
pub mod fs_trust;
pub mod internal_crypto;
#[cfg(any(feature = "metrics-otlp", feature = "otel-otlp"))]
mod otlp_http;
pub mod reload;
#[cfg(all(test, feature = "load-balancer"))]
mod reload_load_balancer_tests;
#[cfg(test)]
mod reload_tests;

pub use config::*;

#[cfg(test)]
mod test_support {
    pub use fluxheim_common::test_support::*;
}
