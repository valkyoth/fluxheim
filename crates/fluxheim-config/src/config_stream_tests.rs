use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::{Config, StreamRouteConfig};
use crate::config_stream::{
    DEFAULT_STREAM_MAX_CONNECTIONS, StreamConfig, acquire_stream_connection_slot,
};

#[test]
fn stream_config_accepts_valid_tcp_route() {
    let config: StreamConfig = toml::from_str(
        r#"
enabled = true

[[routes]]
name = "postgres"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:5432"
"#,
    )
    .unwrap();

    assert!(config.validate().is_ok());
}

#[test]
fn stream_route_defaults_to_bounded_connection_cap() {
    let config: StreamConfig = toml::from_str(
        r#"
enabled = true

[[routes]]
name = "postgres"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:5432"
"#,
    )
    .unwrap();

    assert_eq!(
        config.routes[0].max_connections,
        DEFAULT_STREAM_MAX_CONNECTIONS
    );
    assert_eq!(config.routes[0].proxy_header_timeout_secs, 10);
    assert!(config.validate().is_ok());
}

#[test]
fn stream_config_bounds_proxy_header_timeout() {
    let zero: StreamConfig = toml::from_str(
        r#"
enabled = true

[[routes]]
name = "postgres"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:5432"
proxy_header_timeout_secs = 0
"#,
    )
    .unwrap();
    assert!(zero.validate().is_err());

    let excessive: StreamConfig = toml::from_str(
        r#"
enabled = true

[[routes]]
name = "postgres"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:5432"
proxy_header_timeout_secs = 61
"#,
    )
    .unwrap();
    assert!(excessive.validate().is_err());
}

#[test]
fn stream_route_accepts_explicit_unlimited_connection_cap() {
    let config: StreamConfig = toml::from_str(
        r#"
enabled = true

[[routes]]
name = "postgres"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:5432"
max_connections = 0
"#,
    )
    .unwrap();

    assert_eq!(config.routes[0].max_connections, 0);
    assert!(config.validate().is_ok());
}

#[test]
fn stream_config_rejects_duplicate_listeners() {
    let config: StreamConfig = toml::from_str(
        r#"
enabled = true

[[routes]]
name = "one"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:5432"

[[routes]]
name = "two"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:6432"
"#,
    )
    .unwrap();

    assert!(config.validate().is_err());
}

#[test]
fn stream_config_accepts_route_local_downstream_proxy_protocol() {
    let config: StreamConfig = toml::from_str(
        r#"
enabled = true

[[routes]]
name = "postgres"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:5432"
downstream_proxy_protocol = "v2"
trusted_proxies = ["127.0.0.1", "10.0.0.0/8"]
"#,
    )
    .unwrap();

    assert!(config.validate().is_ok());
}

#[test]
fn stream_config_rejects_downstream_proxy_protocol_without_trusted_proxies() {
    let config: StreamConfig = toml::from_str(
        r#"
enabled = true

[[routes]]
name = "postgres"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:5432"
downstream_proxy_protocol = "v1"
"#,
    )
    .unwrap();

    assert!(config.validate().is_err());
}

#[test]
fn stream_config_rejects_zero_max_connection_bytes() {
    let config: StreamConfig = toml::from_str(
        r#"
enabled = true

[[routes]]
name = "postgres"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:5432"
max_connection_bytes = 0
"#,
    )
    .unwrap();

    assert!(config.validate().is_err());
}

#[test]
fn stream_config_rejects_upstream_tls_material_without_tls() {
    let config: StreamConfig = toml::from_str(
        r#"
enabled = true

[[routes]]
name = "postgres"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:5432"
upstream_ca_path = "/etc/fluxheim/upstreams/ca.pem"
"#,
    )
    .unwrap();

    assert!(config.validate().is_err());
}

#[test]
fn stream_config_rejects_inconsistent_upstream_tls_verification() {
    let config: StreamConfig = toml::from_str(
        r#"
enabled = true

[[routes]]
name = "postgres"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:5432"
upstream_tls = true
upstream_verify_cert = false
upstream_verify_hostname = true
"#,
    )
    .unwrap();

    assert!(config.validate().is_err());
}

#[test]
fn stream_config_rejects_upstream_proxy_protocol_with_tls() {
    let config: StreamConfig = toml::from_str(
        r#"
enabled = true

[[routes]]
name = "postgres"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:5432"
upstream_tls = true
upstream_proxy_protocol = "v1"
"#,
    )
    .unwrap();

    assert!(config.validate().is_err());
}

#[test]
fn stream_config_rejects_invalid_upstream_weights() {
    let config: StreamConfig = toml::from_str(
        r#"
enabled = true

[[routes]]
name = "postgres"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:5432"
upstream_weights = [1]
"#,
    )
    .unwrap();

    assert!(config.validate().is_err());
}

#[test]
fn stream_config_rejects_invalid_backup_and_drain_policy() {
    let config: StreamConfig = toml::from_str(
        r#"
enabled = true

[[routes]]
name = "postgres"
listen = ["127.0.0.1:15432"]
upstreams = ["127.0.0.1:5432", "127.0.0.1:6432"]
backup_upstreams = ["127.0.0.1:5432"]
drain_upstreams = ["127.0.0.1:5432"]
"#,
    )
    .unwrap();

    assert!(config.validate().is_err());
}

#[test]
fn stream_config_accepts_source_acls_and_private_dns_opt_in() {
    let config: StreamConfig = toml::from_str(
        r#"
enabled = true

[[routes]]
name = "postgres"
listen = ["127.0.0.1:15432"]
upstream = "db.internal.example:5432"
allow_sources = ["10.0.0.0/8", "2001:db8::/32"]
deny_sources = ["10.0.0.13"]
upstream_dns_allow_private_addresses = true
"#,
    )
    .unwrap();

    assert!(config.validate().is_ok());
    assert!(config.routes[0].upstream_dns_allow_private_addresses);
}

#[test]
fn stream_config_rejects_invalid_source_acl_matchers() {
    let config: StreamConfig = toml::from_str(
        r#"
enabled = true

[[routes]]
name = "postgres"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:5432"
allow_sources = ["not-a-cidr"]
"#,
    )
    .unwrap();

    assert!(config.validate().is_err());
}

#[test]
fn stream_enabled_allows_no_http_listeners() {
    let mut config = Config::default();
    config.server.listen = Vec::new();
    config.stream.enabled = true;
    config.stream.routes = vec![StreamRouteConfig {
        name: "postgres".to_owned(),
        listen: vec!["127.0.0.1:15432".to_owned()],
        upstream: Some("127.0.0.1:5432".to_owned()),
        ..StreamRouteConfig::default()
    }];

    assert!(config.validate().is_ok());
}

#[test]
fn stream_connection_slots_respect_limit() {
    let current = Arc::new(AtomicUsize::new(0));
    let first = acquire_stream_connection_slot(&current, 1).unwrap();
    assert!(acquire_stream_connection_slot(&current, 1).is_none());
    drop(first);
    assert_eq!(current.load(Ordering::Acquire), 0);
    assert!(acquire_stream_connection_slot(&current, 1).is_some());
}
