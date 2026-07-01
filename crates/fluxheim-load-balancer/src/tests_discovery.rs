#![allow(unused_imports)]

use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use fluxheim_config::{
    LoadBalanceConfig, LoadBalanceHealthCheckConfig, LoadBalanceHealthCheckExpectedStatusRange,
    LoadBalanceHealthCheckProtocol, LoadBalanceManagedCookieSameSite,
    LoadBalancePassiveHealthConfig, LoadBalancePersistenceConfig, LoadBalancePersistenceMode,
    LoadBalanceQueueConfig, LoadBalanceSelection, LoadBalanceSlowStartConfig, ProxyConfig,
};
use tokio::sync::watch;

#[cfg(not(feature = "privacy-mode"))]
use super::LoadBalancerCircuitState;
use super::backend::FluxBackend;
use super::persistence::{MAX_PERSISTENCE_KEY_BYTES, cookie_key, request_header_key};
use super::selection::least_connections_score_is_lower;
use super::state::PassiveBackendHealth;
use super::tests_support::{install_test_crypto_provider, request, slow_start_blocking_sample};
use super::{
    LoadBalancedUpstreamReporter, LoadBalancerDiscoveryMode, LoadBalancerPersistenceOutcome,
    LoadBalancerQueueOutcome, LoadBalancerRuntimeBackendSetOperation,
    LoadBalancerRuntimeBackendState, PassiveHealthState, SlowStartState, UpstreamLoadBalancer,
    backend_key,
};
use fluxheim_common::test_support::{safe_child_path, unique_temp_path};

#[test]
fn builds_round_robin_from_proxy_upstreams() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    assert_eq!(balancer.backend_count(), 2);
    assert_eq!(
        balancer.runtime_stats().discovery_mode,
        LoadBalancerDiscoveryMode::Static
    );
    let stats = balancer.runtime_stats();
    assert_eq!(stats.discovery.mode, LoadBalancerDiscoveryMode::Static);
    assert!(!stats.discovery.refresh_enabled);
    assert_eq!(stats.discovery.success_count, 1);
    assert_eq!(stats.discovery.failure_count, 0);
    assert!(balancer.select(&request(), None).is_some());
}

#[test]
fn builds_weighted_round_robin_from_proxy_upstreams() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_weights: vec![1, 4],
        upstream_aliases: vec!["origin-a".to_owned(), "origin-b".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    assert_eq!(balancer.backend_count(), 2);
    assert_eq!(balancer.backend_weights(), [1, 4]);
    let selected = balancer.select(&request(), None).unwrap();
    assert!(selected.has_connection_permit());
    assert_eq!(selected.address().to_string(), selected.authority());
    assert!(
        matches!(selected.alias(), Some("origin-a") | Some("origin-b")),
        "selected alias should come from configured upstream_aliases"
    );
}

#[test]
fn builds_round_robin_from_proxy_upstreams_file() {
    install_test_crypto_provider();
    let root = unique_temp_path("lb-upstreams-file");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("upstreams.txt");
    std::fs::write(
        &path,
        "# generated service-discovery output\n127.0.0.1:3000\n127.0.0.1:3001\n",
    )
    .unwrap();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstream: None,
        upstreams_file: Some(path),
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    assert_eq!(balancer.backend_count(), 2);
    assert_eq!(
        balancer.runtime_stats().discovery_mode,
        LoadBalancerDiscoveryMode::File
    );
    let stats = balancer.runtime_stats();
    assert_eq!(stats.discovery.mode, LoadBalancerDiscoveryMode::File);
    assert!(stats.discovery.refresh_enabled);
    assert_eq!(stats.discovery.update_frequency_secs, Some(5));
    assert_eq!(stats.discovery.success_count, 1);
    assert!(balancer.select(&request(), None).is_some());
}

#[test]
fn builds_round_robin_from_dns_refreshed_proxy_upstreams() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstream: None,
        upstreams: vec!["localhost:3000".to_owned()],
        upstream_dns_refresh_secs: Some(2),
        upstream_dns_allow_private_backends: true,
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    assert!(balancer.backend_count() >= 1);
    assert_eq!(
        balancer.runtime_stats().discovery_mode,
        LoadBalancerDiscoveryMode::Dns
    );
    let stats = balancer.runtime_stats();
    assert_eq!(stats.discovery.mode, LoadBalancerDiscoveryMode::Dns);
    assert!(stats.discovery.refresh_enabled);
    assert_eq!(stats.discovery.update_frequency_secs, Some(2));
    assert_eq!(stats.discovery.success_count, 1);
    assert!(balancer.select(&request(), None).is_some());
}
