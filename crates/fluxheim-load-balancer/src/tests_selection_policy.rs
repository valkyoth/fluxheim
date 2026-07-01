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
fn priority_groups_prefer_highest_available_group() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_priority_groups: vec![10, 100],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            passive_health: LoadBalancePassiveHealthConfig {
                enabled: true,
                consecutive_failure: 1,
                ejection_secs: 60,
                ..LoadBalancePassiveHealthConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let preferred = balancer.select(&request(), None).unwrap();
    assert_eq!(preferred.backend.addr.to_string(), "127.0.0.1:3001");
    preferred.reporter.unwrap().record_failure();

    let fallback = balancer.select(&request(), None).unwrap();
    assert_eq!(fallback.backend.addr.to_string(), "127.0.0.1:3000");
}

#[test]
fn priority_groups_apply_to_least_connections() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_priority_groups: vec![10, 100],
        load_balance: LoadBalanceConfig {
            selection: LoadBalanceSelection::LeastConnections,
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let selected = balancer.select(&request(), None).unwrap();
    assert_eq!(selected.backend.addr.to_string(), "127.0.0.1:3001");
}

#[test]
fn priority_group_min_active_activates_lower_group() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec![
            "127.0.0.1:3000".to_owned(),
            "127.0.0.1:3001".to_owned(),
            "127.0.0.1:3002".to_owned(),
        ],
        upstream_priority_groups: vec![100, 100, 50],
        upstream_priority_group_min_active: 2,
        upstream_max_in_flight: vec![1, 1, 1],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            passive_health: LoadBalancePassiveHealthConfig {
                enabled: true,
                consecutive_failure: 1,
                ejection_secs: 60,
                ..LoadBalancePassiveHealthConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let failed = balancer.select(&request(), None).unwrap();
    assert_eq!(failed.backend.addr.to_string(), "127.0.0.1:3000");
    failed.reporter.unwrap().record_failure();

    let activated = balancer.select(&request(), None).unwrap();
    assert_eq!(activated.backend.addr.to_string(), "127.0.0.1:3002");

    let remaining_preferred = balancer.select(&request(), None).unwrap();
    assert_eq!(
        remaining_preferred.backend.addr.to_string(),
        "127.0.0.1:3001"
    );
}

#[test]
fn preferred_locality_selects_local_backend_with_fallback() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_localities: vec!["remote".to_owned(), "local".to_owned()],
        preferred_upstream_localities: vec!["local".to_owned()],
        upstream_tags: vec![
            vec!["remote".to_owned()],
            vec!["local".to_owned(), "blue".to_owned()],
        ],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let selected = balancer.select(&request(), None).unwrap();
    assert_eq!(selected.backend.addr.to_string(), "127.0.0.1:3001");

    balancer
        .set_runtime_backend_state(
            "127.0.0.1:3001",
            LoadBalancerRuntimeBackendState::ForcedDown,
        )
        .unwrap();
    let fallback = balancer.select(&request(), None).unwrap();
    assert_eq!(fallback.backend.addr.to_string(), "127.0.0.1:3000");

    let stats = balancer.runtime_stats();
    let local = stats
        .backends
        .iter()
        .find(|backend| backend.locality.as_deref() == Some("local"))
        .expect("local backend status");
    assert!(local.locality_preferred);
    assert_eq!(local.tags, ["local".to_owned(), "blue".to_owned()]);
}

#[test]
fn upstream_max_in_flight_skips_capped_backend() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_max_in_flight: vec![1, 2],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let first = balancer.select(&request(), None).unwrap();
    assert_eq!(first.backend.addr.to_string(), "127.0.0.1:3000");

    let second = balancer.select(&request(), None).unwrap();
    assert_eq!(second.backend.addr.to_string(), "127.0.0.1:3001");

    let third = balancer.select(&request(), None).unwrap();
    assert_eq!(third.backend.addr.to_string(), "127.0.0.1:3001");

    assert!(balancer.select(&request(), None).is_none());
    drop(first);

    let fourth = balancer.select(&request(), None).unwrap();
    assert_eq!(fourth.backend.addr.to_string(), "127.0.0.1:3000");
}

#[test]
fn least_time_learns_from_recorded_latency() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            selection: LoadBalanceSelection::LeastTime,
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let first = balancer.select(&request(), None).unwrap();
    let first_addr = first.backend.addr.to_string();
    first
        .reporter
        .unwrap()
        .record_status(200, Some(Duration::from_millis(200)));

    let second = balancer.select(&request(), None).unwrap();
    let second_addr = second.backend.addr.to_string();
    assert_ne!(first_addr, second_addr);
    second
        .reporter
        .unwrap()
        .record_status(200, Some(Duration::from_millis(50)));

    let selected = balancer.select(&request(), None).unwrap();
    assert_eq!(selected.backend.addr.to_string(), second_addr);
}

#[test]
fn builds_power_of_two_selection_from_proxy_upstreams() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            selection: LoadBalanceSelection::PowerOfTwo,
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let selected = balancer.select(&request(), None).unwrap();
    assert!(selected.permit.is_some());
}
