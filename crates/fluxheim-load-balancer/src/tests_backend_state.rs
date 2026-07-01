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
fn runtime_backend_state_overrides_selection_by_alias() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_aliases: vec!["primary-a".to_owned(), "primary-b".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let mutation = balancer
        .set_runtime_backend_state("primary-a", LoadBalancerRuntimeBackendState::Drained)
        .unwrap();
    #[cfg(not(feature = "privacy-mode"))]
    assert_eq!(mutation.address, "127.0.0.1:3000");
    assert_eq!(mutation.alias.as_deref(), Some("primary-a"));
    let stats = balancer.runtime_stats();
    assert_eq!(stats.drained_backend_count, 1);
    assert_eq!(stats.runtime_overridden_backend_count, 1);
    assert_eq!(stats.runtime_drained_backend_count, 1);
    assert_eq!(stats.runtime_disabled_backend_count, 0);
    assert_eq!(stats.runtime_forced_down_backend_count, 0);
    assert_eq!(stats.primary_available_backend_count, 1);
    let runtime_drained = stats
        .backends
        .iter()
        .find(|backend| backend.alias.as_deref() == Some("primary-a"))
        .expect("runtime drained backend status");
    assert_eq!(
        runtime_drained.runtime_state_override,
        Some(LoadBalancerRuntimeBackendState::Drained)
    );
    assert!(runtime_drained.runtime_state_changed_at_unix_secs.is_some());
    for _ in 0..4 {
        let selected = balancer.select(&request(), None).unwrap();
        assert_eq!(selected.backend.addr.to_string(), "127.0.0.1:3001");
    }

    balancer
        .set_runtime_backend_state("primary-b", LoadBalancerRuntimeBackendState::Disabled)
        .unwrap();
    let stats = balancer.runtime_stats();
    assert_eq!(stats.drained_backend_count, 1);
    assert_eq!(stats.disabled_backend_count, 1);
    assert_eq!(stats.runtime_overridden_backend_count, 2);
    assert_eq!(stats.runtime_drained_backend_count, 1);
    assert_eq!(stats.runtime_disabled_backend_count, 1);
    assert_eq!(stats.runtime_forced_down_backend_count, 0);
    assert_eq!(stats.primary_available_backend_count, 0);
    let runtime_disabled = stats
        .backends
        .iter()
        .find(|backend| backend.alias.as_deref() == Some("primary-b"))
        .expect("runtime disabled backend status");
    assert!(
        runtime_disabled
            .runtime_state_changed_at_unix_secs
            .is_some()
    );
    assert!(balancer.select(&request(), None).is_none());

    balancer
        .set_runtime_backend_state("primary-a", LoadBalancerRuntimeBackendState::Normal)
        .unwrap();
    let stats = balancer.runtime_stats();
    assert_eq!(stats.runtime_overridden_backend_count, 1);
    assert_eq!(stats.runtime_drained_backend_count, 0);
    assert_eq!(stats.runtime_disabled_backend_count, 1);
    assert_eq!(stats.runtime_forced_down_backend_count, 0);
    let normal = stats
        .backends
        .iter()
        .find(|backend| backend.alias.as_deref() == Some("primary-a"))
        .expect("normal backend status");
    assert_eq!(normal.runtime_state_changed_at_unix_secs, None);
    let selected = balancer.select(&request(), None).unwrap();
    assert_eq!(selected.backend.addr.to_string(), "127.0.0.1:3000");
}

#[test]
fn runtime_backend_state_supports_forced_down() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_aliases: vec!["primary-a".to_owned(), "primary-b".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let mutation = balancer
        .set_runtime_backend_state("primary-a", LoadBalancerRuntimeBackendState::ForcedDown)
        .unwrap();
    assert_eq!(mutation.state, LoadBalancerRuntimeBackendState::ForcedDown);
    assert_eq!(mutation.state.as_str(), "forced_down");

    let stats = balancer.runtime_stats();
    assert_eq!(stats.disabled_backend_count, 1);
    assert_eq!(stats.runtime_overridden_backend_count, 1);
    assert_eq!(stats.runtime_disabled_backend_count, 0);
    assert_eq!(stats.runtime_forced_down_backend_count, 1);
    assert_eq!(stats.primary_available_backend_count, 1);
    let forced_down = stats
        .backends
        .iter()
        .find(|backend| backend.alias.as_deref() == Some("primary-a"))
        .expect("forced down backend status");
    assert!(forced_down.disabled);
    assert_eq!(
        forced_down.runtime_state_override,
        Some(LoadBalancerRuntimeBackendState::ForcedDown)
    );

    for _ in 0..4 {
        let selected = balancer.select(&request(), None).unwrap();
        assert_eq!(selected.backend.addr.to_string(), "127.0.0.1:3001");
    }

    balancer
        .set_runtime_backend_state("primary-a", LoadBalancerRuntimeBackendState::Normal)
        .unwrap();
    let stats = balancer.runtime_stats();
    assert_eq!(stats.disabled_backend_count, 0);
    assert_eq!(stats.runtime_overridden_backend_count, 0);
    assert_eq!(stats.runtime_forced_down_backend_count, 0);
}

#[cfg(not(feature = "privacy-mode"))]
#[test]
fn manual_resume_clears_passive_ejection() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_aliases: vec!["primary-a".to_owned(), "primary-b".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            passive_health: LoadBalancePassiveHealthConfig {
                enabled: true,
                consecutive_failure: 1,
                ejection_secs: 60,
                ..LoadBalancePassiveHealthConfig::default()
            },
            slow_start: LoadBalanceSlowStartConfig {
                enabled: true,
                duration_secs: 30,
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let failed = balancer.select(&request(), None).unwrap();
    let failed_addr = failed.backend.addr.to_string();
    failed.reporter.unwrap().record_failure();
    let stats = balancer.runtime_stats();
    let ejected = stats
        .backends
        .iter()
        .find(|backend| backend.address.as_deref() == Some(failed_addr.as_str()))
        .expect("ejected backend status");
    assert!(ejected.passive_ejected);
    assert_eq!(ejected.circuit_state, LoadBalancerCircuitState::Open);

    let mutation = balancer
        .set_runtime_backend_state(&failed_addr, LoadBalancerRuntimeBackendState::ManualResume)
        .unwrap();
    assert_eq!(mutation.state.as_str(), "manual_resume");

    let stats = balancer.runtime_stats();
    let resumed = stats
        .backends
        .iter()
        .find(|backend| backend.address.as_deref() == Some(failed_addr.as_str()))
        .expect("resumed backend status");
    assert!(!resumed.passive_ejected);
    assert_eq!(resumed.circuit_state, LoadBalancerCircuitState::Closed);
    assert_eq!(resumed.passive_consecutive_failures, None);
    assert_eq!(stats.circuit_open_backend_count, 0);
}
