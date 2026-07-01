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

#[tokio::test]
async fn load_balancer_queue_waits_for_saturated_pool_capacity() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_max_in_flight: vec![1, 1],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            queue: LoadBalanceQueueConfig {
                max_waiting: 1,
                timeout_ms: 250,
                retry_interval_ms: 5,
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let held_a = balancer.select(&request(), None).unwrap();
    let held_b = balancer.select(&request(), None).unwrap();
    assert!(balancer.select(&request(), None).is_none());
    assert!(balancer.runtime_stats().queue.enabled);

    let request = request();
    let (selected, _) = tokio::join!(
        async { balancer.select_or_wait_result(&request, None).await },
        async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(held_a);
            drop(held_b);
        }
    );

    assert_eq!(
        selected.queue_outcome,
        Some(LoadBalancerQueueOutcome::Waited)
    );
    let selected = selected.selected.expect("queued selection should complete");
    assert!(
        selected.backend.addr.to_string() == "127.0.0.1:3000"
            || selected.backend.addr.to_string() == "127.0.0.1:3001"
    );
    assert_eq!(balancer.runtime_stats().queue.waiting, 0);
}

#[tokio::test]
async fn load_balancer_queue_reports_full_and_timeout() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_max_in_flight: vec![1, 1],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            queue: LoadBalanceQueueConfig {
                max_waiting: 1,
                timeout_ms: 25,
                retry_interval_ms: 5,
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let _held_a = balancer.select(&request(), None).unwrap();
    let _held_b = balancer.select(&request(), None).unwrap();

    let request = request();
    let (timed_out, full) = tokio::join!(
        async { balancer.select_or_wait_result(&request, None).await },
        async {
            tokio::time::sleep(Duration::from_millis(5)).await;
            balancer.select_or_wait_result(&request, None).await
        }
    );

    assert_eq!(full.queue_outcome, Some(LoadBalancerQueueOutcome::Full));
    assert!(full.selected.is_none());
    assert_eq!(
        timed_out.queue_outcome,
        Some(LoadBalancerQueueOutcome::Timeout)
    );
    assert!(timed_out.selected.is_none());
    assert_eq!(balancer.runtime_stats().queue.waiting, 0);
}
