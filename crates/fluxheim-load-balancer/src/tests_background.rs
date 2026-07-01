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
async fn tcp_health_check_transitions_backend_readiness() {
    install_test_crypto_provider();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = listener.local_addr().unwrap().to_string();
    drop(listener);

    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec![upstream.clone(), "127.0.0.1:1".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            health_check: LoadBalanceHealthCheckConfig {
                enabled: true,
                protocol: LoadBalanceHealthCheckProtocol::Tcp,
                consecutive_success: 2,
                consecutive_failure: 2,
                interval_secs: 1,
                connect_timeout_secs: Some(1),
                ..LoadBalanceHealthCheckConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    assert_eq!(balancer.runtime_stats().ready_backend_count, 2);

    balancer.run_health_check(false).await;
    assert_eq!(balancer.runtime_stats().ready_backend_count, 2);
    balancer.run_health_check(false).await;
    assert_eq!(balancer.runtime_stats().ready_backend_count, 0);

    let listener = std::net::TcpListener::bind(&upstream).unwrap();
    balancer.run_health_check(false).await;
    assert_eq!(balancer.runtime_stats().ready_backend_count, 0);
    balancer.run_health_check(false).await;
    assert_eq!(balancer.runtime_stats().ready_backend_count, 1);
    drop(listener);
}

#[test]
fn builds_background_service_and_shared_selector() {
    install_test_crypto_provider();
    let (balancer, _service) = UpstreamLoadBalancer::background_service_from_proxy_config(
        "test",
        "test",
        None,
        &ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            ..ProxyConfig::default()
        },
    )
    .unwrap()
    .unwrap();

    assert_eq!(balancer.backend_count(), 2);
    assert!(balancer.select(&request(), None).is_some());
}

#[tokio::test]
async fn load_balancer_background_service_notifies_ready_after_initial_update() {
    install_test_crypto_provider();
    let (_balancer, service) = UpstreamLoadBalancer::background_service_from_proxy_config(
        "test",
        "test",
        None,
        &ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            ..ProxyConfig::default()
        },
    )
    .unwrap()
    .unwrap();

    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let (ready_sender, mut ready_receiver) = watch::channel(false);
    let service_task = tokio::spawn(async move {
        service
            .start(
                crate::background::FluxShutdown::new(shutdown_receiver),
                crate::background::FluxBackgroundReady::new(move || {
                    ready_sender.send_replace(true);
                }),
            )
            .await;
    });

    tokio::time::timeout(Duration::from_secs(1), async {
        while !*ready_receiver.borrow_and_update() {
            ready_receiver.changed().await.unwrap();
        }
    })
    .await
    .unwrap();

    shutdown_sender.send(true).unwrap();
    service_task.await.unwrap();
}

#[tokio::test]
async fn load_balancer_background_service_runs_under_native_supervisor() {
    install_test_crypto_provider();
    let (_balancer, service) = UpstreamLoadBalancer::background_service_from_proxy_config(
        "test",
        "test",
        None,
        &ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            ..ProxyConfig::default()
        },
    )
    .unwrap()
    .unwrap();

    let supervisor = fluxheim_runtime::NativeBackgroundSupervisor::new();
    let (ready_sender, mut ready_receiver) = watch::channel(false);
    let handle = supervisor.spawn_service_with_ready(service.into_native_service(), move || {
        ready_sender.send_replace(true);
    });

    tokio::time::timeout(Duration::from_secs(1), async {
        while !*ready_receiver.borrow_and_update() {
            ready_receiver.changed().await.unwrap();
        }
    })
    .await
    .unwrap();

    assert_eq!(
        handle.kind(),
        Some(fluxheim_runtime::BackgroundTaskKind::LoadBalancerRefresh)
    );
    assert!(supervisor.shutdown());
    handle.join().await.unwrap();
}

#[test]
fn stays_disabled_without_load_balanced_upstreams() {
    let without_upstreams =
        UpstreamLoadBalancer::from_proxy_config(&ProxyConfig::default()).unwrap();
    let single_upstream = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["missing-container.test:3000".to_owned()],
        ..ProxyConfig::default()
    })
    .unwrap();

    assert!(without_upstreams.is_none());
    assert!(single_upstream.is_none());
}
