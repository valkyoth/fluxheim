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
fn configures_tcp_health_check() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            health_check: LoadBalanceHealthCheckConfig {
                enabled: true,
                interval_secs: 3,
                consecutive_success: 2,
                consecutive_failure: 4,
                parallel: true,
                ..LoadBalanceHealthCheckConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    assert_eq!(
        balancer.health_check_frequency(),
        Some(Duration::from_secs(3))
    );
    assert!(balancer.parallel_health_check());
}

#[test]
fn slow_start_gates_new_backends_until_warmed() {
    let state = SlowStartState::from_config(&LoadBalanceSlowStartConfig {
        enabled: true,
        duration_secs: 60,
    });
    let backend = FluxBackend::new("127.0.0.1:3000").unwrap();
    state
        .sample_counter
        .store(slow_start_blocking_sample(&backend), Ordering::Relaxed);

    assert!(!state.permits(&backend));
    state.backends.lock().unwrap().insert(
        backend_key(&backend),
        Instant::now() - Duration::from_secs(61),
    );
    assert!(state.permits(&backend));
}
#[test]
fn slow_start_read_only_reports_majority_warm() {
    let state = SlowStartState::from_config(&LoadBalanceSlowStartConfig {
        enabled: true,
        duration_secs: 60,
    });
    let backend = FluxBackend::new("127.0.0.1:3000").unwrap();
    state
        .backends
        .lock()
        .unwrap()
        .insert(backend_key(&backend), Instant::now());
    assert!(!state.permits_read_only(&backend));

    state.backends.lock().unwrap().insert(
        backend_key(&backend),
        Instant::now() - Duration::from_secs(31),
    );
    assert!(state.permits_read_only(&backend));
}

#[test]
fn slow_start_does_not_outage_all_warming_backends() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            slow_start: LoadBalanceSlowStartConfig {
                enabled: true,
                duration_secs: 60,
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    assert!(balancer.select(&request(), None).is_some());
}

#[test]
fn passive_recovery_restarts_slow_start_window() {
    let slow_start = Arc::new(SlowStartState::from_config(&LoadBalanceSlowStartConfig {
        enabled: true,
        duration_secs: 60,
    }));
    let backend = FluxBackend::new("127.0.0.1:3000").unwrap();
    let key = backend_key(&backend);
    slow_start
        .backends
        .lock()
        .unwrap()
        .insert(key, Instant::now() - Duration::from_secs(61));
    assert!(slow_start.permits(&backend));

    let reporter = LoadBalancedUpstreamReporter::new(
        key,
        Some(Arc::new(PassiveHealthState::from_config(
            &LoadBalancePassiveHealthConfig {
                enabled: true,
                consecutive_failure: 1,
                ejection_secs: 1,
                ..LoadBalancePassiveHealthConfig::default()
            },
        ))),
        Some(slow_start.clone()),
        None,
    );
    let outcome = reporter.record_failure();
    assert!(outcome.failed);
    assert!(outcome.ejected);

    slow_start
        .sample_counter
        .store(slow_start_blocking_sample(&backend), Ordering::Relaxed);
    assert!(!slow_start.permits(&backend));
}

#[cfg(not(feature = "privacy-mode"))]
#[test]
fn passive_health_ejects_failed_backend() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
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
    let failed_addr = failed.backend.addr;
    let outcome = failed.reporter.unwrap().record_status(503, None);
    assert!(outcome.failed);
    assert!(outcome.ejected);
    let stats = balancer.runtime_stats();
    let failed_addr_text = failed_addr.to_string();
    let failed_stats = stats
        .backends
        .iter()
        .find(|backend| backend.address.as_deref() == Some(failed_addr_text.as_str()))
        .expect("failed backend stats");
    assert!(failed_stats.passive_ejected);
    assert_eq!(failed_stats.circuit_state, LoadBalancerCircuitState::Open);
    assert!(failed_stats.passive_ejection_remaining_secs.is_some());
    assert_eq!(stats.circuit_open_backend_count, 1);
    let next = balancer.select(&request(), None).unwrap();
    assert_ne!(failed_addr, next.backend.addr);
}

#[test]
fn passive_health_floor_prevents_full_pool_outage() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
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

    let first = balancer.select(&request(), None).unwrap();
    let first_addr = first.backend.addr;
    assert!(first.reporter.unwrap().record_failure().ejected);
    let second = balancer.select(&request(), None).unwrap();
    let second_addr = second.backend.addr;
    assert_ne!(first_addr, second_addr);
    assert!(second.reporter.unwrap().record_failure().ejected);

    let stats = balancer.runtime_stats();
    assert_eq!(stats.passive_ejected_backend_count, 2);
    assert_eq!(stats.available_backend_count, 0);
    let selected = balancer
        .select(&request(), None)
        .expect("passive health floor keeps a backend selectable");
    assert!(selected.backend.addr == first_addr || selected.backend.addr == second_addr);
}

#[test]
fn passive_health_floor_can_be_disabled_for_strict_fail_closed() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            passive_health: LoadBalancePassiveHealthConfig {
                enabled: true,
                consecutive_failure: 1,
                ejection_secs: 60,
                min_healthy_backends: 0,
                ..LoadBalancePassiveHealthConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let first = balancer.select(&request(), None).unwrap();
    first.reporter.unwrap().record_failure();
    let second = balancer.select(&request(), None).unwrap();
    second.reporter.unwrap().record_failure();

    assert!(balancer.select(&request(), None).is_none());
}

#[cfg(not(feature = "privacy-mode"))]
#[test]
fn runtime_status_reports_passive_failure_count_before_ejection() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            passive_health: LoadBalancePassiveHealthConfig {
                enabled: true,
                consecutive_failure: 2,
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
    let failed_addr_text = failed.backend.addr.to_string();
    let outcome = failed.reporter.unwrap().record_status(503, None);
    assert!(outcome.failed);
    assert!(!outcome.ejected);
    let stats = balancer.runtime_stats();
    let failed_stats = stats
        .backends
        .iter()
        .find(|backend| backend.address.as_deref() == Some(failed_addr_text.as_str()))
        .expect("failed backend stats");
    assert_eq!(failed_stats.passive_consecutive_failures, Some(1));
    assert!(!failed_stats.passive_ejected);
    assert_eq!(failed_stats.circuit_state, LoadBalancerCircuitState::Closed);
    assert_eq!(stats.circuit_open_backend_count, 0);
}

#[test]
fn passive_health_accepts_failure_status_ranges() {
    let health = PassiveHealthState::from_config(&LoadBalancePassiveHealthConfig {
        enabled: true,
        failure_status_ranges: vec![LoadBalanceHealthCheckExpectedStatusRange {
            start: 520,
            end: 529,
        }],
        ..LoadBalancePassiveHealthConfig::default()
    });

    assert!(health.failure_status(520));
    assert!(health.failure_status(529));
    assert!(!health.failure_status(503));
}

#[test]
fn passive_health_prune_keeps_live_and_active_ejections() {
    let health = PassiveHealthState::from_config(&LoadBalancePassiveHealthConfig {
        enabled: true,
        ..LoadBalancePassiveHealthConfig::default()
    });
    let now = Instant::now();
    health.backends.lock().unwrap().extend([
        (
            1,
            PassiveBackendHealth {
                consecutive_failures: 1,
                ejected_until: None,
            },
        ),
        (
            2,
            PassiveBackendHealth {
                consecutive_failures: 1,
                ejected_until: None,
            },
        ),
        (
            3,
            PassiveBackendHealth {
                consecutive_failures: 0,
                ejected_until: Some(now + Duration::from_secs(60)),
            },
        ),
        (
            4,
            PassiveBackendHealth {
                consecutive_failures: 0,
                ejected_until: Some(now - Duration::from_secs(1)),
            },
        ),
    ]);
    health.prune_stale(&[1].into_iter().collect());
    let backends = health.backends.lock().unwrap();

    assert!(backends.contains_key(&1));
    assert!(!backends.contains_key(&2));
    assert!(backends.contains_key(&3));
    assert!(!backends.contains_key(&4));
}

#[test]
fn passive_health_ejects_slow_backend() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            passive_health: LoadBalancePassiveHealthConfig {
                enabled: true,
                consecutive_failure: 1,
                ejection_secs: 60,
                max_latency_ms: 100,
                ..LoadBalancePassiveHealthConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let failed = balancer.select(&request(), None).unwrap();
    let failed_addr = failed.backend.addr;
    let outcome = failed
        .reporter
        .unwrap()
        .record_status(200, Some(Duration::from_millis(150)));
    assert!(outcome.failed);
    assert!(outcome.ejected);
    let next = balancer.select(&request(), None).unwrap();
    assert_ne!(failed_addr, next.backend.addr);
}

#[test]
fn backup_upstreams_are_used_after_primary_ejection() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        backup_upstreams: vec!["127.0.0.1:3001".to_owned()],
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

    let primary = balancer.select(&request(), None).unwrap();
    assert_eq!(primary.backend.addr.to_string(), "127.0.0.1:3000");
    primary.reporter.unwrap().record_failure();
    let stats = balancer.runtime_stats();
    assert_eq!(stats.primary_available_backend_count, 0);
    assert_eq!(stats.backup_available_backend_count, 1);
    assert_eq!(stats.passive_ejected_backend_count, 1);
    let backup = balancer.select(&request(), None).unwrap();
    assert_eq!(backup.backend.addr.to_string(), "127.0.0.1:3001");
}

#[test]
fn drained_upstreams_do_not_receive_new_selections() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        drain_upstreams: vec!["127.0.0.1:3000".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    for _ in 0..4 {
        let selected = balancer.select(&request(), None).unwrap();
        assert_eq!(selected.backend.addr.to_string(), "127.0.0.1:3001");
    }
    let stats = balancer.runtime_stats();
    assert_eq!(stats.drained_backend_count, 1);
    assert_eq!(stats.primary_available_backend_count, 1);
}

#[test]
fn disabled_upstreams_do_not_receive_new_selections() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        disabled_upstreams: vec!["127.0.0.1:3000".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    for _ in 0..4 {
        let selected = balancer.select(&request(), None).unwrap();
        assert_eq!(selected.backend.addr.to_string(), "127.0.0.1:3001");
    }
    let stats = balancer.runtime_stats();
    assert_eq!(stats.disabled_backend_count, 1);
    assert_eq!(stats.primary_available_backend_count, 1);
    let disabled = stats
        .backends
        .iter()
        .find(|backend| backend.disabled)
        .expect("disabled backend status");
    assert!(!disabled.ready);
}
