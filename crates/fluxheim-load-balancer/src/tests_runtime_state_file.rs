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

#[cfg(not(feature = "privacy-mode"))]
#[test]
fn runtime_state_snapshot_restores_overrides_and_persistence() {
    install_test_crypto_provider();
    let config = ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            persistence: LoadBalancePersistenceConfig {
                enabled: true,
                ttl_secs: 60,
                table_max_entries: 16,
                ..LoadBalancePersistenceConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    };
    let balancer = UpstreamLoadBalancer::from_proxy_config(&config)
        .unwrap()
        .unwrap();

    let first = balancer
        .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))))
        .unwrap();
    assert_eq!(first.backend.addr.to_string(), "127.0.0.1:3000");
    drop(first);
    balancer
        .set_runtime_backend_state(
            "127.0.0.1:3001",
            LoadBalancerRuntimeBackendState::ForcedDown,
        )
        .unwrap();
    balancer
        .set_runtime_backend_weight("127.0.0.1:3000", Some(7))
        .unwrap();

    let snapshot = balancer.runtime_state_snapshot();
    let restored = UpstreamLoadBalancer::from_proxy_config(&config)
        .unwrap()
        .unwrap();
    let restore = restored.restore_runtime_state_snapshot(&snapshot).unwrap();
    assert_eq!(restore.persistence_entries, 1);

    let stats = restored.runtime_stats();
    let backend_a = stats
        .backends
        .iter()
        .find(|backend| backend.address.as_deref() == Some("127.0.0.1:3000"))
        .expect("backend a");
    assert_eq!(backend_a.runtime_weight_override, Some(7));
    assert_eq!(backend_a.persistence_entry_count, 1);
    let backend_b = stats
        .backends
        .iter()
        .find(|backend| backend.address.as_deref() == Some("127.0.0.1:3001"))
        .expect("backend b");
    assert_eq!(
        backend_b.runtime_state_override,
        Some(LoadBalancerRuntimeBackendState::ForcedDown)
    );

    let second = restored
        .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))))
        .unwrap();
    assert_eq!(second.backend.addr.to_string(), "127.0.0.1:3000");
    assert_eq!(
        second.persistence_outcome,
        Some(LoadBalancerPersistenceOutcome::Hit)
    );
}

#[test]
fn runtime_state_file_restores_configured_balancer_state() {
    install_test_crypto_provider();
    let dir = unique_temp_path("lb-runtime-state-configured");
    std::fs::create_dir_all(&dir).unwrap();
    let state_file = safe_child_path(&dir, "lb-state.json");
    let config = ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            runtime_state_file: Some(state_file.clone()),
            persistence: LoadBalancePersistenceConfig {
                enabled: true,
                ttl_secs: 60,
                table_max_entries: 16,
                ..LoadBalancePersistenceConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    };
    let balancer = UpstreamLoadBalancer::from_proxy_config(&config)
        .unwrap()
        .unwrap();

    let first = balancer
        .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))))
        .unwrap();
    assert_eq!(first.backend.addr.to_string(), "127.0.0.1:3000");
    drop(first);
    balancer
        .set_runtime_backend_state("127.0.0.1:3001", LoadBalancerRuntimeBackendState::Disabled)
        .unwrap();
    assert!(state_file.exists());

    let restored = UpstreamLoadBalancer::from_proxy_config(&config)
        .unwrap()
        .unwrap();
    let stats = restored.runtime_stats();
    assert_eq!(stats.persistence.entry_count, 1);
    assert_eq!(stats.runtime_disabled_backend_count, 1);

    let second = restored
        .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))))
        .unwrap();
    assert_eq!(second.backend.addr.to_string(), "127.0.0.1:3000");
    assert_eq!(
        second.persistence_outcome,
        Some(LoadBalancerPersistenceOutcome::Hit)
    );
}

#[test]
fn runtime_state_file_ignores_invalid_state_without_poisoning_pool() {
    install_test_crypto_provider();
    let dir = unique_temp_path("lb-runtime-state-invalid");
    std::fs::create_dir_all(&dir).unwrap();
    let state_file = safe_child_path(&dir, "lb-state.json");
    std::fs::write(
        &state_file,
        r#"{"version":999,"runtime_overrides":{"states":[],"weights":[]},"persistence":null}"#,
    )
    .unwrap();
    let config = ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            runtime_state_file: Some(state_file),
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    };

    let balancer = UpstreamLoadBalancer::from_proxy_config(&config)
        .unwrap()
        .unwrap();
    let selected = balancer.select(&request(), None).unwrap();
    assert_eq!(selected.backend.addr.to_string(), "127.0.0.1:3000");
}

#[test]
fn runtime_state_file_restore_is_all_or_nothing() {
    install_test_crypto_provider();
    let dir = unique_temp_path("lb-runtime-state-atomic-restore");
    std::fs::create_dir_all(&dir).unwrap();
    let state_file = safe_child_path(&dir, "lb-state.json");
    let disabled_key = backend_key(&FluxBackend::new("127.0.0.1:3001").unwrap());
    std::fs::write(
        &state_file,
        format!(
            r#"{{
  "version": 1,
  "runtime_overrides": {{
    "states": [
      {{
        "key": {disabled_key},
        "state": "disabled",
        "changed_at_unix_secs": 1
      }}
    ],
    "weights": []
  }},
  "persistence": {{
    "entries": [
      {{
        "key": [],
        "backend_key": {disabled_key},
        "ttl_remaining_secs": 60
      }}
    ]
  }}
}}"#
        ),
    )
    .unwrap();
    let config = ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            runtime_state_file: Some(state_file),
            persistence: LoadBalancePersistenceConfig {
                enabled: true,
                ttl_secs: 60,
                table_max_entries: 16,
                ..LoadBalancePersistenceConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    };

    let balancer = UpstreamLoadBalancer::from_proxy_config(&config)
        .unwrap()
        .unwrap();
    let stats = balancer.runtime_stats();
    assert_eq!(stats.runtime_disabled_backend_count, 0);
    assert_eq!(stats.persistence.entry_count, 0);
}
