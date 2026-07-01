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
fn runtime_weight_override_changes_round_robin_distribution() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_weights: vec![1, 1],
        upstream_aliases: vec!["origin-a".to_owned(), "origin-b".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let mutation = balancer
        .set_runtime_backend_weight("origin-a", Some(4))
        .unwrap();
    assert_eq!(mutation.configured_weight, 1);
    assert_eq!(mutation.effective_weight, 4);
    assert_eq!(mutation.runtime_weight_override, Some(4));
    balancer
        .set_runtime_backend_weight("origin-b", Some(1))
        .unwrap();

    let selected_aliases = (0..5)
        .map(|_| {
            balancer
                .select(&request(), None)
                .unwrap()
                .alias
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        selected_aliases,
        ["origin-a", "origin-a", "origin-a", "origin-a", "origin-b"]
    );

    let stats = balancer.runtime_stats();
    let origin_a = stats
        .backends
        .iter()
        .find(|backend| backend.alias.as_deref() == Some("origin-a"))
        .unwrap();
    assert_eq!(origin_a.weight, 1);
    assert_eq!(origin_a.effective_weight, 4);
    assert_eq!(origin_a.runtime_weight_override, Some(4));
    assert!(origin_a.runtime_weight_changed_at_unix_secs.is_some());

    let reset = balancer
        .set_runtime_backend_weight("origin-a", None)
        .unwrap();
    assert_eq!(reset.effective_weight, 1);
    assert_eq!(reset.runtime_weight_override, None);
}

#[test]
fn runtime_weight_override_rejects_hash_selection() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_aliases: vec!["origin-a".to_owned(), "origin-b".to_owned()],
        load_balance: LoadBalanceConfig {
            selection: LoadBalanceSelection::SourceHash,
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let error = balancer
        .set_runtime_backend_weight("origin-a", Some(4))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}

#[test]
fn runtime_backend_set_mutations_update_static_pool() {
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

    let added = balancer
        .add_runtime_backend_member("127.0.0.1:3002", 3)
        .unwrap();
    assert_eq!(
        added.operation,
        LoadBalancerRuntimeBackendSetOperation::Added
    );
    assert_eq!(added.configured_weight, 3);
    assert_eq!(added.backend_count, 3);
    assert_eq!(balancer.backend_count(), 3);
    assert_eq!(balancer.backend_weights(), [1, 1, 3]);

    let duplicate = balancer
        .add_runtime_backend_member("127.0.0.1:3002", 3)
        .unwrap_err();
    assert_eq!(duplicate.kind(), io::ErrorKind::AlreadyExists);

    let updated = balancer
        .update_runtime_backend_member("127.0.0.1:3002", None, Some(5))
        .unwrap();
    assert_eq!(
        updated.operation,
        LoadBalancerRuntimeBackendSetOperation::Updated
    );
    assert_eq!(updated.configured_weight, 5);
    assert_eq!(updated.backend_count, 3);
    assert_eq!(balancer.backend_weights(), [1, 1, 5]);

    let removed = balancer
        .remove_runtime_backend_member("127.0.0.1:3002")
        .unwrap();
    assert_eq!(
        removed.operation,
        LoadBalancerRuntimeBackendSetOperation::Removed
    );
    assert_eq!(removed.backend_count, 2);
    assert_eq!(balancer.backend_count(), 2);
    assert_eq!(balancer.backend_weights(), [1, 1]);
}

#[test]
fn runtime_backend_set_update_rejects_aliased_address_retarget() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_aliases: vec!["origin-a".to_owned(), "origin-b".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let updated = balancer
        .update_runtime_backend_member("origin-a", None, Some(3))
        .unwrap();
    assert_eq!(updated.member, "127.0.0.1:3000");
    assert_eq!(updated.alias.as_deref(), Some("origin-a"));
    assert_eq!(updated.configured_weight, 3);

    let error = balancer
        .update_runtime_backend_member("origin-a", Some("127.0.0.1:3002"), None)
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("aliased"));
}

#[test]
fn runtime_backend_set_remove_reports_resolved_member_address_for_alias() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_aliases: vec!["origin-a".to_owned(), "origin-b".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let removed = balancer.remove_runtime_backend_member("origin-a").unwrap();

    assert_eq!(removed.member, "127.0.0.1:3000");
    assert_eq!(removed.alias.as_deref(), Some("origin-a"));
    assert_eq!(
        removed.operation,
        LoadBalancerRuntimeBackendSetOperation::Removed
    );
}

#[test]
fn runtime_backend_set_remove_rejects_in_flight_member() {
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
    let selected = balancer.select(&request(), None).unwrap();
    let member = selected.backend.addr.to_string();

    let error = balancer.remove_runtime_backend_member(&member).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    drop(selected);
    assert!(balancer.remove_runtime_backend_member(&member).is_ok());
}

#[test]
fn runtime_backend_set_remove_prunes_local_persistence() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
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
    })
    .unwrap()
    .unwrap();
    let selected = balancer
        .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))))
        .unwrap();
    let member = selected.backend.addr.to_string();
    assert_eq!(balancer.runtime_stats().persistence.entry_count, 1);

    drop(selected);
    let removed = balancer.remove_runtime_backend_member(&member).unwrap();
    assert_eq!(
        removed.operation,
        LoadBalancerRuntimeBackendSetOperation::Removed
    );
    assert_eq!(balancer.runtime_stats().persistence.entry_count, 0);
}

#[test]
fn runtime_backend_set_remove_clears_runtime_override_state() {
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
    balancer
        .set_runtime_backend_state(
            "127.0.0.1:3001",
            LoadBalancerRuntimeBackendState::ForcedDown,
        )
        .unwrap();
    assert_eq!(
        balancer.runtime_stats().runtime_forced_down_backend_count,
        1
    );

    balancer
        .remove_runtime_backend_member("127.0.0.1:3001")
        .unwrap();
    balancer
        .add_runtime_backend_member("127.0.0.1:3001", 1)
        .unwrap();

    let stats = balancer.runtime_stats();
    assert_eq!(stats.runtime_overridden_backend_count, 0);
    assert_eq!(stats.runtime_forced_down_backend_count, 0);
    assert_eq!(stats.primary_available_backend_count, 2);
}

#[test]
fn runtime_backend_set_mutation_rejects_maglev_selection() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            selection: LoadBalanceSelection::MaglevUriHash,
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let error = balancer
        .add_runtime_backend_member("127.0.0.1:3002", 1)
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("static-ring"));
}

#[test]
fn runtime_backend_set_mutation_rejects_nginx_consistent_selection() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            selection: LoadBalanceSelection::NginxConsistentUriHash,
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let error = balancer
        .add_runtime_backend_member("127.0.0.1:3002", 1)
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("static-ring"));
}

#[test]
fn runtime_backend_set_mutation_rejects_dynamic_discovery_pools() {
    install_test_crypto_provider();
    let root = unique_temp_path("lb-runtime-mutation-dynamic-file");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("upstreams.txt");
    std::fs::write(&path, "127.0.0.1:3000\n127.0.0.1:3001\n").unwrap();
    let file_balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
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

    let error = file_balancer
        .add_runtime_backend_member("127.0.0.1:3002", 1)
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("static upstream pools"));

    let dns_balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
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

    let error = dns_balancer
        .add_runtime_backend_member("127.0.0.1:3002", 1)
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("static upstream pools"));
}
