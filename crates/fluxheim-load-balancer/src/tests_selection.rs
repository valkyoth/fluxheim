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
fn builds_hash_selection_from_proxy_upstreams() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            selection: LoadBalanceSelection::SourceHash,
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let client_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
    let first = balancer.select(&request(), Some(client_ip)).unwrap();
    let second = balancer.select(&request(), Some(client_ip)).unwrap();
    assert_eq!(first.backend.addr, second.backend.addr);
}

#[test]
fn builds_nginx_consistent_uri_hash_selection_from_static_proxy_upstreams() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_weights: vec![1, 2],
        load_balance: LoadBalanceConfig {
            selection: LoadBalanceSelection::NginxConsistentUriHash,
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let first = balancer.select(&request(), None).unwrap();
    let second = balancer.select(&request(), None).unwrap();
    assert_eq!(first.backend.addr, second.backend.addr);
    assert_eq!(
        balancer.runtime_stats().selection,
        LoadBalanceSelection::NginxConsistentUriHash
    );
}

#[test]
fn rejects_nginx_consistent_hash_with_dynamic_discovery() {
    install_test_crypto_provider();
    let root = unique_temp_path("lb-nginx-consistent-dynamic-file");
    std::fs::create_dir_all(&root).unwrap();
    let path = safe_child_path(&root, "upstreams.txt");
    std::fs::write(&path, "127.0.0.1:3000\n127.0.0.1:3001\n").unwrap();
    let error = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams_file: Some(path),
        load_balance: LoadBalanceConfig {
            selection: LoadBalanceSelection::NginxConsistentUriHash,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("nginx-compatible Ketama selections require static proxy.upstreams"),
        "{error}"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn builds_consistent_header_hash_selection_from_proxy_upstreams() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            selection: LoadBalanceSelection::ConsistentHeaderHash,
            hash_header: Some("x-session".to_owned()),
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let mut request = request();
    request.insert_header("x-session", "abc").unwrap();
    let first = balancer.select(&request, None).unwrap();
    let second = balancer.select(&request, None).unwrap();
    assert_eq!(first.backend.addr, second.backend.addr);
}

#[test]
fn builds_cookie_hash_selection_from_proxy_upstreams() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            selection: LoadBalanceSelection::CookieHash,
            hash_cookie: Some("session".to_owned()),
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let mut request = request();
    request
        .insert_header("cookie", "other=1; session=abc; theme=dark")
        .unwrap();
    let first = balancer.select(&request, None).unwrap();
    let second = balancer.select(&request, None).unwrap();
    assert_eq!(first.backend.addr, second.backend.addr);
}

#[test]
fn builds_maglev_uri_hash_selection_from_static_proxy_upstreams() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec![
            "127.0.0.1:3000".to_owned(),
            "127.0.0.1:3001".to_owned(),
            "127.0.0.1:3002".to_owned(),
        ],
        load_balance: LoadBalanceConfig {
            selection: LoadBalanceSelection::MaglevUriHash,
            max_iterations: 16,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let first = balancer.select(&request(), None).unwrap();
    let second = balancer.select(&request(), None).unwrap();
    assert_eq!(first.backend.addr, second.backend.addr);
    assert_eq!(
        balancer.runtime_stats().selection,
        LoadBalanceSelection::MaglevUriHash
    );
}

#[test]
fn maglev_skips_disabled_table_target() {
    install_test_crypto_provider();
    let disabled = "127.0.0.1:3000".to_owned();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec![
            disabled.clone(),
            "127.0.0.1:3001".to_owned(),
            "127.0.0.1:3002".to_owned(),
        ],
        disabled_upstreams: vec![disabled.clone()],
        load_balance: LoadBalanceConfig {
            selection: LoadBalanceSelection::MaglevSourceHash,
            max_iterations: 32,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    for octet in 1..=32 {
        let selected = balancer
            .select(
                &request(),
                Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, octet))),
            )
            .unwrap();
        assert_ne!(selected.backend.addr.to_string(), disabled);
    }
}

#[test]
fn bounded_load_consistent_hash_skips_over_bound_target() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            selection: LoadBalanceSelection::BoundedLoadConsistentUriHash,
            bounded_load_factor_per_mille: 1000,
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let first = balancer.select(&request(), None).unwrap();
    let second = balancer.select(&request(), None).unwrap();

    assert_ne!(first.backend.addr, second.backend.addr);
}

#[test]
fn least_connections_tracks_held_permits() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            selection: LoadBalanceSelection::LeastConnections,
            max_iterations: 8,
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let first = balancer.select(&request(), None).unwrap();
    let first_addr = first.backend.addr;
    let second = balancer.select(&request(), None).unwrap();
    assert_ne!(&first_addr, &second.backend.addr);
    drop(first);
    let third = balancer.select(&request(), None).unwrap();
    assert_eq!(third.backend.addr, first_addr);
}

#[test]
fn least_connections_respects_backend_weights() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_weights: vec![1, 4],
        load_balance: LoadBalanceConfig {
            selection: LoadBalanceSelection::LeastConnections,
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
}

#[test]
fn weighted_two_choice_uses_weighted_connection_pressure() {
    assert!(least_connections_score_is_lower(2, 4, 1, 1));
    assert!(!least_connections_score_is_lower(2, 1, 1, 4));
}
