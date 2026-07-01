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
fn persistence_keys_reject_oversized_header_and_cookie_values() {
    let max_single_header_value = MAX_PERSISTENCE_KEY_BYTES - std::mem::size_of::<usize>();
    let mut header_request = request();
    header_request
        .insert_header("x-session", "a".repeat(max_single_header_value))
        .unwrap();
    assert_eq!(
        request_header_key(&header_request, "x-session")
            .unwrap()
            .len(),
        MAX_PERSISTENCE_KEY_BYTES
    );

    let mut oversized_header_request = request();
    oversized_header_request
        .insert_header("x-session", "a".repeat(max_single_header_value + 1))
        .unwrap();
    assert!(request_header_key(&oversized_header_request, "x-session").is_none());

    let mut cookie_request = request();
    cookie_request
        .insert_header(
            "cookie",
            format!("sid={}", "b".repeat(MAX_PERSISTENCE_KEY_BYTES)),
        )
        .unwrap();
    assert_eq!(
        cookie_key(&cookie_request, "sid").unwrap().len(),
        MAX_PERSISTENCE_KEY_BYTES
    );

    let mut oversized_cookie_request = request();
    oversized_cookie_request
        .insert_header(
            "cookie",
            format!("sid={}", "b".repeat(MAX_PERSISTENCE_KEY_BYTES + 1)),
        )
        .unwrap();
    assert!(cookie_key(&oversized_cookie_request, "sid").is_none());
}

#[test]
fn managed_cookie_persistence_reuses_selected_backend() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            persistence: LoadBalancePersistenceConfig {
                enabled: true,
                mode: LoadBalancePersistenceMode::ManagedCookie,
                cookie: Some("fluxheim_lb".to_owned()),
                ttl_secs: 60,
                table_max_entries: 16,
                managed_cookie_path: Some("/app".to_owned()),
                managed_cookie_same_site: LoadBalanceManagedCookieSameSite::Strict,
                ..LoadBalancePersistenceConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    let first = balancer.select(&request(), None).unwrap();
    let cookie = first
        .managed_affinity_cookie()
        .expect("fresh selection emits managed cookie")
        .header_value
        .as_str();
    assert!(cookie.starts_with("fluxheim_lb="));
    assert!(cookie.contains("; Path=/app"));
    assert!(cookie.contains("; HttpOnly"));
    assert!(cookie.contains("; Secure"));
    assert!(cookie.contains("; SameSite=Strict"));
    let first_backend = backend_key(&first.backend);
    assert_eq!(balancer.runtime_stats().persistence.entry_count, 1);

    let cookie_value = cookie
        .strip_prefix("fluxheim_lb=")
        .and_then(|value| value.split_once(';').map(|(value, _)| value))
        .unwrap();
    let mut persisted_request = request();
    persisted_request
        .insert_header("cookie", format!("fluxheim_lb={cookie_value}"))
        .unwrap();
    let second = balancer.select(&persisted_request, None).unwrap();
    assert_eq!(backend_key(&second.backend), first_backend);
    assert_eq!(
        second.persistence_outcome(),
        Some(LoadBalancerPersistenceOutcome::Hit)
    );
    assert!(second.managed_affinity_cookie().is_none());
    assert_eq!(balancer.runtime_stats().persistence.entry_count, 1);

    let third = balancer.select(&persisted_request, None).unwrap();
    assert_eq!(backend_key(&third.backend), first_backend);
    assert_eq!(
        third.persistence_outcome(),
        Some(LoadBalancerPersistenceOutcome::Hit)
    );
    assert!(third.managed_affinity_cookie().is_none());
}

#[test]
fn managed_cookie_missing_cookie_respects_persistence_table_bound() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            persistence: LoadBalancePersistenceConfig {
                enabled: true,
                mode: LoadBalancePersistenceMode::ManagedCookie,
                cookie: Some("fluxheim_lb".to_owned()),
                ttl_secs: 60,
                table_max_entries: 4,
                ..LoadBalancePersistenceConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    })
    .unwrap()
    .unwrap();

    for _ in 0..16 {
        let selected = balancer.select(&request(), None).unwrap();
        assert!(selected.managed_affinity_cookie.is_some());
    }

    let stats = balancer.runtime_stats();
    assert_eq!(stats.persistence.entry_count, 4);
    assert!(
        stats
            .backends
            .iter()
            .map(|backend| backend.persistence_entry_count)
            .sum::<usize>()
            <= 4
    );
}

#[test]
fn source_ip_persistence_reuses_selected_backend() {
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

    let first = balancer
        .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))))
        .unwrap();
    assert_eq!(first.backend.addr.to_string(), "127.0.0.1:3000");
    assert_eq!(
        first.persistence_outcome,
        Some(LoadBalancerPersistenceOutcome::Miss)
    );
    drop(first);

    let second = balancer
        .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))))
        .unwrap();
    assert_eq!(second.backend.addr.to_string(), "127.0.0.1:3000");
    assert_eq!(
        second.persistence_outcome,
        Some(LoadBalancerPersistenceOutcome::Hit)
    );
    drop(second);

    let different_client = balancer
        .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))))
        .unwrap();
    assert_eq!(different_client.backend.addr.to_string(), "127.0.0.1:3001");
    assert_eq!(
        different_client.persistence_outcome,
        Some(LoadBalancerPersistenceOutcome::Miss)
    );

    let stats = balancer.runtime_stats();
    assert!(stats.persistence_enabled);
    assert_eq!(stats.persistence.entry_count, 2);
    assert_eq!(stats.persistence.table_max_entries, 16);
    assert_eq!(stats.persistence.ttl_secs, 60);
    assert_eq!(
        stats
            .backends
            .iter()
            .map(|backend| backend.persistence_entry_count)
            .sum::<usize>(),
        2
    );
    assert_eq!(
        stats
            .backends
            .iter()
            .find(|backend| backend.address.as_deref() == Some("127.0.0.1:3000"))
            .expect("first persisted backend")
            .persistence_entry_count,
        1
    );
    assert_eq!(
        stats
            .backends
            .iter()
            .find(|backend| backend.address.as_deref() == Some("127.0.0.1:3001"))
            .expect("second persisted backend")
            .persistence_entry_count,
        1
    );
}

#[test]
fn least_sessions_uses_persistence_entry_counts() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: LoadBalanceConfig {
            selection: LoadBalanceSelection::LeastSessions,
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

    let first = balancer
        .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))))
        .unwrap();
    assert_eq!(first.backend.addr.to_string(), "127.0.0.1:3000");
    drop(first);

    let second = balancer
        .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))))
        .unwrap();
    assert_eq!(second.backend.addr.to_string(), "127.0.0.1:3001");

    let stats = balancer.runtime_stats();
    assert_eq!(
        stats
            .backends
            .iter()
            .map(|backend| backend.persistence_entry_count)
            .sum::<usize>(),
        2
    );
}

#[cfg(not(feature = "privacy-mode"))]
#[test]
fn header_persistence_reuses_selected_backend() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec![
            "127.0.0.1:3000".to_owned(),
            "127.0.0.1:3001".to_owned(),
            "127.0.0.1:3002".to_owned(),
        ],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            persistence: LoadBalancePersistenceConfig {
                enabled: true,
                mode: LoadBalancePersistenceMode::Header,
                header: Some("x-session".to_owned()),
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

    let mut first_request = request();
    first_request.insert_header("x-session", "abc").unwrap();
    let first = balancer.select(&first_request, None).unwrap();
    assert_eq!(
        first.persistence_outcome,
        Some(LoadBalancerPersistenceOutcome::Miss)
    );

    let mut second_request = request();
    second_request.insert_header("x-session", "abc").unwrap();
    let second = balancer.select(&second_request, None).unwrap();
    assert_eq!(first.backend.addr, second.backend.addr);
    assert_eq!(
        second.persistence_outcome,
        Some(LoadBalancerPersistenceOutcome::Hit)
    );

    let missing_header = balancer.select(&request(), None).unwrap();
    assert_eq!(missing_header.persistence_outcome, None);

    let stats = balancer.runtime_stats();
    assert!(stats.persistence_enabled);
    assert_eq!(stats.persistence.mode, LoadBalancePersistenceMode::Header);
    assert_eq!(stats.persistence.header.as_deref(), Some("x-session"));
    assert_eq!(stats.persistence.entry_count, 1);
    assert_eq!(
        stats
            .backends
            .iter()
            .map(|backend| backend.persistence_entry_count)
            .sum::<usize>(),
        1
    );

    assert_eq!(balancer.clear_persistence(), 1);
    assert_eq!(balancer.runtime_stats().persistence.entry_count, 0);
}

#[test]
fn cookie_persistence_reuses_selected_backend() {
    install_test_crypto_provider();
    let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
        upstreams: vec![
            "127.0.0.1:3000".to_owned(),
            "127.0.0.1:3001".to_owned(),
            "127.0.0.1:3002".to_owned(),
        ],
        load_balance: LoadBalanceConfig {
            max_iterations: 8,
            persistence: LoadBalancePersistenceConfig {
                enabled: true,
                mode: LoadBalancePersistenceMode::Cookie,
                cookie: Some("sid".to_owned()),
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

    let mut first_request = request();
    first_request
        .insert_header("cookie", "theme=dark; sid=abc")
        .unwrap();
    let first = balancer.select(&first_request, None).unwrap();
    assert_eq!(
        first.persistence_outcome,
        Some(LoadBalancerPersistenceOutcome::Miss)
    );

    let mut second_request = request();
    second_request.insert_header("cookie", "sid=abc").unwrap();
    let second = balancer.select(&second_request, None).unwrap();
    assert_eq!(first.backend.addr, second.backend.addr);
    assert_eq!(
        second.persistence_outcome,
        Some(LoadBalancerPersistenceOutcome::Hit)
    );

    let missing_cookie = balancer.select(&request(), None).unwrap();
    assert_eq!(missing_cookie.persistence_outcome, None);

    let stats = balancer.runtime_stats();
    assert!(stats.persistence_enabled);
    assert_eq!(stats.persistence.mode, LoadBalancePersistenceMode::Cookie);
    assert_eq!(stats.persistence.cookie.as_deref(), Some("sid"));
    assert_eq!(stats.persistence.entry_count, 1);
    assert_eq!(
        stats
            .backends
            .iter()
            .map(|backend| backend.persistence_entry_count)
            .sum::<usize>(),
        1
    );
}

#[test]
fn source_ip_persistence_falls_back_when_stored_backend_is_unavailable() {
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

    let first = balancer
        .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20))))
        .unwrap();
    assert_eq!(first.backend.addr.to_string(), "127.0.0.1:3000");
    first.reporter().unwrap().record_failure();
    drop(first);

    let fallback = balancer
        .select(&request(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20))))
        .unwrap();
    assert_eq!(fallback.backend.addr.to_string(), "127.0.0.1:3001");
    assert_eq!(
        fallback.persistence_outcome(),
        Some(LoadBalancerPersistenceOutcome::Fallback)
    );
}
