use fluxheim_config::{LoadBalancePersistenceMode, LoadBalanceSelection, ProxyConfig};

use super::UpstreamLoadBalancer;
use crate::tests_support::request;

fn config() -> ProxyConfig {
    let mut config = ProxyConfig {
        upstreams: vec![
            "127.0.0.1:3000".into(),
            "127.0.0.1:3001".into(),
            "127.0.0.1:3002".into(),
        ],
        ..ProxyConfig::default()
    };
    config.load_balance.max_iterations = 32;
    config
}

#[test]
fn every_selection_family_excludes_attempted_members_without_disabling_the_pool() {
    for selection in [
        LoadBalanceSelection::RoundRobin,
        LoadBalanceSelection::LeastConnections,
        LoadBalanceSelection::LeastSessions,
        LoadBalanceSelection::LeastTime,
        LoadBalanceSelection::PowerOfTwo,
        LoadBalanceSelection::UriHash,
        LoadBalanceSelection::ConsistentUriHash,
        LoadBalanceSelection::BoundedLoadConsistentUriHash,
        LoadBalanceSelection::NginxConsistentUriHash,
        LoadBalanceSelection::MaglevUriHash,
    ] {
        let mut config = config();
        config.load_balance.selection = selection;
        let pool = UpstreamLoadBalancer::from_proxy_config(&config)
            .unwrap()
            .unwrap();
        let mut attempted = Vec::new();
        for _ in 0..3 {
            let selected = pool
                .select_excluding(&request(), None, &attempted)
                .expect("alternative");
            assert!(!attempted.contains(&selected.address()), "{selection:?}");
            attempted.push(selected.address());
        }
        assert!(
            pool.select_excluding(&request(), None, &attempted)
                .is_none()
        );
        assert!(pool.select(&request(), None).is_some());
        assert!(
            pool.select_excluding(&request(), None, &vec![attempted[0]; 12])
                .is_none()
        );
    }
}

#[test]
fn persisted_failed_backend_does_not_override_retry_exclusion() {
    let mut config = config();
    config.load_balance.persistence.enabled = true;
    config.load_balance.persistence.mode = LoadBalancePersistenceMode::Header;
    config.load_balance.persistence.header = Some("x-session".into());
    let pool = UpstreamLoadBalancer::from_proxy_config(&config)
        .unwrap()
        .unwrap();
    let mut request = request();
    request.insert_header("x-session", "one").unwrap();
    let first = pool.select(&request, None).unwrap().address();
    assert_eq!(pool.select(&request, None).unwrap().address(), first);
    let next = pool
        .select_excluding(&request, None, &[first])
        .unwrap()
        .address();
    assert_ne!(next, first);
    assert_eq!(pool.select(&request, None).unwrap().address(), next);
}

#[test]
fn retry_exclusion_preserves_capacity_and_backup_policy() {
    let mut config = config();
    config.upstream_max_in_flight = vec![1, 1, 1];
    config.backup_upstreams = vec![config.upstreams[2].clone()];
    let pool = UpstreamLoadBalancer::from_proxy_config(&config)
        .unwrap()
        .unwrap();
    let first = pool.select(&request(), None).unwrap();
    let second = pool
        .select_excluding(&request(), None, &[first.address()])
        .unwrap();
    assert_ne!(second.address().port(), 3002);
    let last = pool
        .select_excluding(&request(), None, &[first.address(), second.address()])
        .unwrap();
    assert_eq!(last.address().port(), 3002);
    assert!(pool.select(&request(), None).is_none());
    drop((first, second, last));
    assert!(pool.select(&request(), None).is_some());
    assert_eq!(pool.runtime_stats().queue.waiting, 0);
}
