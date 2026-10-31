//! Characterizations of beta boundaries, not acceptance of unresolved findings.
use super::{UdpProxyApp, udp_log_millis};
use crate::config::Config;
use std::sync::atomic::Ordering;

fn recipe() -> crate::config::UdpRouteConfig {
    let config: Config = toml::from_str(include_str!("../../examples/udp/local.toml")).unwrap();
    config.udp.routes.into_iter().next().unwrap()
}

#[test]
fn idle_setting_does_not_change_runtime_response_budget() {
    let mut route = recipe();
    route.idle_timeout_secs = 1;
    route.validate().unwrap();
    let short = UdpProxyApp::from_config(&route).unwrap();
    route.idle_timeout_secs = 86_400;
    route.validate().unwrap();
    let long = UdpProxyApp::from_config(&route).unwrap();
    // documented contract: idle_timeout_secs is never stored in the runtime app.
    assert_eq!(short.response_timeout(), long.response_timeout());
    assert_eq!(long.response_timeout().as_secs(), 1);
}

#[test]
fn unlimited_route_loses_active_count_while_source_slot_is_held() {
    let mut route = recipe();
    route.max_sessions = 0;
    let app = UdpProxyApp::from_config(&route).unwrap();
    let source = "127.0.0.1".parse().unwrap();
    let slot = app.acquire_session_slot(source).unwrap();
    assert_eq!(app.lock_source_sessions().get(&source), Some(&1));
    // documented contract: the metric samples this zero despite active work.
    assert_eq!(app.active_sessions.load(Ordering::Acquire), 0);
    drop(slot);
    assert!(app.lock_source_sessions().is_empty());
}

#[test]
fn all_ejected_members_still_select_the_weighted_candidate() {
    let mut route = recipe();
    route.upstream = None;
    route.upstreams = vec!["127.0.0.1:19053".into(), "127.0.0.1:19054".into()];
    route.upstream_weights = vec![2, 1];
    route.validate().unwrap();
    let app = UdpProxyApp::from_config(&route).unwrap();
    for upstream in app.upstreams.iter() {
        upstream
            .ejected_until_millis
            .store(udp_log_millis() + 10_000, Ordering::Release);
    }
    for expected in ["127.0.0.1:19053", "127.0.0.1:19053", "127.0.0.1:19054"] {
        assert_eq!(app.select_upstream().authority, expected);
    }
}
