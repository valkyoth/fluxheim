use crate::config::ConfigError;
use crate::config_udp::{
    MAX_UDP_DATAGRAM_BYTES, MAX_UDP_MAX_RESPONSES_PER_SOURCE_PER_SECOND,
    MAX_UDP_MAX_SESSIONS_PER_SOURCE, UdpConfig, UdpRouteConfig, UdpRouteMode,
};

fn route() -> UdpRouteConfig {
    UdpRouteConfig {
        name: "dns-edge".to_owned(),
        mode: UdpRouteMode::DnsLoadBalance,
        listen: vec!["127.0.0.1:5353".to_owned()],
        upstream: None,
        upstreams: vec!["192.0.2.10:53".to_owned(), "192.0.2.11:53".to_owned()],
        upstream_weights: vec![1, 2],
        upstream_aliases: vec!["dns-a".to_owned(), "dns-b".to_owned()],
        idle_timeout_secs: 30,
        response_timeout_secs: 3,
        max_datagram_bytes: 1232,
        max_sessions: 4096,
        max_sessions_per_source: 64,
        max_responses_per_source_per_second: 256,
        passive_health_enabled: true,
        passive_health_failures: 3,
        passive_health_ejection_secs: 10,
    }
}

#[test]
fn disabled_udp_config_accepts_no_routes() {
    UdpConfig::default().validate().unwrap();
}

#[test]
fn disabled_udp_config_rejects_routes() {
    let config = UdpConfig {
        enabled: false,
        routes: vec![route()],
    };
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidUdpProxyPolicy { field, .. }) if field == "udp.routes"
    ));
}

#[cfg(not(feature = "udp-proxy"))]
#[test]
fn enabled_udp_config_rejects_when_not_compiled() {
    let config = UdpConfig {
        enabled: true,
        routes: vec![route()],
    };
    assert_eq!(config.validate(), Err(ConfigError::UdpProxyNotCompiled));
}

#[test]
fn udp_route_rejects_oversized_datagrams() {
    let mut route = route();
    route.max_datagram_bytes = MAX_UDP_DATAGRAM_BYTES + 1;
    assert!(matches!(
        route.validate(),
        Err(ConfigError::InvalidUdpProxyPolicy {
            field: "udp.routes.max_datagram_bytes",
            ..
        })
    ));
}

#[test]
fn udp_route_rejects_oversized_source_limits() {
    let mut config = route();
    config.max_sessions_per_source = MAX_UDP_MAX_SESSIONS_PER_SOURCE + 1;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidUdpProxyPolicy {
            field: "udp.routes.max_sessions_per_source",
            ..
        })
    ));

    let mut config = route();
    config.max_responses_per_source_per_second = MAX_UDP_MAX_RESPONSES_PER_SOURCE_PER_SECOND + 1;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidUdpProxyPolicy {
            field: "udp.routes.max_responses_per_source_per_second",
            ..
        })
    ));
}

#[test]
fn udp_route_rejects_invalid_passive_health_policy() {
    let mut config = route();
    config.passive_health_failures = 0;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidUdpProxyPolicy {
            field: "udp.routes.passive_health_failures",
            ..
        })
    ));

    let mut config = route();
    config.passive_health_ejection_secs = 0;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidProxyTimeout { field })
            if field == "udp.routes.passive_health_ejection_secs"
    ));

    let mut config = route();
    config.passive_health_enabled = false;
    config.passive_health_failures = 0;
    config.passive_health_ejection_secs = 0;
    config.validate().unwrap();
}

#[test]
fn udp_route_rejects_response_timeout_above_idle_timeout() {
    let mut route = route();
    route.idle_timeout_secs = 2;
    route.response_timeout_secs = 3;
    assert!(matches!(
        route.validate(),
        Err(ConfigError::InvalidUdpProxyPolicy {
            field: "udp.routes.response_timeout_secs",
            ..
        })
    ));
}

#[test]
fn udp_route_rejects_duplicate_upstreams() {
    let mut route = route();
    route.upstreams = vec!["192.0.2.10:53".to_owned(), "192.0.2.10:53".to_owned()];
    route.upstream_weights.clear();
    route.upstream_aliases.clear();
    assert!(matches!(
        route.validate(),
        Err(ConfigError::DuplicateUdpUpstream { .. })
    ));
}

#[test]
fn udp_route_rejects_reserved_session_modes() {
    let mut route = route();
    route.mode = UdpRouteMode::QuicPassThrough;
    assert!(matches!(
        route.validate(),
        Err(ConfigError::InvalidUdpProxyPolicy {
            field: "udp.routes.mode",
            ..
        })
    ));
}

#[cfg(feature = "udp-proxy")]
#[test]
fn udp_enabled_allows_empty_http_listeners() {
    let mut config = crate::config::Config::default();
    config.server.listen.clear();
    config.server.tls_listen.clear();
    config.udp = UdpConfig {
        enabled: true,
        routes: vec![route()],
    };

    config.validate().unwrap();
}
