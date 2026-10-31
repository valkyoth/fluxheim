use crate::Config;
use crate::config_udp::UdpRouteMode;

fn recipe() -> Config {
    toml::from_str(include_str!("../../../examples/udp/local.toml")).unwrap()
}

#[cfg(feature = "udp-proxy")]
#[test]
fn udp_guide_modes_validate_with_no_http_listener() {
    let mut config = recipe();
    config.udp.validate().unwrap();
    assert!(config.server.listen.is_empty());
    config.udp.routes[0].mode = UdpRouteMode::SyslogForward;
    config.udp.validate().unwrap();
    let syslog: Config = toml::from_str(include_str!("../../../examples/udp/syslog.toml")).unwrap();
    syslog.udp.validate().unwrap();
}

#[cfg(not(feature = "udp-proxy"))]
#[test]
fn udp_guide_is_rejected_without_beta_feature() {
    assert!(matches!(
        recipe().udp.validate(),
        Err(crate::ConfigError::UdpProxyNotCompiled)
    ));
}

#[test]
fn udp_guide_rejects_reserved_modes_and_out_of_range_options() {
    let route = recipe().udp.routes.remove(0);
    for mode in [UdpRouteMode::QuicPassThrough, UdpRouteMode::GameProxy] {
        let mut invalid = route.clone();
        invalid.mode = mode;
        assert!(invalid.validate().is_err());
    }
    for (field, value) in [
        ("idle_timeout_secs", 0),
        ("idle_timeout_secs", 86401),
        ("response_timeout_secs", 0),
        ("response_timeout_secs", 31),
        ("max_datagram_bytes", 0),
        ("max_datagram_bytes", 65508),
        ("max_sessions", 1000001),
        ("max_sessions_per_source", 1000001),
        ("max_responses_per_source_per_second", 1000001),
        ("passive_health_failures", 0),
        ("passive_health_failures", 1001),
        ("passive_health_ejection_secs", 0),
        ("passive_health_ejection_secs", 86401),
    ] {
        let mut config: toml::Value =
            toml::from_str(include_str!("../../../examples/udp/local.toml")).unwrap();
        config["udp"]["routes"][0][field] = toml::Value::Integer(value);
        let decoded: Config = config.try_into().unwrap();
        assert!(decoded.udp.routes[0].validate().is_err(), "{field}={value}");
    }
}

#[test]
fn udp_aliases_follow_shared_64_byte_rule_not_error_message() {
    let mut route = recipe().udp.routes.remove(0);
    route.upstream = None;
    route.upstreams = vec!["127.0.0.1:19053".into()];
    route.upstream_aliases = vec!["a".repeat(64)];
    route.validate().unwrap();
    for alias in ["a".repeat(65), "dns:primary".into()] {
        route.upstream_aliases = vec![alias];
        assert!(route.validate().is_err());
    }
}
