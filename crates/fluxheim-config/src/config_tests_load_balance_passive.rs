use super::super::*;

#[test]
fn validates_load_balance_passive_health() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance.passive_health]
            enabled = true
            consecutive_failure = 2
            ejection_secs = 10
            min_healthy_backends = 2
            failure_statuses = [500, 502, 503]
            failure_status_ranges = [{ start = 520, end = 529 }]
            max_latency_ms = 250
            "#,
    )
    .unwrap();
    config.validate().unwrap();
    assert_eq!(
        config
            .proxy
            .load_balance
            .passive_health
            .min_healthy_backends,
        2
    );
    assert_eq!(config.proxy.load_balance.passive_health.max_latency_ms, 250);
    assert_eq!(
        config
            .proxy
            .load_balance
            .passive_health
            .failure_status_ranges[0]
            .start,
        520
    );

    let invalid_status: Config = toml::from_str(
        r#"
            [proxy.load_balance.passive_health]
            enabled = true
            failure_statuses = [404]
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_status.validate(),
        Err(ConfigError::InvalidLoadBalancePassiveHealth {
            field: "proxy.load_balance.passive_health.failure_statuses"
        })
    );

    let invalid_status_range: Config = toml::from_str(
        r#"
            [proxy.load_balance.passive_health]
            enabled = true
            failure_status_ranges = [{ start = 499, end = 503 }]
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_status_range.validate(),
        Err(ConfigError::InvalidLoadBalancePassiveHealth {
            field: "proxy.load_balance.passive_health.failure_status_ranges"
        })
    );

    let invalid_latency: Config = toml::from_str(
        r#"
            [proxy.load_balance.passive_health]
            max_latency_ms = 600001
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_latency.validate(),
        Err(ConfigError::InvalidLoadBalancePassiveHealth {
            field: "proxy.load_balance.passive_health.max_latency_ms"
        })
    );

    let invalid_floor: Config = toml::from_str(
        r#"
            [proxy.load_balance.passive_health]
            min_healthy_backends = 4097
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_floor.validate(),
        Err(ConfigError::InvalidLoadBalancePassiveHealth {
            field: "proxy.load_balance.passive_health.min_healthy_backends"
        })
    );
}

#[test]
fn rejects_invalid_load_balance_slow_start() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance.slow_start]
            enabled = true
            duration_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidLoadBalanceSlowStart {
            field: "proxy.load_balance.slow_start.duration_secs"
        })
    );
}
