use super::super::*;

#[test]
fn rejects_invalid_load_balance_health_check() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            interval_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.interval_secs"
        })
    );

    let invalid_timeout: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            connect_timeout_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        invalid_timeout.validate(),
        Err(ConfigError::InvalidProxyTimeout {
            field: "proxy.load_balance.health_check.connect_timeout_secs"
        })
    );
}

#[test]
fn rejects_invalid_http_load_balance_health_check() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "http"
            path = "relative"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.path"
        })
    );

    let lowercase_method: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "http"
            method = "get"
            "#,
    )
    .unwrap();
    assert_eq!(
        lowercase_method.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.method"
        })
    );

    let request_header_on_tcp: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "tcp"

            [[proxy.load_balance.health_check.request_headers]]
            name = "Authorization"
            value = "Bearer token"
            "#,
    )
    .unwrap();
    assert_eq!(
        request_header_on_tcp.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.request_headers"
        })
    );

    let reserved_request_header: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "http"

            [[proxy.load_balance.health_check.request_headers]]
            name = "Host"
            value = "other.example.test"
            "#,
    )
    .unwrap();
    assert_eq!(
        reserved_request_header.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.request_headers"
        })
    );

    let duplicate_request_header: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "http"

            [[proxy.load_balance.health_check.request_headers]]
            name = "Authorization"
            value = "Bearer token"

            [[proxy.load_balance.health_check.request_headers]]
            name = "authorization"
            value = "Bearer other"
            "#,
    )
    .unwrap();
    assert_eq!(
        duplicate_request_header.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.request_headers"
        })
    );

    let invalid_grpc_service: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "grpc"
            grpc_service = "../bad"
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_grpc_service.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.grpc_service"
        })
    );

    let grpc_with_http_matchers: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "grpc"
            expected_body_contains = ["SERVING"]
            "#,
    )
    .unwrap();
    assert_eq!(
        grpc_with_http_matchers.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.protocol"
        })
    );

    let invalid_json_matcher: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "http"
            expected_body_json = [{ path = "status..nested", equals = "ok" }]
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_json_matcher.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.expected_body_json"
        })
    );

    let invalid_health_weight_floor: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "http"
            health_weight_min_percent = 0
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_health_weight_floor.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.health_weight_min_percent"
        })
    );

    let invalid_expected_header: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "http"

            [[proxy.load_balance.health_check.expected_headers]]
            name = "bad header"
            value = "ready"
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_expected_header.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.expected_headers"
        })
    );

    let duplicate_expected_header: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "http"

            [[proxy.load_balance.health_check.expected_headers]]
            name = "x-health"
            value = "ready"

            [[proxy.load_balance.health_check.expected_headers]]
            name = "X-Health"
            value = "still-ready"
            "#,
    )
    .unwrap();
    assert_eq!(
        duplicate_expected_header.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.expected_headers"
        })
    );

    let invalid_status_range: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "http"

            [[proxy.load_balance.health_check.expected_status_ranges]]
            start = 399
            end = 200
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_status_range.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.expected_status_ranges"
        })
    );

    let invalid_body_substring: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "http"
            expected_body_contains = [""]
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_body_substring.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.expected_body_contains"
        })
    );
}
