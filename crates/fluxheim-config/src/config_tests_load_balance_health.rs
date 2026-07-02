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

    let exec_without_allowlist: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "exec"
            exec_command = "/usr/local/libexec/fluxheim-health"
            "#,
    )
    .unwrap();
    assert_eq!(
        exec_without_allowlist.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.exec_allowed_commands"
        })
    );

    let exec_relative_command: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "exec"
            exec_command = "health-check"
            exec_allowed_commands = ["health-check"]
            "#,
    )
    .unwrap();
    assert_eq!(
        exec_relative_command.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.exec_command"
        })
    );

    let exec_parent_component_command: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "exec"
            exec_command = "/usr/local/../libexec/fluxheim-health"
            exec_allowed_commands = ["/usr/local/../libexec/fluxheim-health"]
            "#,
    )
    .unwrap();
    assert_eq!(
        exec_parent_component_command.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.exec_command"
        })
    );

    let exec_current_component_allowlist: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "exec"
            exec_command = "/usr/local/libexec/fluxheim-health"
            exec_allowed_commands = ["/usr/local/libexec/./fluxheim-health"]
            "#,
    )
    .unwrap();
    assert_eq!(
        exec_current_component_allowlist.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.exec_allowed_commands"
        })
    );

    let exec_not_allowed: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "exec"
            exec_command = "/usr/local/libexec/fluxheim-health"
            exec_allowed_commands = ["/usr/local/libexec/other-health"]
            "#,
    )
    .unwrap();
    assert_eq!(
        exec_not_allowed.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.exec_allowed_commands"
        })
    );

    let exec_with_http_matcher: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "exec"
            exec_command = "/usr/local/libexec/fluxheim-health"
            exec_allowed_commands = ["/usr/local/libexec/fluxheim-health"]
            expected_statuses = [200]
            "#,
    )
    .unwrap();
    assert_eq!(
        exec_with_http_matcher.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.protocol"
        })
    );

    let exec_parallel: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "exec"
            exec_command = "/usr/local/libexec/fluxheim-health"
            exec_allowed_commands = ["/usr/local/libexec/fluxheim-health"]
            parallel = true
            "#,
    )
    .unwrap();
    assert_eq!(
        exec_parallel.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.parallel"
        })
    );

    let exec_with_network_field: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "exec"
            exec_command = "/usr/local/libexec/fluxheim-health"
            exec_allowed_commands = ["/usr/local/libexec/fluxheim-health"]
            host = "app.internal"
            "#,
    )
    .unwrap();
    assert_eq!(
        exec_with_network_field.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.host"
        })
    );

    let exec_with_connect_timeout: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "exec"
            exec_command = "/usr/local/libexec/fluxheim-health"
            exec_allowed_commands = ["/usr/local/libexec/fluxheim-health"]
            connect_timeout_secs = 1
            "#,
    )
    .unwrap();
    assert_eq!(
        exec_with_connect_timeout.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.connect_timeout_secs"
        })
    );

    let redis_with_http_matcher: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "redis"
            expected_statuses = [200]
            "#,
    )
    .unwrap();
    assert_eq!(
        redis_with_http_matcher.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.protocol"
        })
    );

    let redis_parallel: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "redis"
            parallel = true
            "#,
    )
    .unwrap();
    assert_eq!(
        redis_parallel.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.parallel"
        })
    );

    let mysql_with_http_matcher: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "mysql"
            expected_statuses = [200]
            "#,
    )
    .unwrap();
    assert_eq!(
        mysql_with_http_matcher.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.protocol"
        })
    );

    let mysql_parallel: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "mysql"
            parallel = true
            "#,
    )
    .unwrap();
    assert_eq!(
        mysql_parallel.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.parallel"
        })
    );

    let postgres_with_http_matcher: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "postgres"
            expected_statuses = [200]
            "#,
    )
    .unwrap();
    assert_eq!(
        postgres_with_http_matcher.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.protocol"
        })
    );

    let postgres_parallel: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "postgres"
            parallel = true
            "#,
    )
    .unwrap();
    assert_eq!(
        postgres_parallel.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.parallel"
        })
    );
}
