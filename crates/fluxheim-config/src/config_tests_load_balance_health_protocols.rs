use super::super::*;

#[test]
fn rejects_invalid_exec_load_balance_health_check() {
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
}

#[test]
fn rejects_http_fields_on_database_load_balance_health_checks() {
    for protocol in ["redis", "mysql", "postgres"] {
        let with_http_matcher: Config = toml::from_str(&format!(
            r#"
            [proxy.load_balance.health_check]
            protocol = "{protocol}"
            expected_statuses = [200]
            "#
        ))
        .unwrap();
        assert_eq!(
            with_http_matcher.validate(),
            Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.protocol"
            })
        );

        let parallel: Config = toml::from_str(&format!(
            r#"
            [proxy.load_balance.health_check]
            protocol = "{protocol}"
            parallel = true
            "#
        ))
        .unwrap();
        assert_eq!(
            parallel.validate(),
            Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.parallel"
            })
        );
    }
}
