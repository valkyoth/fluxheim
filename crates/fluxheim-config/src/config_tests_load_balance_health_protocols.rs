use super::super::*;

#[test]
fn rejects_invalid_exec_load_balance_health_check() {
    let mut exec_without_allowlist = valid_exec_health_check_config();
    exec_without_allowlist
        .proxy
        .load_balance
        .health_check
        .exec_allowed_commands
        .clear();
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

    #[cfg(unix)]
    let parent_command = "/usr/local/../libexec/fluxheim-health";
    #[cfg(windows)]
    let parent_command = r"C:\fluxheim\..\libexec\fluxheim-health.exe";
    let mut exec_parent_component_command = valid_exec_health_check_config();
    exec_parent_component_command
        .proxy
        .load_balance
        .health_check
        .exec_command = Some(parent_command.to_owned());
    exec_parent_component_command
        .proxy
        .load_balance
        .health_check
        .exec_allowed_commands = vec![parent_command.to_owned()];
    assert_eq!(
        exec_parent_component_command.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.exec_command"
        })
    );

    #[cfg(unix)]
    let current_component_command = "/usr/local/libexec/./fluxheim-health";
    #[cfg(windows)]
    let current_component_command = r"C:\fluxheim\libexec\.\fluxheim-health.exe";
    let mut exec_current_component_allowlist = valid_exec_health_check_config();
    exec_current_component_allowlist
        .proxy
        .load_balance
        .health_check
        .exec_allowed_commands = vec![current_component_command.to_owned()];
    assert_eq!(
        exec_current_component_allowlist.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.exec_allowed_commands"
        })
    );

    let mut exec_not_allowed = valid_exec_health_check_config();
    let other_command = std::env::current_exe()
        .unwrap()
        .with_file_name("other-health-check")
        .display()
        .to_string();
    exec_not_allowed
        .proxy
        .load_balance
        .health_check
        .exec_allowed_commands = vec![other_command];
    assert_eq!(
        exec_not_allowed.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.exec_allowed_commands"
        })
    );

    let mut exec_with_http_matcher = valid_exec_health_check_config();
    exec_with_http_matcher
        .proxy
        .load_balance
        .health_check
        .expected_statuses = vec![200];
    assert_eq!(
        exec_with_http_matcher.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.protocol"
        })
    );

    let mut exec_parallel = valid_exec_health_check_config();
    exec_parallel.proxy.load_balance.health_check.parallel = true;
    assert_eq!(
        exec_parallel.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.parallel"
        })
    );

    let mut exec_with_network_field = valid_exec_health_check_config();
    exec_with_network_field.proxy.load_balance.health_check.host = Some("app.internal".to_owned());
    assert_eq!(
        exec_with_network_field.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.host"
        })
    );

    let mut exec_with_connect_timeout = valid_exec_health_check_config();
    exec_with_connect_timeout
        .proxy
        .load_balance
        .health_check
        .connect_timeout_secs = Some(1);
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
