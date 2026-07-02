use super::super::*;

#[test]
fn rejects_invalid_load_balance_max_iterations() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            max_iterations = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidLoadBalanceMaxIterations)
    );
}

#[test]
fn validates_load_balance_runtime_state_file_path() {
    let root = secure_test_dir("config-lb-runtime-state");
    fs::create_dir_all(safe_child_path(&root, "state")).unwrap();
    let config_path = safe_child_path(&root, "fluxheim.toml");
    fs::write(
        &config_path,
        r#"
            [proxy.load_balance]
            runtime_state_file = "state/lb.json"
            "#,
    )
    .unwrap();

    let config = Config::load_without_runtime_paths(Some(&config_path)).unwrap();
    let expected = root.join("state/lb.json");
    assert_eq!(
        config.proxy.load_balance.runtime_state_file.as_deref(),
        Some(expected.as_path())
    );

    #[cfg(unix)]
    {
        let path = unique_world_writable_child("config-lb-runtime-world-writable", "lb.json");
        let config: Config = toml::from_str(&format!(
            r#"
                [proxy.load_balance]
                runtime_state_file = "{}"
                "#,
            path.display()
        ))
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsafePath { field, .. })
                if field == "proxy.load_balance.runtime_state_file"
        ));
    }
}

#[test]
fn validates_load_balance_hash_selection() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "consistent-header-hash"
            hash_header = "x-session"
            "#,
    )
    .unwrap();
    config.validate().unwrap();

    let missing_header: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "header-hash"
            "#,
    )
    .unwrap();
    assert!(matches!(
        missing_header.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));

    let unused_header: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "source-hash"
            hash_header = "x-session"
            "#,
    )
    .unwrap();
    assert!(matches!(
        unused_header.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));

    let cookie: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "cookie-hash"
            hash_cookie = "session"
            "#,
    )
    .unwrap();
    cookie.validate().unwrap();

    let missing_cookie: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "consistent-cookie-hash"
            "#,
    )
    .unwrap();
    assert!(matches!(
        missing_cookie.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));

    let power_of_two: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "power-of-two"
            "#,
    )
    .unwrap();
    power_of_two.validate().unwrap();

    let power_of_two_alias: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "power-of-two-choices"
            "#,
    )
    .unwrap();
    assert_eq!(
        power_of_two_alias.proxy.load_balance.selection,
        LoadBalanceSelection::PowerOfTwo
    );
    power_of_two_alias.validate().unwrap();

    let weighted_least_connections: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "weighted-least-connections"
            "#,
    )
    .unwrap();
    weighted_least_connections.validate().unwrap();

    let ratio_least_connections: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "ratio-least-connections"
            "#,
    )
    .unwrap();
    ratio_least_connections.validate().unwrap();

    let least_time: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "least-time"
            "#,
    )
    .unwrap();
    least_time.validate().unwrap();

    let bounded_load_consistent_uri: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "bounded-load-consistent-uri-hash"
            bounded_load_factor_per_mille = 1500
            "#,
    )
    .unwrap();
    assert_eq!(
        bounded_load_consistent_uri.proxy.load_balance.selection,
        LoadBalanceSelection::BoundedLoadConsistentUriHash
    );
    bounded_load_consistent_uri.validate().unwrap();

    let bounded_load_consistent_header: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "bounded-load-consistent-header-hash"
            hash_header = "x-session"
            "#,
    )
    .unwrap();
    bounded_load_consistent_header.validate().unwrap();

    let invalid_bounded_load_factor: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "round-robin"
            bounded_load_factor_per_mille = 1500
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_bounded_load_factor.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));

    let maglev_alias: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "maglev"
            "#,
    )
    .unwrap();
    assert_eq!(
        maglev_alias.proxy.load_balance.selection,
        LoadBalanceSelection::MaglevSourceHash
    );
    maglev_alias.validate().unwrap();

    let maglev_uri: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "maglev-uri-hash"
            "#,
    )
    .unwrap();
    assert_eq!(
        maglev_uri.proxy.load_balance.selection,
        LoadBalanceSelection::MaglevUriHash
    );
    maglev_uri.validate().unwrap();

    let maglev_header: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "maglev-header-hash"
            hash_header = "x-session"
            "#,
    )
    .unwrap();
    maglev_header.validate().unwrap();

    let nginx_consistent_alias: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "ketama"
            "#,
    )
    .unwrap();
    assert_eq!(
        nginx_consistent_alias.proxy.load_balance.selection,
        LoadBalanceSelection::NginxConsistentSourceHash
    );
    nginx_consistent_alias.validate().unwrap();

    let nginx_consistent_uri: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "nginx-consistent-uri-hash"
            "#,
    )
    .unwrap();
    assert_eq!(
        nginx_consistent_uri.proxy.load_balance.selection,
        LoadBalanceSelection::NginxConsistentUriHash
    );
    nginx_consistent_uri.validate().unwrap();

    let nginx_consistent_header: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "ketama-header-hash"
            hash_header = "x-session"
            "#,
    )
    .unwrap();
    assert_eq!(
        nginx_consistent_header.proxy.load_balance.selection,
        LoadBalanceSelection::NginxConsistentHeaderHash
    );
    nginx_consistent_header.validate().unwrap();

    let least_sessions: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "least-sessions"

            [proxy.load_balance.persistence]
            enabled = true
            "#,
    )
    .unwrap();
    #[cfg(not(feature = "privacy-mode"))]
    least_sessions.validate().unwrap();
    #[cfg(feature = "privacy-mode")]
    assert_eq!(
        least_sessions.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence is not available in privacy-mode builds"
        })
    );

    let least_sessions_without_persistence: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "least-sessions"
            "#,
    )
    .unwrap();
    assert!(matches!(
        least_sessions_without_persistence.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));
}

#[test]
fn rejects_static_ring_selection_for_dynamic_upstream_discovery() {
    let root = crate::test_support::unique_temp_path("static-ring-dynamic");
    fs::create_dir_all(&root).unwrap();
    let upstreams_file = root.join("upstreams.txt");
    fs::write(&upstreams_file, "127.0.0.1:3001\n127.0.0.1:3002\n").unwrap();

    let file_config: Config = toml::from_str(&format!(
        r#"
            [proxy]
            upstreams_file = "{}"

            [proxy.load_balance]
            selection = "nginx-consistent-uri-hash"
            "#,
        upstreams_file.display()
    ))
    .unwrap();
    let file_error = file_config.validate().expect_err("file static-ring config");
    #[cfg(feature = "load-balancer")]
    assert!(matches!(
        file_error,
        ConfigError::InvalidLoadBalanceSelection { .. }
    ));
    #[cfg(not(feature = "load-balancer"))]
    assert!(matches!(
        file_error,
        ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstreams_file",
            ..
        }
    ));

    let dns_config: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["localhost:3001", "localhost:3002"]
            upstream_dns_refresh_secs = 5

            [proxy.load_balance]
            selection = "maglev-uri-hash"
            "#,
    )
    .unwrap();
    let dns_error = dns_config.validate().expect_err("DNS static-ring config");
    #[cfg(feature = "load-balancer")]
    assert!(matches!(
        dns_error,
        ConfigError::InvalidLoadBalanceSelection { .. }
    ));
    #[cfg(not(feature = "load-balancer"))]
    assert!(matches!(
        dns_error,
        ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_dns_refresh_secs",
            ..
        }
    ));
}

#[test]
fn rejects_invalid_load_balance_all_down_status() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            all_down_status = 404
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));
}

#[test]
fn rejects_invalid_load_balance_queue_policy() {
    let waiting_without_timeout: Config = toml::from_str(
        r#"
            [proxy.load_balance.queue]
            max_waiting = 10
            "#,
    )
    .unwrap();
    assert!(matches!(
        waiting_without_timeout.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));

    let timeout_without_waiting: Config = toml::from_str(
        r#"
            [proxy.load_balance.queue]
            timeout_ms = 100
            "#,
    )
    .unwrap();
    assert!(matches!(
        timeout_without_waiting.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));

    let invalid_retry_interval: Config = toml::from_str(
        r#"
            [proxy.load_balance.queue]
            max_waiting = 10
            timeout_ms = 100
            retry_interval_ms = 0
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_retry_interval.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));
}
