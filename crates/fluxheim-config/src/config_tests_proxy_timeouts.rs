use super::*;

#[test]
fn rejects_zero_proxy_timeouts() {
    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            read_timeout_secs = 0
            downstream_min_send_rate_bytes_per_sec = 1
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProxyTimeout {
            field: "proxy.read_timeout_secs"
        })
    );

    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            downstream_read_timeout_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProxyTimeout {
            field: "proxy.downstream_read_timeout_secs"
        })
    );

    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            downstream_write_timeout_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProxyTimeout {
            field: "proxy.downstream_write_timeout_secs"
        })
    );

    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            downstream_total_response_timeout_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProxyTimeout {
            field: "proxy.downstream_total_response_timeout_secs"
        })
    );

    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            downstream_min_send_rate_bytes_per_sec = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProxyTimeout {
            field: "proxy.downstream_min_send_rate_bytes_per_sec"
        })
    );
}

#[test]
fn rejects_unbounded_proxy_timeouts() {
    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            read_timeout_secs = 86401
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProxyTimeout {
            field: "proxy.read_timeout_secs"
        })
    );

    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3000"

            [proxy.auth_request]
            enabled = true
            url = "http://127.0.0.1:3001/auth"
            read_timeout_secs = 86401
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProxyTimeout {
            field: "proxy.auth_request.read_timeout_secs"
        })
    );
}

#[test]
fn parses_proxy_downstream_timeout_defaults_from_toml() {
    let config: Config = toml::from_str(
        r#"
            [server]
            listen = ["127.0.0.1:18080"]

            [proxy]
            upstream = "origin.example.test:8080"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.proxy.downstream_write_timeout_secs,
        Some(DEFAULT_PROXY_DOWNSTREAM_WRITE_TIMEOUT_SECS)
    );
    assert_eq!(
        config.proxy.downstream_total_response_timeout_secs,
        Some(DEFAULT_PROXY_DOWNSTREAM_TOTAL_RESPONSE_TIMEOUT_SECS)
    );
}
