use super::super::*;

#[test]
fn rejects_invalid_proxy_upstream_tls_material_policy() {
    let without_tls: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            upstream_ca_path = "tests/fixtures/tls/localhost-cert.pem"
            "#,
    )
    .unwrap();
    assert_eq!(
        without_tls.validate(),
        Err(ConfigError::InvalidProxyTlsPolicy {
            reason: "upstream TLS trust roots or client certificates require upstream_tls = true"
        })
    );

    let incomplete_mtls: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            upstream_tls = true
            upstream_sni = "origin.example.test"
            upstream_client_cert_path = "tests/fixtures/tls/localhost-cert.pem"
            "#,
    )
    .unwrap();
    assert_eq!(
        incomplete_mtls.validate(),
        Err(ConfigError::InvalidProxyTlsPolicy {
            reason: "upstream_client_cert_path and upstream_client_key_path must be configured together"
        })
    );
}

#[test]
fn rejects_invalid_proxy_upstream_policy() {
    let auth_request: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"

            [proxy.auth_request]
            enabled = true
            url = "http://127.0.0.1:4180/auth"
            forward_headers = ["authorization", "cookie"]
            allow_response_headers = ["x-auth-request-user"]
            "#,
    )
    .unwrap();
    assert!(auth_request.validate().is_ok());
    assert!(auth_request.proxy.auth_request.enabled);

    let auth_request_without_url: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"

            [proxy.auth_request]
            enabled = true
            "#,
    )
    .unwrap();
    assert_eq!(
        auth_request_without_url.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.auth_request",
            reason: "enabled auth_request requires url",
        })
    );

    let mirror_without_url: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"

            [proxy.mirror]
            enabled = true
            "#,
    )
    .unwrap();
    #[cfg(feature = "traffic-mirror")]
    assert_eq!(
        mirror_without_url.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.mirror",
            reason: "enabled traffic mirroring requires base_url",
        })
    );
    #[cfg(not(feature = "traffic-mirror"))]
    assert_eq!(
        mirror_without_url.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.mirror",
            reason: "traffic mirroring requires building Fluxheim with the traffic-mirror feature",
        })
    );

    #[cfg(feature = "traffic-mirror")]
    {
        let mirror: Config = toml::from_str(
            r#"
                [proxy]
                upstream = "127.0.0.1:3001"

                [proxy.mirror]
                enabled = true
                base_url = "http://127.0.0.1:9000"
                sample_per_mille = 250
                methods = ["GET", "HEAD"]
                forward_headers = ["user-agent"]
                max_in_flight = 8
                "#,
        )
        .unwrap();
        assert!(mirror.validate().is_ok());
        assert!(mirror.proxy.mirror.enabled);
        assert_eq!(mirror.proxy.mirror.max_in_flight, 8);
    }

    let websocket: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            websocket = true
            "#,
    )
    .unwrap();
    assert!(websocket.validate().is_ok());
    assert!(websocket.proxy.websocket);

    let websocket_with_h2: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            websocket = true
            upstream_http_version = "http2"
            "#,
    )
    .unwrap();
    assert_eq!(
        websocket_with_h2.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.websocket",
            reason: "HTTP/1.1 upgrade proxying requires upstream_http_version = \"http1\"",
        })
    );

    let unknown_backup: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            backup_upstreams = ["127.0.0.1:3999"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        unknown_backup.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let overlapping_policy: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            backup_upstreams = ["127.0.0.1:3002"]
            drain_upstreams = ["127.0.0.1:3002"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        overlapping_policy.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let disabled_overlap: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            drain_upstreams = ["127.0.0.1:3002"]
            disabled_upstreams = ["127.0.0.1:3002"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        disabled_overlap.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let no_primary: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002", "127.0.0.1:3003"]
            backup_upstreams = ["127.0.0.1:3001"]
            drain_upstreams = ["127.0.0.1:3002"]
            disabled_upstreams = ["127.0.0.1:3003"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        no_primary.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let h2_options_without_h2: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_h2_max_streams = 64
            "#,
    )
    .unwrap();
    assert!(matches!(
        h2_options_without_h2.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let plaintext_h2c_upgrade: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_http_version = "http1-and-http2"
            upstream_h2c_upgrade = true
            "#,
    )
    .unwrap();
    plaintext_h2c_upgrade.validate().unwrap();

    let h2c_upgrade_for_pure_h2: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_http_version = "http2"
            upstream_h2c_upgrade = true
            "#,
    )
    .unwrap();
    assert!(matches!(
        h2c_upgrade_for_pure_h2.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let h2c_upgrade_for_tls: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_tls = true
            upstream_sni = "origin.example.test"
            upstream_http_version = "http1-and-http2"
            upstream_h2c_upgrade = true
            "#,
    )
    .unwrap();
    assert!(matches!(
        h2c_upgrade_for_tls.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let too_many_h2_streams: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_http_version = "http2"
            upstream_h2_max_streams = 1025
            "#,
    )
    .unwrap();
    assert!(matches!(
        too_many_h2_streams.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let zero_h2_ping_interval: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_http_version = "http2"
            upstream_h2_ping_interval_secs = 0
            "#,
    )
    .unwrap();
    assert!(matches!(
        zero_h2_ping_interval.validate(),
        Err(ConfigError::InvalidProxyTimeout { .. })
    ));

    let zero_upstream_total_connection_timeout: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_total_connection_timeout_secs = 0
            "#,
    )
    .unwrap();
    assert!(matches!(
        zero_upstream_total_connection_timeout.validate(),
        Err(ConfigError::InvalidProxyTimeout { .. })
    ));

    let zero_upstream_idle_timeout: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_idle_timeout_secs = 0
            "#,
    )
    .unwrap();
    assert!(matches!(
        zero_upstream_idle_timeout.validate(),
        Err(ConfigError::InvalidProxyTimeout { .. })
    ));

    let incomplete_tcp_keepalive: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_tcp_keepalive_idle_secs = 30
            upstream_tcp_keepalive_count = 3
            "#,
    )
    .unwrap();
    assert!(matches!(
        incomplete_tcp_keepalive.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let invalid_tcp_keepalive_count: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_tcp_keepalive_idle_secs = 30
            upstream_tcp_keepalive_interval_secs = 10
            upstream_tcp_keepalive_count = 0
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_tcp_keepalive_count.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let invalid_tcp_recv_buffer: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_tcp_recv_buffer_bytes = "512MiB"
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_tcp_recv_buffer.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let invalid_dscp: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_dscp = 64
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_dscp.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));
}
