use super::super::*;

#[test]
fn parses_proxy_upstream_pool() {
    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002", "127.0.0.1:3003"]
            upstream_weights = [1, 3, 1]
            upstream_priority_groups = [100, 50, 10]
            upstream_priority_group_min_active = 2
            upstream_localities = ["site-a", "site-b", "site-a"]
            preferred_upstream_localities = ["site-a"]
            upstream_max_in_flight = [10, 30, 5]
            upstream_aliases = ["app-a", "app-b", "app-c"]
            upstream_tags = [["blue", "primary"], ["blue"], ["canary"]]
            backup_upstreams = ["127.0.0.1:3002"]
            disabled_upstreams = ["127.0.0.1:3003"]
            connect_timeout_secs = 5
            upstream_total_connection_timeout_secs = 10
            upstream_idle_timeout_secs = 120
            upstream_tcp_keepalive_idle_secs = 30
            upstream_tcp_keepalive_interval_secs = 10
            upstream_tcp_keepalive_count = 3
            upstream_tcp_user_timeout_ms = 15000
            upstream_tcp_recv_buffer_bytes = "1MiB"
            upstream_dscp = 46
            upstream_tcp_fast_open = true
            read_timeout_secs = 60
            send_timeout_secs = 30
            upstream_tls = true
            upstream_sni = "origin.example.test"
            upstream_verify_cert = true
            upstream_verify_hostname = true
            upstream_alternative_cn = "fallback-origin.example.test"
            upstream_ca_path = "tests/fixtures/tls/localhost-cert.pem"
            upstream_client_cert_path = "tests/fixtures/tls/localhost-cert.pem"
            upstream_client_key_path = "tests/fixtures/tls/localhost-key.pem"
            upstream_proxy_protocol = "v2"
            upstream_http_version = "http1-and-http2"
            upstream_h2_max_streams = 64
            upstream_h2_ping_interval_secs = 30

            [proxy.load_balance]
            max_iterations = 16
            all_down_status = 503

            [proxy.load_balance.health_check]
            enabled = true
            protocol = "http"
            interval_secs = 2
            consecutive_success = 2
            consecutive_failure = 3
            parallel = true
            method = "HEAD"
            path = "/healthz"
            host = "app.internal"
            expected_statuses = [200, 204]
            expected_body_contains = ["ready"]
            expected_body_json = [
                { path = "status", equals = "ready" },
                { path = "database.connected", equals = "true" },
            ]
            health_weight_min_percent = 30
            reuse_connection = true
            port_override = 8081
            connect_timeout_secs = 1
            read_timeout_secs = 2

            [[proxy.load_balance.health_check.request_headers]]
            name = "Authorization"
            value = "Bearer health-token"

            [[proxy.load_balance.health_check.expected_headers]]
            name = "x-fluxheim-health"
            value = "ready"

            [[proxy.load_balance.health_check.expected_status_ranges]]
            start = 300
            end = 399

            [proxy.load_balance.slow_start]
            enabled = true
            duration_secs = 45

            [proxy.load_balance.persistence]
            enabled = true
            mode = "source-ip"
            ttl_secs = 600
            table_max_entries = 4096

            [proxy.load_balance.queue]
            max_waiting = 32
            timeout_ms = 250
            retry_interval_ms = 5

            [[proxy.error_pages]]
            status = 502
            path = "/502.html"

            [proxy.error_pages.web]
            root = "/srv/fluxheim/errors"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.proxy.upstreams,
        [
            "127.0.0.1:3001".to_owned(),
            "127.0.0.1:3002".to_owned(),
            "127.0.0.1:3003".to_owned()
        ]
    );
    assert_eq!(config.proxy.upstream_weights, [1, 3, 1]);
    assert_eq!(config.proxy.upstream_priority_groups, [100, 50, 10]);
    assert_eq!(config.proxy.upstream_priority_group_min_active, 2);
    assert_eq!(
        config.proxy.upstream_localities,
        ["site-a", "site-b", "site-a"]
    );
    assert_eq!(config.proxy.preferred_upstream_localities, ["site-a"]);
    assert_eq!(config.proxy.upstream_max_in_flight, [10, 30, 5]);
    assert_eq!(config.proxy.upstream_aliases, ["app-a", "app-b", "app-c"]);
    assert_eq!(
        config.proxy.upstream_tags,
        [
            vec!["blue".to_owned(), "primary".to_owned()],
            vec!["blue".to_owned()],
            vec!["canary".to_owned()]
        ]
    );
    assert_eq!(config.proxy.backup_upstreams, ["127.0.0.1:3002"]);
    assert_eq!(config.proxy.disabled_upstreams, ["127.0.0.1:3003"]);
    assert_eq!(config.proxy.connect_timeout_secs, Some(5));
    assert_eq!(
        config.proxy.upstream_total_connection_timeout_secs,
        Some(10)
    );
    assert_eq!(config.proxy.upstream_idle_timeout_secs, Some(120));
    assert_eq!(config.proxy.upstream_tcp_keepalive_idle_secs, Some(30));
    assert_eq!(config.proxy.upstream_tcp_keepalive_interval_secs, Some(10));
    assert_eq!(config.proxy.upstream_tcp_keepalive_count, Some(3));
    assert_eq!(config.proxy.upstream_tcp_user_timeout_ms, Some(15000));
    assert_eq!(
        config
            .proxy
            .upstream_tcp_recv_buffer_bytes
            .map(ByteSize::as_u64),
        Some(1024 * 1024)
    );
    assert_eq!(config.proxy.upstream_dscp, Some(46));
    assert!(config.proxy.upstream_tcp_fast_open);
    assert_eq!(config.proxy.read_timeout_secs, Some(60));
    assert_eq!(config.proxy.send_timeout_secs, Some(30));
    assert!(config.proxy.upstream_tls);
    assert_eq!(
        config.proxy.upstream_sni.as_deref(),
        Some("origin.example.test")
    );
    assert!(config.proxy.upstream_verify_cert);
    assert!(config.proxy.upstream_verify_hostname);
    assert_eq!(
        config.proxy.upstream_alternative_cn.as_deref(),
        Some("fallback-origin.example.test")
    );
    assert_eq!(
        config.proxy.upstream_ca_path.as_deref(),
        Some(Path::new("tests/fixtures/tls/localhost-cert.pem"))
    );
    assert_eq!(
        config.proxy.upstream_client_cert_path.as_deref(),
        Some(Path::new("tests/fixtures/tls/localhost-cert.pem"))
    );
    assert_eq!(
        config.proxy.upstream_client_key_path.as_deref(),
        Some(Path::new("tests/fixtures/tls/localhost-key.pem"))
    );
    assert_eq!(
        config.proxy.upstream_proxy_protocol,
        UpstreamProxyProtocol::V2
    );
    assert_eq!(
        config.proxy.upstream_http_version,
        UpstreamHttpVersion::Http1AndHttp2
    );
    assert!(!config.proxy.upstream_h2c_upgrade);
    assert_eq!(config.proxy.upstream_h2_max_streams, Some(64));
    assert_eq!(config.proxy.upstream_h2_ping_interval_secs, Some(30));
    assert_eq!(config.proxy.error_pages.len(), 1);
    assert_eq!(config.proxy.error_pages[0].status, 502);
    assert_eq!(config.proxy.error_pages[0].path, "/502.html");
    assert_eq!(config.proxy.load_balance.max_iterations, 16);
    assert_eq!(config.proxy.load_balance.all_down_status, 503);
    assert!(config.proxy.load_balance.health_check.enabled);
    assert_eq!(
        config.proxy.load_balance.health_check.protocol,
        LoadBalanceHealthCheckProtocol::Http
    );
    assert_eq!(config.proxy.load_balance.health_check.interval_secs, 2);
    assert_eq!(
        config.proxy.load_balance.health_check.consecutive_success,
        2
    );
    assert_eq!(
        config.proxy.load_balance.health_check.consecutive_failure,
        3
    );
    assert!(config.proxy.load_balance.health_check.parallel);
    assert_eq!(config.proxy.load_balance.health_check.method, "HEAD");
    assert_eq!(config.proxy.load_balance.health_check.path, "/healthz");
    assert_eq!(
        config.proxy.load_balance.health_check.host.as_deref(),
        Some("app.internal")
    );
    assert_eq!(
        config.proxy.load_balance.health_check.request_headers[0].name,
        "Authorization"
    );
    assert_eq!(
        config.proxy.load_balance.health_check.request_headers[0].value,
        "Bearer health-token"
    );
    let serialized_request_header =
        toml::to_string(&config.proxy.load_balance.health_check.request_headers[0]).unwrap();
    assert!(serialized_request_header.contains("Authorization"));
    assert!(!serialized_request_header.contains("Bearer health-token"));
    assert!(!serialized_request_header.contains("value"));
    assert!(
        format!(
            "{:?}",
            config.proxy.load_balance.health_check.request_headers[0]
        )
        .contains("[REDACTED]")
    );
    assert_eq!(
        config.proxy.load_balance.health_check.expected_statuses,
        vec![200, 204]
    );
    assert_eq!(
        config.proxy.load_balance.health_check.expected_headers[0].name,
        "x-fluxheim-health"
    );
    assert_eq!(
        config.proxy.load_balance.health_check.expected_headers[0].value,
        "ready"
    );
    assert_eq!(
        config
            .proxy
            .load_balance
            .health_check
            .expected_body_contains,
        vec!["ready".to_owned()]
    );
    assert_eq!(
        config.proxy.load_balance.health_check.expected_body_json[0].path,
        "status"
    );
    assert_eq!(
        config.proxy.load_balance.health_check.expected_body_json[1].equals,
        "true"
    );
    assert_eq!(
        config
            .proxy
            .load_balance
            .health_check
            .health_weight_min_percent,
        30
    );
    assert_eq!(
        config
            .proxy
            .load_balance
            .health_check
            .expected_status_ranges[0]
            .start,
        300
    );
    assert_eq!(
        config
            .proxy
            .load_balance
            .health_check
            .expected_status_ranges[0]
            .end,
        399
    );
    assert!(config.proxy.load_balance.health_check.reuse_connection);
    assert_eq!(
        config.proxy.load_balance.health_check.port_override,
        Some(8081)
    );
    assert_eq!(
        config.proxy.load_balance.health_check.connect_timeout_secs,
        Some(1)
    );
    assert_eq!(
        config.proxy.load_balance.health_check.read_timeout_secs,
        Some(2)
    );

    let grpc_config: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "grpc"
            host = "grpc.internal"
            grpc_service = "example.Health"

            [[proxy.load_balance.health_check.request_headers]]
            name = "Authorization"
            value = "Bearer grpc-health"
            "#,
    )
    .unwrap();
    grpc_config.validate().unwrap();
    assert_eq!(
        grpc_config.proxy.load_balance.health_check.protocol,
        LoadBalanceHealthCheckProtocol::Grpc
    );
    assert_eq!(
        grpc_config
            .proxy
            .load_balance
            .health_check
            .grpc_service
            .as_deref(),
        Some("example.Health")
    );

    let exec_config: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "exec"
            exec_command = "/usr/local/libexec/fluxheim-health"
            exec_args = ["--probe"]
            exec_allowed_commands = ["/usr/local/libexec/fluxheim-health"]
            exec_timeout_secs = 2
            "#,
    )
    .unwrap();
    exec_config.validate().unwrap();
    assert_eq!(
        exec_config.proxy.load_balance.health_check.protocol,
        LoadBalanceHealthCheckProtocol::Exec
    );
    assert_eq!(
        exec_config
            .proxy
            .load_balance
            .health_check
            .exec_command
            .as_deref(),
        Some("/usr/local/libexec/fluxheim-health")
    );
    let redis_config: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "redis"
            connect_timeout_secs = 2
            read_timeout_secs = 2
            "#,
    )
    .unwrap();
    redis_config.validate().unwrap();
    assert_eq!(
        redis_config.proxy.load_balance.health_check.protocol,
        LoadBalanceHealthCheckProtocol::Redis
    );
    let mysql_config: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "mysql"
            connect_timeout_secs = 2
            read_timeout_secs = 2
            "#,
    )
    .unwrap();
    mysql_config.validate().unwrap();
    assert_eq!(
        mysql_config.proxy.load_balance.health_check.protocol,
        LoadBalanceHealthCheckProtocol::Mysql
    );
    let postgres_config: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "postgres"
            connect_timeout_secs = 2
            read_timeout_secs = 2
            "#,
    )
    .unwrap();
    postgres_config.validate().unwrap();
    assert_eq!(
        postgres_config.proxy.load_balance.health_check.protocol,
        LoadBalanceHealthCheckProtocol::Postgres
    );
    assert!(config.proxy.load_balance.slow_start.enabled);
    assert_eq!(config.proxy.load_balance.slow_start.duration_secs, 45);
    assert!(config.proxy.load_balance.persistence.enabled);
    assert_eq!(
        config.proxy.load_balance.persistence.mode,
        LoadBalancePersistenceMode::SourceIp
    );
    assert_eq!(config.proxy.load_balance.persistence.ttl_secs, 600);
    assert_eq!(
        config.proxy.load_balance.persistence.table_max_entries,
        4096
    );
    assert_eq!(config.proxy.load_balance.queue.max_waiting, 32);
    assert_eq!(config.proxy.load_balance.queue.timeout_ms, 250);
    assert_eq!(config.proxy.load_balance.queue.retry_interval_ms, 5);
    #[cfg(not(feature = "privacy-mode"))]
    config.validate().unwrap();
    #[cfg(feature = "privacy-mode")]
    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence is not available in privacy-mode builds"
        })
    );
}
