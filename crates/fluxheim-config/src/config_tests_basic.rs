use super::*;

#[test]
fn parses_minimal_toml() {
    let config: Config = toml::from_str(
        r#"
            [server]
            listen = ["127.0.0.1:18080"]
            tls_listen = ["127.0.0.1:18443"]

            [proxy]
            upstream = "origin.example.test:443"
            upstream_tls = true
            upstream_sni = "origin.example.test"
            downstream_read_timeout_secs = 45
            downstream_write_timeout_secs = 20
            downstream_total_response_timeout_secs = 240
            downstream_min_send_rate_bytes_per_sec = 8192
            "#,
    )
    .unwrap();

    assert_eq!(config.server.listen, ["127.0.0.1:18080"]);
    assert_eq!(config.server.tls_listen, ["127.0.0.1:18443"]);
    assert_eq!(
        config.proxy.upstream.as_deref(),
        Some("origin.example.test:443")
    );
    assert!(config.proxy.upstream_tls);
    assert_eq!(config.proxy.upstream_sni(), "origin.example.test");
    assert_eq!(config.proxy.downstream_read_timeout_secs, Some(45));
    assert_eq!(config.proxy.downstream_write_timeout_secs, Some(20));
    assert_eq!(
        config.proxy.downstream_total_response_timeout_secs,
        Some(240)
    );
    assert_eq!(
        config.proxy.downstream_min_send_rate_bytes_per_sec,
        Some(8192)
    );
}

#[test]
fn parses_server_process_settings() {
    let root = unique_temp_path("config-process-settings");
    fs::create_dir(&root).unwrap();
    let error_log = safe_child_path(&root, "error.log");
    let pid_file = safe_child_path(&root, "fluxheim.pid");
    let upgrade_sock = safe_child_path(&root, "fluxheim-upgrade.sock");
    let certificate_reload_sock = safe_child_path(&root, "fluxheim-cert-reload.sock");
    let config: Config = toml::from_str(&format!(
        r#"
            [server.process]
            daemon = false
            error_log = "{}"
            pid_file = "{}"
            upgrade_sock = "{}"
            certificate_reload_sock = "{}"
            threads = 4
            listener_tasks_per_fd = 2
            work_stealing = false
            upstream_keepalive_pool_size = 512
            max_retries = 8
            grace_period_seconds = 10
            graceful_shutdown_timeout_seconds = 30
            "#,
        error_log.display(),
        pid_file.display(),
        upgrade_sock.display(),
        certificate_reload_sock.display()
    ))
    .unwrap();

    assert!(!config.server.process.daemon);
    assert_eq!(
        config.server.process.error_log.as_deref(),
        Some(error_log.as_path())
    );
    assert_eq!(config.server.process.pid_file, pid_file);
    assert_eq!(config.server.process.upgrade_sock, upgrade_sock);
    assert_eq!(
        config.server.process.certificate_reload_sock,
        certificate_reload_sock
    );
    assert_eq!(config.server.process.threads, 4);
    assert_eq!(config.server.process.listener_tasks_per_fd, 2);
    assert!(!config.server.process.work_stealing);
    assert_eq!(config.server.process.upstream_keepalive_pool_size, 512);
    assert_eq!(config.server.process.max_retries, 8);
    assert_eq!(config.server.process.grace_period_seconds, Some(10));
    assert_eq!(
        config.server.process.graceful_shutdown_timeout_seconds,
        Some(30)
    );
    config.validate().unwrap();
}

#[test]
fn rejects_unbounded_upstream_keepalive_pool_size() {
    let config: Config = toml::from_str(
        r#"
            [server.process]
            upstream_keepalive_pool_size = 16385
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProcessSetting {
            field: "server.process.upstream_keepalive_pool_size"
        })
    );
}

#[test]
fn parses_static_cache_headers() {
    let config: Config = toml::from_str(
        r#"
            [web]
            root = "public"
            cache_control = "public, max-age=31536000, immutable"
            expires = "Wed, 21 Oct 2030 07:28:00 GMT"

            [web.directory_listing]
            enabled = true
            exact_size = true
            local_time = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.web.cache_control,
        "public, max-age=31536000, immutable"
    );
    assert_eq!(
        config.web.expires.as_deref(),
        Some("Wed, 21 Oct 2030 07:28:00 GMT")
    );
    assert!(config.web.directory_listing.enabled);
    assert!(config.web.directory_listing.exact_size);
    assert!(config.web.directory_listing.local_time);
}
