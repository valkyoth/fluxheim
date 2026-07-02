use super::*;

#[test]
fn conf_d_proxy_fragment_extends_without_replacing_main_trust_policy() {
    let dir = TestDir::new("config-file-with-conf-d-proxy-fragment");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [proxy]
            upstream = "origin.example.test:443"
            upstream_tls = true
            upstream_sni = "origin.example.test"
            upstream_verify_cert = true
            upstream_verify_hostname = true

            [proxy.auth_request]
            enabled = true
            url = "https://auth.example.test/check"
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/20-proxy-timeouts.toml"),
        r#"
            [proxy]
            connect_timeout_secs = 5
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(
        config.proxy.upstream.as_deref(),
        Some("origin.example.test:443")
    );
    assert!(config.proxy.upstream_tls);
    assert_eq!(
        config.proxy.upstream_sni.as_deref(),
        Some("origin.example.test")
    );
    assert!(config.proxy.upstream_verify_cert);
    assert!(config.proxy.upstream_verify_hostname);
    assert!(config.proxy.auth_request.enabled);
    assert_eq!(
        config.proxy.auth_request.url.as_deref(),
        Some("https://auth.example.test/check")
    );
    assert_eq!(config.proxy.connect_timeout_secs, Some(5));
}

#[test]
fn conf_d_proxy_nested_fragments_merge_without_replacing_security_policy() {
    let dir = TestDir::new("config-file-with-conf-d-proxy-nested-fragment");
    let runtime_state_file = safe_child_path(
        &secure_test_dir("config-conf-d-proxy-lb-state"),
        "state.json",
    );
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        format!(
            r#"
            include_conf_d = true

            [proxy]
            upstreams = ["origin-a.example.test:443", "origin-b.example.test:443"]

            [proxy.auth_request]
            enabled = true
            url = "https://auth.example.test/check"
            forward_headers = ["x-request-id"]
            allow_response_headers = ["x-user"]
            connect_timeout_secs = 2
            read_timeout_secs = 5

            [proxy.mirror]
            enabled = false
            base_url = "https://mirror.example.test"
            sample_per_mille = 250
            methods = ["GET"]
            forward_headers = ["x-request-id"]
            timeout_secs = 2
            max_in_flight = 32

            [proxy.load_balance]
            selection = "header-hash"
            hash_header = "x-session"
            max_iterations = 16
            all_down_status = 503
            runtime_state_file = "{}"

            [proxy.load_balance.health_check]
            enabled = true
            protocol = "http"
            path = "/healthz"
            expected_statuses = [200]

            [proxy.load_balance.persistence]
            enabled = true
            mode = "header"
            header = "x-session"
            ttl_secs = 600

            [proxy.load_balance.retry]
            enabled = true
            statuses = [502]
            budget_per_window = 10

            [proxy.load_balance.queue]
            max_waiting = 32
            timeout_ms = 250
            "#,
            runtime_state_file.display()
        ),
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/20-proxy-nested-policy.toml"),
        r#"
            [proxy.auth_request]
            read_timeout_secs = 7

            [proxy.mirror]
            timeout_secs = 4

            [proxy.load_balance.passive_health]
            enabled = true
            consecutive_failure = 4
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert!(config.proxy.auth_request.enabled);
    assert_eq!(
        config.proxy.auth_request.url.as_deref(),
        Some("https://auth.example.test/check")
    );
    assert_eq!(config.proxy.auth_request.forward_headers, ["x-request-id"]);
    assert_eq!(config.proxy.auth_request.allow_response_headers, ["x-user"]);
    assert_eq!(config.proxy.auth_request.connect_timeout_secs, 2);
    assert_eq!(config.proxy.auth_request.read_timeout_secs, 7);

    assert!(!config.proxy.mirror.enabled);
    assert_eq!(
        config.proxy.mirror.base_url.as_deref(),
        Some("https://mirror.example.test")
    );
    assert_eq!(config.proxy.mirror.sample_per_mille, 250);
    assert_eq!(config.proxy.mirror.methods, ["GET"]);
    assert_eq!(config.proxy.mirror.forward_headers, ["x-request-id"]);
    assert_eq!(config.proxy.mirror.timeout_secs, 4);
    assert_eq!(config.proxy.mirror.max_in_flight, 32);

    assert_eq!(
        config.proxy.load_balance.selection,
        LoadBalanceSelection::HeaderHash
    );
    assert_eq!(
        config.proxy.load_balance.hash_header.as_deref(),
        Some("x-session")
    );
    assert_eq!(config.proxy.load_balance.max_iterations, 16);
    assert_eq!(config.proxy.load_balance.all_down_status, 503);
    assert_eq!(
        config.proxy.load_balance.runtime_state_file.as_deref(),
        Some(runtime_state_file.as_path())
    );
    assert!(config.proxy.load_balance.health_check.enabled);
    assert_eq!(
        config.proxy.load_balance.health_check.protocol,
        LoadBalanceHealthCheckProtocol::Http
    );
    assert_eq!(config.proxy.load_balance.health_check.path, "/healthz");
    assert_eq!(
        config.proxy.load_balance.health_check.expected_statuses,
        [200]
    );
    assert!(config.proxy.load_balance.persistence.enabled);
    assert_eq!(
        config.proxy.load_balance.persistence.mode,
        LoadBalancePersistenceMode::Header
    );
    assert_eq!(
        config.proxy.load_balance.persistence.header.as_deref(),
        Some("x-session")
    );
    assert_eq!(config.proxy.load_balance.persistence.ttl_secs, 600);
    assert!(config.proxy.load_balance.retry.enabled);
    assert_eq!(config.proxy.load_balance.retry.statuses, [502]);
    assert_eq!(config.proxy.load_balance.retry.budget_per_window, 10);
    assert_eq!(config.proxy.load_balance.queue.max_waiting, 32);
    assert_eq!(config.proxy.load_balance.queue.timeout_ms, 250);
    assert!(config.proxy.load_balance.passive_health.enabled);
    assert_eq!(
        config.proxy.load_balance.passive_health.consecutive_failure,
        4
    );

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

#[test]
fn conf_d_admin_fragment_extends_without_replacing_main_auth_policy() {
    let dir = TestDir::new("config-file-with-conf-d-admin-fragment");
    let snapshot_store = secure_test_dir("config-conf-d-admin-snapshots");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        format!(
            r#"
                include_conf_d = true

                [admin]
                enabled = true
                listen = "127.0.0.1:19090"
                token_env = "FLUXHEIM_ADMIN_TOKEN"
                snapshot_store = "{}"

                [admin.health]
                response = "minimal"

                [admin.auth_throttle]
                per_source_failures = 3
                global_failures = 50
                "#,
            snapshot_store.display()
        ),
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/20-admin-ops.toml"),
        r#"
            [admin.ops_socket]
            path = "fluxheim-ops.sock"
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert!(config.admin.enabled);
    assert_eq!(config.admin.listen, "127.0.0.1:19090");
    assert_eq!(
        config.admin.token_env.as_deref(),
        Some("FLUXHEIM_ADMIN_TOKEN")
    );
    assert_eq!(
        config.admin.snapshot_store.as_deref(),
        Some(snapshot_store.as_path())
    );
    assert_eq!(
        config.admin.health.response,
        AdminHealthResponseMode::Minimal
    );
    assert_eq!(config.admin.auth_throttle.per_source_failures, 3);
    assert_eq!(config.admin.auth_throttle.global_failures, 50);
    assert_eq!(
        config.admin.ops_socket.path,
        dir.child("conf.d/fluxheim-ops.sock")
    );
}

#[test]
fn conf_d_compression_fragment_keeps_main_resource_limits() {
    let dir = TestDir::new("config-file-with-conf-d-compression-fragment");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [compression]
            enabled = true
            gzip = true
            brotli = false
            min_bytes = "1KiB"
            max_input_bytes = "64MiB"
            max_output_bytes = "128MiB"
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/20-compression.toml"),
        r#"
            [compression]
            brotli = true
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert!(config.compression.enabled);
    assert!(config.compression.gzip);
    assert!(config.compression.brotli);
    assert_eq!(
        config.compression.max_input_bytes,
        ByteSize::from_bytes(64 * 1024 * 1024)
    );
    assert_eq!(
        config.compression.max_output_bytes,
        ByteSize::from_bytes(128 * 1024 * 1024)
    );
}

#[test]
fn conf_d_cache_fragment_keeps_main_disk_encryption_policy() {
    let dir = TestDir::new("config-file-with-conf-d-cache-fragment");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::create_dir_all(dir.child("cache")).unwrap();
    fs::write(dir.child("cache.key"), "local-cache-key").unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [cache]
            enabled = true
            max_object_bytes = "16MiB"

            [cache.disk]
            enabled = true
            path = "cache"
            max_size_bytes = "256MiB"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            key_file = "cache.key"
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/20-cache-policy.toml"),
        r#"
            [cache]
            default_status_ttl_secs = 60
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert!(config.cache.enabled);
    assert!(config.cache.disk.enabled);
    assert!(config.cache.disk.encryption.enabled);
    assert_eq!(
        config.cache.disk.path.as_deref(),
        Some(dir.child("cache").as_path())
    );
    assert_eq!(
        config.cache.disk.encryption.key_file.as_deref(),
        Some(dir.child("cache.key").as_path())
    );
    assert_eq!(config.cache.default_status_ttl_secs, Some(60));
}

#[test]
fn conf_d_web_fragment_keeps_main_static_root_and_dotfile_policy() {
    let dir = TestDir::new("config-file-with-conf-d-web-fragment");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::create_dir_all(dir.child("site")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [web]
            root = "site"
            deny_dotfiles = true
            index_files = ["index.html", "index.htm"]
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/20-web-listing.toml"),
        r#"
            [web.directory_listing]
            enabled = true
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(
        config.web.root.as_deref(),
        Some(dir.child("site").as_path())
    );
    assert!(config.web.deny_dotfiles);
    assert_eq!(config.web.index_files, ["index.html", "index.htm"]);
    assert!(config.web.directory_listing.enabled);
}

#[test]
#[cfg(feature = "stream-proxy")]
fn conf_d_stream_fragment_keeps_main_routes() {
    let dir = TestDir::new("config-file-with-conf-d-stream-fragment");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [stream]
            enabled = true

            [[stream.routes]]
            name = "database"
            listen = ["127.0.0.1:19091"]
            upstream = "127.0.0.1:5432"
            upstream_tls = true
            upstream_sni = "db.example.test"
            upstream_verify_cert = true
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/20-stream-enabled.toml"),
        r#"
            [stream]
            enabled = true
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert!(config.stream.enabled);
    assert_eq!(config.stream.routes.len(), 1);
    assert_eq!(config.stream.routes[0].name, "database");
    assert!(config.stream.routes[0].upstream_tls);
    assert_eq!(
        config.stream.routes[0].upstream_sni.as_deref(),
        Some("db.example.test")
    );
}

#[test]
fn rejects_stream_tls_verified_ip_upstream_without_explicit_sni() {
    let config: Config = toml::from_str(
        r#"
            [stream]
            enabled = true

            [[stream.routes]]
            name = "database"
            listen = ["127.0.0.1:19091"]
            upstream = "127.0.0.1:5432"
            upstream_tls = true
            upstream_verify_cert = true
            "#,
    )
    .unwrap();

    #[cfg(feature = "stream-proxy")]
    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidStreamProxyPolicy {
            field: "stream.routes.upstream_sni",
            reason: "IP-addressed upstreams with upstream_tls and upstream_verify_cert require explicit upstream_sni"
        })
    );
    #[cfg(not(feature = "stream-proxy"))]
    assert_eq!(config.validate(), Err(ConfigError::StreamProxyNotCompiled));
}
