use super::super::*;

#[test]
fn parses_php_fpm_vhost_config() {
    let root = unique_temp_path("config-php-fpm-root");
    std::fs::create_dir_all(&root).unwrap();
    let spool_dir = unique_temp_path("config-php-fpm-spool");
    std::fs::create_dir_all(&spool_dir).unwrap();
    #[cfg(windows)]
    let fpm_root = r"C:\app\public";
    #[cfg(not(windows))]
    let fpm_root = "/app/public";
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            preset = "wordpress"
            enabled = true
            runtime = "php-fpm"
            root = '{}'
            resolve_root_symlink = true
            fpm_root = '{}'
            index = "index.php"
            allowed_extensions = ["php"]
            deny_path_prefixes = ["/wp-content/uploads/", "/uploads"]
            try_files = "wordpress"
            pass_request_headers = false
            pass_request_body = false
            stderr_log = false
            stderr_log_level = "error"
            stderr_max_bytes = "4KiB"
            stderr_failure_patterns = ["PHP Fatal error:"]
            hide_response_headers = ["x-powered-by", "x-internal"]
            ignore_origin_cache_headers = true
            intercept_error_statuses = [404, 500, 502]
            request_timeout_secs = 30
            max_in_flight = 6
            max_request_body_bytes = "16MiB"
            request_body_spool_threshold_bytes = "1MiB"
            request_body_spool_dir = '{}'
            max_response_bytes = "8MiB"
            max_response_header_bytes = "32KiB"
            path_info = "split"

            [[vhosts.php.error_pages]]
            status = 502
            path = "/502.html"

            [vhosts.php.error_pages.web]
            root = '{}'
            index_files = ["index.html"]

            [vhosts.php.params]
            APP_ENV = "production"
            APP_MEMORY_LIMIT = "256M"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            keepalive = true
            pool_max_idle = 4
            idle_timeout_secs = 45
            max_retries = 2
            retry_timeout_secs = 5
            retry_methods = ["GET", "HEAD"]
            retry_invalid_response = true
            retry_statuses = [500, 502, 503]
            "#,
        test_process_config_toml("config-php-fpm-process"),
        root.display(),
        fpm_root,
        spool_dir.display(),
        root.display()
    ))
    .unwrap();

    config.validate().unwrap();
    let php = &config.vhosts[0].php;
    assert_eq!(php.preset, crate::PhpPreset::WordPress);
    assert!(php.enabled);
    assert_eq!(php.runtime, crate::PhpRuntime::PhpFpm);
    assert_eq!(php.root.as_deref(), Some(root.as_path()));
    assert!(php.resolve_root_symlink);
    assert_eq!(
        php.fpm_root.as_deref(),
        Some(std::path::Path::new(fpm_root))
    );
    assert_eq!(
        php.deny_path_prefixes,
        ["/wp-content/uploads/".to_owned(), "/uploads".to_owned()]
    );
    assert_eq!(php.try_files, crate::PhpTryFilesMode::WordPress);
    assert!(!php.pass_request_headers);
    assert!(!php.pass_request_body);
    assert!(!php.stderr_log);
    assert_eq!(php.stderr_log_level, crate::PhpStderrLogLevel::Error);
    assert_eq!(php.stderr_max_bytes.as_u64(), 4 * 1024);
    assert_eq!(php.stderr_failure_patterns, ["PHP Fatal error:".to_owned()]);
    assert_eq!(
        php.hide_response_headers,
        ["x-powered-by".to_owned(), "x-internal".to_owned()]
    );
    assert!(php.ignore_origin_cache_headers);
    assert_eq!(php.intercept_error_statuses, [404, 500, 502]);
    assert_eq!(php.max_in_flight, 6);
    assert_eq!(php.error_pages.len(), 1);
    assert_eq!(php.error_pages[0].status, 502);
    assert_eq!(php.error_pages[0].path, "/502.html");
    assert_eq!(php.allowed_extensions, ["php"]);
    assert_eq!(
        php.max_request_body_bytes.unwrap().as_u64(),
        16 * 1024 * 1024
    );
    assert_eq!(
        php.request_body_spool_threshold_bytes.unwrap().as_u64(),
        1024 * 1024
    );
    assert_eq!(
        php.request_body_spool_dir.as_deref(),
        Some(spool_dir.as_path())
    );
    assert_eq!(php.max_response_bytes.as_u64(), 8 * 1024 * 1024);
    assert_eq!(php.max_response_header_bytes.as_u64(), 32 * 1024);
    assert_eq!(php.path_info, crate::PhpPathInfoMode::Split);
    assert_eq!(
        php.params.get("APP_ENV").map(String::as_str),
        Some("production")
    );
    assert_eq!(
        php.params.get("APP_MEMORY_LIMIT").map(String::as_str),
        Some("256M")
    );
    assert_eq!(php.fpm.tcp.as_deref(), Some("127.0.0.1:9000"));
    assert!(php.fpm.tcp_upstreams.is_empty());
    assert!(php.fpm.keepalive);
    assert_eq!(php.fpm.pool_max_idle, 4);
    assert_eq!(php.fpm.idle_timeout_secs, 45);
    assert_eq!(php.fpm.max_retries, 2);
    assert_eq!(php.fpm.retry_timeout_secs, Some(5));
    assert_eq!(php.fpm.retry_methods, ["GET", "HEAD"]);
    assert!(php.fpm.retry_invalid_response);
    assert_eq!(php.fpm.retry_statuses, [500, 502, 503]);

    let mut wordpress_php = php.clone();
    wordpress_php.apply_preset_defaults();
    assert_eq!(wordpress_php.try_files, crate::PhpTryFilesMode::WordPress);
    assert!(
        wordpress_php
            .deny_path_prefixes
            .contains(&"/wp-content/uploads/".to_owned())
    );
    assert!(
        wordpress_php
            .deny_path_prefixes
            .contains(&"/files/".to_owned())
    );
}

#[test]
fn parses_php_fpm_tcp_upstreams() {
    let root = unique_temp_path("config-php-fpm-upstreams-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = '{}'

            [vhosts.php.fpm]
            tcp_upstreams = ["127.0.0.1:9000", "127.0.0.1:9001"]
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-fpm-upstreams-process"),
        root.display()
    ))
    .unwrap();

    config.validate().unwrap();
    assert_eq!(
        config.vhosts[0].php.fpm.tcp_upstreams,
        ["127.0.0.1:9000".to_owned(), "127.0.0.1:9001".to_owned()]
    );
}

#[cfg(unix)]
#[test]
fn parses_managed_php_fpm_config() {
    let root = secure_test_dir("config-php-fpm-managed-root");
    let socket_dir = secure_test_dir("config-php-fpm-managed-socket");
    let session_dir = secure_test_dir("config-php-fpm-managed-session");
    let upload_dir = secure_test_dir("config-php-fpm-managed-upload");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = '{}'

            [vhosts.php.fpm]
            mode = "managed"
            php_fpm_binary = "/usr/bin/env"
            socket_dir = '{}'
            workers = 4
            max_requests_per_worker = 250
            process_manager = "dynamic"
            start_servers = 2
            min_spare_servers = 1
            max_spare_servers = 3
            max_spawn_rate = 8
            listen_backlog = 128
            listen_owner = "fluxheim"
            listen_group = "php"
            listen_mode = "0660"
            request_terminate_timeout_secs = 30
            request_terminate_timeout_track_finished = true
            request_slowlog_timeout_secs = 5
            request_slowlog_trace_depth = 16
            decorate_workers_output = false
            session_save_path = '{}'
            upload_tmp_dir = '{}'
            user = "fluxheim"
            group = "fluxheim"
            "#,
        test_process_config_toml("config-php-fpm-managed-process"),
        root.display(),
        socket_dir.display(),
        session_dir.display(),
        upload_dir.display()
    ))
    .unwrap();

    config.validate().unwrap();
    let php = &config.vhosts[0].php;
    assert_eq!(php.fpm.mode, crate::PhpFpmMode::Managed);
    assert_eq!(
        php.fpm.php_fpm_binary.as_deref(),
        Some(Path::new("/usr/bin/env"))
    );
    assert_eq!(php.fpm.socket_dir.as_deref(), Some(socket_dir.as_path()));
    assert_eq!(php.fpm.workers, 4);
    assert_eq!(php.fpm.max_requests_per_worker, 250);
    assert_eq!(
        php.fpm.process_manager,
        crate::PhpFpmProcessManager::Dynamic
    );
    assert_eq!(php.fpm.start_servers, Some(2));
    assert_eq!(php.fpm.min_spare_servers, Some(1));
    assert_eq!(php.fpm.max_spare_servers, Some(3));
    assert_eq!(php.fpm.max_spawn_rate, Some(8));
    assert_eq!(php.fpm.listen_backlog, Some(128));
    assert_eq!(php.fpm.listen_owner.as_deref(), Some("fluxheim"));
    assert_eq!(php.fpm.listen_group.as_deref(), Some("php"));
    assert_eq!(php.fpm.listen_mode.as_deref(), Some("0660"));
    assert_eq!(php.fpm.request_terminate_timeout_secs, Some(30));
    assert!(php.fpm.request_terminate_timeout_track_finished);
    assert_eq!(php.fpm.request_slowlog_timeout_secs, Some(5));
    assert_eq!(php.fpm.request_slowlog_trace_depth, 16);
    assert!(!php.fpm.decorate_workers_output);
    assert_eq!(
        php.fpm.session_save_path.as_deref(),
        Some(session_dir.as_path())
    );
    assert_eq!(
        php.fpm.upload_tmp_dir.as_deref(),
        Some(upload_dir.as_path())
    );
    assert_eq!(php.fpm.user.as_deref(), Some("fluxheim"));
    assert_eq!(php.fpm.group.as_deref(), Some("fluxheim"));
    assert!(php.fpm.socket.is_none());
    assert!(php.fpm.tcp.is_none());
    assert!(php.fpm.tcp_upstreams.is_empty());
}

#[cfg(not(unix))]
#[test]
fn rejects_managed_php_fpm_without_unix_process_support() {
    let root = secure_test_dir("config-php-managed-unsupported-root");
    let config: Config = toml::from_str(&format!(
        r#"
            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = '{}'

            [vhosts.php.fpm]
            mode = "managed"
        "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate().unwrap_err(),
        ConfigError::VhostSection {
            vhost: "php".to_owned(),
            section: "php",
            source: Box::new(ConfigError::InvalidPhpConfig {
                field: "php.fpm.mode",
                reason: "managed php-fpm requires Unix sockets",
            }),
        }
    );
}
