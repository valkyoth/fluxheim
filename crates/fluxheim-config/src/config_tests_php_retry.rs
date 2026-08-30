use super::super::*;

#[test]
fn rejects_php_fpm_with_socket_and_tcp() {
    let root = unique_temp_path("config-php-fpm-conflict-root");
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
            socket = "/run/php/php-fpm.sock"
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-fpm-conflict-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("configure only one of socket, tcp, or tcp_upstreams"),
        "{error}"
    );
}

#[test]
fn rejects_invalid_php_fpm_retry_policy() {
    let root = unique_temp_path("config-php-fpm-invalid-retries-root");
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
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            max_retries = 11
            "#,
        test_process_config_toml("config-php-fpm-invalid-retries-process"),
        root.display()
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.max_retries"), "{error}");

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
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            retry_methods = ["GET", "get"]
            "#,
        test_process_config_toml("config-php-fpm-invalid-retry-methods-process"),
        root.display()
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.retry_methods"), "{error}");

    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = '{}'
            server_port = 0

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-invalid-server-port-process"),
        root.display()
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.server_port"), "{error}");

    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = '{}'

            [vhosts.php.params]
            HTTP_AUTHORIZATION = "Bearer fixed"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-http-param-process"),
        root.display()
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("HTTP_* request header"), "{error}");

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
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            retry_methods = ["GET", "POST"]
            "#,
        test_process_config_toml("config-php-fpm-unsafe-retry-method-process"),
        root.display()
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("safe HTTP methods"), "{error}");

    let retry_methods = (0..=crate::MAX_PHP_FPM_RETRY_METHODS)
        .map(|index| format!("\"M{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
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
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            retry_methods = [{}]
            "#,
        test_process_config_toml("config-php-fpm-too-many-retry-methods-process"),
        root.display(),
        retry_methods,
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.retry_methods"), "{error}");
    assert!(error.contains("at most 16 methods"), "{error}");

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
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            retry_timeout_secs = 0
            "#,
        test_process_config_toml("config-php-fpm-invalid-retry-timeout-process"),
        root.display()
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.retry_timeout_secs"), "{error}");

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
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            retry_statuses = [404]
            "#,
        test_process_config_toml("config-php-fpm-invalid-retry-status-process"),
        root.display()
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.retry_statuses"), "{error}");

    let retry_statuses = (0..=crate::MAX_PHP_FPM_RETRY_STATUSES)
        .map(|index| (500 + index).to_string())
        .collect::<Vec<_>>()
        .join(", ");
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
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            retry_statuses = [{}]
            "#,
        test_process_config_toml("config-php-fpm-too-many-retry-statuses-process"),
        root.display(),
        retry_statuses,
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.retry_statuses"), "{error}");
    assert!(error.contains("at most 100 statuses"), "{error}");

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
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            retry_statuses = [500, 500]
            "#,
        test_process_config_toml("config-php-fpm-duplicate-retry-status-process"),
        root.display()
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.retry_statuses"), "{error}");
}
