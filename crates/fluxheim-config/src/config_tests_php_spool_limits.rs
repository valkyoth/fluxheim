use super::super::*;

#[test]
fn rejects_incomplete_php_request_body_spool_config() {
    let root = unique_temp_path("config-php-incomplete-spool-root");
    let spool_dir = unique_temp_path("config-php-incomplete-spool-dir");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&spool_dir).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = '{}'
            request_body_spool_threshold_bytes = "1MiB"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-spool-threshold-without-dir-process"),
        root.display(),
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.request_body_spool_dir"), "{error}");

    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = '{}'
            request_body_spool_dir = '{}'

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-spool-dir-without-threshold-process"),
        root.display(),
        spool_dir.display(),
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("php.request_body_spool_threshold_bytes"),
        "{error}"
    );
}

#[test]
fn rejects_php_request_body_spool_threshold_at_or_above_body_limit() {
    let root = unique_temp_path("config-php-spool-threshold-over-limit-root");
    let spool_dir = unique_temp_path("config-php-spool-threshold-over-limit-dir");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&spool_dir).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = '{}'
            max_request_body_bytes = "8MiB"
            request_body_spool_threshold_bytes = "8MiB"
            request_body_spool_dir = '{}'

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-spool-threshold-over-limit-process"),
        root.display(),
        spool_dir.display(),
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("php.request_body_spool_threshold_bytes"),
        "{error}"
    );
    assert!(
        error.contains("less than php.max_request_body_bytes"),
        "{error}"
    );
}

#[test]
fn rejects_php_request_body_spool_path_that_is_not_directory() {
    let root = unique_temp_path("config-php-spool-file-root");
    let spool_path = unique_temp_path("config-php-spool-file");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(&spool_path, b"not a directory").unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = '{}'
            request_body_spool_threshold_bytes = "1MiB"
            request_body_spool_dir = '{}'

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-spool-file-process"),
        root.display(),
        spool_path.display(),
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.request_body_spool_dir"), "{error}");
    assert!(error.contains("must be a directory"), "{error}");
}

#[cfg(unix)]
#[test]
fn rejects_php_request_body_spool_dir_with_insecure_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let root = unique_temp_path("config-php-spool-insecure-root");
    let spool_dir = unique_temp_path("config-php-spool-insecure-dir");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&spool_dir).unwrap();
    std::fs::set_permissions(&spool_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = '{}'
            request_body_spool_threshold_bytes = "1MiB"
            request_body_spool_dir = '{}'

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-spool-insecure-process"),
        root.display(),
        spool_dir.display(),
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.request_body_spool_dir"), "{error}");
}

#[test]
fn rejects_zero_php_response_limit() {
    let root = unique_temp_path("config-php-zero-response-root");
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
            max_response_bytes = 0

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-zero-response-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.max_response_bytes"), "{error}");
}

#[test]
fn rejects_excessive_php_response_limit() {
    let root = unique_temp_path("config-php-excessive-response-root");
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
            max_response_bytes = "65MiB"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-excessive-response-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.max_response_bytes"), "{error}");
    assert!(error.contains("less than or equal to 64MiB"), "{error}");
}

#[test]
fn rejects_zero_php_response_header_limit() {
    let root = unique_temp_path("config-php-zero-response-header-root");
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
            max_response_header_bytes = 0

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-zero-response-header-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.max_response_header_bytes"), "{error}");
}

#[test]
fn rejects_excessive_php_response_header_limit() {
    let root = unique_temp_path("config-php-excessive-response-header-root");
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
            max_response_header_bytes = "2MiB"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-excessive-response-header-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.max_response_header_bytes"), "{error}");
}

#[test]
fn rejects_zero_php_stderr_limit() {
    let root = unique_temp_path("config-php-zero-stderr-root");
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
            stderr_max_bytes = 0

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-zero-stderr-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.stderr_max_bytes"), "{error}");
}

#[test]
fn rejects_invalid_php_stderr_failure_pattern() {
    let root = unique_temp_path("config-php-bad-stderr-pattern-root");
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
            stderr_failure_patterns = ["PHP\nFatal"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-bad-stderr-pattern-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.stderr_failure_patterns"), "{error}");
}
