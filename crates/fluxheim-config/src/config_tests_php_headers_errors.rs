use super::super::*;

#[test]
fn rejects_too_many_php_stderr_failure_patterns() {
    let root = unique_temp_path("config-php-many-stderr-patterns-root");
    std::fs::create_dir_all(&root).unwrap();
    let patterns = (0..=crate::MAX_PHP_STDERR_FAILURE_PATTERNS)
        .map(|index| format!("\"fatal-{index}\""))
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
            root = "{}"
            stderr_failure_patterns = [{}]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-many-stderr-patterns-process"),
        root.display(),
        patterns,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.stderr_failure_patterns"), "{error}");
    assert!(error.contains("at most 32 patterns"), "{error}");
}

#[test]
fn rejects_invalid_php_hidden_response_header() {
    let root = unique_temp_path("config-php-bad-hidden-header-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            hide_response_headers = ["bad header"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-bad-hidden-header-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.hide_response_headers"), "{error}");
}

#[test]
fn rejects_duplicate_php_hidden_response_header() {
    let root = unique_temp_path("config-php-duplicate-hidden-header-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            hide_response_headers = ["x-powered-by", "X-Powered-By"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-duplicate-hidden-header-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.hide_response_headers"), "{error}");
    assert!(error.contains("duplicate headers"), "{error}");
}

#[test]
fn rejects_too_many_php_hidden_response_headers() {
    let root = unique_temp_path("config-php-many-hidden-headers-root");
    std::fs::create_dir_all(&root).unwrap();
    let headers = (0..=crate::MAX_PHP_HIDE_RESPONSE_HEADERS)
        .map(|index| format!("\"x-hidden-{index}\""))
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
            root = "{}"
            hide_response_headers = [{}]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-many-hidden-headers-process"),
        root.display(),
        headers,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.hide_response_headers"), "{error}");
    assert!(error.contains("at most 64 headers"), "{error}");
}

#[test]
fn rejects_invalid_php_intercept_error_status() {
    let root = unique_temp_path("config-php-bad-intercept-status-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            intercept_error_statuses = [302]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-bad-intercept-status-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.intercept_error_statuses"), "{error}");
}

#[test]
fn rejects_duplicate_php_intercept_error_status() {
    let root = unique_temp_path("config-php-duplicate-intercept-status-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            intercept_error_statuses = [500, 500]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-duplicate-intercept-status-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.intercept_error_statuses"), "{error}");
}

#[test]
fn rejects_too_many_php_intercept_error_statuses() {
    let root = unique_temp_path("config-php-many-intercept-statuses-root");
    std::fs::create_dir_all(&root).unwrap();
    let statuses = (0..=crate::MAX_PHP_INTERCEPT_ERROR_STATUSES)
        .map(|index| (400 + index).to_string())
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
            root = "{}"
            intercept_error_statuses = [{}]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-many-intercept-statuses-process"),
        root.display(),
        statuses,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.intercept_error_statuses"), "{error}");
    assert!(error.contains("at most 200 statuses"), "{error}");
}

#[test]
fn rejects_duplicate_php_error_page_status() {
    let root = unique_temp_path("config-php-duplicate-error-page-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [[vhosts.php.error_pages]]
            status = 502
            path = "/502.html"

            [vhosts.php.error_pages.web]
            root = "{}"

            [[vhosts.php.error_pages]]
            status = 502
            path = "/fallback.html"

            [vhosts.php.error_pages.web]
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-duplicate-error-page-process"),
        root.display(),
        root.display(),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.error_pages.status"), "{error}");
}

#[test]
fn rejects_too_many_php_error_pages() {
    let root = unique_temp_path("config-php-many-error-pages-root");
    std::fs::create_dir_all(&root).unwrap();
    let error_pages = (0..=crate::MAX_PHP_ERROR_PAGES)
        .map(|index| {
            format!(
                r#"
            [[vhosts.php.error_pages]]
            status = {}
            path = "/{}.html"

            [vhosts.php.error_pages.web]
            root = "{}"
                    "#,
                400 + index,
                400 + index,
                root.display()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            {}

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-many-error-pages-process"),
        root.display(),
        error_pages,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.error_pages"), "{error}");
    assert!(error.contains("at most 64 error pages"), "{error}");
}
