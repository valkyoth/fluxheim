use super::super::*;

#[test]
fn rejects_php_fpm_keepalive_without_idle_capacity() {
    let root = unique_temp_path("config-php-fpm-keepalive-zero-pool");
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
            keepalive = true
            pool_max_idle = 0
            "#,
        test_process_config_toml("config-php-fpm-keepalive-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.pool_max_idle"), "{error}");
}

#[test]
fn rejects_php_param_that_overrides_script_filename() {
    let root = unique_temp_path("config-php-param-protected");
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

            [vhosts.php.params]
            SCRIPT_FILENAME = "/tmp/other.php"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-param-protected-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.params"), "{error}");
    assert!(error.contains("managed by Fluxheim"), "{error}");
}

#[test]
fn rejects_php_fpm_ini_control_params() {
    for protected_name in ["PHP_VALUE", "PHP_ADMIN_VALUE"] {
        let root = unique_temp_path(&format!(
            "config-php-param-{}",
            protected_name.to_ascii_lowercase()
        ));
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

                [vhosts.php.params]
                {protected_name} = "memory_limit=256M"

                [vhosts.php.fpm]
                tcp = "127.0.0.1:9000"
                allow_private_tcp_upstreams = true
                "#,
            test_process_config_toml("config-php-param-ini-control-process"),
            root.display()
        ))
        .unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("php.params"), "{error}");
        assert!(error.contains("managed by Fluxheim"), "{error}");
    }
}

#[test]
fn rejects_invalid_php_max_in_flight() {
    let root = unique_temp_path("config-php-max-in-flight");
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
            max_in_flight = 0

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-max-in-flight-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.max_in_flight"), "{error}");
}

#[test]
fn rejects_php_param_control_character_value() {
    let root = unique_temp_path("config-php-param-control");
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

            [vhosts.php.params]
            APP_ENV = "production\u000a"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-param-control-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("control characters"), "{error}");
}

#[test]
fn rejects_too_many_php_params() {
    let root = unique_temp_path("config-php-many-params");
    std::fs::create_dir_all(&root).unwrap();
    let params = (0..=crate::MAX_PHP_PARAMS)
        .map(|index| format!("PARAM_{index} = \"value\""))
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
            root = '{}'

            [vhosts.php.params]
            {}

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-many-params-process"),
        root.display(),
        params,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.params"), "{error}");
    assert!(error.contains("at most 128 parameters"), "{error}");
}

#[test]
fn rejects_php_extension_with_leading_dot() {
    let root = unique_temp_path("config-php-extension-dot-root");
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
            allowed_extensions = [".php"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-extension-dot-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("extensions must be plain extension names"),
        "{error}"
    );
}

#[test]
fn rejects_duplicate_php_allowed_extension() {
    let root = unique_temp_path("config-php-duplicate-extension-root");
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
            allowed_extensions = ["php", "PHP"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-duplicate-extension-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.allowed_extensions"), "{error}");
    assert!(error.contains("duplicate extensions"), "{error}");
}

#[test]
fn rejects_too_many_php_allowed_extensions() {
    let root = unique_temp_path("config-php-many-extensions-root");
    std::fs::create_dir_all(&root).unwrap();
    let extensions = (0..=crate::MAX_PHP_ALLOWED_EXTENSIONS)
        .map(|index| format!("\"php{index}\""))
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
            allowed_extensions = [{}]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-many-extensions-process"),
        root.display(),
        extensions,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.allowed_extensions"), "{error}");
    assert!(error.contains("at most 16 extensions"), "{error}");
}

#[test]
fn rejects_invalid_php_deny_path_prefix() {
    let root = unique_temp_path("config-php-bad-deny-prefix-root");
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
            deny_path_prefixes = ["uploads/../secret"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-bad-deny-prefix-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.deny_path_prefixes"), "{error}");
}

#[test]
fn rejects_duplicate_php_deny_path_prefix() {
    let root = unique_temp_path("config-php-duplicate-deny-prefix-root");
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
            deny_path_prefixes = ["/uploads", "/uploads"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-duplicate-deny-prefix-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.deny_path_prefixes"), "{error}");
}

#[test]
fn rejects_too_many_php_deny_path_prefixes() {
    let root = unique_temp_path("config-php-many-deny-prefixes-root");
    std::fs::create_dir_all(&root).unwrap();
    let prefixes = (0..=crate::MAX_PHP_DENY_PATH_PREFIXES)
        .map(|index| format!("\"/upload-{index}/\""))
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
            deny_path_prefixes = [{}]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-many-deny-prefixes-process"),
        root.display(),
        prefixes,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.deny_path_prefixes"), "{error}");
    assert!(error.contains("at most 128 prefixes"), "{error}");
}
