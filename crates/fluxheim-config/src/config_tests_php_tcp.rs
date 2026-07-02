use super::super::*;

#[test]
fn rejects_too_many_php_fpm_tcp_upstreams() {
    let root = unique_temp_path("config-php-fpm-too-many-upstreams-root");
    std::fs::create_dir_all(&root).unwrap();
    let upstreams = (0..=crate::MAX_PHP_FPM_TCP_UPSTREAMS)
        .map(|index| format!("\"127.0.0.1:{}\"", 9000 + index))
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

            [vhosts.php.fpm]
            tcp_upstreams = [{}]
            "#,
        test_process_config_toml("config-php-fpm-too-many-upstreams-process"),
        root.display(),
        upstreams,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.tcp_upstreams"), "{error}");
    assert!(error.contains("at most 64 upstreams"), "{error}");
}

#[test]
fn rejects_duplicate_php_fpm_tcp_upstreams() {
    let root = unique_temp_path("config-php-fpm-duplicate-upstreams-root");
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

            [vhosts.php.fpm]
            tcp_upstreams = ["php-fpm-a:9000", "PHP-FPM-A:9000"]
            "#,
        test_process_config_toml("config-php-fpm-duplicate-upstreams-process"),
        root.display(),
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.tcp_upstreams"), "{error}");
    assert!(error.contains("duplicate upstreams"), "{error}");
}

#[test]
fn rejects_private_php_fpm_tcp_ip_without_explicit_opt_in() {
    let root = unique_temp_path("config-php-fpm-private-tcp-root");
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

            [vhosts.php.fpm]
            tcp = "10.0.0.5:9000"
            "#,
        test_process_config_toml("config-php-fpm-private-tcp-process"),
        root.display(),
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.tcp"), "{error}");
    assert!(error.contains("allow_private_tcp_upstreams"), "{error}");
}

#[test]
fn rejects_loopback_php_fpm_tcp_ip_without_explicit_opt_in() {
    let root = unique_temp_path("config-php-fpm-loopback-tcp-root");
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

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-fpm-loopback-tcp-process"),
        root.display(),
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.tcp"), "{error}");
    assert!(error.contains("allow_private_tcp_upstreams"), "{error}");
}

#[test]
fn accepts_private_php_fpm_tcp_ip_with_explicit_opt_in() {
    let root = unique_temp_path("config-php-fpm-private-tcp-opt-in-root");
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

            [vhosts.php.fpm]
            tcp = "10.0.0.5:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-fpm-private-tcp-opt-in-process"),
        root.display(),
    ))
    .unwrap();

    config.validate().unwrap();
}

#[test]
fn rejects_unsafe_php_fpm_tcp_ip_even_with_private_opt_in() {
    let root = unique_temp_path("config-php-fpm-unsafe-tcp-root");
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

            [vhosts.php.fpm]
            tcp = "0.0.0.0:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-fpm-unsafe-tcp-process"),
        root.display(),
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.tcp"), "{error}");
    assert!(error.contains("unspecified or multicast"), "{error}");
}

#[test]
fn rejects_mixed_php_fpm_endpoint_modes() {
    let root = unique_temp_path("config-php-fpm-mixed-root");
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

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            tcp_upstreams = ["127.0.0.1:9001"]
            "#,
        test_process_config_toml("config-php-fpm-mixed-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("socket, tcp, or tcp_upstreams"), "{error}");
}
