use super::super::*;

#[cfg(unix)]
#[test]
fn rejects_symlinked_managed_php_fpm_binary() {
    let root = secure_test_dir("config-php-fpm-managed-binary-root");
    let socket_dir = secure_test_dir("config-php-fpm-managed-binary-socket");
    let binary_dir = secure_test_dir("config-php-fpm-managed-binary-dir");
    let real_binary = safe_child_path(&binary_dir, "php-fpm.real");
    let symlink_binary = safe_child_path(&binary_dir, "php-fpm");
    fs::write(&real_binary, b"#!/bin/sh\n").unwrap();
    std::os::unix::fs::symlink(&real_binary, &symlink_binary).unwrap();
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
            php_fpm_binary = '{}'
            socket_dir = '{}'
            "#,
        test_process_config_toml("config-php-fpm-managed-binary-process"),
        root.display(),
        symlink_binary.display(),
        socket_dir.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.php_fpm_binary"), "{error}");
    assert!(error.contains("regular executable file"), "{error}");
}

#[cfg(unix)]
#[test]
fn rejects_managed_php_fpm_dynamic_without_spare_bounds() {
    let root = secure_test_dir("config-php-fpm-managed-dynamic-root");
    let socket_dir = secure_test_dir("config-php-fpm-managed-dynamic-socket");
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
            process_manager = "dynamic"
            "#,
        test_process_config_toml("config-php-fpm-managed-dynamic-process"),
        root.display(),
        socket_dir.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.min_spare_servers"), "{error}");
}

#[cfg(unix)]
#[test]
fn rejects_managed_php_fpm_dynamic_inverted_spare_bounds() {
    let root = secure_test_dir("config-php-fpm-managed-dynamic-inverted-root");
    let socket_dir = secure_test_dir("config-php-fpm-managed-dynamic-inverted-socket");
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
            process_manager = "dynamic"
            min_spare_servers = 3
            max_spare_servers = 2
            "#,
        test_process_config_toml("config-php-fpm-managed-dynamic-inverted-process"),
        root.display(),
        socket_dir.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.max_spare_servers"), "{error}");
    assert!(error.contains("min_spare_servers"), "{error}");
}

#[cfg(unix)]
#[test]
fn rejects_managed_php_fpm_with_external_endpoint() {
    let root = secure_test_dir("config-php-fpm-managed-endpoint-root");
    let socket_dir = secure_test_dir("config-php-fpm-managed-endpoint-socket");
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
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        test_process_config_toml("config-php-fpm-managed-endpoint-process"),
        root.display(),
        socket_dir.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.mode"), "{error}");
    assert!(error.contains("private socket"), "{error}");
}

#[cfg(unix)]
#[test]
fn rejects_managed_php_fpm_user_without_group() {
    let root = secure_test_dir("config-php-fpm-managed-user-root");
    let socket_dir = secure_test_dir("config-php-fpm-managed-user-socket");
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
            user = "fluxheim"
            "#,
        test_process_config_toml("config-php-fpm-managed-user-process"),
        root.display(),
        socket_dir.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.user"), "{error}");
    assert!(error.contains("user and group"), "{error}");
}

#[cfg(unix)]
#[test]
fn rejects_managed_php_fpm_listen_owner_without_group() {
    let root = secure_test_dir("config-php-fpm-managed-listen-owner-root");
    let socket_dir = secure_test_dir("config-php-fpm-managed-listen-owner-socket");
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
            listen_owner = "fluxheim"
            "#,
        test_process_config_toml("config-php-fpm-managed-listen-owner-process"),
        root.display(),
        socket_dir.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.listen_owner"), "{error}");
    assert!(error.contains("listen_owner and listen_group"), "{error}");
}

#[cfg(unix)]
#[test]
fn rejects_managed_php_fpm_unsafe_listen_mode() {
    let root = secure_test_dir("config-php-fpm-managed-listen-mode-root");
    let socket_dir = secure_test_dir("config-php-fpm-managed-listen-mode-socket");
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
            listen_mode = "0666"
            "#,
        test_process_config_toml("config-php-fpm-managed-listen-mode-process"),
        root.display(),
        socket_dir.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.listen_mode"), "{error}");
    assert!(error.contains("0600"), "{error}");
}

#[test]
fn rejects_external_php_fpm_with_managed_fields() {
    let root = secure_test_dir("config-php-fpm-external-managed-root");
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
            user = "fluxheim"
            "#,
        test_process_config_toml("config-php-fpm-external-managed-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.mode"), "{error}");
    assert!(error.contains("managed php-fpm fields"), "{error}");
}
