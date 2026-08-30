use super::*;
use crate::config_loader::MAX_CONFIG_DIRECTORY_FILES;

#[test]
fn conf_d_tls_acme_fragment_preserves_main_tls_settings() {
    let dir = TestDir::new("config-file-with-tls-acme-conf-d");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::create_dir_all(dir.child("site")).unwrap();
    fs::write(dir.child("site/index.html"), "ok").unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [server]
            listen = ["127.0.0.1:19090"]
            default_vhost = "example"

            [tls]
            enabled = true
            backend = "rustls"
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/acme.toml"),
        format!(
            r#"
                [tls.acme]
                enabled = true
                storage = '{}'
                contact_email = "admin@example.test"
                default_issuer = "letsencrypt"
                challenge = "http-01"
                "#,
            dir.child("acme").display()
        ),
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/vhost.toml"),
        format!(
            r#"
                [[vhosts]]
                name = "example"
                hosts = ["example.test"]

                [vhosts.tls]
                enabled = true

                [vhosts.tls.acme]
                enabled = true
                domains = ["example.test"]

                [vhosts.web]
                root = '{}'
                "#,
            dir.child("site").display()
        ),
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert!(config.tls.enabled);
    assert!(config.tls.acme.enabled);
    assert_eq!(config.vhosts.len(), 1);
    assert!(config.vhosts[0].tls.enabled);
    assert!(config.vhosts[0].tls.acme.enabled);
}

#[test]
fn loading_main_config_file_does_not_load_conf_d_without_opt_in() {
    let dir = TestDir::new("config-file-with-conf-d-no-opt-in");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [server]
            listen = ["127.0.0.1:19090"]
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/10-vhost.toml"),
        r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert!(config.vhosts.is_empty());
}

#[test]
fn loading_config_directory_also_loads_conf_d_after_top_level_files() {
    let dir = TestDir::new("config-dir-with-conf-d");
    fs::create_dir_all(dir.child("conf.d/site")).unwrap();
    fs::write(
        dir.child("00-server.toml"),
        r#"
            [server]
            listen = ["127.0.0.1:19090"]
            default_vhost = "example"
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/10-vhost.toml"),
        r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.web]
            root = "site"
            "#,
    )
    .unwrap();

    let config = Config::load(Some(dir.path())).unwrap();

    assert_eq!(config.server.default_vhost, Some("example".to_owned()));
    assert_eq!(config.vhosts.len(), 1);
    assert_eq!(config.vhosts[0].web.root, Some(dir.child("conf.d/site")));
}

#[test]
fn rejects_config_directory_with_too_many_toml_files() {
    let dir = TestDir::new("config-dir-too-many-files");
    for index in 0..=MAX_CONFIG_DIRECTORY_FILES {
        fs::write(dir.child(&format!("{index:03}.toml")), "[server]\n").unwrap();
    }

    let error = Config::load(Some(dir.path())).unwrap_err();

    assert!(
        matches!(error, ConfigLoadError::Read(error) if error.kind() == std::io::ErrorKind::InvalidData)
    );
}

#[test]
fn resolves_relative_cache_disk_paths_from_config_file() {
    let dir = TestDir::new("cache-path");
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [cache.disk]
            enabled = true
            path = "cache"
            max_size_bytes = "1GiB"
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(config.cache.disk.path, Some(dir.child("cache")));
}

#[test]
fn resolves_relative_server_process_paths_from_config_file() {
    let dir = TestDir::new("server-process-paths");
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [server.process]
            error_log = "logs/error.log"
            pid_file = "run/fluxheim.pid"
            upgrade_sock = "run/fluxheim-upgrade.sock"
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(
        config.server.process.error_log,
        Some(dir.child("logs/error.log"))
    );
    assert_eq!(
        config.server.process.pid_file,
        dir.child("run/fluxheim.pid")
    );
    assert_eq!(
        config.server.process.upgrade_sock,
        dir.child("run/fluxheim-upgrade.sock")
    );
}

#[test]
fn resolves_relative_logging_file_path_from_config_file() {
    let dir = TestDir::new("logging-file-path");
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [logging.file]
            path = "logs/fluxheim.log"
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(
        config.logging.file.path,
        Some(dir.child("logs/fluxheim.log"))
    );
}

#[test]
fn resolves_relative_tls_paths_from_config_file() {
    let dir = TestDir::new("tls-paths");
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [[tls.certificates]]
            cert_path = "tls/fullchain.pem"
            key_path = "tls/key.pem"

            [tls.acme]
            storage = "acme"

            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.tls.certificate]
            cert_path = "vhosts/example/fullchain.pem"
            key_path = "vhosts/example/key.pem"
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(
        config.tls.certificates[0].cert_path,
        dir.child("tls/fullchain.pem")
    );
    assert_eq!(config.tls.acme.storage, Some(dir.child("acme")));
    assert_eq!(
        config.vhosts[0].tls.certificate.as_ref().unwrap().key_path,
        dir.child("vhosts/example/key.pem")
    );
}

#[test]
fn rejects_config_relative_paths_with_parent_traversal() {
    let dir = TestDir::new("unsafe-paths");
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [web]
            root = "../outside"
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();

    assert!(matches!(
        error,
        ConfigLoadError::Validate(ConfigError::UnsafePath { .. })
    ));
}
