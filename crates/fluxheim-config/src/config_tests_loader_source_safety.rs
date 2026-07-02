use super::*;
use crate::config_loader::MAX_CONFIG_FILE_BYTES;

#[cfg(unix)]
#[test]
fn rejects_runtime_path_below_symlinked_directory() {
    let dir = TestDir::new("runtime-path-parent-symlink");
    let real_dir = dir.child("real");
    let symlink_dir = dir.child("linked");
    fs::create_dir_all(safe_child_path(&real_dir, "public")).unwrap();
    std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [web]
            root = "linked/public"
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();

    assert!(matches!(
        error,
        ConfigLoadError::Validate(ConfigError::UnsafePath { field, .. })
            if field == "web.root"
    ));
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_runtime_path() {
    let dir = TestDir::new("runtime-path-symlink");
    let real_root = dir.child("public-real");
    let symlink_root = dir.child("public");
    fs::create_dir(&real_root).unwrap();
    std::os::unix::fs::symlink(&real_root, &symlink_root).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [web]
            root = "public"
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();

    assert!(matches!(
        error,
        ConfigLoadError::Validate(ConfigError::UnsafePath { field, .. })
            if field == "web.root"
    ));
}

#[cfg(unix)]
#[test]
fn accepts_final_php_root_symlink_when_enabled() {
    let dir = TestDir::new("php-root-final-symlink");
    let real_root = dir.child("releases/current");
    let symlink_root = dir.child("public");
    fs::create_dir_all(&real_root).unwrap();
    std::os::unix::fs::symlink(&real_root, &symlink_root).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "public"
            resolve_root_symlink = true

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(
        config.vhosts[0].php.root.as_deref(),
        Some(symlink_root.as_path())
    );
    assert!(config.vhosts[0].php.resolve_root_symlink);
}

#[cfg(unix)]
#[test]
fn rejects_existing_php_fpm_root_symlink() {
    let dir = TestDir::new("php-fpm-root-symlink");
    let local_root = dir.child("local-public");
    let fpm_real_root = dir.child("fpm-real-public");
    let fpm_symlink_root = dir.child("fpm-public");
    fs::create_dir_all(&local_root).unwrap();
    fs::create_dir_all(&fpm_real_root).unwrap();
    std::os::unix::fs::symlink(&fpm_real_root, &fpm_symlink_root).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "local-public"
            fpm_root = "fpm-public"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();

    assert!(matches!(
        error,
        ConfigLoadError::Validate(ConfigError::VhostSection {
            vhost,
            section: "php",
            source,
        }) if vhost == "php"
            && matches!(
                *source,
                ConfigError::UnsafePath { ref field, .. } if field == "vhosts.php.fpm_root"
            )
    ));
}

#[cfg(unix)]
#[test]
fn rejects_php_root_below_symlinked_parent_when_final_symlink_enabled() {
    let dir = TestDir::new("php-root-parent-symlink");
    let real_dir = dir.child("real");
    let symlink_dir = dir.child("linked");
    fs::create_dir_all(safe_child_path(&real_dir, "public")).unwrap();
    std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "linked/public"
            resolve_root_symlink = true

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();

    assert!(matches!(
        error,
        ConfigLoadError::Validate(ConfigError::VhostSection {
            vhost,
            section: "php",
            source,
        }) if vhost == "php"
            && matches!(
                *source,
                ConfigError::UnsafePath { ref field, .. } if field == "vhosts.php.root"
            )
    ));
}

#[test]
fn rejects_non_toml_config_file() {
    let dir = TestDir::new("non-toml-config");
    let path = dir.child("fluxheim.txt");
    fs::write(&path, "[server]\n").unwrap();

    let error = Config::load(Some(&path)).unwrap_err();

    assert!(matches!(error, ConfigLoadError::InvalidPath { .. }));
}

#[test]
fn rejects_oversized_config_file() {
    let dir = TestDir::new("oversized-config");
    let path = dir.child("fluxheim.toml");
    fs::write(&path, vec![b'#'; (MAX_CONFIG_FILE_BYTES + 1) as usize]).unwrap();

    let error = Config::load(Some(&path)).unwrap_err();

    assert!(
        matches!(error, ConfigLoadError::Read(error) if error.kind() == std::io::ErrorKind::InvalidData)
    );
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_config_file() {
    let dir = TestDir::new("config-file-symlink");
    let real_path = dir.child("real.toml");
    let symlink_path = dir.child("fluxheim.toml");
    fs::write(&real_path, "[server]\n").unwrap();
    std::os::unix::fs::symlink(&real_path, &symlink_path).unwrap();

    let error = Config::load(Some(&symlink_path)).unwrap_err();

    assert!(matches!(error, ConfigLoadError::InvalidPath { .. }));
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_config_directory_source() {
    let dir = TestDir::new("config-dir-symlink");
    let real_dir = dir.child("real");
    let symlink_dir = dir.child("linked");
    fs::create_dir(&real_dir).unwrap();
    fs::write(safe_child_path(&real_dir, "fluxheim.toml"), "[server]\n").unwrap();
    std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

    let error = Config::load(Some(&symlink_dir)).unwrap_err();

    assert!(matches!(error, ConfigLoadError::InvalidPath { .. }));
}

#[cfg(unix)]
#[test]
fn rejects_config_source_below_symlinked_directory() {
    let dir = TestDir::new("config-dir-parent-symlink");
    let real_dir = dir.child("real");
    let symlink_dir = dir.child("linked");
    fs::create_dir(&real_dir).unwrap();
    fs::write(safe_child_path(&real_dir, "fluxheim.toml"), "[server]\n").unwrap();
    std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

    let error = Config::load(Some(&safe_child_path(&symlink_dir, "fluxheim.toml"))).unwrap_err();

    assert!(matches!(error, ConfigLoadError::InvalidPath { .. }));
}

#[cfg(unix)]
#[test]
fn ignores_symlinked_config_directory_entries() {
    let dir = TestDir::new("config-dir-entry-symlink");
    let outside_dir = TestDir::new("config-dir-entry-symlink-outside");
    let outside = outside_dir.child("outside.toml");
    fs::write(
        dir.child("00-server.toml"),
        r#"
            [server]
            listen = ["127.0.0.1:19090"]
            "#,
    )
    .unwrap();
    fs::write(
        &outside,
        r#"
            [[vhosts]]
            name = "linked"
            hosts = ["linked.example"]
            "#,
    )
    .unwrap();
    std::os::unix::fs::symlink(&outside, dir.child("10-linked.toml")).unwrap();

    let config = Config::load(Some(dir.path())).unwrap();

    assert_eq!(config.server.listen, ["127.0.0.1:19090"]);
    assert!(config.vhosts.is_empty());
}
