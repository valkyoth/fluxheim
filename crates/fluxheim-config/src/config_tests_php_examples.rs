use super::super::*;

#[test]
fn php_flat_root_recipe_exposes_only_explicit_static_asset() {
    let mut config: Config =
        toml::from_str(include_str!("../../../examples/php/flat-root.toml")).unwrap();
    let root = secure_test_dir("php-flat-root-guide");
    let vhost = &mut config.vhosts[0];
    vhost.php.root = Some(root.clone());
    vhost.routes[0].web.as_mut().unwrap().root = Some(root);
    vhost.validate(false).unwrap();
    assert!(vhost.web.root.is_none());
    assert_eq!(vhost.routes.len(), 1);
    assert_eq!(
        vhost.routes[0].path_exact.as_deref(),
        Some("/assets/style.css")
    );
    assert!(vhost.routes[0].path_prefix.is_none());
    assert!(vhost.php.deny_path_prefixes.contains(&"/uploads/".into()));
}

#[test]
fn php_external_guide_recipe_validates_and_preserves_wordpress_denies() {
    let mut config: Config =
        toml::from_str(include_str!("../../../examples/php/external.toml")).unwrap();
    let root = secure_test_dir("php-guide-external");
    config.vhosts[0].php.root = Some(root.clone());
    config.vhosts[0].web.root = Some(root);
    config.vhosts[0].php.apply_preset_defaults();
    config.vhosts[0].validate(false).unwrap();
    assert_eq!(
        config.vhosts[0].php.try_files,
        crate::PhpTryFilesMode::WordPress
    );
    assert!(
        config.vhosts[0]
            .php
            .deny_path_prefixes
            .contains(&"/uploads/".into())
    );
    assert_eq!(config.vhosts[0].php.max_in_flight, 4);
    assert!(
        !config.vhosts[0]
            .web
            .index_files
            .contains(&"index.php".into())
    );
    config.vhosts[0].php.fpm.allow_private_tcp_upstreams = false;
    assert!(config.vhosts[0].validate(false).is_err());
}

#[test]
fn php_guide_managed_recipe_has_platform_gated_validation() {
    let mut config: Config =
        toml::from_str(include_str!("../../../examples/php/managed.toml")).unwrap();
    config.vhosts[0].php.root = Some(secure_test_dir("php-guide-managed-root"));
    #[cfg(unix)]
    {
        config.vhosts[0].php.fpm.php_fpm_binary = Some(secure_test_executable("php-guide-binary"));
        config.vhosts[0].php.fpm.socket_dir = Some(secure_test_dir("php-guide-socket"));
        config.vhosts[0].php.validate("vhosts.php").unwrap();
        config.vhosts[0].php.fpm.tcp = Some("127.0.0.1:9000".into());
        assert!(config.vhosts[0].php.validate("vhosts.php").is_err());
    }
    #[cfg(not(unix))]
    assert!(config.vhosts[0].php.validate("vhosts.php").is_err());
}
