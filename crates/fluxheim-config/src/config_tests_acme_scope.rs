use super::*;
use crate::ValidationScope;

fn fixture(root: &Path) -> Config {
    let mut config: Config = toml::from_str(
        r#"
        [tls]
        enabled = true
        [tls.acme]
        enabled = true
        storage = "placeholder"
        contact_email = "test@example.test"
        [[vhosts]]
        name = "scope"
        hosts = ["scope.example.test"]
        [vhosts.tls]
        enabled = true
        [vhosts.tls.acme]
        enabled = true
        [vhosts.php]
        enabled = true
        [vhosts.php.fpm]
        mode = "managed"
        php_fpm_binary = "placeholder"
        socket_dir = "placeholder"
        [cache]
        enabled = true
        [cache.memory]
        enabled = true
    "#,
    )
    .unwrap();
    config.tls.acme.storage = Some(root.join("acme"));
    config.vhosts[0].php.fpm.php_fpm_binary = Some(root.join("missing-php-fpm"));
    config.vhosts[0].php.fpm.socket_dir = Some(root.join("php"));
    config
}

#[cfg(feature = "acme")]
#[test]
fn acme_scope_preserves_config_without_requiring_server_runtime() {
    let root = secure_test_dir("acme-scope-runtime");
    let config = fixture(&root);
    let before = config.clone();
    config.validate_for_scope(ValidationScope::Acme).unwrap();
    assert_eq!(config, before);
    assert!(config.validate_for_scope(ValidationScope::Server).is_err());
    assert!(config.validate().is_err());
    let path = root.join("fluxheim.toml");
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let loaded = Config::load_for_scope(Some(&path), ValidationScope::Acme).unwrap();
    assert!(loaded.cache.enabled);
    assert_eq!(loaded.vhosts[0].php.fpm, config.vhosts[0].php.fpm);
    assert!(Config::load(Some(&path)).is_err());
    assert!(Config::load_without_runtime_paths(Some(&path)).is_err());
}

#[cfg(not(feature = "acme"))]
#[test]
fn acme_scope_requires_acme_capability() {
    let config = fixture(&secure_test_dir("acme-scope-feature"));
    assert!(
        config
            .validate_for_scope(ValidationScope::Acme)
            .unwrap_err()
            .to_string()
            .contains("acme feature")
    );
}

#[cfg(feature = "acme")]
#[test]
fn acme_scope_rejects_invalid_consumed_configuration() {
    let config = fixture(&secure_test_dir("acme-scope-invalid"));
    let mut variants = Vec::new();
    let mut invalid = config.clone();
    invalid.tls.acme.storage = None;
    variants.push(invalid);
    let mut invalid = config.clone();
    invalid.tls.acme.issuers[0].directory_url = "http://issuer.test/directory".into();
    variants.push(invalid);
    let mut invalid = config.clone();
    invalid.tls.acme.default_issuer = "unknown".into();
    variants.push(invalid);
    let mut invalid = config.clone();
    invalid.tls.acme.renewal.retry_max_secs = 0;
    variants.push(invalid);
    let mut invalid = config.clone();
    invalid.vhosts[0].tls.acme.domains = vec!["bad/host".into()];
    variants.push(invalid);
    let mut invalid = config.clone();
    invalid.vhosts[0].hosts = vec!["bad/host".into()];
    variants.push(invalid);
    let mut invalid = config.clone();
    invalid.vhosts.push(invalid.vhosts[0].clone());
    variants.push(invalid);
    let mut invalid = config.clone();
    invalid.vhosts[0].name.clear();
    variants.push(invalid);
    let mut invalid = config.clone();
    invalid.tls.profile = TlsPolicyProfile::Modern;
    invalid.tls.min_protocol = Some(TlsProtocolVersion::Tls12);
    variants.push(invalid);
    let mut invalid = config.clone();
    invalid.tls.fips.required = true;
    variants.push(invalid);
    let mut invalid = config.clone();
    invalid.tls.acme.challenge = crate::AcmeChallenge::TlsAlpn01;
    variants.push(invalid);
    let mut invalid = config;
    invalid.vhosts[0].acme_challenge.enabled = true;
    variants.push(invalid);
    for (index, invalid) in variants.iter().enumerate() {
        assert!(
            invalid.validate_for_scope(ValidationScope::Acme).is_err(),
            "case {index}"
        );
    }
}

#[cfg(feature = "acme")]
#[test]
fn acme_scope_keeps_include_parsing_and_unknown_field_rejection() {
    let root = secure_test_dir("acme-scope-includes");
    fs::create_dir(root.join("conf.d")).unwrap();
    let path = root.join("fluxheim.toml");
    fs::write(&path, "include_conf_d = true\n").unwrap();
    let include = root.join("conf.d/site.toml");
    fs::write(&include, toml::to_string(&fixture(&root)).unwrap()).unwrap();
    assert_eq!(
        Config::load_for_scope(Some(&path), ValidationScope::Acme)
            .unwrap()
            .vhosts
            .len(),
        1
    );
    fs::write(&include, "unknown_field = true").unwrap();
    assert!(Config::load_for_scope(Some(&path), ValidationScope::Acme).is_err());
    fs::write(&include, "[invalid").unwrap();
    assert!(Config::load_for_scope(Some(&path), ValidationScope::Acme).is_err());
}

#[cfg(all(feature = "acme", unix))]
#[test]
fn acme_scope_keeps_path_and_include_trust_boundaries() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = secure_test_dir("acme-scope-trust");
    let config = fixture(&root);
    let real = root.join("real");
    fs::create_dir(&real).unwrap();
    let link = root.join("link");
    symlink(&real, &link).unwrap();
    let mut invalid = config.clone();
    invalid.tls.acme.storage = Some(link.join("acme"));
    assert!(invalid.validate_for_scope(ValidationScope::Acme).is_err());
    invalid.tls.acme.storage = Some(real.join("acme"));
    fs::set_permissions(&real, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(invalid.validate_for_scope(ValidationScope::Acme).is_err());
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    invalid = config.clone();
    invalid.tls.acme.issuers[0].ca_bundle_file = Some(link.join("ca.pem"));
    assert!(invalid.validate_for_scope(ValidationScope::Acme).is_err());
    invalid = config.clone();
    invalid.tls.acme.issuers[0].eab = Some(crate::AcmeExternalAccountBindingConfig {
        key_id_file: Some(link.join("kid")),
        hmac_key_file: Some(link.join("hmac")),
        key_id_env: None,
        key_id_credential: None,
        hmac_key_env: None,
        hmac_key_credential: None,
    });
    assert!(invalid.validate_for_scope(ValidationScope::Acme).is_err());
    let path = root.join("fluxheim.toml");
    fs::write(&path, "include_conf_d = true\n").unwrap();
    symlink(&real, root.join("conf.d")).unwrap();
    assert!(Config::load_for_scope(Some(&path), ValidationScope::Acme).is_err());

    let mut control = config;
    control.server.process.certificate_reload_sock = link.join("reload.sock");
    control.validate_for_scope(ValidationScope::Acme).unwrap();
    assert!(control.validate_certificate_reload_path().is_err());
    control.server.process.certificate_reload_sock = real.join("reload.sock");
    control.validate_certificate_reload_path().unwrap();
}
