use super::super::*;

#[test]
fn rejects_too_many_tls_curve_preferences() {
    let curve_preferences = (0..=super::super::super::MAX_TLS_CURVE_PREFERENCES)
        .map(|_| "\"X25519\"")
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            curve_preferences = [{curve_preferences}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "tls.curve_preferences".to_owned(),
            max: super::super::super::MAX_TLS_CURVE_PREFERENCES,
        })
    );
}

#[test]
fn rejects_too_many_tls_cipher_suites() {
    let cipher_suites = (0..=super::super::super::MAX_TLS_CIPHER_SUITES)
        .map(|_| "\"TLS_AES_256_GCM_SHA384\"")
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            cipher_suites = [{cipher_suites}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "tls.cipher_suites".to_owned(),
            max: super::super::super::MAX_TLS_CIPHER_SUITES,
        })
    );
}

#[test]
fn rejects_too_many_tls_certificates() {
    let certificates = (0..=super::super::super::MAX_TLS_CERTIFICATES)
        .map(|index| {
            format!(
                r#"
                    [[tls.certificates]]
                    cert_path = "tests/fixtures/tls/cert-{index}.pem"
                    key_path = "tests/fixtures/tls/key-{index}.pem"
                    "#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let config: Config = toml::from_str(&certificates).unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "tls.certificates".to_owned(),
            max: super::super::super::MAX_TLS_CERTIFICATES,
        })
    );
}

#[test]
fn accepts_tls_client_auth_required_with_ca_bundle() {
    let config: Config = toml::from_str(
        r#"
            [tls.client_auth]
            mode = "required"
            ca_path = "tests/fixtures/tls/localhost-cert.pem"
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert_eq!(config.tls.client_auth.mode, TlsClientAuthMode::Required);
    assert_eq!(
        config.tls.client_auth.ca_path.as_deref(),
        Some(std::path::Path::new(
            "tests/fixtures/tls/localhost-cert.pem"
        ))
    );
}

#[test]
fn accepts_and_resolves_tls_client_auth_crl_path() {
    let directory = TestDir::new("tls-client-auth-crl");
    let config_path = directory.child("fluxheim.toml");
    std::fs::write(
        &config_path,
        r#"
            [tls.client_auth]
            mode = "required"
            ca_path = "tls/client-ca.pem"
            crl_path = "tls/client.crl.pem"
        "#,
    )
    .unwrap();

    let config = Config::load(Some(&config_path)).unwrap();
    let expected = directory.path().join("tls/client.crl.pem");

    assert_eq!(
        config.tls.client_auth.crl_path.as_deref(),
        Some(expected.as_path())
    );
}

#[test]
fn rejects_tls_client_auth_without_ca_bundle() {
    let config: Config = toml::from_str(
        r#"
            [tls.client_auth]
            mode = "optional"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.client_auth.ca_path",
            reason: "tls.client_auth.mode requires a client CA bundle path"
        })
    );
}

#[test]
fn rejects_tls_client_auth_crl_while_client_auth_is_off() {
    let config: Config = toml::from_str(
        r#"
            [tls.client_auth]
            crl_path = "tls/client.crl.pem"
        "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.client_auth.crl_path",
            reason: "tls.client_auth.crl_path requires client authentication to be enabled"
        })
    );
}

#[test]
fn rejects_removed_s2n_tls_backend() {
    let error = toml::from_str::<Config>(
        r#"
            [tls]
            backend = "s2n"
            "#,
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("s2n"));
    assert!(error.contains("unknown variant"));
}

#[test]
fn rejects_too_many_acme_issuers() {
    let issuers = (0..=super::super::super::MAX_ACME_ISSUERS)
        .map(|index| {
            format!(
                r#"
                    [[tls.acme.issuers]]
                    name = "issuer-{index}"
                    directory_url = "https://issuer-{index}.example.test/acme/directory"
                    "#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let config: Config = toml::from_str(&issuers).unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "tls.acme.issuers".to_owned(),
            max: super::super::super::MAX_ACME_ISSUERS,
        })
    );
}

#[test]
fn rejects_too_many_vhost_acme_domains() {
    let storage = secure_test_dir("config-vhost-acme-too-many-domains");
    let domains = (0..=super::super::super::MAX_VHOST_ACME_DOMAINS)
        .map(|index| format!("\"alias-{index}.example.test\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            default_issuer = "letsencrypt"

            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.tls.acme]
            enabled = true
            domains = [{domains}]
            "#,
        storage.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::VhostSection {
            vhost: "gateway".to_owned(),
            section: "tls",
            source: Box::new(ConfigError::InvalidConfigListLength {
                field: "vhosts.tls.acme.domains".to_owned(),
                max: super::super::super::MAX_VHOST_ACME_DOMAINS,
            })
        })
    );
}

#[test]
fn rejects_modern_tls_policy_with_tls12_override() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            profile = "modern"
            min_protocol = "tls1.2"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.min_protocol",
            reason: "tls.profile = \"modern\" requires min_protocol = \"tls1.3\""
        })
    );
}

#[test]
fn rejects_tls12_cipher_suites_with_tls13_minimum() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            min_protocol = "tls1.3"
            cipher_suites = ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.cipher_suites",
            reason: "TLS 1.2 cipher suites cannot be used when min_protocol = \"tls1.3\""
        })
    );
}

#[test]
fn rejects_removed_boringssl_tls_backend() {
    let error = toml::from_str::<Config>(
        r#"
            [tls]
            backend = "boringssl"
            "#,
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("boringssl"));
    assert!(error.contains("unknown variant"));
}

#[test]
fn allows_intermediate_profile_with_tls13_minimum_when_ciphers_are_implicit() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            profile = "intermediate"
            min_protocol = "VersionTLS13"
            "#,
    )
    .unwrap();

    assert_eq!(config.tls.profile, TlsPolicyProfile::Intermediate);
    assert_eq!(
        config.tls.effective_min_protocol(),
        TlsProtocolVersion::Tls13
    );
    config.validate().unwrap();
}

#[cfg(unix)]
#[test]
fn rejects_tls_certificate_paths_under_world_writable_parent() {
    let cert_path = unique_world_writable_child("config-tls-world-writable", "fullchain.pem");
    let key_path = safe_child_path(&secure_test_dir("config-tls-world-writable-key"), "key.pem");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            enabled = true

            [[tls.certificates]]
            cert_path = "{}"
            key_path = "{}"
            "#,
        cert_path.display(),
        key_path.display()
    ))
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "tls.certificates.cert_path"
    ));
}

#[cfg(unix)]
#[test]
fn rejects_tls_certificate_paths_under_group_writable_parent() {
    let cert_path = unique_group_writable_child("config-tls-group-writable", "fullchain.pem");
    let key_path = safe_child_path(&secure_test_dir("config-tls-group-writable-key"), "key.pem");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            enabled = true

            [[tls.certificates]]
            cert_path = "{}"
            key_path = "{}"
            "#,
        cert_path.display(),
        key_path.display()
    ))
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "tls.certificates.cert_path"
    ));
}
