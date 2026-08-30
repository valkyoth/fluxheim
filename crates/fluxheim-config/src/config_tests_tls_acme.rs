use super::super::*;

#[cfg(unix)]
#[test]
fn rejects_acme_paths_under_world_writable_parent() {
    let storage = unique_world_writable_child("config-acme-world-writable", "acme");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls.acme]
            enabled = true
            storage = '{}'
            contact_email = "admin@example.test"
            default_issuer = "actalis"

            [[tls.acme.issuers]]
            name = "actalis"
            directory_url = "https://acme-api.actalis.com/acme/directory"

            [tls.acme.issuers.eab]
            key_id_env = "FLUXHEIM_ACTALIS_EAB_KID"
            hmac_key_env = "FLUXHEIM_ACTALIS_EAB_HMAC_KEY"
            "#,
        storage.display()
    ))
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "tls.acme.storage"
    ));
}

#[test]
fn path_inspection_error_mentions_permissions_and_service_user() {
    let error = ConfigError::PathInspectionFailed {
            field: "tls.acme.storage".to_owned(),
            path: PathBuf::from("/var/lib/fluxheim/acme"),
            reason: "permission denied while checking path ownership and symlinks: Permission denied (os error 13)".to_owned(),
        };
    let message = error.to_string();
    assert!(message.contains("could not be inspected"));
    assert!(message.contains("permission denied"));
    assert!(message.contains("Fluxheim service user"));
}

#[cfg(unix)]
#[test]
fn rejects_acme_eab_secret_paths_under_world_writable_parent() {
    let storage = secure_test_dir("config-acme-eab-storage");
    let key_id_file = unique_world_writable_child("config-acme-eab-world-writable", "key-id");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls.acme]
            enabled = true
            storage = '{}'
            contact_email = "admin@example.test"
            default_issuer = "actalis"

            [[tls.acme.issuers]]
            name = "actalis"
            directory_url = "https://acme-api.actalis.com/acme/directory"

            [tls.acme.issuers.eab]
            key_id_file = '{}'
            hmac_key_env = "FLUXHEIM_ACTALIS_EAB_HMAC_KEY"
            "#,
        storage.display(),
        key_id_file.display()
    ))
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnsafePath { field, .. })
            if field == "tls.acme.issuers.actalis.eab.key_id_file"
    ));
}

#[test]
fn accepts_acme_eab_credential_sources() {
    let storage = secure_test_dir("config-acme-eab-credentials");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls.acme]
            enabled = true
            storage = '{}'
            contact_email = "admin@example.test"
            default_issuer = "actalis"

            [[tls.acme.issuers]]
            name = "actalis"
            directory_url = "https://acme-api.actalis.com/acme/directory"

            [tls.acme.issuers.eab]
            key_id_credential = "actalis-eab-kid"
            hmac_key_credential = "actalis-eab-hmac-key"
            "#,
        storage.display()
    ))
    .unwrap();

    let eab = config.tls.acme.issuers[0].eab.as_ref().unwrap();
    assert_eq!(eab.key_id_credential.as_deref(), Some("actalis-eab-kid"));
    assert_eq!(
        eab.hmac_key_credential.as_deref(),
        Some("actalis-eab-hmac-key")
    );
    config.validate().unwrap();
}

#[test]
fn rejects_unsafe_acme_eab_credential_source() {
    let storage = secure_test_dir("config-acme-eab-unsafe-credential");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls.acme]
            enabled = true
            storage = '{}'
            contact_email = "admin@example.test"
            default_issuer = "actalis"

            [[tls.acme.issuers]]
            name = "actalis"
            directory_url = "https://acme-api.actalis.com/acme/directory"

            [tls.acme.issuers.eab]
            key_id_credential = "../actalis-eab-kid"
            hmac_key_credential = "actalis-eab-hmac-key"
            "#,
        storage.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidAcmeEabCredentialName {
            issuer: "actalis".to_owned(),
            field: "key_id",
            credential: "../actalis-eab-kid".to_owned(),
        })
    );
}

#[test]
fn rejects_zero_acme_renewal_duration() {
    let config: Config = toml::from_str(
        r#"
            [tls.acme.renewal]
            renew_before_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidAcmeRenewalDuration {
            field: "tls.acme.renewal.renew_before_secs"
        })
    );
}

#[test]
fn rejects_local_acme_renew_after_datetime() {
    let config: Config = toml::from_str(
        r#"
            [tls.acme.renewal]
            renew_after = 2026-06-01T00:00:00
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidAcmeRenewAfterDatetime)
    );
}

#[test]
fn rejects_acme_renewal_retry_initial_over_max() {
    let config: Config = toml::from_str(
        r#"
            [tls.acme.renewal]
            retry_initial_secs = 60
            retry_max_secs = 30
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::AcmeRenewalRetryInitialExceedsMax)
    );
}

#[test]
fn rejects_enabled_acme_without_storage() {
    let config: Config = toml::from_str(
        r#"
            [tls.acme]
            enabled = true
            contact_email = "admin@example.test"
            "#,
    )
    .unwrap();

    assert_eq!(config.validate(), Err(ConfigError::MissingAcmeStorage));
}

#[test]
fn rejects_vhost_tls_without_certificate_source() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.tls]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::VhostSection {
            vhost: "example".to_owned(),
            section: "tls",
            source: Box::new(ConfigError::TlsEnabledWithoutCertificateSource {
                scope: "vhosts.tls"
            })
        })
    );
}

#[test]
fn rejects_vhost_acme_without_global_acme() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.tls.acme]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::VhostSection {
            vhost: "example".to_owned(),
            section: "tls",
            source: Box::new(ConfigError::VhostAcmeWithoutGlobalAcme {
                scope: "vhosts.tls"
            })
        })
    );
}

#[test]
fn accepts_vhost_acme_inheriting_exact_hosts() {
    let storage = secure_test_dir("config-vhost-acme-exact-hosts");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls.acme]
            enabled = true
            storage = '{}'
            contact_email = "admin@example.test"

            [[vhosts]]
            name = "example"
            hosts = ["example.test", "*.example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.tls.acme]
            enabled = true
            "#,
        storage.display()
    ))
    .unwrap();

    config.validate().unwrap();
}

#[cfg(feature = "acme")]
#[test]
fn accepts_tls_alias_vhost_covered_by_managed_acme_san() {
    let storage = secure_test_dir("config-vhost-acme-san-alias");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls.acme]
            enabled = true
            storage = '{}'
            contact_email = "admin@example.test"

            [[vhosts]]
            name = "apex"
            hosts = ["example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.tls.acme]
            enabled = true
            domains = ["example.test", "www.example.test"]

            [[vhosts]]
            name = "www"
            hosts = ["www.example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.redirect]
            enabled = true
            to = "https://example.test{{uri}}"
            "#,
        storage.display()
    ))
    .unwrap();

    config.validate().unwrap();
}

#[test]
fn rejects_duplicate_vhost_acme_domains() {
    let storage = secure_test_dir("config-vhost-acme-duplicate-domains");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls.acme]
            enabled = true
            storage = '{}'
            contact_email = "admin@example.test"

            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.tls.acme]
            enabled = true
            domains = ["Example.Test", "example.test"]
            "#,
        storage.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::VhostSection {
            vhost: "example".to_owned(),
            section: "tls",
            source: Box::new(ConfigError::DuplicateVhostAcmeDomain {
                scope: "vhosts.tls",
                domain: "example.test".to_owned(),
            })
        })
    );
}

#[test]
fn rejects_terms_acceptance_without_the_reviewed_url() {
    let mut config = Config::default();
    config.tls.acme.issuers[0].terms_of_service_agreed = true;
    config.tls.acme.issuers[0].terms_of_service_url = None;

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidAcmeTermsOfServiceAcceptance {
            issuer: "letsencrypt".to_owned(),
        })
    );
}

#[test]
fn rejects_unadvertised_terms_override_without_explicit_acceptance() {
    let mut config = Config::default();
    config.tls.acme.issuers[0].allow_unadvertised_terms_of_service = true;

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidAcmeTermsOfServiceAcceptance {
            issuer: "letsencrypt".to_owned(),
        })
    );
}
