use super::super::*;

#[test]
fn accepts_cache_disk_encryption_local_file() {
    let root = unique_temp_path("config-cache-encryption-local");
    let secrets = root.join("secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}/cache"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            algorithm = "aes-256-gcm"
            key_id = "cache-v1"
            key_file = "{}/cache-key"
            "#,
        root.display(),
        secrets.display()
    ))
    .unwrap();

    assert!(config.cache.disk.encryption.enabled);
    assert_eq!(
        config.cache.disk.encryption.provider,
        CacheDiskEncryptionProvider::Local
    );
    assert_eq!(config.validate(), Ok(()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn accepts_cache_disk_encryption_local_credential() {
    let root = unique_temp_path("config-cache-encryption-credential");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            key_credential = "fluxheim-cache-key"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(config.validate(), Ok(()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn rejects_enabled_cache_disk_encryption_without_secret_source() {
    let root = unique_temp_path("config-cache-encryption-missing-key");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope: "cache",
            field: "key",
            reason: "must be read from a file or systemd/container credential",
        })
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn rejects_conflicting_cache_disk_encryption_secret_sources() {
    let root = unique_temp_path("config-cache-encryption-conflict");
    let secrets = root.join("secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}/cache"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            key_file = "{}/cache-key"
            key_credential = "fluxheim-cache-key"
            "#,
        root.display(),
        secrets.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope: "cache",
            field: "key",
            reason: "cannot use more than one secret source",
        })
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn rejects_unimplemented_local_cache_disk_encryption_algorithm() {
    let root = unique_temp_path("config-cache-encryption-local-algorithm");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            algorithm = "xchacha20-poly1305"
            key_credential = "fluxheim-cache-key"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope: "cache",
            field: "disk.encryption.algorithm",
            reason: "local provider currently supports only \"aes-256-gcm\"",
        })
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn accepts_cache_disk_encryption_openbao_transit_provider() {
    let root = unique_temp_path("config-cache-encryption-openbao");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "openbao-transit"
            algorithm = "xchacha20-poly1305"

            [cache.disk.encryption.openbao]
            address = "https://openbao.internal.example"
            mount = "transit"
            key_name = "fluxheim-cache"
            token_credential = "openbao-token"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.cache.disk.encryption.provider,
        CacheDiskEncryptionProvider::OpenbaoTransit
    );
    assert_eq!(config.validate(), Ok(()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn rejects_plain_http_openbao_non_loopback_address() {
    let root = unique_temp_path("config-cache-encryption-openbao-http");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "openbao-transit"

            [cache.disk.encryption.openbao]
            address = "http://openbao.internal.example"
            mount = "transit"
            key_name = "fluxheim-cache"
            token_credential = "openbao-token"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope: "cache",
            field: "disk.encryption.openbao.address",
            reason: "must be an http://127.0.0.1, http://[::1], or https:// URL without credentials, query, or fragment",
        })
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn rejects_plain_http_openbao_malformed_ipv6_loopback_authority() {
    let root = unique_temp_path("config-cache-encryption-openbao-ipv6-tail");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "openbao-transit"

            [cache.disk.encryption.openbao]
            address = "http://[::1]attacker.example.test/v1"
            mount = "transit"
            key_name = "fluxheim-cache"
            token_credential = "openbao-token"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope: "cache",
            field: "disk.encryption.openbao.address",
            reason: "must be an http://127.0.0.1, http://[::1], or https:// URL without credentials, query, or fragment",
        })
    );

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn rejects_disk_cache_under_world_writable_parent() {
    let path = unique_world_writable_child("config-cache-world-writable", "cache");
    let config: Config = toml::from_str(&format!(
        r#"
            [cache.disk]
            enabled = true
            path = "{}"
            "#,
        path.display()
    ))
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "cache.disk.path"
    ));
}
