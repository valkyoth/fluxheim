use super::super::*;

#[test]
fn rejects_invalid_cache_method() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            enabled = true
            methods = ["get"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheMethod {
            scope: "cache",
            method: "get".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_cache_extension() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            enabled = true
            image_extensions = [".jpg"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheImageExtension {
            scope: "cache",
            extension: ".jpg".to_owned()
        })
    );
}

#[test]
fn rejects_enabled_cache_without_storage_tier() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::CacheEnabledWithoutStorageTier { scope: "cache" })
    );
}

#[test]
fn requires_disk_cache_path_when_enabled() {
    let config: Config = toml::from_str(
        r#"
            [cache.disk]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::MissingCacheDiskPath { scope: "cache" })
    );
}

#[test]
fn parses_filesystem_disk_cache_backend() {
    let root = unique_temp_path("config-cache-filesystem-backend");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            backend = "filesystem"
            path = "{}"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(config.cache.disk.backend, CacheDiskBackend::Filesystem);
    assert_eq!(config.validate(), Ok(()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn accepts_storage_bin_backend() {
    let root = unique_temp_path("config-cache-storage-bin-backend");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            backend = "storage-bin"
            path = "{}"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(config.cache.disk.backend, CacheDiskBackend::StorageBin);
    assert_eq!(config.validate(), Ok(()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn parses_reserved_storage_bin_backend_options() {
    let root = unique_temp_path("config-cache-storage-bin-options");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true
            max_object_bytes = "32MiB"

            [cache.disk]
            enabled = true
            backend = "storage-bin"
            path = "{}"
            max_size_bytes = "2GiB"

            [cache.disk.storage_bin]
            bin_size_bytes = "512MiB"
            preallocate = true
            max_open_bins = 8
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(config.cache.disk.backend, CacheDiskBackend::StorageBin);
    assert_eq!(
        config.cache.disk.storage_bin.bin_size_bytes,
        ByteSize::from_bytes(512 * 1024 * 1024)
    );
    assert!(config.cache.disk.storage_bin.preallocate);
    assert_eq!(config.cache.disk.storage_bin.max_open_bins, 8);
    assert_eq!(config.validate(), Ok(()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn rejects_storage_bin_smaller_than_cache_object_limit() {
    let root = unique_temp_path("config-cache-storage-bin-too-small");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true
            max_object_bytes = "64MiB"

            [cache.disk]
            enabled = true
            backend = "storage-bin"
            path = "{}"
            max_size_bytes = "2GiB"

            [cache.disk.storage_bin]
            bin_size_bytes = "32MiB"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::CacheStorageBinSmallerThanMaxObject { scope: "cache" })
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn rejects_zero_storage_bin_max_open_bins() {
    let root = unique_temp_path("config-cache-storage-bin-open-bins");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            backend = "storage-bin"
            path = "{}"
            max_size_bytes = "2GiB"

            [cache.disk.storage_bin]
            max_open_bins = 0
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheStorageBinMaxOpenBins { scope: "cache" })
    );

    let _ = std::fs::remove_dir_all(root);
}
