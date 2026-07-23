use super::native_http1_cache_backend::{
    acquire_native_storage_bin_lease, prepare_native_storage_bin_layout_locked,
};
use super::{NativeDiskCache, NativeDiskCacheBackend};
use fluxheim_config::{ByteSize, CacheConfig, CacheDiskBackend, CacheDiskStorageBinConfig};

const STORAGE_BIN_LEASE_CHILD_ROOT: &str = "FLUXHEIM_STORAGE_BIN_LEASE_CHILD_ROOT";
const STORAGE_BIN_LEASE_CHILD_MAX_BYTES: &str = "FLUXHEIM_STORAGE_BIN_LEASE_CHILD_MAX_BYTES";
const STORAGE_BIN_LEASE_CHILD_CONFIRMED: &str = "fluxheim-storage-bin-lease-child-confirmed";

fn storage_bin_config(path: &std::path::Path) -> CacheConfig {
    CacheConfig {
        enabled: true,
        max_object_bytes: ByteSize::from_bytes(1024),
        disk: fluxheim_config::CacheDiskConfig {
            enabled: true,
            backend: CacheDiskBackend::StorageBin,
            path: Some(path.to_path_buf()),
            max_size_bytes: ByteSize::from_bytes(1024 * 1024),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(64 * 1024),
                preallocate: false,
                max_open_bins: 4,
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn storage_bin_lease_child_process() {
    let Some(root) = std::env::var_os(STORAGE_BIN_LEASE_CHILD_ROOT) else {
        return;
    };
    let mut config = storage_bin_config(std::path::Path::new(&root));
    if let Ok(max_bytes) = std::env::var(STORAGE_BIN_LEASE_CHILD_MAX_BYTES) {
        config.disk.max_size_bytes = ByteSize::from_bytes(max_bytes.parse().unwrap());
    }

    let error = NativeDiskCacheBackend::from_config(&config).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    println!("{STORAGE_BIN_LEASE_CHILD_CONFIRMED}");
}

#[test]
fn storage_bin_lease_rejects_second_process() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("cache");
    let config = storage_bin_config(&root);
    let _cache = NativeDiskCache::from_config(&config).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("native_http1_cache::lease_tests::storage_bin_lease_child_process")
        .arg("--nocapture")
        .env(STORAGE_BIN_LEASE_CHILD_ROOT, &root)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains(STORAGE_BIN_LEASE_CHILD_CONFIRMED));
}

#[test]
fn storage_bin_loser_cannot_mutate_winner_layout() {
    let directory = tempfile::tempdir().unwrap();
    let configured_root = directory.path().join("cache");
    let winner_config = storage_bin_config(&configured_root);
    let root = super::prepare_native_storage_bin_root_for_lease(&winner_config).unwrap();
    let _lease = acquire_native_storage_bin_lease(&root).unwrap();

    assert!(!root.join(".fluxheim-storage-bin-v1").exists());
    assert!(!root.join("bins").exists());
    prepare_native_storage_bin_layout_locked(&winner_config, &root).unwrap();
    let manifest_path = root.join(".fluxheim-storage-bin-v1");
    let winning_manifest = std::fs::read(&manifest_path).unwrap();

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("native_http1_cache::lease_tests::storage_bin_lease_child_process")
        .arg("--nocapture")
        .env(STORAGE_BIN_LEASE_CHILD_ROOT, &root)
        .env(
            STORAGE_BIN_LEASE_CHILD_MAX_BYTES,
            (2 * 1024 * 1024).to_string(),
        )
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains(STORAGE_BIN_LEASE_CHILD_CONFIRMED));
    assert_eq!(std::fs::read(manifest_path).unwrap(), winning_manifest);
}
