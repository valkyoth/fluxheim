use super::*;

#[test]
fn documented_filesystem_recovery_currently_leaves_unindexed_files() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = storage_bin_config(&directory.path().canonicalize().unwrap());
    config.disk.backend = CacheDiskBackend::Filesystem;
    let cache = NativeDiskCache::from_config(&config).unwrap();
    cache
        .store(disk_cache_store_key("valid"), &disk_cache_entry(b"body"))
        .unwrap();
    drop(cache);
    let shard = directory.path().join("aa");
    std::fs::create_dir_all(&shard).unwrap();
    let corrupt = shard.join(format!("{}.fhc", "0".repeat(64)));
    let leftover = shard.join(".aaaaaaaaaaaaaaaaaaaaaaaa.tmp");
    std::fs::write(&corrupt, b"invalid object").unwrap();
    std::fs::write(&leftover, b"incomplete object").unwrap();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&leftover)
        .unwrap();
    file.set_modified(SystemTime::UNIX_EPOCH).unwrap();
    drop(file);

    let recovered = NativeDiskCache::from_config(&config).unwrap();
    assert_eq!(recovered.stats().entries, 1);
    assert!(recovered.get("valid", |_| None).is_some());
    // documented contract: these files remain outside tracked occupancy/eviction.
    assert!(corrupt.exists());
    assert!(leftover.exists());
    assert!(!directory.path().join(".fluxheim-disk-index-v1").exists());
}

#[test]
fn documented_storage_bin_missing_index_is_cold_without_object_salvage() {
    let directory = tempfile::tempdir().unwrap();
    let config = storage_bin_config(&directory.path().canonicalize().unwrap());
    let cache = NativeDiskCache::from_config(&config).unwrap();
    cache
        .store(disk_cache_store_key("valid"), &disk_cache_entry(b"body"))
        .unwrap();
    drop(cache);
    let index = directory.path().join(".fluxheim-storage-bin-index-v1");
    assert!(index.exists());
    std::fs::remove_file(index).unwrap();
    let recovered = NativeDiskCache::from_config(&config).unwrap();
    assert_eq!(recovered.stats().entries, 0);
    assert!(recovered.get("valid", |_| None).is_none());
    recovered
        .store(disk_cache_store_key("new"), &disk_cache_entry(b"new"))
        .unwrap();
    assert_eq!(&*recovered.get("new", |_| None).unwrap().body, b"new");
}
