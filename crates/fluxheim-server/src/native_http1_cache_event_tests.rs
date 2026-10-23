use super::*;

#[test]
fn operational_cache_read_corruption_is_a_miss_and_write_failure_is_reported() {
    let capture = fluxheim_observability::event_test_support::Capture::start();
    let directory = tempfile::tempdir().unwrap();
    let mut config = storage_bin_config(directory.path());
    config.disk.backend = CacheDiskBackend::Filesystem;
    config.disk.path = Some(directory.path().join("cache"));
    let cache = NativeDiskCache::from_config(&config).unwrap();
    let key = "SECRET-CANARY";
    cache
        .store(
            disk_cache_store_key(key),
            &disk_cache_entry(b"private body"),
        )
        .unwrap();
    let record = cache.with_state(|state| state.objects.get(key).unwrap().clone());
    let NativeDiskCacheLocation::Filesystem(path) = record.location else {
        panic!("filesystem fixture")
    };
    std::fs::write(&path, b"corrupt SECRET-CANARY").unwrap();
    assert!(cache.get_combined(key).is_none());
    capture.assert_reason("cache_read", 1);
    // The object's shard cannot be traversed as a directory any more.
    let shard = path.parent().unwrap();
    std::fs::remove_dir(shard).unwrap();
    std::fs::write(shard, b"not a directory").unwrap();
    assert!(
        cache
            .store(
                disk_cache_store_key(key),
                &disk_cache_entry(b"private body")
            )
            .is_err()
    );
    capture.assert_reason("cache_write", 1);
    assert!(
        capture
            .events()
            .iter()
            .all(|event| !event.to_string().contains(key))
    );
}

#[test]
fn operational_cache_encryption_setup_failure_does_not_emit_key_path() {
    let capture = fluxheim_observability::event_test_support::Capture::start();
    let directory = tempfile::tempdir().unwrap();
    let mut config = storage_bin_config(directory.path());
    config.disk.encryption.enabled = true;
    config.disk.encryption.key_file = Some(directory.path().join("SECRET-CANARY"));
    config.disk.encryption.key_id = Some("local".into());
    assert!(NativeDiskCache::from_config(&config).is_none());
    capture.assert_reason("cache_encryption", 1);
    assert!(
        capture
            .events()
            .iter()
            .all(|event| !event.to_string().contains("SECRET-CANARY"))
    );
}
