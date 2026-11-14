use super::super::native_http1_cache_recovery::{FILESYSTEM_OBJECT_LIMIT, RECOVERY_ENTRY_LIMIT};
use super::*;

fn filesystem_config(root: &std::path::Path) -> CacheConfig {
    let mut config = storage_bin_config(root);
    config.disk.backend = CacheDiskBackend::Filesystem;
    config.disk.max_size_bytes = ByteSize::from_bytes(64 * 1024 * 1024);
    config
}

fn object_files(root: &std::path::Path) -> usize {
    std::fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().unwrap().is_dir())
        .map(|entry| std::fs::read_dir(entry.path()).unwrap().count())
        .sum()
}

#[test]
fn filesystem_admission_production_limit_reserves_recovery_headroom() {
    assert_eq!(FILESYSTEM_OBJECT_LIMIT, 57_344);
    assert_eq!(RECOVERY_ENTRY_LIMIT - FILESYSTEM_OBJECT_LIMIT, 8_192);
    let mut state = NativeDiskCacheState {
        filesystem_object_limit: Some(FILESYSTEM_OBJECT_LIMIT),
        ..Default::default()
    };
    for index in 0..FILESYSTEM_OBJECT_LIMIT {
        state.insert_object(
            format!("/asset.css?q={index}"),
            NativeDiskCacheRecord {
                location: NativeDiskCacheLocation::Filesystem(std::path::PathBuf::from("unused")),
                weight: 1,
                accessed_at: SystemTime::UNIX_EPOCH,
            },
        );
    }
    state.bytes = FILESYSTEM_OBJECT_LIMIT as u64;
    assert!(!state.key_admissible("new", 1, u64::MAX));
    assert!(state.key_admissible("/asset.css?q=0", 1, u64::MAX));
    state.filesystem_object_limit = None;
    assert!(
        state.key_admissible("new", 1, u64::MAX),
        "bins have no filesystem object cap"
    );
}

#[test]
#[ignore = "manual full-size filesystem inventory qualification"]
fn filesystem_admission_full_inventory_churn_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let config = filesystem_config(dir.path());
    let cache = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
    let limit = cache.with_state(|s| s.filesystem_object_limit.unwrap());
    assert!(limit > 57_000 && limit <= FILESYSTEM_OBJECT_LIMIT);
    let mut body = disk_cache_entry(b"tiny");
    body.expires_at = Instant::now() + Duration::from_secs(3600);
    std::thread::scope(|scope| {
        for writer in 0..8 {
            let (cache, body) = (&cache, &body);
            scope.spawn(move || {
                for index in 0..8_192 {
                    cache
                        .store(
                            disk_cache_store_key(&format!("/asset.css?q={writer}-{index}")),
                            body,
                        )
                        .unwrap();
                }
            });
        }
    });
    cache.store(disk_cache_store_key("last"), &body).unwrap();
    assert_eq!(cache.stats().entries, limit as u64);
    assert_eq!(object_files(dir.path()), limit);
    assert!(cache.stats().size_bytes < cache.max_bytes);
    drop(cache);
    let recovered = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
    assert_eq!(recovered.stats().entries, limit as u64);
    assert_eq!(&*recovered.get("last", |_| None).unwrap().body, b"tiny");
}

#[test]
fn filesystem_admission_reservations_bound_concurrent_writers_and_refund() {
    let dir = tempfile::tempdir().unwrap();
    let cache = NativeDiskCache::try_from_config(&filesystem_config(dir.path()))
        .unwrap()
        .unwrap();
    cache.with_state_mut(|state| state.filesystem_object_limit = Some(4));
    let barrier = std::sync::Barrier::new(16);
    let admitted = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for index in 0..16 {
            let (cache, barrier, admitted) = (&cache, &barrier, &admitted);
            scope.spawn(move || {
                barrier.wait();
                let reservation = cache.reserve_admission(&format!("key-{index}"), 100);
                if reservation.is_some() {
                    admitted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                barrier.wait();
                assert_eq!(cache.with_state(|state| state.pending_objects), 4);
                barrier.wait();
                drop(reservation);
            });
        }
    });
    assert_eq!(admitted.load(std::sync::atomic::Ordering::Relaxed), 4);
    assert_eq!(
        cache.with_state(|s| (s.pending_objects, s.pending_bytes)),
        (0, 0)
    );
    let full_bytes = cache.reserve_admission("bytes", cache.max_bytes).unwrap();
    assert!(cache.reserve_admission("overflow", 1).is_none());
    drop(full_bytes);
    assert!(cache.reserve_admission("refunded", 1).is_some());
}

#[test]
fn filesystem_admission_query_churn_evicts_and_restarts_plain_and_encrypted() {
    use std::io::Write as _;
    for encrypted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");
        let mut config = filesystem_config(&root);
        if encrypted {
            let key = dir.path().join("key");
            #[cfg(windows)]
            let mut file = fluxheim_config::fs_trust::create_confidential_file(&key).unwrap();
            #[cfg(unix)]
            let mut file = {
                use std::os::unix::fs::OpenOptionsExt as _;
                std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&key)
                    .unwrap()
            };
            file.write_all("42".repeat(32).as_bytes()).unwrap();
            config.disk.encryption.enabled = true;
            config.disk.encryption.key_file = Some(key);
        }
        let cache = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
        // Exercise the production eviction/reservation path with a small test
        // budget; the separate boundary test checks the full production value.
        cache.with_state_mut(|state| state.filesystem_object_limit = Some(8));
        std::thread::scope(|scope| {
            for writer in 0..8 {
                let cache = &cache;
                scope.spawn(move || {
                    for index in 0..24 {
                        let key = format!("/asset.css?q={writer}-{index}");
                        cache
                            .store(disk_cache_store_key(&key), &disk_cache_entry(b"tiny"))
                            .unwrap();
                        assert!(cache.stats().entries <= 8);
                    }
                });
            }
        });
        cache
            .store(disk_cache_store_key("last"), &disk_cache_entry(b"last"))
            .unwrap();
        let entries = cache.stats().entries;
        assert!(entries > 0 && entries <= 8);
        assert_eq!(object_files(&root), entries as usize);
        assert!(cache.stats().size_bytes < cache.max_bytes / 100);
        assert_eq!(
            cache.with_state(|s| (s.pending_objects, s.pending_bytes)),
            (0, 0)
        );
        drop(cache);
        for _ in 0..2 {
            let recovered = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
            assert_eq!(recovered.stats().entries, entries);
            assert_eq!(&*recovered.get("last", |_| None).unwrap().body, b"last");
        }
    }
}

#[test]
fn filesystem_admission_retained_entries_reduce_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("cache");
    let config = filesystem_config(&root);
    let cache = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
    let before = cache.with_state(|s| s.filesystem_object_limit.unwrap());
    drop(cache);
    std::fs::write(root.join("operator-note"), b"preserve").unwrap();
    let cache = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
    assert_eq!(
        cache.with_state(|s| s.filesystem_object_limit),
        Some(before - 1)
    );
    assert_eq!(
        std::fs::read(root.join("operator-note")).unwrap(),
        b"preserve"
    );
}

#[test]
fn filesystem_admission_failed_unlink_preserves_charge_and_stops_churn() {
    let dir = tempfile::tempdir().unwrap();
    let config = filesystem_config(dir.path());
    let cache = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
    cache.with_state_mut(|s| s.filesystem_object_limit = Some(1));
    cache
        .store(disk_cache_store_key("old"), &disk_cache_entry(b"old"))
        .unwrap();
    let record = cache.with_state(|s| s.objects["old"].clone());
    let NativeDiskCacheLocation::Filesystem(path) = record.location else {
        unreachable!()
    };
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap(); // Deterministic unlink failure on every OS.
    for index in 0..20 {
        cache
            .store(
                disk_cache_store_key(&format!("new-{index}")),
                &disk_cache_entry(b"new"),
            )
            .unwrap();
    }
    assert_eq!(cache.stats().entries, 1);
    assert_eq!(cache.stats().size_bytes, record.weight);
    assert!(cache.with_state(|s| s.filesystem_writes_blocked));
    assert_eq!(object_files(dir.path()), 1);
}

#[test]
fn filesystem_admission_write_failure_refunds_and_stops_more_temporaries() {
    let dir = tempfile::tempdir().unwrap();
    let cache = NativeDiskCache::try_from_config(&filesystem_config(dir.path()))
        .unwrap()
        .unwrap();
    cache
        .store(disk_cache_store_key("old"), &disk_cache_entry(b"old"))
        .unwrap();
    let location = cache.with_state(|s| s.objects["old"].location.clone());
    let NativeDiskCacheLocation::Filesystem(path) = location else {
        unreachable!()
    };
    assert!(cache.remove_combined("old"));
    std::fs::create_dir(&path).unwrap();
    assert!(
        cache
            .store(disk_cache_store_key("old"), &disk_cache_entry(b"new"))
            .is_err()
    );
    assert_eq!(
        cache.with_state(|s| (s.pending_objects, s.pending_bytes)),
        (0, 0)
    );
    for index in 0..20 {
        cache
            .store(
                disk_cache_store_key(&format!("new-{index}")),
                &disk_cache_entry(b"new"),
            )
            .unwrap();
    }
    assert_eq!(cache.stats().entries, 0);
    assert_eq!(object_files(dir.path()), 1);
}
