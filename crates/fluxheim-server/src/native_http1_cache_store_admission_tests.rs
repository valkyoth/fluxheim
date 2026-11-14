use super::super::native_http1_cache_state::native_disk_cache_mutation_lock_stripe;
use super::*;
use crate::blocking_work::{
    NativeBlockingWorkClass, exhaust_disk_cache_blocking_work_for_test,
    try_acquire_request_blocking_work,
};
use std::io::Write as _;

fn configure_encryption(config: &mut CacheConfig, directory: &std::path::Path) {
    let key = directory.join("key");
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
    drop(file);
    config.disk.encryption.enabled = true;
    config.disk.encryption.key_file = Some(key);
}

#[test]
fn impossible_bin_store_preserves_objects_accounting_and_restart() {
    for encrypted in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let mut config = storage_bin_config(&directory.path().join("cache"));
        config.max_object_bytes = ByteSize::from_bytes(4096);
        config.disk.storage_bin.bin_size_bytes = ByteSize::from_bytes(4096);
        if encrypted {
            configure_encryption(&mut config, directory.path());
        }
        let cache = NativeDiskCache::from_config(&config).unwrap();
        let keys: Vec<_> = (0..8).map(|n| format!("asset-{n}")).collect();
        for key in &keys {
            cache
                .store(disk_cache_store_key(key), &disk_cache_entry(b"kept"))
                .unwrap();
        }
        let bytes = cache.stats().size_bytes;
        let identities = cache.with_state(|state| {
            keys.iter()
                .map(|key| state.objects[key].identity.clone())
                .collect::<Vec<_>>()
        });
        let mut too_large = disk_cache_entry(b"");
        too_large.body = Arc::from(vec![42; 4096]);
        too_large.body_sha256 = Arc::new(native_cache_body_sha256(&too_large.body));
        too_large.content_length = Some(4096);
        // A permitted body alone fills a bin; serialized/encrypted overhead does not fit.
        for key in ["new-key", keys[0].as_str()] {
            cache.store(disk_cache_store_key(key), &too_large).unwrap();
        }
        // The guard also includes response headers, not only body length.
        let mut headers_too_large = disk_cache_entry(b"small");
        headers_too_large
            .headers
            .push(("x-large".into(), "x".repeat(4096)));
        cache
            .store(disk_cache_store_key("headers"), &headers_too_large)
            .unwrap();
        assert_eq!(cache.stats().entries, 8);
        assert_eq!(cache.stats().size_bytes, bytes);
        cache.with_state(|state| {
            assert_eq!((state.pending_objects, state.pending_bytes), (0, 0));
            for (key, identity) in keys.iter().zip(&identities) {
                assert!(Arc::ptr_eq(&state.objects[key].identity, identity));
            }
        });
        for key in &keys {
            assert_eq!(&*cache.get_combined(key).unwrap().body, b"kept");
        }
        drop(cache);
        let cache = NativeDiskCache::from_config(&config).unwrap();
        assert_eq!(cache.stats().entries, 8);
        assert_eq!(cache.stats().size_bytes, bytes);
        for key in &keys {
            assert_eq!(&*cache.get_combined(key).unwrap().body, b"kept");
        }
        cache
            .store(disk_cache_store_key("new-key"), &disk_cache_entry(b"fits"))
            .unwrap();
        assert_eq!(&*cache.get_combined("new-key").unwrap().body, b"fits");
    }
}

#[test]
fn encoded_object_exactly_one_bin_is_admitted() {
    for encrypted in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let mut config = storage_bin_config(&directory.path().join("probe"));
        if encrypted {
            configure_encryption(&mut config, directory.path());
        }
        let entry = disk_cache_entry(b"boundary");
        let cache = NativeDiskCache::from_config(&config).unwrap();
        cache.store(disk_cache_store_key("key"), &entry).unwrap();
        let encoded_size = cache.stats().size_bytes;
        drop(cache);
        config.disk.path = Some(directory.path().join("exact"));
        config.disk.storage_bin.bin_size_bytes = ByteSize::from_bytes(encoded_size);
        config.disk.max_size_bytes = ByteSize::from_bytes(encoded_size);
        let cache = NativeDiskCache::from_config(&config).unwrap();
        cache.store(disk_cache_store_key("key"), &entry).unwrap();
        assert_eq!(cache.stats().entries, 1);
        assert_eq!(cache.stats().size_bytes, encoded_size);
        assert_eq!(&*cache.get_combined("key").unwrap().body, b"boundary");
    }
}

fn colliding_keys(key: &str) -> Vec<String> {
    let stripe = native_disk_cache_mutation_lock_stripe(key);
    (0..100_000)
        .map(|n| format!("candidate-{n}"))
        .filter(|candidate| native_disk_cache_mutation_lock_stripe(candidate) == stripe)
        .take(32)
        .collect()
}

fn rejected_read_validation_does_not_wait_or_remove_a_new_generation() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let directory = tempfile::tempdir().unwrap();
        let mut config = storage_bin_config(directory.path());
        config.disk.backend = backend;
        let cache = NativeDiskCache::from_config(&config).unwrap();
        cache
            .store(disk_cache_store_key("key"), &disk_cache_entry(b"old"))
            .unwrap();
        let old = cache.with_state(|state| state.objects["key"].clone());
        let guard = cache.try_lock_key_read("key").unwrap();
        let result = cache.lookup_combined_map::<()>("key", |_| None);
        drop(guard);
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(cache.stats().entries, 1);
        cache
            .store(disk_cache_store_key("key"), &disk_cache_entry(b"new"))
            .unwrap();
        assert!(!cache.remove_if_unchanged("key", &old).unwrap());
        assert_eq!(&*cache.get_combined("key").unwrap().body, b"new");
        assert!(
            cache
                .lookup_combined_map::<()>("key", |_| None)
                .unwrap()
                .is_none()
        );
        assert_eq!(cache.stats().entries, 0);
    }
}

#[test]
fn contended_store_child() {
    if std::env::var_os("FLUXHEIM_CONTENDED_STORE_CHILD").is_none() {
        return;
    }
    rejected_read_validation_does_not_wait_or_remove_a_new_generation();
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let directory = tempfile::tempdir().unwrap();
        let mut config = storage_bin_config(directory.path());
        config.disk.backend = backend;
        let cache = NativeDiskCache::from_config(&config).unwrap();
        let held_key = "held";
        let independent = (0..1000)
            .map(|n| format!("independent-{n}"))
            .find(|key| {
                native_disk_cache_mutation_lock_stripe(key)
                    != native_disk_cache_mutation_lock_stripe(held_key)
            })
            .unwrap();
        cache
            .store(disk_cache_store_key(held_key), &disk_cache_entry(b"held"))
            .unwrap();
        cache
            .store(
                disk_cache_store_key(&independent),
                &disk_cache_entry(b"independent"),
            )
            .unwrap();
        let bytes = cache.stats().size_bytes;
        let keys = colliding_keys(held_key);
        assert_eq!(keys.len(), 32);
        // Even a full cache must check incoming-key contention before evicting.
        cache.with_state_mut(|state| state.filesystem_object_limit = Some(2));
        for writer_held in [false, true] {
            let read_guard = (!writer_held).then(|| cache.try_lock_key_read(held_key).unwrap());
            let write_guard = writer_held.then(|| cache.lock_key_mutation(held_key));
            // Hold all actual global disk-worker permits before starting the writers.
            let permits = exhaust_disk_cache_blocking_work_for_test();
            let (sent, received) = std::sync::mpsc::channel();
            std::thread::scope(|scope| {
                for (key, permit) in keys.iter().zip(permits) {
                    let (cache, sent) = (&cache, sent.clone());
                    scope.spawn(move || {
                        let result =
                            cache.store(disk_cache_store_key(key), &disk_cache_entry(b"skip"));
                        drop(permit);
                        sent.send(result).unwrap();
                    });
                }
                // The parent watchdog kills this child if a regression blocks here.
                for _ in 0..32 {
                    received
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap()
                        .unwrap();
                }
                let permit =
                    try_acquire_request_blocking_work(NativeBlockingWorkClass::DiskCache).unwrap();
                assert_eq!(
                    &*cache.lookup_combined(&independent).unwrap().unwrap().body,
                    b"independent"
                );
                drop(permit);
                assert_eq!(exhaust_disk_cache_blocking_work_for_test().len(), 32);
                assert_eq!(cache.stats().entries, 2);
                assert_eq!(cache.stats().size_bytes, bytes);
            });
            drop(read_guard);
            drop(write_guard);
        }
        // Force eviction of a busy oldest victim, on a different stripe than the incoming key.
        cache.with_state_mut(|state| {
            state.touch_object(held_key, SystemTime::UNIX_EPOCH);
            state.filesystem_object_limit = Some(2);
        });
        let incoming = format!("{independent}-new");
        assert_ne!(
            native_disk_cache_mutation_lock_stripe(&incoming),
            native_disk_cache_mutation_lock_stripe(held_key)
        );
        for writer_held in [false, true] {
            let read_guard = (!writer_held).then(|| cache.try_lock_key_read(held_key).unwrap());
            let write_guard = writer_held.then(|| cache.lock_key_mutation(held_key));
            let permit =
                try_acquire_request_blocking_work(NativeBlockingWorkClass::DiskCache).unwrap();
            cache
                .store(disk_cache_store_key(&incoming), &disk_cache_entry(b"skip"))
                .unwrap();
            drop(permit);
            assert_eq!(cache.stats().entries, 2);
            assert_eq!(cache.stats().size_bytes, bytes);
            assert_eq!(
                cache.with_state(|state| (state.pending_objects, state.pending_bytes)),
                (0, 0)
            );
            assert!(cache.lookup_combined(&incoming).unwrap().is_none());
            assert_eq!(exhaust_disk_cache_blocking_work_for_test().len(), 32);
            drop(read_guard);
            drop(write_guard);
        }
        cache
            .store(disk_cache_store_key(&incoming), &disk_cache_entry(b"works"))
            .unwrap();
        assert_eq!(&*cache.get_combined(&incoming).unwrap().body, b"works");
    }
}

#[test]
fn contended_stores_and_evictions_release_disk_workers() {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_http1_cache::tests::store_admission::contended_store_child",
            "--nocapture",
        ])
        .env("FLUXHEIM_CONTENDED_STORE_CHILD", "1")
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("contended cache stores did not release disk workers");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
