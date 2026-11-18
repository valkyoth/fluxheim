use super::*;

#[test]
fn index_capacity_rejects_new_keys_but_allows_replacement_and_purge_at_capacity() {
    for encrypted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut config = storage_bin_config(&dir.path().join("cache"));
        if encrypted {
            super::store_admission::configure_encryption(&mut config, dir.path());
        }
        let cache = NativeDiskCache::from_config(&config).unwrap();
        let weight = fluxheim_cache::StorageBinIndexBudget::maximum_row_bytes(if encrypted {
            64
        } else {
            1
        })
        .unwrap();
        cache.with_state_mut(|s| s.bin_index.as_mut().unwrap().limit = 2 * weight);
        for k in ["A", "B"] {
            cache
                .store(disk_cache_store_key(k), &disk_cache_entry(b"first"))
                .unwrap();
        }
        cache.checkpoint_for_test();
        let free = cache.stats().free_size_bytes;
        cache
            .store(disk_cache_store_key("C"), &disk_cache_entry(b"rejected"))
            .unwrap();
        assert!(cache.get_combined("C").is_none());
        assert_eq!(free, cache.stats().free_size_bytes);
        cache
            .store(disk_cache_store_key("B"), &disk_cache_entry(b"replaced"))
            .unwrap();
        assert_eq!(&*cache.get_combined("B").unwrap().body, b"replaced");
        assert!(cache.remove_combined("A"));
        drop(cache);
        let cache = NativeDiskCache::from_config(&config).unwrap();
        assert!(cache.get_combined("A").is_none());
        assert_eq!(&*cache.get_combined("B").unwrap().body, b"replaced");
        cache.with_state_mut(|s| s.bin_index.as_mut().unwrap().limit = 2 * weight);
        cache
            .store(disk_cache_store_key("C"), &disk_cache_entry(b"admitted"))
            .unwrap();
        cache
            .store(disk_cache_store_key("D"), &disk_cache_entry(b"full"))
            .unwrap();
        assert!(cache.get_combined("C").is_some());
        assert!(cache.get_combined("D").is_none());
    }
}

#[test]
fn invalid_bin_snapshot_cannot_restore_hard_purged_record_from_shared_extent_file() {
    for encrypted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut config = storage_bin_config(&dir.path().join("cache"));
        if encrypted {
            super::store_admission::configure_encryption(&mut config, dir.path());
        }
        let cache = NativeDiskCache::from_config(&config).unwrap();
        for key in ["A", "B"] {
            cache
                .store(disk_cache_store_key(key), &disk_cache_entry(b"body"))
                .unwrap();
        }
        cache.checkpoint_for_test();
        let NativeDiskCacheBackend::StorageBin(bin) = &cache.backend else {
            unreachable!()
        };
        let initial = fluxheim_cache::read_storage_bin_index(&bin.layout).unwrap();
        assert_eq!(initial.len(), 2);
        assert_eq!(initial[0].location.bin_id, initial[1].location.bin_id);
        // Inject an invariant failure directly, independently of normal admission.
        cache.with_state_mut(|s| {
            let mut bad = s.objects["B"].clone();
            if encrypted {
                let NativeDiskCacheLocation::StorageBin(location) = &mut bad.location else {
                    unreachable!()
                };
                location.len = 0;
            }
            s.insert_object("x".repeat(32 * 1024 + 1), bad);
        });
        assert!(cache.remove_combined("A"));
        drop(cache);
        let cache = NativeDiskCache::from_config(&config).unwrap();
        assert!(cache.get_combined("A").is_none());
        assert_eq!(cache.stats().entries, 0);
        cache
            .store(disk_cache_store_key("new"), &disk_cache_entry(b"new"))
            .unwrap();
        assert!(cache.get_combined("new").is_some());
    }
}

#[test]
fn recovery_retains_only_rows_with_future_checkpoint_headroom() {
    let dir = tempfile::tempdir().unwrap();
    let cache =
        NativeDiskCache::from_config(&storage_bin_config(&dir.path().join("cache"))).unwrap();
    for key in ["A", "B"] {
        cache
            .store(disk_cache_store_key(key), &disk_cache_entry(b"body"))
            .unwrap();
    }
    cache.checkpoint_for_test();
    let mut index = super::super::native_http1_cache_admission::BinIndexAdmission::new(false);
    index.limit = fluxheim_cache::StorageBinIndexBudget::maximum_row_bytes(1).unwrap();
    let mut recovered = NativeDiskCacheState {
        bin_index: Some(index),
        ..Default::default()
    };
    cache.rebuild_storage_bin_backend(&mut recovered).unwrap();
    assert_eq!(recovered.objects.len(), 1);
    assert!(recovered.objects.contains_key("A"));
    assert_eq!(recovered.purge_index.len(), 1);
    assert!(!recovered.bin_index_admissible("B"));
    cache.with_state_mut(|s| *s = recovered);
    let stats = cache.stats();
    assert_eq!(
        stats.allocated_size_bytes - stats.free_size_bytes,
        stats.size_bytes
    );
    cache.checkpoint_for_test();
    let NativeDiskCacheBackend::StorageBin(bin) = &cache.backend else {
        unreachable!()
    };
    assert_eq!(
        fluxheim_cache::read_storage_bin_index(&bin.layout)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn concurrent_bin_index_reservations_share_and_refund_the_last_row() {
    let dir = tempfile::tempdir().unwrap();
    let cache =
        NativeDiskCache::from_config(&storage_bin_config(&dir.path().join("cache"))).unwrap();
    cache.with_state_mut(|s| {
        s.bin_index.as_mut().unwrap().limit =
            fluxheim_cache::StorageBinIndexBudget::maximum_row_bytes(1).unwrap()
    });
    let barrier = std::sync::Barrier::new(8);
    let admitted = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for n in 0..8 {
            let (cache, barrier, admitted) = (&cache, &barrier, &admitted);
            scope.spawn(move || {
                barrier.wait();
                let reservation = cache.reserve_bin_index(&n.to_string());
                if reservation.is_some() {
                    admitted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                barrier.wait();
                drop(reservation);
            });
        }
    });
    assert_eq!(admitted.into_inner(), 1);
    assert!(cache.reserve_bin_index("z").is_some());
}

#[test]
fn storage_bin_busy_read_keeps_object_accounting_and_purge_index() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = storage_bin_config(&directory.path().join("cache"));
    config.disk.storage_bin.max_open_bins = 1;
    let cache = NativeDiskCache::from_config(&config).unwrap();
    cache
        .store(
            disk_cache_store_key("retained"),
            &disk_cache_entry(b"original"),
        )
        .unwrap();
    let bytes = cache.with_state(|state| state.bytes);
    for _ in 0..32 {
        assert_eq!(
            cache
                .get_combined_with_reader("retained", |_| {
                    Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                })
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(cache.with_state(|state| state.bytes), bytes);
        assert!(cache.with_state(|state| state.objects.contains_key("retained")));
        assert_eq!(
            cache
                .with_state(|state| state.purge_index.combined_keys_for_primary("retained"))
                .len(),
            1
        );
    }
    assert_eq!(&*cache.get_combined("retained").unwrap().body, b"original");
    assert!(cache.remove_combined("retained"));
    cache
        .store(
            disk_cache_store_key("replacement"),
            &disk_cache_entry(b"new"),
        )
        .unwrap();
    assert_eq!(&*cache.get_combined("replacement").unwrap().body, b"new");
    drop(cache);
    let reopened = NativeDiskCache::from_config(&config).unwrap();
    assert_eq!(&*reopened.get_combined("replacement").unwrap().body, b"new");
}

#[test]
fn storage_bin_read_keeps_allocation_until_purge_can_reclaim() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Arc::new(
        NativeDiskCache::from_config(&storage_bin_config(&directory.path().join("cache"))).unwrap(),
    );
    cache
        .store(disk_cache_store_key("held"), &disk_cache_entry(b"original"))
        .unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let reader_cache = Arc::clone(&cache);
    let reader = std::thread::spawn(move || {
        reader_cache
            .get_combined_with_reader("held", |record| {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                reader_cache.read_record(record)
            })
            .unwrap()
            .unwrap()
    });
    entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let purge_cache = Arc::clone(&cache);
    let purge = std::thread::spawn(move || {
        assert!(purge_cache.remove_combined("held"));
        done_tx.send(()).unwrap();
    });
    assert!(done_rx.recv_timeout(Duration::from_millis(50)).is_err());
    assert_eq!(cache.stats().entries, 1);
    release_tx.send(()).unwrap();
    assert_eq!(&*reader.join().unwrap().body, b"original");
    purge.join().unwrap();
    assert_eq!(cache.stats().entries, 0);
    cache
        .store(disk_cache_store_key("next"), &disk_cache_entry(b"next"))
        .unwrap();
    assert_eq!(&*cache.get_combined("next").unwrap().body, b"next");
}

#[test]
fn disk_cache_thirty_two_same_key_reads_overlap() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let directory = tempfile::tempdir().unwrap();
        let mut config = storage_bin_config(&directory.path().join("cache"));
        config.disk.backend = backend;
        config.disk.storage_bin.max_open_bins = 64;
        let cache = NativeDiskCache::from_config(&config).unwrap();
        cache
            .store(
                disk_cache_store_key("shared"),
                &disk_cache_entry(b"original"),
            )
            .unwrap();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let release = (Mutex::new(false), std::sync::Condvar::new());
        std::thread::scope(|scope| {
            let mut readers = Vec::new();
            for _ in 0..32 {
                let (cache, release, entered) = (&cache, &release, entered_tx.clone());
                readers.push(scope.spawn(move || {
                    cache.get_combined_with_reader("shared", |record| {
                        entered.send(()).unwrap();
                        let (guard, timeout) = release
                            .1
                            .wait_timeout_while(
                                release.0.lock().unwrap(),
                                Duration::from_secs(10),
                                |released| !*released,
                            )
                            .unwrap();
                        assert!(!timeout.timed_out());
                        drop(guard);
                        cache.read_record(record)
                    })
                }));
            }
            let mut simultaneous = 0;
            for _ in 0..32 {
                if entered_rx.recv_timeout(Duration::from_secs(5)).is_err() {
                    break;
                }
                simultaneous += 1;
            }
            *release.0.lock().unwrap() = true;
            release.1.notify_all();
            for reader in readers {
                assert_eq!(&*reader.join().unwrap().unwrap().unwrap().body, b"original");
            }
            assert_eq!(
                simultaneous, 32,
                "same-key reads serialized for {backend:?}"
            );
        });
    }
}

#[test]
fn disk_cache_busy_writer_and_cleanup_never_wait_or_remove_a_replacement() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let directory = tempfile::tempdir().unwrap();
        let mut config = storage_bin_config(&directory.path().join("cache"));
        config.disk.backend = backend;
        let cache = NativeDiskCache::from_config(&config).unwrap();
        cache
            .store(
                disk_cache_store_key("shared"),
                &disk_cache_entry(b"original"),
            )
            .unwrap();
        let expected = cache.with_state(|state| state.objects["shared"].clone());
        let writer = cache.lock_key_mutation("shared");
        assert_eq!(
            cache.lookup_combined("shared").unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(writer);
        let reader = cache.try_lock_key_read("shared").unwrap();
        assert_eq!(
            cache
                .get_combined_with_reader("shared", |_| Err(std::io::Error::other(
                    "injected read failure"
                )))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(reader);
        assert_eq!(&*cache.get_combined("shared").unwrap().body, b"original");
        cache
            .store(
                disk_cache_store_key("shared"),
                &disk_cache_entry(b"replaced"),
            )
            .unwrap();
        assert!(!cache.remove_if_unchanged("shared", &expected).unwrap());
        assert_eq!(&*cache.get_combined("shared").unwrap().body, b"replaced");
        let current = cache.with_state(|state| state.objects["shared"].clone());
        cache.with_state_mut(|state| state.touch_object("shared", SystemTime::UNIX_EPOCH));
        assert!(cache.remove_if_unchanged("shared", &current).unwrap());
        assert!(cache.get_combined("shared").is_none());
    }
}
