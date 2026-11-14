use super::*;

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
        assert!(
            cache
                .get_combined_with_reader("retained", |_| {
                    Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                })
                .is_none()
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
