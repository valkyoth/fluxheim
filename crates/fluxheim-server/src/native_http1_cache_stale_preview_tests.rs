use super::*;
use std::path::PathBuf;

fn matrix(test: impl Fn(&NativeDiskCache, &str, &str)) {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        for encrypted in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let mut config = storage_bin_config(&root.path().join("cache"));
            config.disk.backend = backend;
            if encrypted {
                super::super::store_admission::configure_encryption(&mut config, root.path());
            }
            let cache = Arc::new(NativeDiskCache::from_config(&config).unwrap());
            let scope = format!("preview-{}", root.path().display());
            register_native_disk_cache_purge_handle(scope.as_str().into(), None, &cache);
            test(
                &cache,
                &scope,
                &fluxheim_cache::cache_user_tag(&scope, None),
            );
        }
    }
}

fn data_path(cache: &NativeDiskCache, key: &str) -> PathBuf {
    cache.with_state(|s| match (&cache.backend, &s.objects[key].location) {
        (_, NativeDiskCacheLocation::Filesystem(p)) => p.clone(),
        (NativeDiskCacheBackend::StorageBin(bin), NativeDiskCacheLocation::StorageBin(loc)) => {
            bin.layout.bin_path(loc.bin_id)
        }
        _ => unreachable!(),
    })
}

#[test]
fn bounded_preview_preserves_objects_lru_indexes_bytes_and_allocation() {
    matrix(|cache, scope, tag| {
        let mut entry = disk_cache_entry(b"value");
        store(cache, scope, "fresh", &entry);
        entry.expires_at = Instant::now() - Duration::from_secs(2);
        store(cache, scope, "expired", &entry);
        entry.stale_if_error_until = Some(Instant::now() + Duration::from_secs(120));
        store(cache, scope, "stale", &entry);
        let mut paths = ["fresh", "expired", "stale"]
            .map(|k| data_path(cache, k))
            .to_vec();
        if let NativeDiskCacheBackend::StorageBin(bin) = &cache.backend {
            cache.checkpoint_for_test();
            cache.suspend_periodic_checkpoint_for_test();
            paths.push(fluxheim_cache::storage_bin_index_path(&bin.layout.root));
        }
        let bytes = || {
            paths
                .iter()
                .map(|p| std::fs::read(p).unwrap())
                .collect::<Vec<_>>()
        };
        let inventory = || {
            cache.with_state(|s| {
                (
                    s.objects.clone(),
                    s.eviction_order.clone(),
                    s.lookup_attempts,
                )
            })
        };
        let before = (inventory(), cache.stats(), bytes());
        for (index, (stale, expired)) in [(0, 0), (1, 1), (1, 0)].into_iter().enumerate() {
            let r = purge_native_disk_cache_stale(scope, None, tag, 1, true).unwrap();
            assert_eq!(
                (r.scanned, r.stale, r.disk_inspection.expired, r.purged),
                (1, stale, expired, 0)
            );
            assert_eq!(r.truncated, index < 2);
        }
        assert_eq!(before, (inventory(), cache.stats(), bytes()));
        let held = cache.try_lock_key_mutation("expired").unwrap();
        assert!(
            purge_native_disk_cache_stale(scope, None, tag, 10, true)
                .unwrap()
                .truncated
        );
        drop(held);
        assert_eq!(before, (inventory(), cache.stats(), bytes()));
        let cleanup = purge_native_disk_cache_stale(scope, None, tag, 10, false).unwrap();
        assert_eq!((cleanup.stale, cleanup.purged), (2, 2));
        assert_eq!(cache.stats().entries, 1);
        assert!(cache.get("fresh", |_| None).is_some());
    });
}

#[test]
fn damaged_or_missing_objects_are_not_counted_or_removed_as_stale() {
    matrix(|cache, scope, tag| {
        store(cache, scope, "key", &disk_cache_entry(b"value"));
        let path = data_path(cache, "key");
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        for dry_run in [true, false] {
            let r = purge_native_disk_cache_stale(scope, None, tag, 1, dry_run).unwrap();
            assert_eq!(
                (r.disk_inspection.invalid, r.scanned, r.stale, r.purged),
                (1, 0, 0, 0)
            );
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
        std::fs::remove_file(&path).unwrap();
        let r = purge_native_disk_cache_stale(scope, None, tag, 1, true).unwrap();
        assert_eq!((r.disk_inspection.missing, r.stale, r.purged), (1, 0, 0));
        assert!(!path.exists());
        std::fs::create_dir(&path).unwrap();
        let r = purge_native_disk_cache_stale(scope, None, tag, 1, true).unwrap();
        assert_eq!((r.disk_inspection.unreadable, r.stale, r.purged), (1, 0, 0));
        assert!(path.is_dir());
        assert_eq!(cache.stats().entries, 1);
        assert_eq!(cache.stats().purge_index_entries, 1);
    });
}

#[test]
fn memory_preview_does_not_repair_orphaned_index_rows() {
    let root = tempfile::tempdir().unwrap();
    let scope = format!("memory-preview-{}", root.path().display());
    let state = Arc::new(Mutex::new(
        crate::native_http1_cache::NativeMemoryCacheState::default(),
    ));
    crate::native_http1_proxy_runtime::register_native_memory_cache_purge_handle(
        scope.as_str().into(),
        None,
        &state,
    );
    let tag = fluxheim_cache::cache_user_tag(&scope, None);
    let index = state.lock().unwrap().purge_index.clone();
    index.insert("orphan".into(), "orphan".into(), tag.clone());
    let preview = crate::purge_native_memory_cache_stale(&scope, None, &tag, 1, true);
    assert_eq!((preview.scanned, preview.purged, index.len()), (0, 0, 1));
    crate::purge_native_memory_cache_stale(&scope, None, &tag, 1, false);
    assert_eq!(index.len(), 0);
}
