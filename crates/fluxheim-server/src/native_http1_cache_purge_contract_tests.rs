use super::*;
use crate::{purge_native_disk_cache_stale, purge_native_disk_cache_user_tag};

#[test]
fn background_progress_child() {
    if std::env::var_os("FLUXHEIM_PURGE_PROGRESS_CHILD").is_none() {
        return;
    }
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let (_root, cache, scope) = fixture(backend);
        store(&cache, &scope, "fresh", &disk_cache_entry(b"fresh"));
        let mut stale = disk_cache_entry(b"stale");
        stale.expires_at = Instant::now() - Duration::from_secs(2);
        stale.stale_if_error_until = Some(Instant::now() + Duration::from_secs(120));
        store(&cache, &scope, "old", &stale);
        let first = crate::purge_native_disk_cache_stale_all(1, 1).unwrap();
        assert_eq!(first.scanned, 1);
        assert_eq!(first.purged, 0);
        assert!(first.truncated);
        let second = crate::purge_native_disk_cache_stale_all(1, 1).unwrap();
        assert_eq!(second.purged, 1);
        assert!(!second.truncated);
        store(&cache, &scope, "old", &stale);
        let both = crate::purge_native_disk_cache_stale_all(1, 2).unwrap();
        assert_eq!(both.scanned, 2);
        assert_eq!(both.purged, 1);
        assert!(!both.truncated);
    }
}

#[test]
fn background_ticks_advance_and_report_final_batch_completion() {
    use fluxheim_common::test_process::{TestBinary, self_command};
    let mut child = self_command(TestBinary::NativeServer)
        .unwrap()
        .args([
            "--exact",
            "native_http1_cache::tests::purge_contract::background_progress_child",
            "--nocapture",
        ])
        .env("FLUXHEIM_PURGE_PROGRESS_CHILD", "1")
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
            panic!("background purge exceeded bounded test deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn fixture(backend: CacheDiskBackend) -> (tempfile::TempDir, Arc<NativeDiskCache>, String) {
    let directory = tempfile::tempdir().unwrap();
    let mut config = storage_bin_config(&directory.path().canonicalize().unwrap());
    config.disk.backend = backend;
    let cache = Arc::new(NativeDiskCache::from_config(&config).unwrap());
    let scope = format!("purge-contract-{}", directory.path().display());
    register_native_disk_cache_purge_handle(Arc::from(scope.as_str()), None, &cache);
    (directory, cache, scope)
}

#[test]
fn disk_selectors_complete_bounded_passes_and_preserve_other_objects_on_restart() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        for encrypted in [false, true] {
            for selector in 0..4 {
                let directory = tempfile::tempdir().unwrap();
                let mut config = storage_bin_config(&directory.path().join("cache"));
                config.disk.backend = backend;
                if encrypted {
                    super::store_admission::configure_encryption(&mut config, directory.path());
                }
                let cache = Arc::new(NativeDiskCache::from_config(&config).unwrap());
                let scope = format!("purge-selectors-{}", directory.path().display());
                register_native_disk_cache_purge_handle(Arc::from(scope.as_str()), None, &cache);
                let tag = fluxheim_cache::cache_user_tag(&scope, None);
                for key in ["other", "a", "b", "c"] {
                    let mut identity = disk_cache_store_key(key);
                    identity.user_tag = tag.clone();
                    if key != "other" {
                        identity.index_path = Some("/assets/file.css".into());
                        identity.cache_tags = vec!["assets".into()];
                    }
                    cache.store(identity, &disk_cache_entry(b"body")).unwrap();
                }
                let mut purged = 0;
                for n in 0..4 {
                    let result = match selector {
                        0 => crate::purge_native_disk_cache_path_prefix(
                            &scope, None, &tag, "/assets/", 1, false,
                        ),
                        1 => crate::purge_native_disk_cache_path_exact(
                            &scope,
                            None,
                            &tag,
                            "/assets/file.css",
                            1,
                            false,
                        ),
                        2 => crate::purge_native_disk_cache_path_pattern(
                            &scope,
                            None,
                            &tag,
                            "/assets/*.css",
                            1,
                            false,
                        ),
                        _ => crate::purge_native_disk_cache_tag(
                            &scope, None, &tag, "assets", 1, false,
                        ),
                    };
                    assert_eq!(result.examined, 1);
                    assert_eq!(result.truncated, n < 3);
                    purged += result.purged;
                }
                assert_eq!(purged, 3);
                assert_eq!(cache.stats().entries, 1);
                drop(cache);
                let recovered = NativeDiskCache::from_config(&config).unwrap();
                assert!(recovered.get("other", |_| None).is_some());
                for key in ["a", "b", "c"] {
                    assert!(recovered.get(key, |_| None).is_none());
                }
            }
        }
    }
}

#[test]
fn filesystem_soft_batches_advance_without_counting_stale_objects_twice() {
    let (_directory, cache, scope) = fixture(CacheDiskBackend::Filesystem);
    let mut entry = disk_cache_entry(b"body");
    entry.stale_if_error_until = Some(Instant::now() + Duration::from_secs(120));
    for key in ["a", "b", "c"] {
        store(&cache, &scope, key, &entry);
    }
    let tag = fluxheim_cache::cache_user_tag(&scope, None);
    for n in 0..3 {
        let result = purge_native_disk_cache_user_tag(&scope, None, &tag, 1, true);
        assert_eq!(result.purged, 1);
        assert_eq!(result.truncated, n < 2);
    }
    let repeat = purge_native_disk_cache_user_tag(&scope, None, &tag, 3, true);
    assert_eq!(repeat.purged, 0);
    assert!(!repeat.truncated);
    assert_eq!(cache.stats().entries, 3);
}

#[test]
fn failed_filesystem_unlink_preserves_accounting_and_requires_retry() {
    let (_directory, cache, scope) = fixture(CacheDiskBackend::Filesystem);
    store(&cache, &scope, "a", &disk_cache_entry(b"body"));
    let record = cache.with_state(|state| state.objects["a"].clone());
    let NativeDiskCacheLocation::Filesystem(path) = record.location else {
        unreachable!()
    };
    let bytes = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let before = cache.stats();
    let tag = fluxheim_cache::cache_user_tag(&scope, None);
    let failed = purge_native_disk_cache_user_tag(&scope, None, &tag, 1, false);
    assert_eq!(failed.purged, 0);
    assert!(failed.truncated);
    assert_eq!(cache.stats().entries, before.entries);
    assert_eq!(cache.stats().size_bytes, before.size_bytes);
    std::fs::remove_dir(&path).unwrap();
    std::fs::write(&path, bytes).unwrap();
    let recovered = purge_native_disk_cache_user_tag(&scope, None, &tag, 1, false);
    assert_eq!(recovered.purged, 1);
    assert!(!recovered.truncated);
}

#[test]
fn failed_bin_release_preserves_accounting_and_requires_retry() {
    let (_directory, cache, scope) = fixture(CacheDiskBackend::StorageBin);
    store(&cache, &scope, "a", &disk_cache_entry(b"body"));
    let record = cache.with_state(|state| state.objects["a"].clone());
    cache.with_state_mut(|state| {
        if let NativeDiskCacheLocation::StorageBin(location) =
            &mut state.objects.get_mut("a").unwrap().location
        {
            location.bin_id = u64::MAX;
        }
    });
    let before = cache.stats();
    let tag = fluxheim_cache::cache_user_tag(&scope, None);
    let failed = purge_native_disk_cache_user_tag(&scope, None, &tag, 1, false);
    assert_eq!(failed.purged, 0);
    assert!(failed.truncated);
    assert_eq!(cache.stats().entries, before.entries);
    assert_eq!(cache.stats().size_bytes, before.size_bytes);
    cache.with_state_mut(|state| {
        state.objects.get_mut("a").unwrap().location = record.location;
    });
    let recovered = purge_native_disk_cache_user_tag(&scope, None, &tag, 1, false);
    assert_eq!(recovered.purged, 1);
    assert!(!recovered.truncated);
}

#[test]
fn busy_disk_mutation_is_reported_and_later_batches_recover() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let (_directory, cache, scope) = fixture(backend);
        store(&cache, &scope, "a", &disk_cache_entry(b"body"));
        let tag = fluxheim_cache::cache_user_tag(&scope, None);
        let guard = cache.try_lock_key_read("a").unwrap();
        let busy = purge_native_disk_cache_user_tag(&scope, None, &tag, 1, false);
        assert_eq!(busy.purged, 0);
        assert!(busy.truncated);
        drop(guard);
        let retry = purge_native_disk_cache_user_tag(&scope, None, &tag, 1, false);
        assert_eq!(retry.purged, 1);
        assert!(!retry.truncated);
    }
}

fn store(cache: &NativeDiskCache, scope: &str, key: &str, entry: &NativeMemoryCacheEntry) {
    let mut identity = disk_cache_store_key(key);
    identity.user_tag = fluxheim_cache::cache_user_tag(scope, None);
    cache.store(identity, entry).unwrap();
}

#[test]
fn memory_stale_and_soft_scans_progress_and_do_not_recount_changes() {
    use crate::native_http1_cache::NativeMemoryCacheState;
    let directory = tempfile::tempdir().unwrap();
    let scope = format!("memory-progress-{}", directory.path().display());
    let tag = fluxheim_cache::cache_user_tag(&scope, None);
    let state = Arc::new(Mutex::new(NativeMemoryCacheState::default()));
    crate::native_http1_proxy_runtime::register_native_memory_cache_purge_handle(
        Arc::from(scope.as_str()),
        None,
        &state,
    );
    {
        let mut state = state.lock().unwrap();
        for key in ["fresh", "old", "last"] {
            let mut entry = disk_cache_entry(b"body");
            if key == "old" {
                entry.expires_at = Instant::now() - Duration::from_secs(1);
            }
            state.bytes += entry.weight;
            state.objects.insert(key.into(), entry);
            state
                .purge_index
                .insert(key.into(), key.into(), tag.clone());
        }
    }
    let first = crate::purge_native_memory_cache_stale(&scope, None, &tag, 1, false);
    assert_eq!(first.purged, 0);
    assert!(first.truncated);
    let second = crate::purge_native_memory_cache_stale(&scope, None, &tag, 1, false);
    assert_eq!(second.purged, 1);
    assert!(second.truncated);
    assert!(!crate::purge_native_memory_cache_stale(&scope, None, &tag, 1, false).truncated);
    for n in 0..2 {
        let result = crate::purge_native_memory_cache_user_tag(&scope, None, &tag, 1, true);
        assert_eq!(result.purged, 1);
        assert_eq!(result.truncated, n == 0);
    }
    let repeated = crate::purge_native_memory_cache_user_tag(&scope, None, &tag, 2, true);
    assert_eq!(repeated.purged, 0);
    assert!(!repeated.truncated);
    assert_eq!(state.lock().unwrap().objects.len(), 2);
}

#[test]
fn live_disk_generations_share_batch_budget_and_all_receive_work() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let (_one, a, scope) = fixture(backend);
        let (_two, b, _) = fixture(backend);
        register_native_disk_cache_purge_handle(Arc::from(scope.as_str()), None, &b);
        let tag = fluxheim_cache::cache_user_tag(&scope, None);
        for cache in [&a, &b] {
            for key in ["a", "b", "c"] {
                store(cache, &scope, key, &disk_cache_entry(b"body"));
            }
        }
        // Other parallel tests can register targets too; rotation still reaches
        // both retained generations without multiplying the per-call budget.
        for _ in 0..1000 {
            let result = purge_native_disk_cache_user_tag(&scope, None, &tag, 2, false);
            assert!(result.examined <= 2);
            assert!(result.purged <= 2);
            if a.stats().entries + b.stats().entries == 0 {
                break;
            }
            assert!(result.truncated);
        }
        assert_eq!(a.stats().entries + b.stats().entries, 0);
        assert!(!purge_native_disk_cache_user_tag(&scope, None, &tag, 10, false).truncated);
    }
}

#[test]
fn disk_purge_reports_and_advances_remaining_matches() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let (_directory, cache, scope) = fixture(backend);
        for key in ["a", "b", "c"] {
            store(&cache, &scope, key, &disk_cache_entry(b"body"));
        }
        let tag = fluxheim_cache::cache_user_tag(&scope, None);
        let result = purge_native_disk_cache_user_tag(&scope, None, &tag, 1, false);
        assert_eq!((result.matched, result.purged), (1, 1));
        assert!(result.truncated);
        assert_eq!(cache.stats().entries, 2);
        assert!(cache.get("b", |_| None).is_some());
        assert!(cache.get("c", |_| None).is_some());
        let rest = purge_native_disk_cache_user_tag(&scope, None, &tag, 3, false);
        assert_eq!(rest.purged, 2);
        assert!(!rest.truncated);
        assert_eq!(cache.stats().entries, 0);
    }
}

#[test]
fn stale_scan_advances_past_fresh_prefix() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let (_directory, cache, scope) = fixture(backend);
        store(&cache, &scope, "fresh-first", &disk_cache_entry(b"fresh"));
        let mut stale = disk_cache_entry(b"stale");
        stale.expires_at = Instant::now() - Duration::from_secs(2);
        stale.stale_if_error_until = Some(Instant::now() + Duration::from_secs(60));
        store(&cache, &scope, "stale-second", &stale);
        let tag = fluxheim_cache::cache_user_tag(&scope, None);
        for dry_run in [true, false] {
            let result = purge_native_disk_cache_stale(&scope, None, &tag, 1, dry_run);
            assert_eq!((result.scanned, result.stale, result.purged), (1, 0, 0));
            assert!(result.truncated);
            assert_eq!(cache.stats().entries, 2);
        }
        let result = purge_native_disk_cache_stale(&scope, None, &tag, 1, false);
        assert_eq!((result.scanned, result.stale, result.purged), (1, 1, 1));
        assert!(!result.truncated);
        assert!(cache.get("fresh-first", |_| None).is_some());
    }
}

#[test]
fn documented_bin_soft_purge_currently_deletes_the_stale_copy() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let (_directory, cache, scope) = fixture(backend);
        let mut entry = disk_cache_entry(b"retained-body");
        entry.stale_if_error_until = Some(Instant::now() + Duration::from_secs(120));
        store(&cache, &scope, "asset", &entry);
        let tag = fluxheim_cache::cache_user_tag(&scope, None);
        let result = purge_native_disk_cache_user_tag(&scope, None, &tag, 10, true);
        assert_eq!((result.matched, result.purged), (1, 1));
        let retained = cache.get("asset", |_| None);
        if matches!(backend, CacheDiskBackend::StorageBin) {
            assert!(retained.is_none()); // documented contract: soft becomes hard.
            assert_eq!(cache.stats().entries, 0);
        } else {
            let retained = retained.unwrap();
            assert_eq!(&*retained.body, b"retained-body");
            assert!(retained.expires_at <= Instant::now());
        }
    }
}

#[test]
fn documented_disk_stale_dry_run_currently_removes_expired_objects() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let (_directory, cache, scope) = fixture(backend);
        let mut entry = disk_cache_entry(b"expired-body");
        entry.expires_at = Instant::now() - Duration::from_secs(2);
        store(&cache, &scope, "expired", &entry);
        assert_eq!(cache.stats().entries, 1);
        let tag = fluxheim_cache::cache_user_tag(&scope, None);
        let result = purge_native_disk_cache_stale(&scope, None, &tag, 10, true);
        assert_eq!((result.scanned, result.stale, result.purged), (0, 0, 0));
        // documented contract: a supposedly read-only scan removed the object.
        assert_eq!(cache.stats().entries, 0);
        assert_eq!(cache.with_state(|state| state.purge_index.len()), 0);
    }
}
