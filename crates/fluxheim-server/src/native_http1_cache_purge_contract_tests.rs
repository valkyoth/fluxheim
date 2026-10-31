use super::*;
use crate::{purge_native_disk_cache_stale, purge_native_disk_cache_user_tag};

fn fixture(backend: CacheDiskBackend) -> (tempfile::TempDir, Arc<NativeDiskCache>, String) {
    let directory = tempfile::tempdir().unwrap();
    let mut config = storage_bin_config(&directory.path().canonicalize().unwrap());
    config.disk.backend = backend;
    let cache = Arc::new(NativeDiskCache::from_config(&config).unwrap());
    let scope = format!("purge-contract-{}", directory.path().display());
    register_native_disk_cache_purge_handle(Arc::from(scope.as_str()), None, &cache);
    (directory, cache, scope)
}

fn store(cache: &NativeDiskCache, scope: &str, key: &str, entry: &NativeMemoryCacheEntry) {
    let mut identity = disk_cache_store_key(key);
    identity.user_tag = fluxheim_cache::cache_user_tag(scope, None);
    cache.store(identity, entry).unwrap();
}

// Characterizations of pending corrections, not desired purge semantics.
#[test]
fn documented_disk_purge_currently_hides_remaining_matches() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let (_directory, cache, scope) = fixture(backend);
        for key in ["a", "b", "c"] {
            store(&cache, &scope, key, &disk_cache_entry(b"body"));
        }
        let tag = fluxheim_cache::cache_user_tag(&scope, None);
        let result = purge_native_disk_cache_user_tag(&scope, None, &tag, 1, false);
        assert_eq!((result.matched, result.purged), (1, 1));
        assert!(!result.truncated); // documented contract: two matches still exist.
        assert_eq!(cache.stats().entries, 2);
        assert!(cache.get("b", |_| None).is_some());
        assert!(cache.get("c", |_| None).is_some());
        let rest = purge_native_disk_cache_user_tag(&scope, None, &tag, 3, false);
        assert_eq!(rest.purged, 2);
        assert_eq!(cache.stats().entries, 0);
    }
}

#[test]
fn documented_stale_scan_currently_repeats_the_fresh_prefix() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let (_directory, cache, scope) = fixture(backend);
        store(&cache, &scope, "fresh-first", &disk_cache_entry(b"fresh"));
        let mut stale = disk_cache_entry(b"stale");
        stale.expires_at = Instant::now() - Duration::from_secs(2);
        stale.stale_if_error_until = Some(Instant::now() + Duration::from_secs(60));
        store(&cache, &scope, "stale-second", &stale);
        let tag = fluxheim_cache::cache_user_tag(&scope, None);
        for dry_run in [true, false, false] {
            let result = purge_native_disk_cache_stale(&scope, None, &tag, 1, dry_run);
            assert_eq!((result.scanned, result.stale, result.purged), (1, 0, 0));
            assert!(!result.truncated); // documented contract: no scan continuation.
            assert_eq!(cache.stats().entries, 2);
        }
        let result = purge_native_disk_cache_stale(&scope, None, &tag, 2, false);
        assert_eq!((result.scanned, result.stale, result.purged), (2, 1, 1));
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
