use super::native_http1_cache_purge::{
    native_disk_cache_purge_registry_is_unlocked_for_test, purge_native_disk_cache,
};
use super::{
    NativeDiskCache, NativeDiskCacheBackend, NativeDiskCacheLocation, NativeDiskCacheRecord,
    NativeDiskCacheState, native_disk_cache_mutation_locks, native_peer_fill_cache_ttl,
    register_native_disk_cache_purge_handle,
};
use fluxheim_config::{ByteSize, CacheConfig};
use http::HeaderMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

fn headers(values: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            headers.append(name, value);
        }
    }
    headers
}

#[test]
fn native_peer_fill_cache_ttl_subtracts_upstream_age() {
    let cache = CacheConfig::default();
    let headers = headers(&[("cache-control", "max-age=60"), ("age", "50")]);

    assert_eq!(
        native_peer_fill_cache_ttl(200, &headers, &cache),
        Some(Duration::from_secs(10))
    );
}

#[test]
fn native_peer_fill_cache_ttl_rejects_fully_aged_peer_response() {
    let cache = CacheConfig::default();
    let headers = headers(&[("cache-control", "max-age=60"), ("age", "60")]);

    assert_eq!(native_peer_fill_cache_ttl(200, &headers, &cache), None);
}

#[test]
fn disk_cache_purge_callback_runs_outside_registry_lock() {
    let cache = Arc::new(NativeDiskCache {
        root: std::env::temp_dir().join(format!(
            "fluxheim-native-cache-purge-lock-{}",
            std::process::id()
        )),
        max_bytes: 1024,
        max_object_bytes: ByteSize::from_bytes(1024),
        backend: NativeDiskCacheBackend::Filesystem,
        encryption: None,
        state: Mutex::new(NativeDiskCacheState::default()),
        mutation_locks: native_disk_cache_mutation_locks(),
    });
    let vhost: Arc<str> = Arc::from(format!("purge-lock-test-{}", std::process::id()));
    register_native_disk_cache_purge_handle(vhost.clone(), None, &cache);

    let mut callback_saw_unlocked_registry = false;
    let purged = purge_native_disk_cache(vhost.as_ref(), None, |_| {
        callback_saw_unlocked_registry = native_disk_cache_purge_registry_is_unlocked_for_test();
        true
    });

    assert!(purged);
    assert!(callback_saw_unlocked_registry);
}

#[test]
fn disk_cache_remove_combined_waits_for_key_mutation_lock() {
    let cache = Arc::new(NativeDiskCache {
        root: std::env::temp_dir().join(format!(
            "fluxheim-native-cache-key-lock-{}",
            std::process::id()
        )),
        max_bytes: 1024,
        max_object_bytes: ByteSize::from_bytes(1024),
        backend: NativeDiskCacheBackend::Filesystem,
        encryption: None,
        state: Mutex::new(NativeDiskCacheState::default()),
        mutation_locks: native_disk_cache_mutation_locks(),
    });
    let combined = "same-key-race";
    cache.with_state_mut(|state| {
        state.objects.insert(
            combined.to_owned(),
            NativeDiskCacheRecord {
                location: NativeDiskCacheLocation::Filesystem(cache.root.join("object.fhc")),
                weight: 8,
                accessed_at: SystemTime::now(),
            },
        );
        state.bytes = 8;
    });

    let guard = cache.lock_key_mutation(combined);
    let (sender, receiver) = std::sync::mpsc::channel();
    let cache_for_thread = cache.clone();
    let handle = std::thread::spawn(move || {
        let removed = cache_for_thread.remove_combined(combined);
        sender.send(removed).expect("send removal result");
    });

    assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
    drop(guard);
    assert_eq!(receiver.recv_timeout(Duration::from_secs(5)), Ok(true));
    handle.join().expect("join removal thread");
}
