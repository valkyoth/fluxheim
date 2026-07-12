use super::native_http1_cache_backend::{
    acquire_native_storage_bin_lease, prepare_native_storage_bin_layout_locked,
};
use super::native_http1_cache_purge::{
    native_disk_cache_purge_registry_is_unlocked_for_test, purge_native_disk_cache,
};
use super::native_http1_cache_storage_bin::native_storage_bin_index_worker_count;
use super::{
    NativeDiskCache, NativeDiskCacheBackend, NativeDiskCacheLocation, NativeDiskCacheRecord,
    NativeDiskCacheState, NativeDiskCacheStoreKey, NativeMemoryCacheEntry,
    native_disk_cache_mutation_locks, native_peer_fill_cache_ttl,
    register_native_disk_cache_purge_handle,
};
use fluxheim_config::{ByteSize, CacheConfig, CacheDiskBackend, CacheDiskStorageBinConfig};
use http::HeaderMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

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

fn storage_bin_config(path: &std::path::Path) -> CacheConfig {
    CacheConfig {
        enabled: true,
        max_object_bytes: ByteSize::from_bytes(1024),
        disk: fluxheim_config::CacheDiskConfig {
            enabled: true,
            backend: CacheDiskBackend::StorageBin,
            path: Some(path.to_path_buf()),
            max_size_bytes: ByteSize::from_bytes(1024 * 1024),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(64 * 1024),
                preallocate: false,
                max_open_bins: 4,
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

fn disk_cache_entry(body: &'static [u8]) -> NativeMemoryCacheEntry {
    let now = Instant::now();
    NativeMemoryCacheEntry {
        status: 200,
        reason: "OK".to_owned(),
        headers: vec![("cache-control".to_owned(), "max-age=60".to_owned())],
        content_length: Some(body.len() as u64),
        body: Arc::from(body),
        expires_at: now + Duration::from_secs(60),
        stale_while_revalidate_until: None,
        stale_if_error_until: None,
        stored_at: now,
        weight: 64,
    }
}

fn disk_cache_store_key(key: &str) -> NativeDiskCacheStoreKey {
    NativeDiskCacheStoreKey {
        combined: key.to_owned(),
        primary: key.to_owned(),
        user_tag: "cache.test".to_owned(),
        index_path: Some(format!("/{key}")),
        cache_tags: Vec::new(),
        vary_fields: Vec::new(),
    }
}

#[test]
fn disabled_disk_cache_does_not_require_a_path() {
    let config = CacheConfig {
        enabled: true,
        memory: fluxheim_config::CacheMemoryConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(NativeDiskCache::from_config(&config).is_none());
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
        state: Arc::new(Mutex::new(NativeDiskCacheState::default())),
        mutation_locks: native_disk_cache_mutation_locks(),
        index_flush: None,
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
        state: Arc::new(Mutex::new(NativeDiskCacheState::default())),
        mutation_locks: native_disk_cache_mutation_locks(),
        index_flush: None,
    });
    let combined = "same-key-race";
    cache.with_state_mut(|state| {
        state.insert_object(
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

#[test]
fn disk_cache_eviction_order_updates_without_scanning_objects() {
    let mut state = NativeDiskCacheState::default();
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    let new = SystemTime::UNIX_EPOCH + Duration::from_secs(2);
    for (key, accessed_at) in [("old", old), ("new", new)] {
        state.insert_object(
            key.to_owned(),
            NativeDiskCacheRecord {
                location: NativeDiskCacheLocation::Filesystem(std::path::PathBuf::from(key)),
                weight: 1,
                accessed_at,
            },
        );
    }

    assert_eq!(state.oldest_key().as_deref(), Some("old"));
    state.touch_object("old", new + Duration::from_secs(1));
    assert_eq!(state.oldest_key().as_deref(), Some("new"));
    state.remove_object("new");
    assert_eq!(state.oldest_key().as_deref(), Some("old"));
}

#[test]
fn storage_bin_index_flush_coalesces_and_flushes_on_shutdown() {
    let directory = tempfile::tempdir().unwrap();
    let config = CacheConfig {
        enabled: true,
        max_object_bytes: ByteSize::from_bytes(64),
        disk: fluxheim_config::CacheDiskConfig {
            enabled: true,
            backend: CacheDiskBackend::StorageBin,
            path: Some(directory.path().join("cache")),
            max_size_bytes: ByteSize::from_bytes(128),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(64),
                preallocate: false,
                max_open_bins: 4,
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let cache = NativeDiskCache::from_config(&config).unwrap();
    let second_directory = tempfile::tempdir().unwrap();
    let mut second_config = config.clone();
    second_config.disk.path = Some(second_directory.path().join("cache"));
    let second_cache = NativeDiskCache::from_config(&second_config).unwrap();
    assert_eq!(native_storage_bin_index_worker_count(), 1);
    drop(second_cache);
    let NativeDiskCacheBackend::StorageBin(storage_bin) = &cache.backend else {
        return;
    };
    let layout = storage_bin.layout.clone();
    cache.with_state_mut(|state| {
        state.insert_object(
            "coalesced".to_owned(),
            NativeDiskCacheRecord {
                location: NativeDiskCacheLocation::StorageBin(
                    fluxheim_cache::StorageBinObjectLocation {
                        bin_id: 0,
                        offset: 0,
                        len: 8,
                    },
                ),
                weight: 8,
                accessed_at: SystemTime::UNIX_EPOCH,
            },
        );
    });
    for _ in 0..100 {
        cache.persist_storage_bin_index();
    }
    drop(cache);

    let entries = fluxheim_cache::read_storage_bin_index(&layout).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].combined_key, "coalesced");
}

#[test]
fn disk_cache_rejects_record_whose_embedded_key_does_not_match_lookup() {
    let directory = tempfile::tempdir().unwrap();
    let config = CacheConfig {
        enabled: true,
        max_object_bytes: ByteSize::from_bytes(1024),
        disk: fluxheim_config::CacheDiskConfig {
            enabled: true,
            path: Some(directory.path().join("cache")),
            max_size_bytes: ByteSize::from_bytes(4096),
            ..Default::default()
        },
        ..Default::default()
    };
    let cache = NativeDiskCache::from_config(&config).unwrap();
    let now = Instant::now();
    let entry = NativeMemoryCacheEntry {
        status: 200,
        reason: "OK".to_owned(),
        headers: vec![("cache-control".to_owned(), "max-age=60".to_owned())],
        content_length: Some(4),
        body: Arc::from(&b"safe"[..]),
        expires_at: now + Duration::from_secs(60),
        stale_while_revalidate_until: None,
        stale_if_error_until: None,
        stored_at: now,
        weight: 64,
    };
    cache
        .store(
            NativeDiskCacheStoreKey {
                combined: "expected-key".to_owned(),
                primary: "expected-key".to_owned(),
                user_tag: "cache.test".to_owned(),
                index_path: Some("/asset".to_owned()),
                cache_tags: Vec::new(),
                vary_fields: Vec::new(),
            },
            &entry,
        )
        .unwrap();
    let record = cache
        .with_state(|state| state.objects.get("expected-key").cloned())
        .unwrap();
    cache.with_state_mut(|state| state.insert_object("wrong-key".to_owned(), record));

    assert!(cache.get("wrong-key", |_| None).is_none());
    assert!(cache.with_state(|state| !state.objects.contains_key("wrong-key")));
}

#[test]
fn live_cache_inspection_uses_registered_allocator_during_inserts() {
    let directory = tempfile::tempdir().unwrap();
    let config = storage_bin_config(&directory.path().join("cache"));
    let cache = Arc::new(NativeDiskCache::from_config(&config).unwrap());
    let vhost: Arc<str> = Arc::from(format!("inspect-live-{}", std::process::id()));
    register_native_disk_cache_purge_handle(vhost.clone(), None, &cache);
    cache
        .store(disk_cache_store_key("first"), &disk_cache_entry(b"first"))
        .unwrap();

    let writer = Arc::clone(&cache);
    let insert = std::thread::spawn(move || {
        writer
            .store(disk_cache_store_key("second"), &disk_cache_entry(b"second"))
            .unwrap();
    });
    let first = super::inspect_native_disk_cache_object(&vhost, None, &config, "first", &[]);
    insert.join().unwrap();
    let second = super::inspect_native_disk_cache_object(&vhost, None, &config, "second", &[]);

    assert_eq!(first.unwrap().body_bytes, 5);
    assert_eq!(second.unwrap().body_bytes, 6);
    assert_eq!(cache.stats().entries, 2);
}

#[test]
fn filesystem_cache_inspection_rebuilds_index_without_live_allocator() {
    let directory = tempfile::tempdir().unwrap();
    let config = CacheConfig {
        enabled: true,
        max_object_bytes: ByteSize::from_bytes(1024),
        disk: fluxheim_config::CacheDiskConfig {
            enabled: true,
            path: Some(directory.path().join("cache")),
            max_size_bytes: ByteSize::from_bytes(4096),
            ..Default::default()
        },
        ..Default::default()
    };
    let cache = NativeDiskCache::from_config(&config).unwrap();
    cache
        .store(
            disk_cache_store_key("standalone"),
            &disk_cache_entry(b"body"),
        )
        .unwrap();
    drop(cache);

    let metadata = super::inspect_native_disk_cache_object(
        "standalone-inspection.test",
        None,
        &config,
        "standalone",
        &[],
    )
    .unwrap();

    assert_eq!(metadata.body_bytes, 4);
}

#[test]
fn storage_bin_inspection_does_not_construct_unregistered_allocator() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("cache");
    let config = storage_bin_config(&root);

    assert!(
        super::inspect_native_disk_cache_object(
            "unregistered-storage-bin.test",
            None,
            &config,
            "missing",
            &[],
        )
        .is_none()
    );
    assert!(!root.exists());
}

const STORAGE_BIN_LEASE_CHILD_ROOT: &str = "FLUXHEIM_STORAGE_BIN_LEASE_CHILD_ROOT";
const STORAGE_BIN_LEASE_CHILD_MAX_BYTES: &str = "FLUXHEIM_STORAGE_BIN_LEASE_CHILD_MAX_BYTES";
const STORAGE_BIN_LEASE_CHILD_CONFIRMED: &str = "fluxheim-storage-bin-lease-child-confirmed";

#[test]
fn storage_bin_lease_child_process() {
    let Some(root) = std::env::var_os(STORAGE_BIN_LEASE_CHILD_ROOT) else {
        return;
    };
    let mut config = storage_bin_config(std::path::Path::new(&root));
    if let Ok(max_bytes) = std::env::var(STORAGE_BIN_LEASE_CHILD_MAX_BYTES) {
        config.disk.max_size_bytes = ByteSize::from_bytes(max_bytes.parse().unwrap());
    }

    let error = NativeDiskCacheBackend::from_config(&config).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    println!("{STORAGE_BIN_LEASE_CHILD_CONFIRMED}");
}

#[test]
fn storage_bin_lease_rejects_second_process() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("cache");
    let config = storage_bin_config(&root);
    let _cache = NativeDiskCache::from_config(&config).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("native_http1_cache::tests::storage_bin_lease_child_process")
        .arg("--nocapture")
        .env(STORAGE_BIN_LEASE_CHILD_ROOT, &root)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains(STORAGE_BIN_LEASE_CHILD_CONFIRMED));
}

#[test]
fn storage_bin_loser_cannot_mutate_winner_layout() {
    let directory = tempfile::tempdir().unwrap();
    let configured_root = directory.path().join("cache");
    let winner_config = storage_bin_config(&configured_root);
    let root = super::prepare_native_storage_bin_root_for_lease(&winner_config).unwrap();
    let _lease = acquire_native_storage_bin_lease(&root).unwrap();

    assert!(!root.join(".fluxheim-storage-bin-v1").exists());
    assert!(!root.join("bins").exists());
    prepare_native_storage_bin_layout_locked(&winner_config, &root).unwrap();
    let manifest_path = root.join(".fluxheim-storage-bin-v1");
    let winning_manifest = std::fs::read(&manifest_path).unwrap();

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("native_http1_cache::tests::storage_bin_lease_child_process")
        .arg("--nocapture")
        .env(STORAGE_BIN_LEASE_CHILD_ROOT, &root)
        .env(
            STORAGE_BIN_LEASE_CHILD_MAX_BYTES,
            (2 * 1024 * 1024).to_string(),
        )
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains(STORAGE_BIN_LEASE_CHILD_CONFIRMED));
    assert_eq!(std::fs::read(manifest_path).unwrap(), winning_manifest);
}
