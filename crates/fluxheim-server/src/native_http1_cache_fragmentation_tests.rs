use super::super::native_http1_cache_state::native_disk_cache_mutation_lock_stripe;
use super::*;

fn body_entry(len: usize) -> NativeMemoryCacheEntry {
    let mut entry = disk_cache_entry(b"");
    entry.body = Arc::from(vec![42; len]);
    entry.body_sha256 = Arc::new(native_cache_body_sha256(&entry.body));
    entry.content_length = Some(len as u64);
    entry
}

#[test]
fn storage_bin_fragmented_collision_child() {
    if std::env::var_os("FLUXHEIM_FRAGMENTED_BIN_CHILD").is_none() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let keys: Vec<_> = (0..4).map(|n| format!("/asset.png?item={n:05}")).collect();
    let stripe = native_disk_cache_mutation_lock_stripe(&keys[1]);
    let incoming = (4..10_000)
        .map(|n| format!("/asset.png?item={n:05}"))
        .find(|key| native_disk_cache_mutation_lock_stripe(key) == stripe)
        .unwrap();
    assert_ne!(incoming, keys[1]);
    let large = body_entry(1200);
    let small = body_entry(800);
    let replacement = body_entry(1300);
    // Determine encoded sizes using the real serializer, including metadata.
    let mut config = storage_bin_config(&directory.path().join("probe"));
    config.max_object_bytes = ByteSize::from_bytes(4096);
    let probe = NativeDiskCache::from_config(&config).unwrap();
    probe.store(disk_cache_store_key(&keys[0]), &large).unwrap();
    probe.store(disk_cache_store_key(&keys[1]), &small).unwrap();
    probe
        .store(disk_cache_store_key(&incoming), &replacement)
        .unwrap();
    let (large_len, small_len, incoming_len) = probe.with_state(|state| {
        (
            state.objects[&keys[0]].weight,
            state.objects[&keys[1]].weight,
            state.objects[&incoming].weight,
        )
    });
    drop(probe);
    assert!(large_len < incoming_len && incoming_len < large_len + small_len);
    config.disk.path = Some(directory.path().join("fragmented"));
    config.disk.storage_bin.bin_size_bytes = ByteSize::from_bytes(large_len + small_len);
    config.disk.max_size_bytes = ByteSize::from_bytes(2 * (large_len + small_len));
    let cache = NativeDiskCache::from_config(&config).unwrap();
    for (key, entry) in keys.iter().zip([&large, &small, &large, &small]) {
        cache.store(disk_cache_store_key(key), entry).unwrap();
    }
    assert_eq!(cache.stats().entries, 4);
    assert!(cache.remove_combined(&keys[0]));
    assert!(cache.remove_combined(&keys[2]));
    cache.with_state_mut(|state| {
        state.touch_object(&keys[1], SystemTime::UNIX_EPOCH);
        state.touch_object(&keys[3], SystemTime::UNIX_EPOCH + Duration::from_secs(1));
    });
    // Both free holes are too small, even though their sum is sufficient.
    assert!(2 * large_len > incoming_len);
    assert!(
        cache
            .allocate_storage_bin_location(incoming_len)
            .unwrap()
            .is_none()
    );
    assert_eq!(cache.stats().entries, 2, "allocation must not evict");
    cache
        .store(disk_cache_store_key(&incoming), &replacement)
        .unwrap();
    assert!(
        cache.get_combined(&keys[1]).is_none(),
        "same-stripe victim survived"
    );
    assert_eq!(&*cache.get_combined(&keys[3]).unwrap().body, &*small.body);
    assert_eq!(
        &*cache.get_combined(&incoming).unwrap().body,
        &*replacement.body
    );
    assert_eq!(
        cache.with_state(|state| (state.pending_objects, state.pending_bytes)),
        (0, 0)
    );
    assert_eq!(cache.stats().size_bytes, incoming_len + small_len);
    drop(cache);
    let cache = NativeDiskCache::from_config(&config).unwrap();
    assert_eq!(cache.stats().entries, 2);
    assert_eq!(
        &*cache.get_combined(&incoming).unwrap().body,
        &*replacement.body
    );
}

#[test]
fn storage_bin_fragmented_same_stripe_store_finishes_and_restarts() {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_http1_cache::tests::fragmentation::storage_bin_fragmented_collision_child",
            "--nocapture",
        ])
        .env("FLUXHEIM_FRAGMENTED_BIN_CHILD", "1")
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("fragmented same-stripe store did not complete");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
