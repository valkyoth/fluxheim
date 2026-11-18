use super::*;
use fluxheim_common::test_process::{TestBinary, self_command};

#[test]
fn acknowledged_purge_child() {
    let Some(mode) = std::env::var_os("FLUXHEIM_HARD_CHECKPOINT_CHILD") else {
        return;
    };
    let root = std::env::current_dir().unwrap();
    let mut config = storage_bin_config(&root.join("cache"));
    if mode == "encrypted" {
        config.disk.encryption.enabled = true;
        config.disk.encryption.key_file = Some(root.join("key"));
    }
    let cache = Arc::new(NativeDiskCache::from_config(&config).unwrap());
    cache.suspend_periodic_checkpoint_for_test();
    register_native_disk_cache_purge_handle("hard-checkpoint".into(), None, &cache);
    assert!(cache.get("removed", |_| None).is_some());
    if mode == "encrypted" {
        let batch = crate::purge_native_disk_cache_path_exact(
            "hard-checkpoint",
            None,
            "cache.test",
            "/removed",
            32,
            false,
        )
        .unwrap();
        assert_eq!(batch.purged, 1);
    } else {
        assert!(
            crate::purge_native_disk_cache_primary("hard-checkpoint", None, "removed", "removed")
                .unwrap()
        );
    }
    if mode == "batch" {
        assert!(
            crate::purge_native_disk_cache_primary("hard-checkpoint", None, "second", "second")
                .unwrap()
        );
        assert!(cache.get("survivor", |_| None).is_some());
    }
    std::fs::write("acknowledged", []).unwrap();
    // The parent terminates this child without running the cache destructor.
    std::thread::sleep(Duration::from_secs(45));
    panic!("parent did not terminate the qualification child");
}

#[test]
fn acknowledged_purge_survives_exit_without_destructors() {
    for mode in ["plain", "encrypted", "batch"] {
        let root = tempfile::tempdir().unwrap();
        let mut config = storage_bin_config(&root.path().join("cache"));
        if mode == "encrypted" {
            super::store_admission::configure_encryption(&mut config, root.path());
        }
        let cache = NativeDiskCache::from_config(&config).unwrap();
        for key in ["removed", "second", "survivor"] {
            cache
                .store(disk_cache_store_key(key), &disk_cache_entry(b"value"))
                .unwrap();
        }
        drop(cache);
        let mut child = self_command(TestBinary::NativeServer)
            .unwrap()
            .args([
                "--exact",
                "native_http1_cache::tests::hard_checkpoint::acknowledged_purge_child",
            ])
            .current_dir(root.path())
            .env("FLUXHEIM_HARD_CHECKPOINT_CHILD", mode)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if root.path().join("acknowledged").is_file() {
                child.kill().unwrap();
                child.wait().unwrap();
                break;
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "child exited before acknowledgement"
            );
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("hard purge acknowledgement timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let recovered = NativeDiskCache::from_config(&config).unwrap();
        assert!(recovered.get("removed", |_| None).is_none());
        if mode == "batch" {
            assert!(recovered.get("second", |_| None).is_none());
            assert!(recovered.get("survivor", |_| None).is_none());
        } else {
            assert!(recovered.get("survivor", |_| None).is_some());
        }
    }
}

#[test]
fn failed_publication_cannot_be_acknowledged_by_retrying_a_missing_key() {
    let root = tempfile::tempdir().unwrap();
    let config = storage_bin_config(root.path());
    let scope = format!("failed-checkpoint-{}", root.path().display());
    let cache = Arc::new(NativeDiskCache::from_config(&config).unwrap());
    register_native_disk_cache_purge_handle(scope.as_str().into(), None, &cache);
    for key in ["a", "b"] {
        cache
            .store(disk_cache_store_key(key), &disk_cache_entry(b"value"))
            .unwrap();
    }
    cache.checkpoint_for_test();
    cache.suspend_periodic_checkpoint_for_test();
    let path = fluxheim_cache::storage_bin_index_path(root.path());
    let saved = root.path().join("previous");
    std::fs::rename(&path, &saved).unwrap();
    std::fs::create_dir(&path).unwrap();
    let purge = || crate::purge_native_disk_cache_primary(&scope, None, "a", "a");
    assert!(purge().is_err());
    assert!(purge().is_err());
    assert!(cache.reserve_bin_index("new").is_err());
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(saved, path).unwrap();
    assert!(!purge().unwrap());
    let NativeDiskCacheBackend::StorageBin(bin) = &cache.backend else {
        unreachable!()
    };
    assert!(
        fluxheim_cache::read_storage_bin_index(&bin.layout)
            .unwrap()
            .is_empty()
    );
    drop(cache);
    let recovered = NativeDiskCache::from_config(&config).unwrap();
    for key in ["a", "b"] {
        assert!(recovered.get(key, |_| None).is_none());
    }
}

#[test]
fn unpublishable_hard_snapshot_fails_closed_even_if_empty_checkpoint_succeeds() {
    let root = tempfile::tempdir().unwrap();
    let cache = NativeDiskCache::from_config(&storage_bin_config(root.path())).unwrap();
    cache
        .store(disk_cache_store_key("a"), &disk_cache_entry(b"value"))
        .unwrap();
    cache.checkpoint_for_test();
    cache.suspend_periodic_checkpoint_for_test();
    cache.with_state_mut(|state| {
        let record = state.objects["a"].clone();
        state.insert_object("x".repeat(32 * 1024 + 1), record);
    });
    assert!(cache.checkpoint_hard_purge(true).is_err());
    let NativeDiskCacheBackend::StorageBin(bin) = &cache.backend else {
        unreachable!()
    };
    assert!(
        fluxheim_cache::read_storage_bin_index(&bin.layout)
            .unwrap()
            .is_empty()
    );
    assert!(cache.reserve_bin_index("later").is_err());
    assert!(cache.checkpoint_hard_purge(false).is_ok());
}
