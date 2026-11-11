use super::*;

#[tokio::test]
async fn slice_disk_corruption_is_a_miss_including_encrypted_objects() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        for encrypted in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let config = config(root.path(), backend, false, encrypted);
            let cache = NativeProxyMemoryCache::from_config(&config).unwrap();
            let req = request("en");
            let (primary, key) = keys(&cache, &req);
            cache
                .store_origin_slice(
                    &primary,
                    &key,
                    &req,
                    bounds(),
                    &response(b"abcd", "bytes 0-3/8", "\"v1\""),
                )
                .await
                .unwrap();
            drop(cache);
            let mut objects = Vec::new();
            for directory in std::fs::read_dir(root.path().join("objects")).unwrap() {
                let directory = directory.unwrap().path();
                if !directory.is_dir() {
                    continue;
                }
                for file in std::fs::read_dir(directory).unwrap() {
                    let file = file.unwrap().path();
                    if matches!(
                        file.extension().and_then(|ext| ext.to_str()),
                        Some("fhc" | "fhbin")
                    ) {
                        objects.push(file);
                    }
                }
            }
            assert_eq!(objects.len(), 1);
            let file = &objects[0];
            let mut bytes = std::fs::read(file).unwrap();
            if encrypted {
                assert!(!bytes.windows(4).any(|window| window == b"abcd"));
            }
            // Break object framing/authentication without deleting the index.
            bytes[0] ^= 0xff;
            std::fs::write(file, bytes).unwrap();
            let cache = NativeProxyMemoryCache::from_config(&config).unwrap();
            assert!(
                cache
                    .lookup_cached_slice(&key, bounds())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(cache.disk.as_ref().unwrap().stats().entries, 0);
        }
    }
}

#[tokio::test]
async fn slice_storage_bin_missing_index_is_cold_not_unverified_salvage() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path(), CacheDiskBackend::StorageBin, false, false);
    let cache = NativeProxyMemoryCache::from_config(&config).unwrap();
    let req = request("en");
    let (primary, key) = keys(&cache, &req);
    cache
        .store_origin_slice(
            &primary,
            &key,
            &req,
            bounds(),
            &response(b"abcd", "bytes 0-3/8", "\"v1\""),
        )
        .await
        .unwrap();
    drop(cache);
    std::fs::remove_file(root.path().join("objects/.fluxheim-storage-bin-index-v1")).unwrap();
    let cache = NativeProxyMemoryCache::from_config(&config).unwrap();
    assert!(
        cache
            .lookup_cached_slice(&key, bounds())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(cache.disk.as_ref().unwrap().stats().entries, 0);
}
