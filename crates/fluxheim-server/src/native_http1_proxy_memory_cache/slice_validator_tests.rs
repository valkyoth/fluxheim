use super::*;

fn invalid_etags() -> Vec<Vec<&'static str>> {
    vec![
        vec![],
        vec!["W/\"v1\""],
        vec!["v1"],
        vec!["\""],
        vec!["\"v1\", \"v2\""],
        vec!["\"v1\"", "\"v1\""],
        vec!["\"v1\"", "\"v2\""],
        vec!["\"with space\""],
        vec!["\"with\ttab\""],
        vec!["\"with\x7fcontrol\""],
        vec!["\"embedded\"quote\""],
    ]
}

fn replace_etags(headers: &mut Vec<(String, String)>, values: &[&str]) {
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case("etag"));
    headers.extend(values.iter().map(|value| ("ETag".into(), (*value).into())));
}

#[tokio::test]
async fn slice_admission_requires_one_valid_strong_etag() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path(), CacheDiskBackend::Filesystem, true, false);
    let cache = NativeProxyMemoryCache::from_config(&config).unwrap();
    let req = request("en");
    let (primary, key) = keys(&cache, &req);
    for values in invalid_etags() {
        let mut origin = response(b"abcd", "bytes 0-3/8", "\"v1\"");
        origin.remove_header("etag");
        origin.push_header("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT");
        for value in &values {
            origin.push_header("ETag", *value);
        }
        assert!(
            cache
                .store_origin_slice(&primary, &key, &req, bounds(), &origin)
                .await
                .is_none(),
            "{values:?}"
        );
        assert_eq!(cache.disk.as_ref().unwrap().stats().entries, 0);
        assert!(
            lock_native_memory_cache(&cache.state, "test")
                .objects
                .is_empty()
        );
    }
    for value in ["\"v1\"", "\"\"", "\"comma,inside\"", " \"v1\"\t"] {
        assert!(
            cache
                .store_origin_slice(
                    &primary,
                    &key,
                    &req,
                    bounds(),
                    &response(b"abcd", "bytes 0-3/8", value)
                )
                .await
                .is_some(),
            "{value:?}"
        );
    }
}

#[tokio::test]
async fn slice_legacy_invalid_validators_are_removed_from_memory_and_recovered_disk() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        for encrypted in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let config = config(root.path(), backend, true, encrypted);
            let mut cache = NativeProxyMemoryCache::from_config(&config).unwrap();
            let req = request("en");
            let (primary, key) = keys(&cache, &req);
            let good = cache
                .store_origin_slice(
                    &primary,
                    &key,
                    &req,
                    bounds(),
                    &response(b"abcd", "bytes 0-3/8", "\"v1\""),
                )
                .await
                .unwrap()
                .entry;
            for values in invalid_etags() {
                for restart in [false, true] {
                    // Simulate a record admitted by the previous implementation.
                    let mut legacy = good.clone();
                    replace_etags(&mut legacy.headers, &values);
                    legacy.headers.push((
                        "last-modified".into(),
                        "Wed, 21 Oct 2015 07:28:00 GMT".into(),
                    ));
                    cache
                        .store_slice_entry(&primary, &key, req.path(), vec![], legacy)
                        .await;
                    assert_eq!(cache.disk.as_ref().unwrap().stats().entries, 1);
                    if restart {
                        drop(cache);
                        cache = NativeProxyMemoryCache::from_config(&config).unwrap();
                    }
                    assert!(
                        cache
                            .lookup_cached_slice(&key, bounds())
                            .await
                            .unwrap()
                            .is_none(),
                        "{backend:?} {encrypted} {restart} {values:?}"
                    );
                    assert_eq!(cache.disk.as_ref().unwrap().stats().entries, 0);
                    let state = lock_native_memory_cache(&cache.state, "test");
                    assert!(state.objects.is_empty());
                    assert_eq!(state.bytes, 0);
                }
            }
        }
    }
}

#[tokio::test]
async fn slice_hidden_etag_bypasses_existing_entries_and_new_admission() {
    let root = tempfile::tempdir().unwrap();
    let mut config = config(root.path(), CacheDiskBackend::Filesystem, true, false);
    let cache = NativeProxyMemoryCache::from_config(&config).unwrap();
    let req = request("en");
    let (primary, key) = keys(&cache, &req);
    let origin = response(b"abcd", "bytes 0-3/8", "\"v1\"");
    cache
        .store_origin_slice(&primary, &key, &req, bounds(), &origin)
        .await
        .unwrap();
    drop(cache);
    config.hide_response_headers.push("ETag".into());
    let cache = NativeProxyMemoryCache::from_config(&config).unwrap();
    assert!(
        cache
            .store_origin_slice(&primary, &key, &req, bounds(), &origin)
            .await
            .is_none()
    );
    let proxy = NativeHttp1Proxy::new(crate::NativeHttp1Upstream::new("127.0.0.1:1"));
    assert!(
        cache
            .slice_response(
                &req,
                &proxy,
                #[cfg(feature = "wasm")]
                &[]
            )
            .await
            .unwrap()
            .is_none()
    );
}
