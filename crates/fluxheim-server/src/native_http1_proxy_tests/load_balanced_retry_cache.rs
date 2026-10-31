use super::*;
use crate::native_http1_proxy_memory_cache::NativeProxyCacheLookup;

fn cache_config() -> fluxheim_config::CacheConfig {
    let mut config = fluxheim_config::CacheConfig {
        enabled: true,
        status_header: Some("x-cache-status".into()),
        ..Default::default()
    };
    config.memory.enabled = true;
    config.predictor.enabled = false;
    config
}

fn cache_status(response: &crate::NativeHttp1Response) -> Option<&str> {
    response
        .headers()
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-cache-status"))
        .map(|(_, value)| value.as_str())
}

#[tokio::test]
async fn native_load_balanced_retry_caches_only_the_final_success() {
    let origins = origins(&[
        reply(503, ""),
        reply(
            200,
            "Content-Type: image/png\r\nCache-Control: max-age=60\r\n",
        ),
    ])
    .await;
    let mut config = config(&origins);
    config.upstream_priority_groups = vec![20, 10];
    config.load_balance.selection = fluxheim_config::LoadBalanceSelection::LeastTime;
    let proxy = proxy(&config).with_proxy_cache_config(&cache_config());
    let request = native_proxy_test_request_for("/asset.png");
    let first = dispatch(&proxy, request.metadata_snapshot()).await;
    assert_eq!(first.status(), 200);
    assert_eq!(cache_status(&first), Some("MISS"));
    let samples = || {
        proxy
            .load_balancer
            .as_ref()
            .unwrap()
            .runtime_stats()
            .backends
            .iter()
            .map(|b| b.latency_micros)
            .collect::<Vec<_>>()
    };
    let before_hit = samples();
    assert!(before_hit.iter().all(Option::is_some));
    let second = dispatch(&proxy, request).await;
    assert_eq!(cache_status(&second), Some("HIT"));
    assert_eq!(
        samples(),
        before_hit,
        "cache hits must not train upstream latency"
    );
    assert_eq!(calls(&origins), 2);
    assert_eq!(
        proxy
            .load_balancer
            .as_ref()
            .unwrap()
            .runtime_stats()
            .retry
            .admitted,
        1
    );
}

#[tokio::test]
async fn native_load_balanced_retry_foreground_and_background_revalidation_obey_policy() {
    for background in [false, true] {
        for enabled in [false, true] {
            let origins = origins(&[reply(503, ""), "HTTP/1.1 304 Not Modified\r\nCache-Control: max-age=60\r\nConnection: close\r\n\r\n".into()]).await;
            let mut config = config(&origins);
            config.load_balance.retry.enabled = enabled;
            let mut cache_config = cache_config();
            cache_config.stale_if_error_secs = Some(60);
            cache_config.stale_if_error_statuses = vec![503];
            cache_config.stale_while_revalidate_secs = Some(if background { 60 } else { 0 });
            let proxy = proxy(&config).with_proxy_cache_config(&cache_config);
            let cache = proxy.cache.as_ref().unwrap();
            let request = native_proxy_test_request_for("/asset.png");
            let NativeProxyCacheLookup::Miss { key, .. } =
                cache.lookup_with_key_components(&request, &[]).await
            else {
                panic!("expected cache miss")
            };
            let seed = crate::NativeHttp1Response::new(200, "OK", b"seed")
                .with_header("content-type", "image/png")
                .with_header("cache-control", "max-age=60")
                .with_header("etag", "\"v1\"");
            cache.store(&key, &request, &seed).await.unwrap();
            {
                let mut state = cache.state.lock().unwrap();
                let entry = state.objects.get_mut(&key).unwrap();
                entry.expires_at = std::time::Instant::now() - Duration::from_secs(1);
                entry.stale_while_revalidate_until =
                    background.then(|| std::time::Instant::now() + Duration::from_secs(60));
            }
            let response = dispatch(&proxy, request).await;
            if background {
                assert_eq!(cache_status(&response), Some("STALE-UPDATING"));
                tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        if cache.state.lock().unwrap().revalidating.is_empty() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .unwrap();
            } else if enabled {
                assert_eq!(response.status(), 200);
                assert_eq!(response.body(), b"seed");
                assert_eq!(cache_status(&response), Some("REVALIDATED"));
            } else {
                assert_eq!(response.status(), 200);
                assert_eq!(cache_status(&response), Some("STALE"));
            }
            assert_eq!(calls(&origins), if enabled { 2 } else { 1 });
            assert_eq!(
                proxy
                    .load_balancer
                    .as_ref()
                    .unwrap()
                    .runtime_stats()
                    .retry
                    .admitted,
                u64::from(enabled)
            );
            if enabled {
                assert!(
                    cache
                        .state
                        .lock()
                        .unwrap()
                        .objects
                        .get(&key)
                        .unwrap()
                        .expires_at
                        > std::time::Instant::now()
                );
            }
        }
    }
}

#[tokio::test]
async fn native_load_balanced_retry_slice_fill_shares_budget_with_foreground_dispatch() {
    let origins = origins(&[reply(503, ""), reply(206, "Content-Range: bytes 0-1/2\r\nContent-Type: image/png\r\nCache-Control: max-age=60\r\n")]).await;
    let mut config = config(&origins);
    config.upstream_priority_groups = vec![20, 10];
    config.load_balance.retry.budget_per_window = 1;
    config.load_balance.retry.budget_window_secs = 3600;
    let mut cache_config = cache_config();
    cache_config.range.enabled = true;
    cache_config.range.slice.enabled = true;
    cache_config.range.slice.fill_missing = true;
    cache_config.range.slice.size_bytes = fluxheim_config::ByteSize::from_bytes(2);
    let proxy = proxy(&config).with_proxy_cache_config(&cache_config);
    let request = native_proxy_test_request_for("/asset.png");
    let bounds = fluxheim_cache::CacheSliceBounds { start: 0, end: 1 };
    let response = proxy.fetch_origin_slice(&request, bounds).await.unwrap();
    assert_eq!(response.status(), 206);
    assert_eq!(calls(&origins), 2);
    let response = dispatch(&proxy, native_proxy_test_request_for("/other.png")).await;
    assert_eq!(response.status(), 503);
    assert_eq!(calls(&origins), 3);
    let response = proxy.fetch_origin_slice(&request, bounds).await.unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(calls(&origins), 4);
    assert_eq!(
        proxy
            .load_balancer
            .as_ref()
            .unwrap()
            .runtime_stats()
            .retry
            .admitted,
        1
    );
}

#[tokio::test]
async fn native_load_balanced_retry_slice_fallback_does_not_reset_pool_budget() {
    for enabled in [false, true] {
        let origins = origins(&[reply(503, ""), reply(503, "")]).await;
        let mut config = config(&origins);
        config.load_balance.retry.enabled = enabled;
        config.load_balance.retry.max_retries = 1;
        config.load_balance.retry.budget_per_window = 1;
        config.load_balance.retry.budget_window_secs = 3600;
        let mut cache_config = cache_config();
        cache_config.range.enabled = true;
        cache_config.range.slice.enabled = true;
        cache_config.range.slice.fill_missing = true;
        cache_config.range.slice.size_bytes = fluxheim_config::ByteSize::from_bytes(2);
        let proxy = proxy(&config).with_proxy_cache_config(&cache_config);
        let mut request = native_proxy_test_request_for("/asset.png");
        request.headers.push(("range".into(), "bytes=0-1".into()));
        assert_eq!(dispatch(&proxy, request).await.status(), 503);
        // One slice fetch plus the existing full-response fallback. Only the
        // slice fetch can spend the shared budget's single retry admission.
        assert_eq!(calls(&origins), if enabled { 3 } else { 2 });
        assert_eq!(
            proxy
                .load_balancer
                .as_ref()
                .unwrap()
                .runtime_stats()
                .retry
                .admitted,
            u64::from(enabled)
        );
    }
}

#[tokio::test]
async fn native_load_balanced_retry_slice_does_not_bypass_disabled_policy_or_body_limit() {
    for enabled in [false, true] {
        let oversized =
            "HTTP/1.1 206 Test\r\nContent-Length: 100\r\nConnection: close\r\n\r\n".to_owned();
        let origins = origins(&[reply(503, ""), oversized]).await;
        let mut config = config(&origins);
        config.load_balance.retry.enabled = enabled;
        let mut cache_config = cache_config();
        cache_config.range.slice.size_bytes = fluxheim_config::ByteSize::from_bytes(2);
        let proxy = proxy(&config).with_proxy_cache_config(&cache_config);
        let result = proxy
            .fetch_origin_slice(
                &native_proxy_test_request_for("/asset.png"),
                fluxheim_cache::CacheSliceBounds { start: 0, end: 1 },
            )
            .await;
        if enabled {
            assert!(result.is_none());
        } else {
            assert_eq!(result.unwrap().status(), 503);
        }
        assert_eq!(calls(&origins), if enabled { 2 } else { 1 });
    }
}
