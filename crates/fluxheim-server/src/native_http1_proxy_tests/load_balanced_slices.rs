use super::*;
use fluxheim_load_balancer::LoadBalancerRuntimeBackendState as State;

fn slice_cache() -> fluxheim_config::CacheConfig {
    let mut cache = fluxheim_config::CacheConfig {
        enabled: true,
        ..Default::default()
    };
    cache.memory.enabled = true;
    cache.range.enabled = true;
    cache.range.slice.enabled = true;
    cache.range.slice.size_bytes = fluxheim_config::ByteSize::from_bytes(2);
    cache
}

async fn fill(proxy: &NativeHttp1Proxy) -> Option<crate::NativeHttp1Response> {
    tokio::time::timeout(
        Duration::from_secs(3),
        proxy.fetch_origin_slice(
            &native_proxy_test_request(),
            fluxheim_cache::CacheSliceBounds { start: 0, end: 1 },
        ),
    )
    .await
    .unwrap()
}

#[test]
fn native_slice_discovery_only_capability_matches_load_balancer_support() {
    let mut config = fluxheim_config::ProxyConfig {
        upstream: None,
        ..Default::default()
    };
    assert!(!NativeHttp1Proxy::proxy_cache_supported_for_proxy(
        &slice_cache(),
        &config
    ));
    config.upstreams_file = Some("members.txt".into());
    assert!(NativeHttp1Proxy::proxy_cache_supported_for_proxy(
        &slice_cache(),
        &config
    ));
    config.upstreams_file = None;
    config.upstreams_http_url = Some("http://127.0.0.1:9000/members".into());
    assert!(NativeHttp1Proxy::proxy_cache_supported_for_proxy(
        &slice_cache(),
        &config
    ));
}

#[tokio::test]
async fn native_slice_load_balancer_excludes_unavailable_members_and_recovers() {
    for state in [State::Drained, State::Disabled, State::ForcedDown] {
        let origins = origins(&[reply(206, ""), reply(206, "")]).await;
        let mut config = config(&origins);
        config.upstream_priority_groups = vec![20, 10];
        config.backup_upstreams = vec![origins[1].address.to_string()];
        config.load_balance.selection = fluxheim_config::LoadBalanceSelection::LeastTime;
        let proxy = proxy(&config)
            .with_proxy_cache_config(&slice_cache())
            .unwrap();
        let pool = proxy.load_balancer.as_ref().unwrap();
        let first = origins[0].address.to_string();
        pool.set_runtime_backend_state(&first, state).unwrap();
        assert_eq!(fill(&proxy).await.unwrap().status(), 206);
        assert_eq!(origins[0].count.load(Ordering::SeqCst), 0);
        assert_eq!(origins[1].count.load(Ordering::SeqCst), 1);
        pool.set_runtime_backend_state(&first, State::ManualResume)
            .unwrap();
        assert_eq!(fill(&proxy).await.unwrap().status(), 206);
        assert_eq!(origins[0].count.load(Ordering::SeqCst), 1);
        assert!(
            pool.runtime_stats()
                .backends
                .iter()
                .all(|b| b.latency_micros.is_some())
        );
        assert!(
            pool.runtime_stats()
                .backends
                .iter()
                .all(|b| b.in_flight == 0)
        );
    }
}

#[tokio::test]
async fn native_slice_load_balancer_queue_rejection_never_uses_static_fallback() {
    let origins = origins(&[reply(206, ""), reply(206, "")]).await;
    let mut config = config(&origins);
    config.upstream_max_in_flight = vec![1, 1];
    config.load_balance.queue.max_waiting = 1;
    config.load_balance.queue.timeout_ms = 25;
    config.load_balance.queue.retry_interval_ms = 5;
    let proxy = proxy(&config)
        .with_proxy_cache_config(&slice_cache())
        .unwrap();
    let pool = proxy.load_balancer.as_ref().unwrap();
    let first = pool.select(&native_proxy_test_request(), None).unwrap();
    let second = pool.select(&native_proxy_test_request(), None).unwrap();
    assert!(fill(&proxy).await.is_none());
    assert_eq!(calls(&origins), 0);
    assert_eq!(pool.runtime_stats().queue.waiting, 0);
    assert_eq!(pool.runtime_stats().retry.admitted, 0);
    drop((first, second));
    assert_eq!(fill(&proxy).await.unwrap().status(), 206);
    assert_eq!(calls(&origins), 1);
}

#[tokio::test]
async fn native_slice_load_balancer_cancellation_releases_capacity() {
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = fluxheim_config::ProxyConfig {
        upstreams: vec![
            first.local_addr().unwrap().to_string(),
            second.local_addr().unwrap().to_string(),
        ],
        upstream_priority_groups: vec![20, 10],
        upstream_max_in_flight: vec![1, 1],
        ..Default::default()
    };
    config.load_balance.health_check.enabled = false;
    let proxy = proxy(&config)
        .with_proxy_cache_config(&slice_cache())
        .unwrap();
    let pool = proxy.load_balancer.clone().unwrap();
    let task = tokio::spawn(async move { fill(&proxy).await });
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), first.accept())
        .await
        .unwrap()
        .unwrap();
    crate::native_http1_test_utils::read_request_head(&mut stream).await;
    assert_eq!(
        pool.runtime_stats()
            .backends
            .iter()
            .map(|b| b.in_flight)
            .sum::<usize>(),
        1
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(
        pool.runtime_stats()
            .backends
            .iter()
            .all(|b| b.in_flight == 0)
    );
    drop(stream);
}
