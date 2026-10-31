use super::*;
use crate::NativeHttp1Handler;
use crate::native_http1_test_utils::read_request_head;

#[tokio::test]
async fn native_load_balanced_retry_cancellation_releases_member_but_keeps_admission_charge() {
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
    config.load_balance.retry.enabled = true;
    config.load_balance.retry.statuses = vec![503];
    config.load_balance.retry.budget_per_window = 1;
    config.load_balance.retry.budget_window_secs = 3600;
    let proxy = proxy(&config);
    let pool = proxy.load_balancer.clone().unwrap();
    let task = tokio::spawn(async move { proxy.handle(native_proxy_test_request()).await });
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), first.accept())
        .await
        .unwrap()
        .unwrap();
    read_request_head(&mut stream).await;
    stream.write_all(reply(503, "").as_bytes()).await.unwrap();
    drop(stream);
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), second.accept())
        .await
        .unwrap()
        .unwrap();
    read_request_head(&mut stream).await;
    assert_eq!(
        pool.runtime_stats()
            .backends
            .iter()
            .map(|backend| backend.in_flight)
            .sum::<usize>(),
        1
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(
        pool.runtime_stats()
            .backends
            .iter()
            .all(|backend| backend.in_flight == 0)
    );
    assert_eq!(pool.runtime_stats().retry.admitted, 1);
    assert!(pool.retry_sequence("GET", true).reserve(None).is_none());
    drop(stream);
}

#[tokio::test]
async fn native_load_balanced_retry_preserves_initial_queue_and_all_down_status() {
    let origins = origins(&[reply(503, ""), reply(200, "")]).await;
    let mut config = config(&origins);
    config.upstream_max_in_flight = vec![1, 1];
    config.load_balance.all_down_status = 503;
    config.load_balance.queue.max_waiting = 1;
    config.load_balance.queue.timeout_ms = 25;
    config.load_balance.queue.retry_interval_ms = 5;
    let proxy = proxy(&config);
    let pool = proxy.load_balancer.as_ref().unwrap();
    let first = pool.select(&native_proxy_test_request(), None).unwrap();
    let second = pool.select(&native_proxy_test_request(), None).unwrap();
    assert_eq!(
        dispatch(&proxy, native_proxy_test_request()).await.status(),
        503
    );
    assert_eq!(calls(&origins), 0);
    assert_eq!(pool.runtime_stats().queue.waiting, 0);
    assert_eq!(pool.runtime_stats().retry.admitted, 0);
    drop((first, second));
    assert_eq!(
        dispatch(&proxy, native_proxy_test_request()).await.status(),
        200
    );
    assert!(
        pool.runtime_stats()
            .backends
            .iter()
            .all(|backend| backend.in_flight == 0)
    );
}

#[tokio::test]
async fn native_load_balanced_retry_does_not_enter_queue_when_alternative_is_saturated() {
    let origins = origins(&[reply(503, ""), reply(200, "")]).await;
    let mut config = config(&origins);
    config.upstream_max_in_flight = vec![1, 1];
    config.load_balance.queue.max_waiting = 1;
    config.load_balance.queue.timeout_ms = 60_000;
    let proxy = proxy(&config);
    let pool = proxy.load_balancer.as_ref().unwrap();
    let first = pool.select(&native_proxy_test_request(), None).unwrap();
    let second = pool.select(&native_proxy_test_request(), None).unwrap();
    drop(first);
    let response = dispatch(&proxy, native_proxy_test_request()).await;
    assert_eq!(response.status(), 503);
    assert_eq!(calls(&origins), 1);
    assert_eq!(pool.runtime_stats().retry.admitted, 0);
    assert_eq!(pool.runtime_stats().queue.waiting, 0);
    drop(second);
}

#[tokio::test]
async fn native_load_balanced_retry_disabled_prevents_hidden_http1_pool_replay() {
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = fluxheim_config::ProxyConfig {
        upstreams: vec![
            first.local_addr().unwrap().to_string(),
            second.local_addr().unwrap().to_string(),
        ],
        disabled_upstreams: vec![second.local_addr().unwrap().to_string()],
        ..Default::default()
    };
    config.load_balance.health_check.enabled = false;
    let task = tokio::spawn(async move {
        let (mut stream, _) = first.accept().await.unwrap();
        read_request_head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
        // Fail after the second request on the reused connection, not before
        // the proxy has a chance to put that connection in its idle pool.
        read_request_head(&mut stream).await;
        drop(stream);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), first.accept())
                .await
                .is_err(),
            "hidden fresh-connection replay"
        );
    });
    let mut proxy = proxy(&config);
    proxy.upstreams = proxy
        .upstreams
        .into_iter()
        .map(|upstream| upstream.with_pool_max_idle(1))
        .collect();
    assert_eq!(
        dispatch(&proxy, native_proxy_test_request()).await.status(),
        200
    );
    assert_eq!(
        dispatch(&proxy, native_proxy_test_request()).await.status(),
        502
    );
    task.await.unwrap();
    assert_eq!(
        proxy
            .load_balancer
            .as_ref()
            .unwrap()
            .runtime_stats()
            .retry
            .admitted,
        0
    );
}

#[tokio::test]
async fn native_load_balanced_retry_never_commits_a_partial_failed_origin_response() {
    let origins = origins(&[
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\npartial".into(),
        reply(200, ""),
    ])
    .await;
    let listener = proxy_listener_for(proxy(&config(&origins))).await;
    let response = tokio::time::timeout(Duration::from_secs(3), downstream_get(listener, "/"))
        .await
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.ends_with("ok"));
    assert!(!response.contains("partial"));
    assert_eq!(calls(&origins), 2);
}
