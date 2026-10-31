use super::*;
use crate::NativeHttp1Handler;
use crate::native_http1_test_utils::read_request_head;

#[test]
fn native_latency_storage_bounds_preserve_unknown_and_positive_samples() {
    let mut response = crate::NativeHttp1Response::new(200, "OK", b"ok");
    assert_eq!(response.upstream_header_latency(), None);
    response.set_upstream_header_latency(Duration::ZERO);
    assert_eq!(
        response.upstream_header_latency(),
        Some(Duration::from_nanos(1))
    );
    response.set_upstream_header_latency(Duration::MAX);
    assert_eq!(
        response.upstream_header_latency(),
        Some(Duration::from_nanos(u64::MAX))
    );
}

#[tokio::test]
async fn native_latency_http2_stream_queue_and_other_body_do_not_train_header_wait() {
    for streams in [1, 2] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let ready = Arc::new(tokio::sync::Notify::new());
        let seen = ready.clone();
        let origin = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(stream).await.unwrap();
            let mut replies = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    request = connection.accept() => {
                        let Some(Ok((request, mut respond))) = request else { break };
                        let slow = request.uri().path() == "/slow";
                        let mut body = respond.send_response(http::Response::new(()), false).unwrap();
                        if slow { seen.notify_one(); }
                        replies.spawn(async move {
                            if slow { tokio::time::sleep(Duration::from_millis(600)).await; }
                            body.send_data(bytes::Bytes::from_static(b"ok"), true).unwrap();
                        });
                    }
                    Some(result) = replies.join_next() => { result.unwrap(); }
                }
            }
        });
        let upstream = NativeHttp1Upstream::new(address.to_string())
            .with_read_timeout(Duration::from_secs(3))
            .with_http2_policy(
                crate::DownstreamHttp2Policy::default().with_max_concurrent_streams(streams),
            );
        let slow_upstream = upstream.clone();
        let slow = tokio::spawn(async move {
            slow_upstream
                .send(&mut native_proxy_test_request_for("/slow"))
                .await
                .unwrap()
        });
        tokio::time::timeout(Duration::from_secs(3), ready.notified())
            .await
            .unwrap();
        let fast = tokio::time::timeout(
            Duration::from_secs(3),
            upstream.send(&mut native_proxy_test_request_for("/fast")),
        )
        .await
        .unwrap()
        .unwrap();
        let slow = slow.await.unwrap();
        for response in [fast, slow] {
            assert_eq!(response.body(), b"ok");
            assert!(response.upstream_header_latency().unwrap() < Duration::from_millis(300));
        }
        origin.abort();
        let _ = origin.await;
    }
}

#[tokio::test]
async fn native_latency_timeout_is_one_passive_failure_without_a_sample() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let other = origins(&[reply(200, "")]).await;
    let mut config = config(&other);
    config
        .upstreams
        .insert(0, listener.local_addr().unwrap().to_string());
    config.disabled_upstreams = vec![other[0].address.to_string()];
    config.read_timeout_secs = Some(1);
    config.load_balance.retry.enabled = false;
    config.load_balance.selection = fluxheim_config::LoadBalanceSelection::LeastTime;
    config.load_balance.passive_health.enabled = true;
    config.load_balance.passive_health.consecutive_failure = 1;
    config.load_balance.passive_health.min_healthy_backends = 0;
    let proxy = proxy(&config);
    let pool = proxy.load_balancer.clone().unwrap();
    let request = tokio::spawn(async move { dispatch(&proxy, native_proxy_test_request()).await });
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
        .await
        .unwrap()
        .unwrap();
    read_request_head(&mut stream).await;
    assert_eq!(request.await.unwrap().status(), 504);
    let stats = pool.runtime_stats();
    assert!(
        stats
            .backends
            .iter()
            .all(|b| b.latency_micros.is_none() && b.in_flight == 0)
    );
    assert_eq!(stats.passive_ejected_backend_count, 1);
    assert_eq!(stats.retry.admitted, 0);
}

#[tokio::test]
async fn native_latency_records_each_retry_but_not_reset_or_invalid_body() {
    for h2 in [false, true] {
        for failure in [false, true] {
            let origins = if h2 {
                h2_origins(&[if failure { 0 } else { 503 }, 200]).await
            } else {
                origins(&[
                    if failure {
                        "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nshort".into()
                    } else {
                        reply(503, "")
                    },
                    reply(200, ""),
                ])
                .await
            };
            let mut config = config(&origins);
            config.upstream_priority_groups = vec![20, 10];
            config.load_balance.selection = fluxheim_config::LoadBalanceSelection::LeastTime;
            if h2 {
                config.upstream_http_version = fluxheim_config::UpstreamHttpVersion::Http2;
            }
            let proxy = proxy(&config);
            assert_eq!(
                dispatch(&proxy, native_proxy_test_request()).await.status(),
                200
            );
            let stats = proxy.load_balancer.as_ref().unwrap().runtime_stats();
            assert_eq!(calls(&origins), 2);
            assert_eq!(stats.retry.admitted, 1);
            assert_eq!(
                stats
                    .backends
                    .iter()
                    .filter(|b| b.latency_micros.is_some())
                    .count(),
                if failure { 1 } else { 2 }
            );
            assert!(stats.backends.iter().all(|b| b.in_flight == 0));
        }
    }
}

#[tokio::test]
async fn native_latency_excludes_response_body_transfer_for_http1_and_http2() {
    for h2 in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let other = origins(&[reply(200, "")]).await;
        let mut config = config(&other);
        config.upstreams.insert(0, address.to_string());
        config.disabled_upstreams = vec![other[0].address.to_string()];
        config.load_balance.selection = fluxheim_config::LoadBalanceSelection::LeastTime;
        config.load_balance.passive_health.enabled = true;
        config.load_balance.passive_health.max_latency_ms = 500;
        config.load_balance.passive_health.consecutive_failure = 1;
        config.load_balance.passive_health.min_healthy_backends = 0;
        if h2 {
            config.upstream_http_version = fluxheim_config::UpstreamHttpVersion::Http2;
        }
        let origin = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            if h2 {
                let mut connection = h2::server::handshake(stream).await.unwrap();
                let (_, mut respond) = connection.accept().await.unwrap().unwrap();
                let mut body = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let send = async move {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    body.send_data(bytes::Bytes::from_static(b"ok"), true)
                        .unwrap();
                    std::future::pending::<()>().await;
                };
                tokio::select! {
                    () = send => {},
                    _ = async { while connection.accept().await.is_some() {} } => {},
                }
            } else {
                read_request_head(&mut stream).await;
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_secs(1)).await;
                stream.write_all(b"ok").await.unwrap();
            }
        });
        let proxy = proxy(&config);
        let started = std::time::Instant::now();
        let response = dispatch(&proxy, native_proxy_test_request()).await;
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), b"ok");
        assert!(started.elapsed() >= Duration::from_secs(1));
        let stats = proxy.load_balancer.as_ref().unwrap().runtime_stats();
        assert_eq!(stats.passive_ejected_backend_count, 0);
        assert!(
            stats
                .backends
                .iter()
                .any(|b| b.latency_micros.is_some_and(|us| us < 500_000))
        );
        origin.abort();
        let _ = origin.await;
    }
}

#[tokio::test]
async fn native_latency_cancellation_does_not_publish_an_incomplete_sample() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let other = origins(&[reply(200, "")]).await;
    let mut config = config(&other);
    config
        .upstreams
        .insert(0, listener.local_addr().unwrap().to_string());
    config.disabled_upstreams = vec![other[0].address.to_string()];
    config.load_balance.selection = fluxheim_config::LoadBalanceSelection::LeastTime;
    config.load_balance.passive_health.enabled = true;
    config.load_balance.passive_health.consecutive_failure = 1;
    config.load_balance.passive_health.min_healthy_backends = 0;
    let proxy = proxy(&config);
    let pool = proxy.load_balancer.clone().unwrap();
    let request = tokio::spawn(async move { proxy.handle(native_proxy_test_request()).await });
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
        .await
        .unwrap()
        .unwrap();
    read_request_head(&mut stream).await;
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\npartial")
        .await
        .unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    let stats = pool.runtime_stats();
    assert!(
        stats
            .backends
            .iter()
            .all(|b| b.latency_micros.is_none() && b.in_flight == 0)
    );
    assert_eq!(stats.passive_ejected_backend_count, 0);
}
