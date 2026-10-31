use super::*;

#[tokio::test]
async fn native_load_balanced_retry_http2_downstream_preserves_policy_and_body_guard() {
    for upstream_h2 in [false, true] {
        for enabled in [false, true] {
            for body in [false, true] {
                let origins = if upstream_h2 {
                    h2_origins(&[503, 200]).await
                } else {
                    origins(&[reply(503, ""), reply(200, "")]).await
                };
                let mut config = config(&origins);
                config.upstream_priority_groups = vec![20, 10];
                config.load_balance.retry.enabled = enabled;
                config.load_balance.retry.budget_per_window = 1;
                config.load_balance.retry.budget_window_secs = 3600;
                if upstream_h2 {
                    config.upstream_http_version = fluxheim_config::UpstreamHttpVersion::Http2;
                }
                let proxy = Arc::new(proxy(&config));
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let handler = proxy.clone();
                let server = tokio::spawn(async move {
                    let (stream, peer) = listener.accept().await.unwrap();
                    let adapter = Arc::new(crate::NativeHttp2RouteAdapter::new(
                        handler,
                        Some(peer),
                        crate::NativeHttp1RequestContext::default(),
                    ));
                    crate::native_http2_stack::serve_native_http2_connection_until_idle(
                        stream,
                        crate::DownstreamHttp2Policy::default(),
                        adapter,
                        Duration::from_millis(100),
                    )
                    .await
                    .unwrap();
                });
                tokio::time::timeout(Duration::from_secs(5), async {
                    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
                    let (client, connection) = h2::client::handshake(stream).await.unwrap();
                    let driver = tokio::spawn(connection);
                    let mut client = client.ready().await.unwrap();
                    for index in 0..2 {
                        let request = http::Request::builder()
                            .uri("http://proxy.test/retry")
                            .header("content-length", if body { "7" } else { "0" })
                            .body(())
                            .unwrap();
                        let (response, mut send) = client.send_request(request, !body).unwrap();
                        if body {
                            send.send_data(bytes::Bytes::from_static(b"payload"), true)
                                .unwrap();
                        }
                        let mut response = response.await.unwrap();
                        let retried = enabled && !body && index == 0;
                        assert_eq!(response.status().as_u16(), if retried { 200 } else { 503 },
                            "upstream_h2={upstream_h2}, enabled={enabled}, body={body}, index={index}");
                        let mut received = Vec::new();
                        while let Some(chunk) = response.body_mut().data().await {
                            received.extend_from_slice(&chunk.unwrap());
                        }
                        assert_eq!(received, b"ok");
                        drop(send);
                    }
                    drop(client);
                    server.await.unwrap();
                    driver.await.unwrap().unwrap();
                })
                .await
                .unwrap();
                assert_eq!(calls(&origins), if enabled && !body { 3 } else { 2 });
                assert_eq!(
                    proxy
                        .load_balancer
                        .as_ref()
                        .unwrap()
                        .runtime_stats()
                        .retry
                        .admitted,
                    u64::from(enabled && !body)
                );
            }
        }
    }
}
