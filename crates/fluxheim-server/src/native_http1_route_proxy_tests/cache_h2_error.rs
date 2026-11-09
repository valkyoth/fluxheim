use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use fluxheim_config::{CacheStaleErrorKind, ProxyConfig, UpstreamHttpVersion};

#[tokio::test]
async fn stale_h2_reset_policy_survives_static_and_balanced_dispatch() {
    for balanced in [false, true] {
        for allowed in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_address = listener.local_addr().unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let count = calls.clone();
            let origin = tokio::spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (stream, _) = accepted.unwrap();
                            let count = count.clone();
                            connections.spawn(async move {
                                let mut connection = h2::server::handshake(stream).await.unwrap();
                                while let Some(request) = connection.accept().await {
                                    let (_, mut response) = request.unwrap();
                                    let step = count.fetch_add(1, Ordering::SeqCst);
                                    if step == 1 {
                                        // CANCEL avoids transport's intentional REFUSED_STREAM replay.
                                        response.send_reset(h2::Reason::CANCEL);
                                        continue;
                                    }
                                    let body = if step == 0 { b"trusted" } else { b"renewed" };
                                    let head = http::Response::builder().status(200)
                                        .header("content-type", "image/png")
                                        .header("cache-control", "max-age=1")
                                        .header("content-length", "7").body(()).unwrap();
                                    response.send_response(head, false).unwrap()
                                        .send_data(bytes::Bytes::from_static(body), true).unwrap();
                                }
                            });
                        }
                        Some(result) = connections.join_next() => { result.unwrap(); }
                    }
                }
            });
            let mut config = ProxyConfig {
                upstreams: vec![origin_address.to_string()],
                upstream_http_version: UpstreamHttpVersion::Http2,
                ..Default::default()
            };
            config.load_balance.health_check.enabled = false;
            config.load_balance.retry.enabled = false;
            let proxy = if balanced {
                crate::NativeHttp1Proxy::from_proxy_config_with_native_load_balancer(
                    "stale-h2",
                    "route.test",
                    None,
                    &config,
                    DownstreamHttp1Policy::default(),
                    0,
                )
                .unwrap()
                .unwrap()
                .0
            } else {
                crate::NativeHttp1Proxy::from_proxy_config(
                    &config,
                    DownstreamHttp1Policy::default(),
                )
                .unwrap()
                .unwrap()
            };
            let mut cache = native_proxy_memory_cache_config();
            cache.stale_if_error_secs = Some(60);
            cache.stale_if_error_on = vec![if allowed {
                CacheStaleErrorKind::ConnectionClosed
            } else {
                CacheStaleErrorKind::Read
            }];
            let (address, shutdown, task) = route_proxy_listener_with_shutdown(
                NativeHttp1RouteProxy::new(Vec::new(), Some(proxy.with_proxy_cache_config(&cache))),
            )
            .await;
            let first = downstream_get(address, "/asset.png").await;
            assert!(first.ends_with("trusted"), "{first}");
            tokio::time::sleep(Duration::from_millis(1100)).await;
            let failed = downstream_get(address, "/asset.png").await;
            assert_eq!(
                failed.ends_with("trusted"),
                allowed,
                "balanced={balanced}: {failed}"
            );
            assert_eq!(
                response_header(&failed, "x-cache-status").as_deref() == Some("STALE"),
                allowed
            );
            assert_eq!(calls.load(Ordering::SeqCst), 2, "no hidden retry");
            let recovery = downstream_get(address, "/asset.png").await;
            assert!(recovery.ends_with("renewed"), "{recovery}");
            shutdown.send(()).unwrap();
            task.await.unwrap();
            origin.abort();
            assert!(origin.await.unwrap_err().is_cancelled());
        }
    }
}
