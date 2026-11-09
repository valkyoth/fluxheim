use std::time::Duration;

use fluxheim_config::CacheStaleErrorKind;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use super::*;

#[derive(Clone, Copy, Debug)]
enum Fault {
    Closed,
    Protocol,
    Timeout,
}

impl Fault {
    fn kind(self) -> CacheStaleErrorKind {
        match self {
            Self::Closed => CacheStaleErrorKind::ConnectionClosed,
            Self::Protocol => CacheStaleErrorKind::Protocol,
            Self::Timeout => CacheStaleErrorKind::Timeout,
        }
    }
}

// Keep the listener alive through recovery, so a closed response cannot turn
// into an unrelated connect failure when transport replay is exercised.
async fn origin(
    fault: Fault,
    mandatory: bool,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        for step in 0..3 {
            let (mut stream, _) = listener.accept().await.unwrap();
            crate::native_http1_test_utils::read_request_head(&mut stream).await;
            if step == 1 {
                match fault {
                    Fault::Closed => {}
                    Fault::Protocol => {
                        stream.write_all(b"NOT-HTTP\r\n\r\n").await.unwrap();
                    }
                    Fault::Timeout => {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
                continue;
            }
            let body = if step == 0 { "trusted" } else { "renewed" };
            let directive = if mandatory { ", must-revalidate" } else { "" };
            stream.write_all(format!(
                "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=1{directive}\r\ncontent-length: 7\r\nconnection: close\r\n\r\n{body}"
            ).as_bytes()).await.unwrap();
        }
    });
    (address, task)
}

#[tokio::test]
async fn stale_error_reason_is_explicit_across_memory_disk_and_restart() {
    use crate::{NativeHttp1Proxy, NativeHttp1Upstream};
    for tier in ["memory", "disk", "storage-bin"] {
        for fault in [Fault::Closed, Fault::Protocol, Fault::Timeout] {
            for (allowed, mandatory) in [(true, false), (false, false), (true, true)] {
                let root = tempfile::tempdir().unwrap();
                let mut cache = match tier {
                    "disk" => native_proxy_disk_cache_config(root.path().join("cache")),
                    "storage-bin" => {
                        native_proxy_storage_bin_cache_config(root.path().join("cache"))
                    }
                    _ => native_proxy_memory_cache_config(),
                };
                cache.stale_if_error_secs = Some(60);
                cache.stale_if_error_on = vec![if allowed {
                    fault.kind()
                } else {
                    CacheStaleErrorKind::Read
                }];
                let (address, origin_task) = origin(fault, mandatory).await;
                let make_proxy = || {
                    let upstream = NativeHttp1Upstream::new(address.to_string())
                        .with_read_timeout(Duration::from_millis(100));
                    NativeHttp1RouteProxy::new(
                        Vec::new(),
                        Some(NativeHttp1Proxy::new(upstream).with_proxy_cache_config(&cache)),
                    )
                };
                let (mut listener, mut shutdown, mut task) =
                    route_proxy_listener_with_shutdown(make_proxy()).await;
                let first = downstream_get(listener, "/asset.png").await;
                assert!(first.ends_with("trusted"), "{first}");
                assert_eq!(
                    response_header(&first, "x-cache-status").as_deref(),
                    Some("MISS")
                );
                if tier != "memory" {
                    if tier == "storage-bin" {
                        tokio::time::timeout(Duration::from_secs(3), async {
                            while !root
                                .path()
                                .join("cache/.fluxheim-storage-bin-index-v1")
                                .exists()
                            {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                        })
                        .await
                        .unwrap();
                    }
                    shutdown.send(()).unwrap();
                    task.await.unwrap();
                    (listener, shutdown, task) =
                        route_proxy_listener_with_shutdown(make_proxy()).await;
                }
                tokio::time::sleep(Duration::from_millis(1100)).await;
                let failed = downstream_get(listener, "/asset.png").await;
                let served_stale =
                    response_header(&failed, "x-cache-status").as_deref() == Some("STALE");
                assert_eq!(
                    served_stale,
                    allowed && !mandatory,
                    "{tier} {fault:?} allowed={allowed} mandatory={mandatory}: {failed}"
                );
                if served_stale {
                    assert!(failed.ends_with("trusted"));
                } else {
                    assert!(!failed.contains("trusted"));
                    assert!(
                        failed.starts_with("HTTP/1.1 502") || failed.starts_with("HTTP/1.1 504")
                    );
                }
                // Allow the deliberately slow origin exchange to finish before recovery.
                tokio::time::sleep(Duration::from_millis(220)).await;
                let recovery = downstream_get(listener, "/asset.png").await;
                assert!(
                    recovery.ends_with("renewed"),
                    "{tier} {fault:?}: {recovery}"
                );
                origin_task.await.unwrap();
                shutdown.send(()).unwrap();
                task.await.unwrap();
            }
        }
    }
}
