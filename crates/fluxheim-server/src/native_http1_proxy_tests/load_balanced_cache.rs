use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::{DownstreamHttp1Policy, NativeHttp1Proxy};

use super::{downstream_get, proxy_listener_for, response_header};

async fn cacheable_counting_upstream(
    body: &'static str,
    responses: usize,
) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_for_task = Arc::clone(&count);
    tokio::spawn(async move {
        for _ in 0..responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read = stream.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            count_for_task.fetch_add(1, Ordering::Relaxed);
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\ncontent-length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
    });
    (addr, count)
}

async fn delayed_cacheable_counting_upstream(
    body: &'static str,
    delay: Duration,
) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_for_task = Arc::clone(&count);
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read = stream.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            count_for_task.fetch_add(1, Ordering::Release);
            tokio::time::sleep(delay).await;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\ncontent-length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
    });
    (addr, count)
}

fn load_balanced_proxy_config(
    first: std::net::SocketAddr,
    second: std::net::SocketAddr,
) -> fluxheim_config::ProxyConfig {
    fluxheim_config::ProxyConfig {
        upstreams: vec![first.to_string(), second.to_string()],
        load_balance: fluxheim_config::LoadBalanceConfig {
            health_check: fluxheim_config::LoadBalanceHealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

fn load_balanced_proxy(
    name: &str,
    proxy_config: &fluxheim_config::ProxyConfig,
) -> NativeHttp1Proxy {
    NativeHttp1Proxy::from_proxy_config_with_native_load_balancer(
        name,
        "proxy.test",
        None,
        proxy_config,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap()
    .expect("native load-balanced proxy")
    .0
}

#[tokio::test]
async fn native_proxy_caches_load_balanced_response_in_memory() {
    let (first, first_count) = cacheable_counting_upstream("balanced-cache", 1).await;
    let (second, second_count) = cacheable_counting_upstream("balanced-cache", 1).await;
    let proxy_config = load_balanced_proxy_config(first, second);
    let proxy = load_balanced_proxy("lb-cache", &proxy_config);
    let cache = fluxheim_config::CacheConfig {
        enabled: true,
        status_header: Some("x-cache-status".to_owned()),
        memory: fluxheim_config::CacheMemoryConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let proxy = proxy_listener_for(proxy.with_proxy_cache_config(&cache)).await;

    let first_response = downstream_get(proxy, "/asset.png").await;
    let second_response = downstream_get(proxy, "/asset.png").await;

    assert!(first_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first_response.ends_with("balanced-cache"));
    assert_eq!(
        response_header(&first_response, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(second_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second_response.ends_with("balanced-cache"));
    assert_eq!(
        response_header(&second_response, "x-cache-status").as_deref(),
        Some("HIT")
    );
    assert_eq!(
        first_count.load(Ordering::Relaxed) + second_count.load(Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn native_load_balanced_cache_lock_wait_timeout_fails_closed() {
    let (first, first_count) =
        delayed_cacheable_counting_upstream("balanced-slow", Duration::from_millis(1_500)).await;
    let (second, second_count) =
        delayed_cacheable_counting_upstream("balanced-slow", Duration::from_millis(1_500)).await;
    let proxy_config = load_balanced_proxy_config(first, second);
    let proxy = load_balanced_proxy("lb-cache-timeout", &proxy_config);
    let cache = fluxheim_config::CacheConfig {
        enabled: true,
        status_header: Some("x-cache-status".to_owned()),
        status_reason_header: Some("x-cache-reason".to_owned()),
        memory: fluxheim_config::CacheMemoryConfig {
            enabled: true,
            ..Default::default()
        },
        lock: fluxheim_config::CacheLockConfig {
            enabled: true,
            wait_timeout_secs: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let proxy = proxy_listener_for(proxy.with_proxy_cache_config(&cache)).await;

    let first_response = tokio::spawn(async move { downstream_get(proxy, "/asset.png").await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while first_count.load(Ordering::Acquire) + second_count.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let second_response = downstream_get(proxy, "/asset.png").await;
    let first_response = first_response.await.unwrap();

    assert!(first_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second_response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert_eq!(
        response_header(&second_response, "x-cache-reason").as_deref(),
        Some("lock-wait-timeout")
    );
    assert_eq!(
        response_header(&second_response, "retry-after").as_deref(),
        Some("1")
    );
    assert_eq!(
        first_count.load(Ordering::Acquire) + second_count.load(Ordering::Acquire),
        1
    );
}
