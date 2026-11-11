use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{io::AsyncWriteExt, net::TcpListener};

use super::*;
use crate::native_http1_proxy_peer_fill_auth::NativePeerFillAuth;
use sanitization::SecretVec;

#[cfg(feature = "tls-rustls-backend")]
#[path = "cache_peer_transport.rs"]
mod transport;

async fn variant_origin(
    declared: bool,
) -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let head = String::from_utf8(
                crate::native_http1_test_utils::read_request_head(&mut stream).await,
            )
            .unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let values = head
                .lines()
                .filter_map(|line| line.split_once(':'))
                .filter(|(name, _)| name.eq_ignore_ascii_case("x-edition"))
                .map(|(_, value)| value.trim())
                .collect::<Vec<_>>();
            let body = format!("{values:?}");
            let vary = if declared { "vary: X-Edition\r\n" } else { "" };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=120\r\n{vary}content-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (address, calls, task)
}

fn policy(tier: &str, root: &std::path::Path, configured: bool) -> fluxheim_config::CacheConfig {
    let mut cache = match tier {
        "memory" => native_proxy_memory_cache_config(),
        "filesystem" => native_proxy_disk_cache_config(root.to_owned()),
        "storage-bin" => native_proxy_storage_bin_cache_config(root.to_owned()),
        _ => unreachable!(),
    };
    if configured {
        cache.vary_request_headers = vec!["x-edition".into()];
    }
    cache
}

fn proxy(
    origin: std::net::SocketAddr,
    config: &fluxheim_config::CacheConfig,
    key: Option<u8>,
) -> crate::NativeHttp1Proxy {
    let mut proxy = proxy_for(origin).with_proxy_cache_config(config);
    proxy.cache.as_mut().unwrap().peer_fill_auth = key.map(|key| {
        Arc::new(NativePeerFillAuth {
            secret: Arc::new(SecretVec::from_vec(vec![key; 32])),
        })
    });
    proxy
}

async fn fetch(address: std::net::SocketAddr, values: &[&str], path: &str) -> String {
    let headers = values
        .iter()
        .map(|value| format!("X-Edition: {value}\r\n"))
        .collect::<String>();
    tokio::time::timeout(
        Duration::from_secs(5),
        downstream_request(
            address,
            &format!(
                "GET {path} HTTP/1.1\r\nHost: route.test\r\n{headers}Connection: close\r\n\r\n"
            ),
        ),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn peer_variants_real_origin_two_peers_all_storage_tiers() {
    for tier in ["memory", "filesystem", "storage-bin"] {
        for key in [None, Some(42)] {
            for declared in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let (origin, calls, origin_task) = variant_origin(declared).await;
                // The first peer remains cold; only-if-cached must prevent origin access.
                let cold = policy(tier, &root.path().join("cold"), true);
                let warm = policy(tier, &root.path().join("warm"), !declared);
                let (cold_addr, cold_stop, cold_task) = route_proxy_listener_with_shutdown(
                    NativeHttp1RouteProxy::new(Vec::new(), Some(proxy(origin, &cold, key))),
                )
                .await;
                let (warm_addr, warm_stop, warm_task) = route_proxy_listener_with_shutdown(
                    NativeHttp1RouteProxy::new(Vec::new(), Some(proxy(origin, &warm, key))),
                )
                .await;
                let variants: &[&[&str]] =
                    &[&[], &[""], &["special"], &["one", "two"], &["two", "one"]];
                for values in variants {
                    let response = fetch(warm_addr, values, "/asset.png").await;
                    assert!(response.ends_with(&format!("{values:?}")), "{response}");
                    assert_eq!(
                        response_header(&response, "x-cache-status").as_deref(),
                        Some("MISS")
                    );
                }
                assert_eq!(calls.load(Ordering::SeqCst), variants.len());
                let mut front = policy(tier, &root.path().join("front"), true);
                front.peer_fill.enabled = true;
                front.peer_fill.fail_open = true;
                front.peer_fill.peers = [cold_addr, warm_addr]
                    .into_iter()
                    .enumerate()
                    .map(|(i, address)| fluxheim_config::CachePeerConfig {
                        name: format!("peer-{i}"),
                        base_url: format!("http://{address}"),
                    })
                    .collect();
                let (address, stop, task) = route_proxy_listener_with_shutdown(
                    NativeHttp1RouteProxy::new(Vec::new(), Some(proxy(origin, &front, key))),
                )
                .await;
                for values in variants {
                    for expected in ["PEER-HIT", "HIT"] {
                        let response = fetch(address, values, "/asset.png").await;
                        assert!(
                            response.ends_with(&format!("{values:?}")),
                            "{tier} key={key:?} declared={declared}: {response}"
                        );
                        assert_eq!(
                            response_header(&response, "x-cache-status").as_deref(),
                            Some(expected),
                            "{tier}: {response}"
                        );
                        assert!(
                            response_header(&response, "x-fluxheim-peer-fill-context").is_none()
                        );
                    }
                }
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    variants.len(),
                    "peer miss contacted origin"
                );
                let fallback = fetch(address, &["cold"], "/new.png").await;
                assert_eq!(
                    response_header(&fallback, "x-cache-status").as_deref(),
                    Some("MISS")
                );
                assert!(fallback.ends_with("[\"cold\"]"));
                assert_eq!(calls.load(Ordering::SeqCst), variants.len() + 1);
                for (stop, task) in [(stop, task), (cold_stop, cold_task), (warm_stop, warm_task)] {
                    stop.send(()).unwrap();
                    tokio::time::timeout(Duration::from_secs(5), task)
                        .await
                        .unwrap()
                        .unwrap();
                }
                origin_task.abort();
                assert!(origin_task.await.unwrap_err().is_cancelled());
            }
        }
    }
}

#[tokio::test]
async fn peer_variants_unconfigured_origin_field_and_wrong_secret_fall_back() {
    for wrong_key in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (origin, calls, origin_task) = variant_origin(true).await;
        let warm = policy("memory", root.path(), false);
        let (peer, peer_stop, peer_task) = route_proxy_listener_with_shutdown(
            NativeHttp1RouteProxy::new(Vec::new(), Some(proxy(origin, &warm, Some(42)))),
        )
        .await;
        assert!(fetch(peer, &[], "/asset.png").await.ends_with("[]"));
        let mut front = policy("memory", root.path(), wrong_key);
        front.peer_fill.enabled = true;
        front.peer_fill.peers = vec![fluxheim_config::CachePeerConfig {
            name: "peer".into(),
            base_url: format!("http://{peer}"),
        }];
        let (address, stop, task) = route_proxy_listener_with_shutdown(NativeHttp1RouteProxy::new(
            Vec::new(),
            Some(proxy(origin, &front, Some(if wrong_key { 43 } else { 42 }))),
        ))
        .await;
        let response = fetch(address, &["special"], "/asset.png").await;
        assert!(response.ends_with("[\"special\"]"), "{response}");
        assert_eq!(
            response_header(&response, "x-cache-status").as_deref(),
            Some("MISS")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        for (stop, task) in [(stop, task), (peer_stop, peer_task)] {
            stop.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap();
        }
        origin_task.abort();
        assert!(origin_task.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test]
async fn peer_variants_legacy_response_never_enters_local_cache() {
    const RESPONSES: &[&[(&str, &str)]] = &[
        &[(
            "/asset.png",
            "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=120\r\ncontent-length: 5\r\n\r\nwrong",
        )],
        &[(
            "/asset.png",
            "HTTP/1.1 200 OK\r\nx-fluxheim-peer-fill-version: 1\r\ncontent-type: image/png\r\ncache-control: max-age=120\r\ncontent-length: 5\r\n\r\nwrong",
        )],
    ];
    for response in RESPONSES {
        let root = tempfile::tempdir().unwrap();
        let (origin, calls, origin_task) = variant_origin(true).await;
        let peer = upstream_raw_response_sequence(response).await;
        let mut config = policy("memory", root.path(), true);
        config.peer_fill.enabled = true;
        config.peer_fill.peers = vec![fluxheim_config::CachePeerConfig {
            name: "old-peer".into(),
            base_url: format!("http://{peer}"),
        }];
        let (address, stop, task) = route_proxy_listener_with_shutdown(NativeHttp1RouteProxy::new(
            Vec::new(),
            Some(proxy(origin, &config, None)),
        ))
        .await;
        for expected in ["MISS", "HIT"] {
            let response = fetch(address, &["special"], "/asset.png").await;
            assert!(response.ends_with("[\"special\"]"));
            assert_eq!(
                response_header(&response, "x-cache-status").as_deref(),
                Some(expected)
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        origin_task.abort();
        assert!(origin_task.await.unwrap_err().is_cancelled());
    }
}
