use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    DownstreamHttp1Policy, NativeHttp1Proxy, NativeHttp1ProxyConfigError, NativeHttp1Upstream,
    native_http1_test_utils::read_request_head, serve_native_http1_listener,
};

async fn upstream<F, Fut>(handler: F) -> std::net::SocketAddr
where
    F: Fn(Vec<u8>, TcpStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
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
        handler(request, stream).await;
    });
    addr
}

async fn proxy_listener(upstream: std::net::SocketAddr) -> std::net::SocketAddr {
    proxy_listener_for(NativeHttp1Proxy::new(NativeHttp1Upstream::new(
        upstream.to_string(),
    )))
    .await
}

async fn proxy_listener_for(proxy: NativeHttp1Proxy) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let proxy = Arc::new(proxy);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        serve_native_http1_listener(listener, DownstreamHttp1Policy::default(), proxy, async {
            let _ = shutdown_rx.await;
        })
        .await
        .unwrap();
    });
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let _ = shutdown_tx.send(());
    });
    addr
}

async fn counting_upstream(
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
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
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

async fn failover_proxy_listener(
    first: std::net::SocketAddr,
    second: std::net::SocketAddr,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let proxy = Arc::new(
        NativeHttp1Proxy::from_upstreams(vec![
            NativeHttp1Upstream::new(first.to_string())
                .with_connect_timeout(Duration::from_millis(25)),
            NativeHttp1Upstream::new(second.to_string())
                .with_connect_timeout(Duration::from_millis(25)),
        ])
        .unwrap(),
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        serve_native_http1_listener(listener, DownstreamHttp1Policy::default(), proxy, async {
            let _ = shutdown_rx.await;
        })
        .await
        .unwrap();
    });
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let _ = shutdown_tx.send(());
    });
    addr
}

async fn pooled_proxy_listener(upstream: std::net::SocketAddr) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let proxy = Arc::new(NativeHttp1Proxy::new(
        NativeHttp1Upstream::new(upstream.to_string()).with_pool_max_idle(1),
    ));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        serve_native_http1_listener(listener, DownstreamHttp1Policy::default(), proxy, async {
            let _ = shutdown_rx.await;
        })
        .await
        .unwrap();
    });
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let _ = shutdown_tx.send(());
    });
    addr
}

async fn downstream_get(proxy: std::net::SocketAddr, path: &str) -> String {
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

async fn unused_local_address() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

fn proxy_config_with_error_page(root: std::path::PathBuf) -> fluxheim_config::ProxyConfig {
    fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:9".to_owned()),
        connect_timeout_secs: Some(1),
        error_pages: vec![fluxheim_config::ProxyErrorPageConfig {
            status: 502,
            path: "/502.html".to_owned(),
            web: fluxheim_config::WebConfig {
                root: Some(root),
                ..Default::default()
            },
        }],
        ..Default::default()
    }
}

#[tokio::test]
async fn native_proxy_forwards_downstream_request_to_upstream() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /proxied HTTP/1.1\r\n"));
        assert!(request.contains("host: proxy.test\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 12\r\nx-origin: native\r\n\r\nhello native",
            )
            .await
            .unwrap();
    })
    .await;
    let proxy = proxy_listener(upstream).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"GET /proxied HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.contains("x-origin: native\r\n"));
    assert!(response.ends_with("hello native"));
}

#[tokio::test]
async fn native_proxy_fails_over_get_to_second_static_upstream() {
    let first = unused_local_address().await;
    let second = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /failover HTTP/1.1\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 15\r\nx-origin: second\r\n\r\nsecond upstream",
            )
            .await
            .unwrap();
    })
    .await;
    let proxy = failover_proxy_listener(first, second).await;

    let response = downstream_get(proxy, "/failover").await;

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.contains("x-origin: second\r\n"));
    assert!(response.ends_with("second upstream"));
}

#[tokio::test]
async fn native_proxy_serves_configured_error_page_on_bad_gateway() {
    let errors = tempfile::tempdir().unwrap();
    std::fs::write(errors.path().join("502.html"), "native custom 502\n").unwrap();
    let mut config = proxy_config_with_error_page(errors.path().to_path_buf());
    config.upstream = Some(unused_local_address().await.to_string());
    let proxy = NativeHttp1Proxy::from_proxy_config(&config, DownstreamHttp1Policy::default())
        .unwrap()
        .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let response = downstream_get(proxy, "/failing").await;

    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.contains("\r\nConnection: close\r\n"));
    assert!(response.contains("content-type: text/html"));
    assert!(response.ends_with("native custom 502\n"));
}

#[tokio::test]
async fn native_proxy_falls_back_when_configured_error_page_is_too_large() {
    let errors = tempfile::tempdir().unwrap();
    let oversized = std::fs::File::create(errors.path().join("502.html")).unwrap();
    oversized.set_len(64 * 1024 * 1024 + 1).unwrap();
    let mut config = proxy_config_with_error_page(errors.path().to_path_buf());
    config.upstream = Some(unused_local_address().await.to_string());
    let proxy = NativeHttp1Proxy::from_proxy_config(&config, DownstreamHttp1Policy::default())
        .unwrap()
        .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let response = downstream_get(proxy, "/failing").await;

    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(!response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
    assert!(response.ends_with("bad gateway\n"));
}

#[tokio::test]
async fn native_proxy_round_robins_successful_static_upstreams() {
    let first = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /balanced HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-origin: one\r\n\r\none-1")
            .await
            .unwrap();
    })
    .await;
    let second = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /balanced HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-origin: two\r\n\r\ntwo-2")
            .await
            .unwrap();
    })
    .await;
    let proxy = failover_proxy_listener(first, second).await;

    let first_response = downstream_get(proxy, "/balanced").await;
    let second_response = downstream_get(proxy, "/balanced").await;

    assert!(first_response.contains("x-origin: one\r\n"));
    assert!(first_response.ends_with("one-1"));
    assert!(second_response.contains("x-origin: two\r\n"));
    assert!(second_response.ends_with("two-2"));
}

#[tokio::test]
async fn native_proxy_weighted_round_robins_static_upstreams() {
    let (first, first_count) = counting_upstream("one", 2).await;
    let (second, second_count) = counting_upstream("two", 1).await;
    let proxy = NativeHttp1Proxy::from_weighted_upstreams(
        vec![
            NativeHttp1Upstream::new(first.to_string()),
            NativeHttp1Upstream::new(second.to_string()),
        ],
        &[2, 1],
    )
    .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let first_response = downstream_get(proxy, "/weighted").await;
    let second_response = downstream_get(proxy, "/weighted").await;
    let third_response = downstream_get(proxy, "/weighted").await;

    assert!(first_response.ends_with("one"));
    assert!(second_response.ends_with("one"));
    assert!(third_response.ends_with("two"));
    assert_eq!(first_count.load(Ordering::Relaxed), 2);
    assert_eq!(second_count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn native_proxy_does_not_fail_over_unsafe_method() {
    let first = unused_local_address().await;
    let second = upstream(|_, mut stream| async move {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nsecond")
            .await
            .unwrap();
    })
    .await;
    let proxy = failover_proxy_listener(first, second).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"POST /submit HTTP/1.1\r\nHost: proxy.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.ends_with("bad gateway\n"));
}

#[tokio::test]
async fn native_proxy_reuses_origin_connection_for_separate_downstream_clients() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_for_task = Arc::clone(&accepted);
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        accepted_for_task.fetch_add(1, Ordering::AcqRel);

        let first = String::from_utf8(read_request_head(&mut stream).await).unwrap();
        assert!(first.starts_with("GET /one HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\none")
            .await
            .unwrap();

        let second = String::from_utf8(read_request_head(&mut stream).await).unwrap();
        assert!(second.starts_with("GET /two HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\ntwo")
            .await
            .unwrap();
    });
    let proxy = pooled_proxy_listener(upstream).await;

    let first = downstream_get(proxy, "/one").await;
    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("one"));

    let second = downstream_get(proxy, "/two").await;
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("two"));

    assert_eq!(accepted.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn native_proxy_maps_upstream_timeout_to_gateway_timeout() {
    let upstream = upstream(|_, stream| async move {
        let _hold_open = stream;
        tokio::time::sleep(Duration::from_secs(5)).await;
    })
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let proxy = Arc::new(NativeHttp1Proxy::new(
        NativeHttp1Upstream::new(upstream.to_string()).with_read_timeout(Duration::from_millis(25)),
    ));
    tokio::spawn(async move {
        serve_native_http1_listener(
            listener,
            DownstreamHttp1Policy::default(),
            proxy,
            std::future::pending::<()>(),
        )
        .await
        .unwrap();
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"GET /slow HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(response.starts_with("HTTP/1.1 504 Gateway Timeout\r\n"));
    assert!(response.ends_with("gateway timeout\n"));
}

#[test]
fn native_proxy_config_accepts_plain_static_upstream() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        connect_timeout_secs: Some(2),
        read_timeout_secs: Some(3),
        send_timeout_secs: Some(4),
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(
        native.upstream(),
        &NativeHttp1Upstream::new("127.0.0.1:3000")
            .with_connect_timeout(Duration::from_secs(2))
            .with_read_timeout(Duration::from_secs(3))
            .with_write_timeout(Duration::from_secs(4))
    );
}

#[test]
fn native_proxy_config_accepts_ordered_static_upstreams() {
    let proxy = fluxheim_config::ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        connect_timeout_secs: Some(2),
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(native.upstreams().len(), 2);
    assert_eq!(
        native.upstreams()[0],
        NativeHttp1Upstream::new("127.0.0.1:3000").with_connect_timeout(Duration::from_secs(2))
    );
    assert_eq!(
        native.upstreams()[1],
        NativeHttp1Upstream::new("127.0.0.1:3001").with_connect_timeout(Duration::from_secs(2))
    );
}

#[test]
fn native_proxy_config_accepts_weighted_static_upstreams() {
    let proxy = fluxheim_config::ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_weights: vec![2, 1],
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(native.upstream_slots(), &[0, 0, 1]);
}

#[test]
fn native_proxy_config_applies_pool_capacity() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config_with_pool_size(
        &proxy,
        DownstreamHttp1Policy::default(),
        16,
    )
    .unwrap()
    .expect("native proxy");

    assert_eq!(native.upstream().pool_max_idle(), 16);
}

#[test]
fn native_proxy_config_returns_none_without_upstream() {
    let proxy = fluxheim_config::ProxyConfig::disabled();

    let native =
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).unwrap();

    assert!(native.is_none());
}

#[test]
fn native_proxy_config_rejects_unsupported_upstream_features() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_tls: true,
        ..Default::default()
    };
    #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamTls)
    );
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamTlsPolicy)
    );

    let proxy = fluxheim_config::ProxyConfig {
        upstreams_file: Some(std::path::PathBuf::from("/tmp/upstreams.txt")),
        ..Default::default()
    };
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::DynamicUpstreamDiscovery)
    );
}

#[test]
fn native_proxy_config_rejects_unsupported_proxy_policy_layers() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        auth_request: fluxheim_config::AuthRequestConfig {
            enabled: true,
            url: Some("http://127.0.0.1:3001/auth".to_owned()),
            ..Default::default()
        },
        ..Default::default()
    };
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::AuthRequest)
    );

    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        mirror: fluxheim_config::TrafficMirrorConfig {
            enabled: true,
            base_url: Some("http://127.0.0.1:3001".to_owned()),
            ..Default::default()
        },
        ..Default::default()
    };
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::TrafficMirror)
    );

    let errors = tempfile::tempdir().unwrap();
    std::fs::write(errors.path().join("502.html"), "native error page\n").unwrap();
    let proxy = proxy_config_with_error_page(errors.path().to_path_buf());
    assert!(NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).is_ok());
}

#[test]
fn native_proxy_config_rejects_unsupported_transport_and_downstream_policy() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_tcp_keepalive_idle_secs: Some(30),
        ..Default::default()
    };
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamTransportPolicy)
    );

    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        downstream_min_send_rate_bytes_per_sec: Some(1024),
        ..Default::default()
    };
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::DownstreamPolicy)
    );
}
