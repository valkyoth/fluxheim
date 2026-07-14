use fluxheim_runtime::NativeBackgroundSupervisor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{NativeHttp1ProxyRuntime, ServerPlan};

pub(crate) async fn upstream_response(body: &'static str) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
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
    });
    addr
}

async fn upstream_assert_client_identity(expected: &'static str) -> std::net::SocketAddr {
    #[cfg(feature = "privacy-mode")]
    let _ = expected;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
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
        let request = String::from_utf8(request).unwrap();
        #[cfg(not(feature = "privacy-mode"))]
        assert!(
            request
                .lines()
                .any(|line| line.eq_ignore_ascii_case(&format!("x-real-ip: {expected}"))),
            "missing x-real-ip header in request:\n{request}"
        );
        #[cfg(feature = "privacy-mode")]
        assert!(
            !request
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("x-real-ip:")),
            "privacy mode forwarded x-real-ip in request:\n{request}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 8\r\n\r\nproxy-ok")
            .await
            .unwrap();
    });
    addr
}

async fn downstream_get(proxy: std::net::SocketAddr) -> String {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: native.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

async fn downstream_proxy_v1_get(proxy: std::net::SocketAddr, source: &str) -> String {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let request = format!(
        "PROXY TCP4 {source} 127.0.0.1 43210 8080\r\n\
         GET / HTTP/1.1\r\nHost: native.test\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

async fn downstream_proxy_v2_get(
    proxy: std::net::SocketAddr,
    source: std::net::SocketAddr,
    destination: std::net::SocketAddr,
) -> String {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let mut request = fluxheim_protocol::proxy_protocol_v2_header(Some(source), Some(destination));
    request.extend_from_slice(b"GET / HTTP/1.1\r\nHost: native.test\r\nConnection: close\r\n\r\n");
    stream.write_all(&request).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

#[tokio::test]
async fn native_http1_proxy_runtime_binds_launch_plan_and_serves_proxy_listener() {
    let upstream = upstream_response("runtime-ok").await;
    let mut config = fluxheim_config::Config::default();
    config.server.listen = vec!["127.0.0.1:0".to_owned()];
    config.proxy.upstream = Some(upstream.to_string());

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert!(plan.native_runtime_cutover_summary().is_ready());
    let runtime = NativeHttp1ProxyRuntime::bind_from_config(&config, &plan)
        .await
        .expect("bind native proxy runtime");
    assert_eq!(
        runtime.planned_addrs(),
        [std::net::SocketAddr::from(([127, 0, 0, 1], 0))]
    );
    let local_addr = runtime.local_addrs()[0];

    let supervisor = NativeBackgroundSupervisor::new();
    let handle = runtime.start(&supervisor);
    assert_eq!(handle.local_addrs(), [local_addr]);

    let response = downstream_get(local_addr).await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("runtime-ok"));

    assert!(supervisor.shutdown());
    for result in handle.join().await {
        result.expect("native listener stopped cleanly");
    }
}

#[tokio::test]
async fn native_http1_proxy_runtime_adopts_exact_inherited_listener() {
    let upstream = upstream_response("inherited-ok").await;
    let inherited = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let inherited_addr = inherited.local_addr().unwrap();
    let mut config = fluxheim_config::Config::default();
    config.server.listen = vec![inherited_addr.to_string()];
    config.proxy.upstream = Some(upstream.to_string());

    let plan = ServerPlan::from_config(&config).expect("valid inherited listener plan");
    let runtime = NativeHttp1ProxyRuntime::bind_from_config_with_inherited_listeners(
        &config,
        &plan,
        vec![inherited],
    )
    .await
    .expect("adopt inherited listener");
    assert_eq!(runtime.local_addrs(), [inherited_addr]);

    let supervisor = NativeBackgroundSupervisor::new();
    let handle = runtime.start(&supervisor);
    let response = downstream_get(inherited_addr).await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("inherited-ok"));

    assert!(supervisor.shutdown());
    for result in handle.join().await {
        result.expect("inherited listener stopped cleanly");
    }
}

#[tokio::test]
async fn native_http1_proxy_runtime_rejects_inherited_listener_count_mismatch() {
    let mut config = fluxheim_config::Config::default();
    config.server.listen = vec!["127.0.0.1:18080".to_owned()];
    let plan = ServerPlan::from_config(&config).expect("valid listener plan");

    let error = NativeHttp1ProxyRuntime::bind_from_config_with_inherited_listeners(
        &config,
        &plan,
        Vec::new(),
    )
    .await
    .err()
    .expect("missing inherited listener must fail closed");

    assert!(error.to_string().contains("supplied 0 TCP listener(s)"));
}

#[tokio::test]
async fn native_http1_proxy_runtime_rejects_wrong_or_duplicate_inherited_addresses() {
    let expected = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let expected_addr = expected.local_addr().unwrap();
    drop(expected);
    let wrong = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut config = fluxheim_config::Config::default();
    config.server.listen = vec![expected_addr.to_string()];
    let plan = ServerPlan::from_config(&config).expect("valid listener plan");

    let error = NativeHttp1ProxyRuntime::bind_from_config_with_inherited_listeners(
        &config,
        &plan,
        vec![wrong],
    )
    .await
    .err()
    .expect("wrong inherited address must fail closed");
    assert!(error.to_string().contains("did not supply required proxy listener"));

    let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let duplicate_addr = first.local_addr().unwrap();
    let duplicate = first.try_clone().unwrap();
    config.server.listen = vec![
        duplicate_addr.to_string(),
        "127.0.0.1:18081".to_owned(),
    ];
    let plan = ServerPlan::from_config(&config).expect("valid two-listener plan");
    let error = NativeHttp1ProxyRuntime::bind_from_config_with_inherited_listeners(
        &config,
        &plan,
        vec![first, duplicate],
    )
    .await
    .err()
    .expect("duplicate inherited addresses must fail closed");
    assert!(error.to_string().contains("duplicate listener address"));
}

#[cfg(feature = "load-balancer")]
#[tokio::test]
async fn native_http1_proxy_runtime_collects_native_load_balancer_service() {
    let mut config = fluxheim_config::Config::default();
    config.server.listen = vec!["127.0.0.1:0".to_owned()];
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert!(plan.native_runtime_cutover_summary().is_ready());
    let mut runtime = NativeHttp1ProxyRuntime::bind_from_config(&config, &plan)
        .await
        .expect("bind native proxy runtime");

    let services = runtime.take_load_balancer_services();
    assert_eq!(services.len(), 1);
    assert!(services[0].name().contains("root"));
    assert!(runtime.take_load_balancer_services().is_empty());
}

#[cfg(feature = "load-balancer")]
#[tokio::test]
async fn native_http1_proxy_runtime_serves_nginx_consistent_hash_pool() {
    let first = upstream_response("ketama-one").await;
    let second = upstream_response("ketama-two").await;
    let mut config = fluxheim_config::Config::default();
    config.server.listen = vec!["127.0.0.1:0".to_owned()];
    config.proxy.upstreams = vec![first.to_string(), second.to_string()];
    config.proxy.load_balance.selection =
        fluxheim_config::LoadBalanceSelection::NginxConsistentUriHash;
    config.proxy.load_balance.max_iterations = 8;

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert!(plan.native_runtime_cutover_summary().is_ready());
    let runtime = NativeHttp1ProxyRuntime::bind_from_config(&config, &plan)
        .await
        .expect("bind native proxy runtime");
    let local_addr = runtime.local_addrs()[0];

    let supervisor = NativeBackgroundSupervisor::new();
    let handle = runtime.start(&supervisor);

    let response = downstream_get(local_addr).await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("ketama-one") || response.ends_with("ketama-two"));

    assert!(supervisor.shutdown());
    for result in handle.join().await {
        result.expect("native listener stopped cleanly");
    }
}

#[tokio::test]
async fn native_http1_proxy_runtime_accepts_trusted_proxy_protocol_v1_listener() {
    let upstream = upstream_assert_client_identity("203.0.113.10").await;
    let mut config = fluxheim_config::Config::default();
    config.server.listen = vec!["127.0.0.1:0".to_owned()];
    config.server.proxy_protocol = fluxheim_config::DownstreamProxyProtocol::V1;
    config.server.trusted_proxies = vec!["127.0.0.1".to_owned()];
    config.proxy.upstream = Some(upstream.to_string());

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert!(plan.native_runtime_cutover_summary().is_ready());
    let runtime = NativeHttp1ProxyRuntime::bind_from_config(&config, &plan)
        .await
        .expect("bind native proxy runtime");
    let local_addr = runtime.local_addrs()[0];

    let supervisor = NativeBackgroundSupervisor::new();
    let handle = runtime.start(&supervisor);

    let response = downstream_proxy_v1_get(local_addr, "203.0.113.10").await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("proxy-ok"));

    assert!(supervisor.shutdown());
    for result in handle.join().await {
        result.expect("native PROXY listener stopped cleanly");
    }
}

#[tokio::test]
async fn native_http1_proxy_runtime_accepts_trusted_proxy_protocol_v2_listener() {
    let upstream = upstream_assert_client_identity("203.0.113.20").await;
    let mut config = fluxheim_config::Config::default();
    config.server.listen = vec!["127.0.0.1:0".to_owned()];
    config.server.proxy_protocol = fluxheim_config::DownstreamProxyProtocol::V2;
    config.server.trusted_proxies = vec!["127.0.0.1".to_owned()];
    config.proxy.upstream = Some(upstream.to_string());

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert!(plan.native_runtime_cutover_summary().is_ready());
    let runtime = NativeHttp1ProxyRuntime::bind_from_config(&config, &plan)
        .await
        .expect("bind native proxy runtime");
    let local_addr = runtime.local_addrs()[0];

    let supervisor = NativeBackgroundSupervisor::new();
    let handle = runtime.start(&supervisor);

    let response = downstream_proxy_v2_get(
        local_addr,
        std::net::SocketAddr::from(([203, 0, 113, 20], 43210)),
        std::net::SocketAddr::from(([127, 0, 0, 1], 8080)),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("proxy-ok"));

    assert!(supervisor.shutdown());
    for result in handle.join().await {
        result.expect("native PROXY listener stopped cleanly");
    }
}
