use super::*;
use crate::{
    DownstreamHttp2Policy, NativeHttp1RequestContext, NativeHttp2RouteAdapter,
    serve_native_http2_connection,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

async fn request(router: Arc<NativeHttp1HostRouter>, path: &str, h2: bool) -> (u16, String) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut tasks = JoinSet::new();
        let result = if h2 {
            tasks.spawn(async move {
                let (stream, peer) = listener.accept().await.unwrap();
                let adapter = NativeHttp2RouteAdapter::new(
                    router,
                    Some(peer),
                    NativeHttp1RequestContext::default(),
                );
                let _ = serve_native_http2_connection(
                    stream,
                    DownstreamHttp2Policy::default(),
                    Arc::new(adapter),
                )
                .await;
            });
            let (client, connection) =
                h2::client::handshake(TcpStream::connect(address).await.unwrap())
                    .await
                    .unwrap();
            tasks.spawn(async move {
                let _ = connection.await;
            });
            let mut client = client.ready().await.unwrap();
            let (response, _) = client
                .send_request(
                    http::Request::builder()
                        .uri(format!("http://route.test{path}"))
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            let response = response.await.unwrap();
            let status = response.status().as_u16();
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                assert!(bytes.len() + chunk.len() <= 1024);
                body.flow_control().release_capacity(chunk.len()).unwrap();
                bytes.extend_from_slice(&chunk);
            }
            (status, String::from_utf8(bytes).unwrap())
        } else {
            tasks.spawn(async move {
                let _ = serve_native_http1_listener(
                    listener,
                    DownstreamHttp1Policy::default(),
                    router,
                    std::future::pending::<()>(),
                )
                .await;
            });
            let response = downstream_get(address, path).await;
            let status = response.split_whitespace().nth(1).unwrap().parse().unwrap();
            (
                status,
                response.split_once("\r\n\r\n").unwrap().1.to_owned(),
            )
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        result
    })
    .await
    .expect("bounded HTTP policy exchange")
}

async fn check_decoded_route_policy(h2: bool) {
    let fixture = WasmRouteFixture::new(&[("deny", WasmPluginBody::Decision(2))]);
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = origin.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        loop {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                assert!(head.len() < 16 * 1024);
                head.push(stream.read_u8().await.unwrap());
            }
            assert!(String::from_utf8(head).unwrap().starts_with("GET /%72oute "));
            observed.fetch_add(1, Ordering::SeqCst);
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nprotected-origin").await.unwrap();
        }
    });

    // /route is a public redirect. Every other raw path dispatches to the
    // protected origin, with an access-deny attachment on that catch-all route.
    let mut config =
        fixture.config_with_attachments(upstream, vec![wasm_attachment("deny", "protected", 100)]);
    let mut protected = native_route_proxy_test_route();
    protected.name = "protected".into();
    protected.path_exact = None;
    protected.path_prefix = Some("/".into());
    protected.redirect = None;
    protected.proxy = Some(config.vhosts[0].proxy.clone());
    config.vhosts[0].routes.push(protected);
    let router = Arc::new(
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap(),
    );
    assert_eq!(request(Arc::clone(&router), "/private", h2).await.0, 403);
    assert_eq!(request(Arc::clone(&router), "/route", h2).await.0, 302);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    for path in ["/%72oute", "/%72%6fute", "/priv%61te"] {
        assert_eq!(request(Arc::clone(&router), path, h2).await.0, 403);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // Moving the same deny to the decoded route is enforced.
    config.wasm.attachments[0].route = Some("route".into());
    let router = Arc::new(
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap(),
    );
    assert_eq!(request(router, "/%72oute", h2).await.0, 403);

    // Native ACLs intersect both route policies and remain an effective control.
    config.wasm.attachments[0].route = Some("protected".into());
    config.vhosts[0].routes[1].access.deny = vec!["127.0.0.1".into()];
    let router = Arc::new(
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap(),
    );
    assert_eq!(request(router, "/%72oute", h2).await.0, 403);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    config.vhosts[0].routes[1].access.deny.clear();
    config.wasm.attachments.clear();
    let router = Arc::new(
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap(),
    );
    let (status, body) = request(router, "/%72oute", h2).await;
    assert_eq!((status, body.as_str()), (200, "protected-origin"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

#[tokio::test]
async fn wasm_access_checks_both_routes_over_http1() {
    check_decoded_route_policy(false).await;
}

#[tokio::test]
async fn wasm_access_checks_both_routes_over_http2() {
    check_decoded_route_policy(true).await;
}

#[tokio::test]
async fn wasm_access_keeps_initial_decoded_and_selected_route_policies() {
    use fluxheim_config::WasmPluginPhase;
    let mut fixture = WasmRouteFixture::new(&[
        ("deny", WasmPluginBody::Decision(2)),
        ("router", WasmPluginBody::Decision(1)),
    ]);
    let bytes = wat::parse_str(
        "(module (func (export \"fluxheim_route_decision\") (result i32) i32.const 1))",
    )
    .unwrap();
    fs::write(&fixture.plugins[1].path, &bytes).unwrap();
    fixture.plugins[1].sha256 = Some(sha256_hex(&bytes));
    fixture.plugins[1].phases = vec![WasmPluginPhase::RouteDecision];
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    for h2 in [false, true] {
        for scope in [Some("standard"), Some("route"), Some("canary"), None] {
            let mut deny = wasm_attachment("deny", "standard", 100);
            deny.route = scope.map(str::to_owned);
            let mut config = fixture.config_with_attachments(
                address,
                vec![
                    deny,
                    wasm_vhost_attachment_phase("router", 200, WasmPluginPhase::RouteDecision),
                ],
            );
            config.vhosts[0].routes.extend([
                named_proxy_route("standard", "/", address),
                named_proxy_route("canary", "/", address),
            ]);
            let router = Arc::new(
                NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0)
                    .unwrap(),
            );
            assert_eq!(request(router, "/%72oute", h2).await.0, 403, "{scope:?}");
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), origin.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn wasm_access_checks_both_routes_before_websocket_takeover() {
    let fixture = WasmRouteFixture::new(&[("deny", WasmPluginBody::Decision(2))]);
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    let mut config =
        fixture.config_with_attachments(address, vec![wasm_attachment("deny", "protected", 100)]);
    let mut protected = named_proxy_route("protected", "/", address);
    protected.proxy.as_mut().unwrap().websocket = true;
    config.vhosts[0].routes.push(protected);
    let router = Arc::new(
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let _ = serve_native_http1_listener(
            listener,
            DownstreamHttp1Policy::default(),
            router,
            std::future::pending::<()>(),
        )
        .await;
    });
    let response = tokio::time::timeout(Duration::from_secs(5), downstream_request(addr,
        "GET /%72oute HTTP/1.1\r\nHost: route.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 403 "));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), origin.accept())
            .await
            .is_err()
    );
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

#[tokio::test]
async fn wasm_access_allow_does_not_mask_another_routes_failure() {
    let fixture = WasmRouteFixture::new(&[
        ("allow", WasmPluginBody::Decision(1)),
        ("invalid", WasmPluginBody::Decision(9)),
    ]);
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    for h2 in [false, true] {
        for invalid_priority in [50, 200] {
            let mut config = fixture.config_with_attachments(
                address,
                vec![
                    wasm_attachment("allow", "route", 100),
                    wasm_attachment("invalid", "protected", invalid_priority),
                ],
            );
            config.vhosts[0]
                .routes
                .push(named_proxy_route("protected", "/", address));
            let router = Arc::new(
                NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0)
                    .unwrap(),
            );
            assert_eq!(request(router, "/%72oute", h2).await.0, 503);
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), origin.accept())
            .await
            .is_err()
    );
}
