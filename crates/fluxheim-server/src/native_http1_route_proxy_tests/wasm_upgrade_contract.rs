use super::*;
use fluxheim_config::WasmPluginPhase;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

async fn read_head(stream: &mut TcpStream) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            assert!(head.len() < 16 * 1024, "oversized test HTTP head");
            head.push(stream.read_u8().await.unwrap());
        }
        String::from_utf8(head).unwrap()
    })
    .await
    .expect("timed out reading test HTTP head")
}

async fn check_upgrade(
    phase: WasmPluginPhase,
    export: &str,
    decision: i32,
    expected_http: u16,
    expected_upgrade: u16,
) {
    // Exercise both named-route and fallback-vhost attachment paths.
    for route_scope in [true, false] {
        for fail_open in [false, true] {
            if fail_open
                && !matches!(
                    phase,
                    WasmPluginPhase::RequestHeaders | WasmPluginPhase::ResponseHeaders
                )
            {
                continue;
            }
            let expected_http = if fail_open { 200 } else { expected_http };
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let upstream_addr = upstream.local_addr().unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&calls);
            let mut tasks = JoinSet::new();
            tasks.spawn(async move {
            loop {
                let (mut stream, _) = upstream.accept().await.unwrap();
                let request = read_head(&mut stream).await;
                observed.fetch_add(1, Ordering::SeqCst);
                let response: &[u8] = if request.to_ascii_lowercase().contains("upgrade: websocket")
                {
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                };
                stream.write_all(response).await.unwrap();
            }
        });

            let mut fixture = WasmRouteFixture::new(&[("policy", WasmPluginBody::Decision(2))]);
            let bytes = wat::parse_str(format!(
                "(module (func (export \"{export}\") (result i32) i32.const {decision}))"
            ))
            .unwrap();
            let plugin = &mut fixture.plugins[0];
            fs::write(&plugin.path, &bytes).unwrap();
            plugin.sha256 = Some(sha256_hex(&bytes));
            plugin.phases = vec![phase];
            if fail_open {
                plugin.fail_mode = fluxheim_config::WasmPluginFailMode::FailOpen;
            }
            let mut attachment = wasm_attachment("policy", "route", 100);
            attachment.phases = vec![phase];
            if !route_scope {
                attachment.route = None;
            }
            let mut config = fixture.config_with_attachments(upstream_addr, vec![attachment]);
            config.vhosts[0].proxy.websocket = true;
            if route_scope {
                config.vhosts[0].routes[0].redirect = None;
                config.vhosts[0].routes[0].proxy = Some(config.vhosts[0].proxy.clone());
            } else {
                config.vhosts[0].routes.clear();
            }
            let router =
                NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0)
                    .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tasks.spawn(async move {
                let _ = serve_native_http1_listener(
                    listener,
                    DownstreamHttp1Policy::default(),
                    Arc::new(router),
                    std::future::pending::<()>(),
                )
                .await;
            });

            let response = downstream_get(addr, "/route").await;
            assert!(
                response.starts_with(&format!("HTTP/1.1 {expected_http} ")),
                "{response}"
            );
            let before = calls.load(Ordering::SeqCst);
            assert_eq!(
                before,
                usize::from(expected_http == 200 || phase == WasmPluginPhase::ResponseHeaders)
            );

            for (index, path) in ["/route", "/%72oute"].iter().enumerate() {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: route.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").as_bytes()).await.unwrap();
                let head = read_head(&mut stream).await;
                assert!(
                    head.starts_with(&format!("HTTP/1.1 {expected_upgrade} ")),
                    "{head}"
                );
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    before + (index + 1) * usize::from(expected_upgrade == 101)
                );
                drop(stream);
            }
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
    }
}

#[tokio::test]
async fn wasm_route_hooks_prevent_unsupported_upgrade() {
    check_upgrade(
        WasmPluginPhase::RouteDecision,
        "fluxheim_route_decision",
        2,
        403,
        503,
    )
    .await;
}

#[tokio::test]
async fn wasm_request_header_hooks_prevent_unsupported_upgrade() {
    check_upgrade(
        WasmPluginPhase::RequestHeaders,
        "fluxheim_request_headers",
        2,
        503,
        503,
    )
    .await;
}

#[tokio::test]
async fn wasm_response_header_hooks_prevent_unsupported_upgrade() {
    check_upgrade(
        WasmPluginPhase::ResponseHeaders,
        "fluxheim_response_headers",
        2,
        503,
        503,
    )
    .await;
}

#[tokio::test]
async fn wasm_access_denial_still_blocks_upgrade() {
    check_upgrade(
        WasmPluginPhase::AccessDecision,
        "fluxheim_access_decision",
        2,
        403,
        403,
    )
    .await;
}

#[tokio::test]
async fn wasm_access_allow_still_permits_upgrade() {
    check_upgrade(
        WasmPluginPhase::AccessDecision,
        "fluxheim_access_decision",
        1,
        200,
        101,
    )
    .await;
}

#[tokio::test]
async fn wasm_access_error_still_rejects_upgrade() {
    check_upgrade(
        WasmPluginPhase::AccessDecision,
        "fluxheim_access_decision",
        9,
        503,
        503,
    )
    .await;
}

#[tokio::test]
async fn successful_http_hooks_do_not_silently_skip_upgrade_policy() {
    for (phase, export) in [
        (WasmPluginPhase::RouteDecision, "fluxheim_route_decision"),
        (WasmPluginPhase::RequestHeaders, "fluxheim_request_headers"),
        (
            WasmPluginPhase::ResponseHeaders,
            "fluxheim_response_headers",
        ),
    ] {
        check_upgrade(phase, export, 0, 200, 503).await;
    }
}
