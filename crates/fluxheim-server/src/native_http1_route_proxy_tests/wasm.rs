use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::{DownstreamHttp1Policy, NativeHttp1HostRouter, serve_native_http1_listener};

use super::{
    downstream_get, native_route_proxy_test_route, native_route_proxy_test_vhost, response_header,
};

#[tokio::test]
async fn native_wasm_access_decision_denies_before_upstream() {
    let fixture = WasmRouteFixture::new(&[("deny", WasmPluginBody::Decision(2))]);
    let upstream = super::upstream_expect_path("/never", "unexpected").await;
    let router = NativeHttp1HostRouter::from_config(
        &fixture.config_with_attachments(upstream, vec![wasm_attachment("deny", "route", 100)]),
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/route").await;

    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response.ends_with("wasm access denied\n"));
}

#[tokio::test]
async fn native_wasm_access_decision_uses_first_deny_in_priority_order() {
    let fixture = WasmRouteFixture::new(&[
        ("deny", WasmPluginBody::Decision(2)),
        ("invalid", WasmPluginBody::Decision(9)),
    ]);
    let upstream = super::upstream_expect_path("/never", "unexpected").await;
    let router = NativeHttp1HostRouter::from_config(
        &fixture.config_with_attachments(
            upstream,
            vec![
                wasm_attachment("deny", "route", 100),
                wasm_attachment("invalid", "route", 200),
            ],
        ),
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/route").await;

    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
}

#[tokio::test]
async fn native_wasm_access_decision_uses_decoded_policy_route() {
    let fixture = WasmRouteFixture::new(&[("deny", WasmPluginBody::Decision(2))]);
    let upstream = super::upstream_expect_path("/%72oute", "unexpected").await;
    let router = NativeHttp1HostRouter::from_config(
        &fixture.config_with_attachments(upstream, vec![wasm_attachment("deny", "route", 100)]),
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/%72oute").await;

    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
}

#[tokio::test]
async fn native_wasm_access_decision_cannot_override_builtin_route_acl() {
    let fixture = WasmRouteFixture::new(&[("allow", WasmPluginBody::Decision(1))]);
    let upstream = super::upstream_expect_path("/never", "unexpected").await;
    let mut config =
        fixture.config_with_attachments(upstream, vec![wasm_attachment("allow", "route", 100)]);
    config.vhosts[0].routes[0].access = fluxheim_config::AccessPolicyConfig {
        deny: vec!["127.0.0.1".to_owned()],
        ..Default::default()
    };
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/route").await;

    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response.ends_with("forbidden\n"));
}

#[tokio::test]
async fn native_wasm_access_decision_fails_closed_on_invalid_output() {
    let fixture = WasmRouteFixture::new(&[("invalid", WasmPluginBody::Decision(9))]);
    let upstream = super::upstream_expect_path("/never", "unexpected").await;
    let router = NativeHttp1HostRouter::from_config(
        &fixture.config_with_attachments(upstream, vec![wasm_attachment("invalid", "route", 100)]),
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/route").await;

    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response.ends_with("wasm access decision error\n"));
}

#[tokio::test]
async fn native_wasm_access_decision_fails_closed_on_trap() {
    let fixture = WasmRouteFixture::new(&[("trap", WasmPluginBody::Trap)]);
    let upstream = super::upstream_expect_path("/never", "unexpected").await;
    let router = NativeHttp1HostRouter::from_config(
        &fixture.config_with_attachments(upstream, vec![wasm_attachment("trap", "route", 100)]),
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/route").await;

    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response.ends_with("wasm access decision trap\n"));
}

#[tokio::test]
async fn native_wasm_access_decision_fails_closed_on_timeout() {
    let fixture = WasmRouteFixture::new(&[("busy", WasmPluginBody::BusyLoop)]);
    let upstream = super::upstream_expect_path("/never", "unexpected").await;
    let router = NativeHttp1HostRouter::from_config(
        &fixture.config_with_attachments(upstream, vec![wasm_attachment("busy", "route", 100)]),
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/route").await;

    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response.ends_with("wasm access decision timeout\n"));
}

#[tokio::test]
async fn native_wasm_access_decision_enforces_attachment_admission_budget() {
    let fixture = WasmRouteFixture::new(&[("busy", WasmPluginBody::BusyLoop)]);
    let upstream = super::upstream_expect_path("/never", "unexpected").await;
    let router = NativeHttp1HostRouter::from_config(
        &fixture.config_with_attachments(
            upstream,
            vec![wasm_attachment_with_admission("busy", "route", 100, 1)],
        ),
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = router_listener(router).await;

    let first = tokio::spawn(async move { downstream_get(proxy, "/route").await });
    tokio::time::sleep(Duration::from_millis(25)).await;
    let second = downstream_get(proxy, "/route").await;
    let first = first.await.unwrap();

    assert!([first.as_str(), second.as_str()].iter().any(|response| {
        response.starts_with("HTTP/1.1 503 Service Unavailable\r\n")
            && response.ends_with("wasm access decision fail_closed\n")
    }));
}

#[tokio::test]
async fn native_wasm_access_decision_enforces_plugin_admission_budget_across_attachments() {
    let fixture = WasmRouteFixture::new(&[("busy", WasmPluginBody::BusyLoop)]);
    let upstream = super::upstream_expect_path("/never", "unexpected").await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![
            wasm_attachment("busy", "route", 100),
            wasm_attachment("busy", "other", 100),
        ],
    );
    config.vhosts[0].routes.push(other_route());
    config.wasm.plugins[0].admission = Some(fluxheim_config::WasmAdmissionBudgetConfig {
        max_concurrent_executions: 1,
        queue_limit: 0,
    });
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let first = tokio::spawn(async move { downstream_get(proxy, "/route").await });
    tokio::time::sleep(Duration::from_millis(25)).await;
    let second = downstream_get(proxy, "/other").await;
    let first = first.await.unwrap();

    assert!([first.as_str(), second.as_str()].iter().any(|response| {
        response.starts_with("HTTP/1.1 503 Service Unavailable\r\n")
            && response.ends_with("wasm access decision fail_closed\n")
    }));
}

#[tokio::test]
async fn native_wasm_access_decision_enforces_global_admission_budget() {
    let fixture = WasmRouteFixture::new(&[("busy", WasmPluginBody::BusyLoop)]);
    let upstream = super::upstream_expect_path("/never", "unexpected").await;
    let mut config =
        fixture.config_with_attachments(upstream, vec![wasm_attachment("busy", "route", 100)]);
    config.wasm.max_total_concurrent_executions = 1;
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let first = tokio::spawn(async move { downstream_get(proxy, "/route").await });
    tokio::time::sleep(Duration::from_millis(25)).await;
    let second = downstream_get(proxy, "/route").await;
    let first = first.await.unwrap();

    assert!([first.as_str(), second.as_str()].iter().any(|response| {
        response.starts_with("HTTP/1.1 503 Service Unavailable\r\n")
            && response.ends_with("wasm access decision fail_closed\n")
    }));
}

#[tokio::test]
async fn native_wasm_request_and_response_headers_use_bounded_host_calls() {
    let fixture = WasmRouteFixture::new(&[("headers", WasmPluginBody::HeaderPolicy)]);
    let upstream = upstream_expect_policy_header().await;
    let mut config = fixture
        .config_with_attachments(upstream, vec![wasm_attachment_all("headers", "route", 100)]);
    config.vhosts[0].routes[0].path_exact = None;
    config.vhosts[0].routes[0].path_prefix = Some("/gold".to_owned());
    config.vhosts[0].routes[0].redirect = None;
    config.vhosts[0].routes[0].proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/gold/item").await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&response, "x-fluxheim-policy-branch").as_deref(),
        Some("gold")
    );
    assert_eq!(response_header(&response, "x-powered-by"), None);
    assert!(response.ends_with("policy"));
}

#[tokio::test]
async fn native_wasm_forbidden_header_mutation_fails_closed() {
    let fixture = WasmRouteFixture::new(&[("forbidden", WasmPluginBody::ForbiddenHeader)]);
    let upstream = super::upstream_expect_path("/never", "unexpected").await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![wasm_attachment_phase(
            "forbidden",
            "route",
            100,
            fluxheim_config::WasmPluginPhase::RequestHeaders,
        )],
    );
    config.vhosts[0].routes[0].redirect = None;
    config.vhosts[0].routes[0].proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/route").await;

    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response.ends_with("wasm request-headers trap\n"));
}

struct WasmRouteFixture {
    _directory: TempDir,
    root: PathBuf,
    plugins: Vec<fluxheim_config::WasmPluginConfig>,
}

impl WasmRouteFixture {
    fn new(plugins: &[(&str, WasmPluginBody)]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("plugins");
        fs::create_dir(&root).unwrap();
        let plugins = plugins
            .iter()
            .map(|(name, body)| wasm_plugin(&root, name, *body))
            .collect();
        Self {
            _directory: directory,
            root,
            plugins,
        }
    }

    fn config_with_attachments(
        &self,
        upstream: std::net::SocketAddr,
        attachments: Vec<fluxheim_config::WasmAttachmentConfig>,
    ) -> fluxheim_config::Config {
        let mut vhost = native_route_proxy_test_vhost();
        vhost.proxy.upstream = Some(upstream.to_string());
        vhost.routes = vec![native_route_proxy_test_route()];
        let mut config = fluxheim_config::Config {
            vhosts: vec![vhost],
            ..Default::default()
        };
        config.server.default_vhost = Some("route.test".to_owned());
        config.wasm = fluxheim_config::WasmConfig {
            enabled: true,
            plugin_roots: vec![self.root.clone()],
            plugins: self.plugins.clone(),
            attachments,
            ..Default::default()
        };
        config
    }
}

#[derive(Clone, Copy)]
enum WasmPluginBody {
    Decision(i32),
    HeaderPolicy,
    ForbiddenHeader,
    Trap,
    BusyLoop,
}

impl WasmPluginBody {
    fn source(self) -> String {
        match self {
            Self::Decision(decision) => {
                format!(
                    r#"(module (func (export "fluxheim_access_decision") (result i32) i32.const {decision}))"#
                )
            }
            Self::HeaderPolicy => {
                r#"
                (module
                  (import "fluxheim_policy_v1" "context" (func $context (param i32 i32) (result i32)))
                  (import "fluxheim_policy_v1" "set_request_header" (func $set_request_header (param i32 i32) (result i32)))
                  (import "fluxheim_policy_v1" "set_response_header" (func $set_response_header (param i32 i32) (result i32)))
                  (import "fluxheim_policy_v1" "remove_response_header" (func $remove_response_header (param i32 i32) (result i32)))
                  (func (export "fluxheim_request_headers") (result i32)
                    i32.const 1
                    i32.const 0
                    call $context
                    i32.const 3
                    i32.eq
                    if
                      i32.const 1
                      i32.const 4
                      call $set_request_header
                      drop
                    else
                      i32.const 1
                      i32.const 1
                      call $set_request_header
                      drop
                    end
                    i32.const 0)
                  (func (export "fluxheim_response_headers") (result i32)
                    i32.const 2
                    i32.const 4
                    call $set_response_header
                    drop
                    i32.const 3
                    i32.const 0
                    call $remove_response_header
                    drop
                    i32.const 0))
                "#
                .to_owned()
            }
            Self::ForbiddenHeader => {
                r#"
                (module
                  (import "fluxheim_policy_v1" "set_request_header" (func $set_request_header (param i32 i32) (result i32)))
                  (func (export "fluxheim_request_headers") (result i32)
                    i32.const 99
                    i32.const 99
                    call $set_request_header
                    drop
                    i32.const 0))
                "#
                .to_owned()
            }
            Self::Trap => {
                r#"(module (func (export "fluxheim_access_decision") (result i32) unreachable))"#
                    .to_owned()
            }
            Self::BusyLoop => {
                r#"(module (func (export "fluxheim_access_decision") (result i32) (loop br 0) i32.const 1))"#
                    .to_owned()
            }
        }
    }
}

fn wasm_plugin(root: &Path, name: &str, body: WasmPluginBody) -> fluxheim_config::WasmPluginConfig {
    let bytes = wat::parse_str(body.source()).unwrap();
    let path = root.join(format!("{name}.wasm"));
    fs::write(&path, &bytes).unwrap();
    let limits = matches!(body, WasmPluginBody::BusyLoop).then_some(
        fluxheim_config::WasmSandboxLimitsConfig {
            fuel: 1_000_000_000,
            timeout_ms: 150,
            ..Default::default()
        },
    );
    fluxheim_config::WasmPluginConfig {
        name: name.to_owned(),
        path,
        sha256: Some(sha256_hex(&bytes)),
        abi: fluxheim_config::WasmPluginAbi::FluxheimPolicyV1,
        host_call_namespace: fluxheim_config::WasmHostCallNamespace::FluxheimPolicyV1,
        phases: wasm_plugin_phases(body),
        fail_mode: fluxheim_config::WasmPluginFailMode::FailClosed,
        limits,
        admission: None,
    }
}

fn wasm_plugin_phases(body: WasmPluginBody) -> Vec<fluxheim_config::WasmPluginPhase> {
    match body {
        WasmPluginBody::HeaderPolicy => vec![
            fluxheim_config::WasmPluginPhase::RequestHeaders,
            fluxheim_config::WasmPluginPhase::ResponseHeaders,
        ],
        WasmPluginBody::ForbiddenHeader => {
            vec![fluxheim_config::WasmPluginPhase::RequestHeaders]
        }
        WasmPluginBody::Decision(_) | WasmPluginBody::Trap | WasmPluginBody::BusyLoop => {
            vec![fluxheim_config::WasmPluginPhase::AccessDecision]
        }
    }
}

fn wasm_attachment(
    plugin: &str,
    route: &str,
    priority: u32,
) -> fluxheim_config::WasmAttachmentConfig {
    fluxheim_config::WasmAttachmentConfig {
        plugin: plugin.to_owned(),
        vhost: "route.test".to_owned(),
        route: Some(route.to_owned()),
        phases: vec![fluxheim_config::WasmPluginPhase::AccessDecision],
        priority,
        admission: None,
    }
}

fn wasm_attachment_all(
    plugin: &str,
    route: &str,
    priority: u32,
) -> fluxheim_config::WasmAttachmentConfig {
    let mut attachment = wasm_attachment(plugin, route, priority);
    attachment.phases = vec![
        fluxheim_config::WasmPluginPhase::RequestHeaders,
        fluxheim_config::WasmPluginPhase::ResponseHeaders,
    ];
    attachment
}

fn wasm_attachment_phase(
    plugin: &str,
    route: &str,
    priority: u32,
    phase: fluxheim_config::WasmPluginPhase,
) -> fluxheim_config::WasmAttachmentConfig {
    let mut attachment = wasm_attachment(plugin, route, priority);
    attachment.phases = vec![phase];
    attachment
}

fn wasm_attachment_with_admission(
    plugin: &str,
    route: &str,
    priority: u32,
    max_concurrent_executions: u32,
) -> fluxheim_config::WasmAttachmentConfig {
    let mut attachment = wasm_attachment(plugin, route, priority);
    attachment.admission = Some(fluxheim_config::WasmAdmissionBudgetConfig {
        max_concurrent_executions,
        queue_limit: 0,
    });
    attachment
}

fn other_route() -> fluxheim_config::RouteConfig {
    let mut route = native_route_proxy_test_route();
    route.name = "other".to_owned();
    route.path_exact = Some("/other".to_owned());
    route
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

async fn router_listener(router: NativeHttp1HostRouter) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        serve_native_http1_listener(
            listener,
            DownstreamHttp1Policy::default(),
            Arc::new(router),
            async {
                let _ = shutdown_rx.await;
            },
        )
        .await
        .unwrap();
    });
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let _ = shutdown_tx.send(());
    });
    addr
}

async fn upstream_expect_policy_header() -> std::net::SocketAddr {
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
        assert!(
            request.starts_with("GET /gold/item HTTP/1.1\r\n"),
            "unexpected upstream request: {request:?}"
        );
        assert!(
            request
                .lines()
                .any(|line| line.eq_ignore_ascii_case("x-policy-tier: gold")),
            "missing wasm policy header in upstream request: {request:?}"
        );
        assert!(
            !request.lines().any(|line| line
                .split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization")
                    || name.eq_ignore_ascii_case("cookie"))),
            "sensitive client header reached upstream request: {request:?}"
        );
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nx-powered-by: origin\r\ncontent-length: 6\r\n\r\npolicy",
            )
            .await
            .unwrap();
    });
    addr
}
