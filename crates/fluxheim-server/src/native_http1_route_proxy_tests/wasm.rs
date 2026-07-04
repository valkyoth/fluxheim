use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;

use crate::{DownstreamHttp1Policy, NativeHttp1HostRouter, serve_native_http1_listener};

use super::{downstream_get, native_route_proxy_test_route, native_route_proxy_test_vhost};

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
            timeout_ms: 500,
            ..Default::default()
        },
    );
    fluxheim_config::WasmPluginConfig {
        name: name.to_owned(),
        path,
        sha256: Some(sha256_hex(&bytes)),
        abi: fluxheim_config::WasmPluginAbi::FluxheimPolicyV1,
        host_call_namespace: fluxheim_config::WasmHostCallNamespace::FluxheimPolicyV1,
        phases: vec![fluxheim_config::WasmPluginPhase::AccessDecision],
        fail_mode: fluxheim_config::WasmPluginFailMode::FailClosed,
        limits,
        admission: None,
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
