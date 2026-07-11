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
    downstream_get, downstream_request, native_proxy_memory_cache_config,
    native_route_proxy_test_route, native_route_proxy_test_vhost, response_header,
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

#[cfg(feature = "wasm-proxy-abi")]
#[tokio::test]
async fn native_wasm_proxy_preview_log_call_fails_closed() {
    let fixture = WasmRouteFixture::new(&[("proxy_preview", WasmPluginBody::ProxyPreviewLogCall)]);
    let upstream = super::upstream_expect_path("/never", "unexpected").await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![wasm_attachment("proxy_preview", "route", 100)],
    );
    config.wasm.allow_preview_abi = true;
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/route").await;

    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response.ends_with("wasm access decision trap\n"));
}

#[cfg(feature = "wasm-wasi")]
#[tokio::test]
async fn native_wasm_wasi_randomness_grant_executes_on_live_listener() {
    let fixture = WasmRouteFixture::new(&[("wasi", WasmPluginBody::WasiRandomGranted)]);
    let upstream = super::upstream_expect_path("/never", "unexpected").await;
    let mut config =
        fixture.config_with_attachments(upstream, vec![wasm_attachment("wasi", "route", 100)]);
    config.wasm.allow_preview_abi = true;
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/route").await;

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert_eq!(
        response_header(&response, "location").as_deref(),
        Some("https://target.example/route")
    );
}

#[cfg(feature = "wasm-wasi")]
#[tokio::test]
async fn native_wasm_wasi_randomness_without_grant_fails_closed() {
    let fixture = WasmRouteFixture::new(&[("wasi", WasmPluginBody::WasiRandomDenied)]);
    let upstream = super::upstream_expect_path("/never", "unexpected").await;
    let mut config =
        fixture.config_with_attachments(upstream, vec![wasm_attachment("wasi", "route", 100)]);
    config.wasm.allow_preview_abi = true;
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/route").await;

    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response.ends_with("wasm access decision error\n"));
}

#[cfg(feature = "wasm-wasi")]
#[tokio::test]
async fn native_wasm_wasi_stdio_import_remains_denied_with_other_grants() {
    let fixture = WasmRouteFixture::new(&[("wasi", WasmPluginBody::WasiForbiddenFdWrite)]);
    let upstream = super::upstream_expect_path("/never", "unexpected").await;
    let mut config =
        fixture.config_with_attachments(upstream, vec![wasm_attachment("wasi", "route", 100)]);
    config.wasm.allow_preview_abi = true;
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/route").await;

    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response.ends_with("wasm access decision error\n"));
}

#[tokio::test]
async fn native_wasm_access_decision_fails_closed_on_timeout() {
    let fixture = WasmRouteFixture::new(&[("busy", WasmPluginBody::BusyLoop)]);
    let upstream = super::upstream_expect_path("/never", "unexpected").await;
    let mut config =
        fixture.config_with_attachments(upstream, vec![wasm_attachment("busy", "route", 100)]);
    config.wasm.plugins[0]
        .limits
        .as_mut()
        .expect("busy-loop test plugin has explicit limits")
        .timeout_ms = 5;
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
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
async fn native_wasm_cache_admission_budget_does_not_starve_access_hooks() {
    let fixture = WasmRouteFixture::new(&[
        ("cache_busy", WasmPluginBody::CacheLookupBusy),
        ("access", WasmPluginBody::Decision(1)),
    ]);
    let cache_upstream = super::upstream_expect_path("/never", "unexpected").await;
    let access_upstream = upstream_expect_body("/access/item", "access-ok").await;
    let mut cache_route = named_proxy_route("cache", "/cache", cache_upstream);
    cache_route.cache = Some(native_proxy_memory_cache_config());
    let access_route = named_proxy_route("access", "/access", access_upstream);
    let mut vhost = native_route_proxy_test_vhost();
    vhost.routes = vec![cache_route, access_route];
    let mut config = fluxheim_config::Config {
        vhosts: vec![vhost],
        ..Default::default()
    };
    config.server.default_vhost = Some("route.test".to_owned());
    config.wasm = fluxheim_config::WasmConfig {
        enabled: true,
        plugin_roots: vec![fixture.root.clone()],
        plugins: fixture.plugins.clone(),
        attachments: vec![
            wasm_attachment_phase(
                "cache_busy",
                "cache",
                100,
                fluxheim_config::WasmPluginPhase::CacheLookup,
            ),
            wasm_attachment("access", "access", 100),
        ],
        max_total_concurrent_executions: 1,
        max_total_cache_concurrent_executions: 1,
        ..Default::default()
    };
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let cache_request = tokio::spawn(async move { downstream_get(proxy, "/cache/item").await });
    tokio::time::sleep(Duration::from_millis(25)).await;
    let access_response = downstream_get(proxy, "/access/item").await;
    let cache_response = cache_request.await.unwrap();

    assert!(access_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(access_response.ends_with("access-ok"));
    assert!(cache_response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(
        cache_response.contains("wasm cache lookup"),
        "unexpected cache response: {cache_response:?}"
    );
}

#[tokio::test]
async fn native_wasm_cache_admission_budget_is_fair_across_vhosts() {
    let fixture = WasmRouteFixture::new(&[
        ("cache_busy", WasmPluginBody::CacheLookupBusy),
        ("cache_ok", WasmPluginBody::CacheLookupDeviceKey),
    ]);
    let left_upstream = super::upstream_expect_path("/never", "unexpected").await;
    let right_upstream = upstream_expect_body("/cache/item", "right-ok").await;
    let mut left_route = named_proxy_route("cache", "/cache", left_upstream);
    left_route.cache = Some(native_proxy_memory_cache_config());
    let mut right_route = named_proxy_route("cache", "/cache", right_upstream);
    right_route.cache = Some(native_proxy_memory_cache_config());

    let mut left_vhost = native_route_proxy_test_vhost();
    left_vhost.name = "tenant-a".to_owned();
    left_vhost.hosts = vec!["tenant-a.test".to_owned()];
    left_vhost.routes = vec![left_route];

    let mut right_vhost = native_route_proxy_test_vhost();
    right_vhost.name = "tenant-b".to_owned();
    right_vhost.hosts = vec!["tenant-b.test".to_owned()];
    right_vhost.routes = vec![right_route];

    let mut config = fluxheim_config::Config {
        vhosts: vec![left_vhost, right_vhost],
        ..Default::default()
    };
    config.server.default_vhost = Some("tenant-a".to_owned());
    config.wasm = fluxheim_config::WasmConfig {
        enabled: true,
        plugin_roots: vec![fixture.root.clone()],
        plugins: fixture.plugins.clone(),
        attachments: vec![
            fluxheim_config::WasmAttachmentConfig {
                plugin: "cache_busy".to_owned(),
                vhost: "tenant-a".to_owned(),
                route: Some("cache".to_owned()),
                phases: vec![fluxheim_config::WasmPluginPhase::CacheLookup],
                priority: 100,
                admission: None,
            },
            fluxheim_config::WasmAttachmentConfig {
                plugin: "cache_ok".to_owned(),
                vhost: "tenant-b".to_owned(),
                route: Some("cache".to_owned()),
                phases: vec![fluxheim_config::WasmPluginPhase::CacheLookup],
                priority: 100,
                admission: None,
            },
        ],
        max_total_cache_concurrent_executions: 2,
        ..Default::default()
    };
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let first_left = tokio::spawn(async move {
        downstream_request(
            proxy,
            "GET /cache/item HTTP/1.1\r\nHost: tenant-a.test\r\nConnection: close\r\n\r\n",
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    let second_left = downstream_request(
        proxy,
        "GET /cache/item HTTP/1.1\r\nHost: tenant-a.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    let right = downstream_request(
        proxy,
        "GET /cache/item HTTP/1.1\r\nHost: tenant-b.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    let first_left = first_left.await.unwrap();

    assert!(
        second_left.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
        "unexpected same-vhost cache admission response: {second_left:?}"
    );
    assert!(second_left.ends_with("wasm cache lookup fail_closed\n"));
    assert!(right.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(right.ends_with("right-ok"));
    assert!(
        first_left.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
        "unexpected first cache response: {first_left:?}"
    );
}

#[tokio::test]
async fn native_wasm_request_and_response_headers_use_bounded_host_calls() {
    let fixture = WasmRouteFixture::new(&[("headers", WasmPluginBody::HeaderPolicy)]);
    let upstream = upstream_expect_policy_header("/item").await;
    let mut config = fixture
        .config_with_attachments(upstream, vec![wasm_attachment_all("headers", "route", 100)]);
    config.vhosts[0].routes[0].path_exact = None;
    config.vhosts[0].routes[0].path_prefix = Some("/gold".to_owned());
    config.vhosts[0].routes[0].strip_prefix = Some("/gold".to_owned());
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

#[tokio::test]
async fn native_wasm_route_decision_selects_configured_canary_route() {
    let fixture = WasmRouteFixture::new(&[("router", WasmPluginBody::RouteDecision)]);
    let stable = upstream_expect_body("/lb/item", "stable").await;
    let canary = upstream_expect_body("/lb/item", "canary").await;
    let mut config = fixture.config_with_attachments(
        stable,
        vec![wasm_vhost_attachment_phase(
            "router",
            100,
            fluxheim_config::WasmPluginPhase::RouteDecision,
        )],
    );
    config.vhosts[0].routes = vec![
        named_proxy_route("standard", "/lb", stable),
        named_proxy_route("canary", "/lb", canary),
    ];
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_request(
        proxy,
        "GET /lb/item HTTP/1.1\r\nHost: route.test\r\nX-Canary: 1\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("canary"));
}

#[tokio::test]
async fn native_wasm_route_decision_fails_closed_for_unconfigured_branch() {
    let fixture = WasmRouteFixture::new(&[("router", WasmPluginBody::RouteDecision)]);
    let stable = upstream_expect_body("/lb/item", "stable").await;
    let mut config = fixture.config_with_attachments(
        stable,
        vec![wasm_vhost_attachment_phase(
            "router",
            100,
            fluxheim_config::WasmPluginPhase::RouteDecision,
        )],
    );
    config.vhosts[0].routes = vec![named_proxy_route("standard", "/lb", stable)];
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_request(
        proxy,
        "GET /lb/item HTTP/1.1\r\nHost: route.test\r\nX-Canary: 1\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response.ends_with("wasm route decision unavailable\n"));
}

#[tokio::test]
async fn native_wasm_route_decision_does_not_run_before_route_acl() {
    let fixture = WasmRouteFixture::new(&[("router", WasmPluginBody::RouteDecision)]);
    let upstream = super::upstream_expect_path("/never", "unexpected").await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![wasm_vhost_attachment_phase(
            "router",
            100,
            fluxheim_config::WasmPluginPhase::RouteDecision,
        )],
    );
    config.vhosts[0].routes[0].access = fluxheim_config::AccessPolicyConfig {
        deny: vec!["127.0.0.1".to_owned()],
        ..Default::default()
    };
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_request(
        proxy,
        "GET /route HTTP/1.1\r\nHost: route.test\r\nX-Canary: 1\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response.ends_with("forbidden\n"));
}

#[tokio::test]
async fn native_wasm_route_decision_enforces_selected_route_rate_limit() {
    let fixture = WasmRouteFixture::new(&[("router", WasmPluginBody::RouteDecision)]);
    let stable = upstream_expect_body("/limit/item", "stable").await;
    let canary = upstream_expect_body("/limit/item", "canary").await;
    let mut config = fixture.config_with_attachments(
        stable,
        vec![wasm_vhost_attachment_phase(
            "router",
            100,
            fluxheim_config::WasmPluginPhase::RouteDecision,
        )],
    );
    let mut canary_route = named_proxy_route("canary", "/limit", canary);
    canary_route.rate_limit = fluxheim_config::RateLimitConfig {
        enabled: true,
        requests_per_second: 1,
        burst: 1,
        status: 429,
        ..Default::default()
    };
    config.vhosts[0].routes = vec![
        named_proxy_route("standard", "/limit", stable),
        canary_route,
    ];
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let first = downstream_request(
        proxy,
        "GET /limit/item HTTP/1.1\r\nHost: route.test\r\nX-Canary: 1\r\nConnection: close\r\n\r\n",
    )
    .await;
    let second = downstream_request(
        proxy,
        "GET /limit/item HTTP/1.1\r\nHost: route.test\r\nX-Canary: 1\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("canary"));
    assert!(second.starts_with("HTTP/1.1 429 Too Many Requests\r\n"));
    assert!(second.ends_with("rate limited\n"));
}

#[cfg(feature = "load-balancer")]
#[tokio::test]
async fn native_wasm_route_decision_selects_configured_load_balanced_route() {
    let fixture = WasmRouteFixture::new(&[("router", WasmPluginBody::RouteDecision)]);
    let stable = upstream_expect_body("/lb/item", "stable").await;
    let canary_a = upstream_expect_body("/lb/item", "canary-a").await;
    let canary_b = upstream_expect_body("/lb/item", "canary-b").await;
    let mut config = fixture.config_with_attachments(
        stable,
        vec![wasm_vhost_attachment_phase(
            "router",
            100,
            fluxheim_config::WasmPluginPhase::RouteDecision,
        )],
    );
    config.vhosts[0].routes = vec![
        named_proxy_route("standard", "/lb", stable),
        named_load_balanced_route("canary", "/lb", &[canary_a, canary_b]),
    ];
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_request(
        proxy,
        "GET /lb/item HTTP/1.1\r\nHost: route.test\r\nX-Canary: 1\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(
        response.ends_with("canary-a") || response.ends_with("canary-b"),
        "unexpected load-balanced response: {response:?}"
    );
}

#[cfg(feature = "load-balancer")]
#[tokio::test]
async fn native_wasm_route_decision_selects_configured_persistent_route() {
    let fixture = WasmRouteFixture::new(&[("router", WasmPluginBody::RouteDecision)]);
    let stable = upstream_expect_body("/sticky/item", "stable").await;
    let sticky_a = upstream_body_loop("sticky-a", 2).await;
    let sticky_b = upstream_body_loop("sticky-b", 2).await;
    let mut config = fixture.config_with_attachments(
        stable,
        vec![wasm_vhost_attachment_phase(
            "router",
            100,
            fluxheim_config::WasmPluginPhase::RouteDecision,
        )],
    );
    config.vhosts[0].routes = vec![
        named_proxy_route("standard", "/sticky", stable),
        named_persistent_load_balanced_route("canary", "/sticky", &[sticky_a, sticky_b]),
    ];
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let first = downstream_request(
        proxy,
        "GET /sticky/item HTTP/1.1\r\nHost: route.test\r\nX-Canary: 1\r\nConnection: close\r\n\r\n",
    )
    .await;
    let cookie = response_header(&first, "set-cookie")
        .and_then(|value| value.split(';').next().map(str::to_owned))
        .expect("managed persistence cookie is issued");
    let second = downstream_request(
        proxy,
        &format!(
            "GET /sticky/item HTTP/1.1\r\nHost: route.test\r\nX-Canary: 1\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    let first_body = first.split("\r\n\r\n").nth(1).unwrap_or_default();
    let second_body = second.split("\r\n\r\n").nth(1).unwrap_or_default();
    assert_eq!(first_body, second_body);
    assert!(
        first_body == "sticky-a" || first_body == "sticky-b",
        "unexpected persistent backend body: {first_body:?}"
    );
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
#[tokio::test]
async fn native_wasm_route_decision_selects_configured_mirror_route() {
    let fixture = WasmRouteFixture::new(&[("router", WasmPluginBody::RouteDecision)]);
    let origin = upstream_expect_body("/shadow/item", "origin").await;
    let (mirror, mirror_rx) = mirror_endpoint().await;
    let mut config = fixture.config_with_attachments(
        origin,
        vec![wasm_vhost_attachment_phase(
            "router",
            100,
            fluxheim_config::WasmPluginPhase::RouteDecision,
        )],
    );
    config.vhosts[0].routes = vec![
        named_proxy_route("standard", "/shadow", origin),
        named_proxy_route_with_mirror("mirror", "/shadow", origin, mirror),
    ];
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_request(
        proxy,
        "GET /shadow/item HTTP/1.1\r\nHost: route.test\r\nX-Mirror: 1\r\nConnection: close\r\n\r\n",
    )
    .await;
    let mirrored = tokio::time::timeout(Duration::from_secs(2), mirror_rx)
        .await
        .unwrap()
        .unwrap();

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("origin"));
    assert!(mirrored.starts_with("GET /copy/shadow/item HTTP/1.1\r\n"));
    assert!(mirrored.contains("\r\nx-fluxheim-mirror: 1\r\n"));
}

#[tokio::test]
async fn native_wasm_cache_lookup_can_pass_selected_requests_without_storing() {
    let fixture = WasmRouteFixture::new(&[("cache", WasmPluginBody::CacheLookup)]);
    let upstream = super::upstream_cacheable_sequence(&[
        ("/api/item.png", "api-one"),
        ("/api/item.png", "api-two"),
        ("/static/item.png", "static-one"),
    ])
    .await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![wasm_attachment_phase(
            "cache",
            "route",
            100,
            fluxheim_config::WasmPluginPhase::CacheLookup,
        )],
    );
    config.vhosts[0].routes[0].path_exact = None;
    config.vhosts[0].routes[0].path_prefix = Some("/".to_owned());
    config.vhosts[0].routes[0].redirect = None;
    config.vhosts[0].routes[0].proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    config.vhosts[0].routes[0].cache = Some(native_proxy_memory_cache_config());
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let first_api = downstream_get(proxy, "/api/item.png").await;
    let second_api = downstream_get(proxy, "/api/item.png").await;
    let first_static = downstream_get(proxy, "/static/item.png").await;
    let second_static = downstream_get(proxy, "/static/item.png").await;

    assert!(first_api.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first_api.ends_with("api-one"));
    assert_eq!(
        response_header(&first_api, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&first_api, "x-cache-reason").as_deref(),
        Some("wasm-pass")
    );
    assert!(second_api.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second_api.ends_with("api-two"));
    assert_eq!(
        response_header(&second_api, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&second_api, "x-cache-reason").as_deref(),
        Some("wasm-pass")
    );
    assert!(first_static.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first_static.ends_with("static-one"));
    assert_eq!(
        response_header(&first_static, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(second_static.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second_static.ends_with("static-one"));
    assert_eq!(
        response_header(&second_static, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_wasm_cache_lookup_denies_before_cache_lookup() {
    let fixture = WasmRouteFixture::new(&[("cache", WasmPluginBody::CacheLookupDeny)]);
    let upstream = super::upstream_expect_path("/never", "unexpected").await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![wasm_attachment_phase(
            "cache",
            "route",
            100,
            fluxheim_config::WasmPluginPhase::CacheLookup,
        )],
    );
    config.vhosts[0].routes[0].cache = Some(native_proxy_memory_cache_config());
    config.vhosts[0].routes[0].redirect = None;
    config.vhosts[0].routes[0].proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/route").await;

    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response.ends_with("wasm cache lookup denied\n"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
}

#[tokio::test]
async fn native_wasm_cache_lookup_can_add_bounded_cache_key_component() {
    let fixture = WasmRouteFixture::new(&[("cache", WasmPluginBody::CacheLookupDeviceKey)]);
    let upstream = super::upstream_cacheable_sequence(&[
        ("/static/device.png", "mobile-body"),
        ("/static/device.png", "desktop-body"),
    ])
    .await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![wasm_attachment_phase(
            "cache",
            "route",
            100,
            fluxheim_config::WasmPluginPhase::CacheLookup,
        )],
    );
    config.vhosts[0].routes[0].path_exact = None;
    config.vhosts[0].routes[0].path_prefix = Some("/".to_owned());
    config.vhosts[0].routes[0].redirect = None;
    config.vhosts[0].routes[0].proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    config.vhosts[0].routes[0].cache = Some(native_proxy_memory_cache_config());
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let mobile = downstream_request(
        proxy,
        "GET /static/device.png HTTP/1.1\r\nHost: route.test\r\nX-Device-Class: mobile\r\nConnection: close\r\n\r\n",
    )
    .await;
    let desktop = downstream_request(
        proxy,
        "GET /static/device.png HTTP/1.1\r\nHost: route.test\r\nX-Device-Class: desktop\r\nConnection: close\r\n\r\n",
    )
    .await;
    let mobile_hit = downstream_request(
        proxy,
        "GET /static/device.png HTTP/1.1\r\nHost: route.test\r\nX-Device-Class: mobile\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(
        mobile.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected mobile response: {mobile:?}"
    );
    assert!(mobile.ends_with("mobile-body"));
    assert_eq!(
        response_header(&mobile, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(
        desktop.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected desktop response: {desktop:?}"
    );
    assert!(desktop.ends_with("desktop-body"));
    assert_eq!(
        response_header(&desktop, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(
        mobile_hit.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected mobile hit response: {mobile_hit:?}"
    );
    assert!(mobile_hit.ends_with("mobile-body"));
    assert_eq!(
        response_header(&mobile_hit, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_wasm_cache_store_can_skip_storage_after_origin_response() {
    let fixture = WasmRouteFixture::new(&[("cache", WasmPluginBody::CacheStoreSkip)]);
    let upstream = super::upstream_cacheable_sequence(&[
        ("/static/store.png", "store-one"),
        ("/static/store.png", "store-two"),
    ])
    .await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![wasm_attachment_phase(
            "cache",
            "route",
            100,
            fluxheim_config::WasmPluginPhase::CacheStore,
        )],
    );
    config.vhosts[0].routes[0].path_exact = None;
    config.vhosts[0].routes[0].path_prefix = Some("/".to_owned());
    config.vhosts[0].routes[0].redirect = None;
    config.vhosts[0].routes[0].proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    config.vhosts[0].routes[0].cache = Some(native_proxy_memory_cache_config());
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let first = downstream_get(proxy, "/static/store.png").await;
    let second = downstream_get(proxy, "/static/store.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("store-one"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&first, "x-cache-reason").as_deref(),
        Some("wasm-store-skip")
    );
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("store-two"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&second, "x-cache-reason").as_deref(),
        Some("wasm-store-skip")
    );
}

#[tokio::test]
async fn native_wasm_cache_store_can_deny_after_origin_response_before_storage() {
    let fixture = WasmRouteFixture::new(&[("cache", WasmPluginBody::CacheStoreDeny)]);
    let upstream =
        super::upstream_cacheable_sequence(&[("/static/store-deny.png", "hidden-origin")]).await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![wasm_attachment_phase(
            "cache",
            "route",
            100,
            fluxheim_config::WasmPluginPhase::CacheStore,
        )],
    );
    config.vhosts[0].routes[0].path_exact = None;
    config.vhosts[0].routes[0].path_prefix = Some("/".to_owned());
    config.vhosts[0].routes[0].redirect = None;
    config.vhosts[0].routes[0].proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    config.vhosts[0].routes[0].cache = Some(native_proxy_memory_cache_config());
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/static/store-deny.png").await;

    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response.ends_with("wasm cache store denied\n"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&response, "x-cache-reason").as_deref(),
        Some("wasm-store-deny")
    );
}

#[tokio::test]
async fn native_wasm_cache_store_can_override_ttl_with_bounded_value() {
    let fixture = WasmRouteFixture::new(&[("cache", WasmPluginBody::CacheStoreShortTtl)]);
    let upstream = super::upstream_cacheable_sequence(&[
        ("/static/ttl.png", "ttl-one"),
        ("/static/ttl.png", "ttl-two"),
    ])
    .await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![wasm_attachment_phase(
            "cache",
            "route",
            100,
            fluxheim_config::WasmPluginPhase::CacheStore,
        )],
    );
    config.vhosts[0].routes[0].path_exact = None;
    config.vhosts[0].routes[0].path_prefix = Some("/".to_owned());
    config.vhosts[0].routes[0].redirect = None;
    config.vhosts[0].routes[0].proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    config.vhosts[0].routes[0].cache = Some(native_proxy_memory_cache_config());
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let first = downstream_get(proxy, "/static/ttl.png").await;
    let immediate = downstream_get(proxy, "/static/ttl.png").await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let expired = downstream_get(proxy, "/static/ttl.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("ttl-one"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(immediate.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(immediate.ends_with("ttl-one"));
    assert_eq!(
        response_header(&immediate, "x-cache-status").as_deref(),
        Some("HIT")
    );
    assert!(expired.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(expired.ends_with("ttl-two"));
    assert_eq!(
        response_header(&expired, "x-cache-status").as_deref(),
        Some("MISS")
    );
}

#[tokio::test]
async fn native_wasm_cache_store_can_set_bounded_stored_response_header() {
    let fixture = WasmRouteFixture::new(&[("cache", WasmPluginBody::CacheStoreHeader)]);
    let upstream =
        super::upstream_cacheable_sequence(&[("/static/header.png", "header-one")]).await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![wasm_attachment_phase(
            "cache",
            "route",
            100,
            fluxheim_config::WasmPluginPhase::CacheStore,
        )],
    );
    config.vhosts[0].routes[0].path_exact = None;
    config.vhosts[0].routes[0].path_prefix = Some("/".to_owned());
    config.vhosts[0].routes[0].redirect = None;
    config.vhosts[0].routes[0].proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    config.vhosts[0].routes[0].cache = Some(native_proxy_memory_cache_config());
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let first = downstream_get(proxy, "/static/header.png").await;
    let hit = downstream_get(proxy, "/static/header.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("header-one"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(response_header(&first, "x-fluxheim-cache-policy"), None);
    assert!(hit.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(hit.ends_with("header-one"));
    assert_eq!(
        response_header(&hit, "x-cache-status").as_deref(),
        Some("HIT")
    );
    assert_eq!(
        response_header(&hit, "x-fluxheim-cache-policy").as_deref(),
        Some("wasm")
    );
}

#[tokio::test]
async fn native_wasm_cross_family_chain_runs_in_order_with_cache_hit_metadata() {
    let fixture = WasmRouteFixture::new(&[
        ("access", WasmPluginBody::Decision(1)),
        ("headers", WasmPluginBody::HeaderPolicy),
        ("router", WasmPluginBody::RouteDecision),
        ("cache_key", WasmPluginBody::CacheLookupDeviceKey),
        ("cache_store", WasmPluginBody::CacheStoreHeader),
    ]);
    let stable = super::upstream_expect_path("/never", "unexpected").await;
    let canary =
        upstream_expect_policy_header_cacheable_sequence(&[("/gold/item.png", "canary-one")]).await;
    let mut config = fixture.config_with_attachments(
        stable,
        vec![
            wasm_vhost_attachment_phase(
                "access",
                100,
                fluxheim_config::WasmPluginPhase::AccessDecision,
            ),
            wasm_vhost_attachment_all_phases(
                "headers",
                110,
                &[
                    fluxheim_config::WasmPluginPhase::RequestHeaders,
                    fluxheim_config::WasmPluginPhase::ResponseHeaders,
                ],
            ),
            wasm_vhost_attachment_phase(
                "router",
                120,
                fluxheim_config::WasmPluginPhase::RouteDecision,
            ),
            wasm_vhost_attachment_phase(
                "cache_key",
                130,
                fluxheim_config::WasmPluginPhase::CacheLookup,
            ),
            wasm_vhost_attachment_phase(
                "cache_store",
                140,
                fluxheim_config::WasmPluginPhase::CacheStore,
            ),
        ],
    );
    let mut stable_route = named_proxy_route("standard", "/gold", stable);
    stable_route.cache = Some(native_proxy_memory_cache_config());
    let mut canary_route = named_proxy_route("canary", "/gold", canary);
    canary_route.cache = Some(native_proxy_memory_cache_config());
    config.vhosts[0].routes = vec![stable_route, canary_route];
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;
    let request = "GET /gold/item.png HTTP/1.1\r\nHost: route.test\r\nX-Canary: 1\r\nX-Device-Class: mobile\r\nConnection: close\r\n\r\n";

    let first = downstream_request(proxy, request).await;
    let hit = downstream_request(proxy, request).await;

    assert!(
        first.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected first response: {first:?}"
    );
    assert!(first.ends_with("canary-one"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(
        response_header(&first, "x-fluxheim-policy-branch").as_deref(),
        Some("gold")
    );
    assert_eq!(response_header(&first, "x-powered-by"), None);
    assert_eq!(response_header(&first, "x-fluxheim-cache-policy"), None);
    assert!(
        hit.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected hit response: {hit:?}"
    );
    assert!(hit.ends_with("canary-one"));
    assert_eq!(
        response_header(&hit, "x-cache-status").as_deref(),
        Some("HIT")
    );
    assert_eq!(
        response_header(&hit, "x-fluxheim-policy-branch").as_deref(),
        Some("gold")
    );
    assert_eq!(
        response_header(&hit, "x-fluxheim-cache-policy").as_deref(),
        Some("wasm")
    );
}

#[tokio::test]
async fn native_wasm_cache_store_forbidden_header_fails_closed() {
    let fixture = WasmRouteFixture::new(&[("cache", WasmPluginBody::CacheStoreForbiddenHeader)]);
    let upstream =
        super::upstream_cacheable_sequence(&[("/static/forbidden-header.png", "hidden-origin")])
            .await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![wasm_attachment_phase(
            "cache",
            "route",
            100,
            fluxheim_config::WasmPluginPhase::CacheStore,
        )],
    );
    config.vhosts[0].routes[0].path_exact = None;
    config.vhosts[0].routes[0].path_prefix = Some("/".to_owned());
    config.vhosts[0].routes[0].redirect = None;
    config.vhosts[0].routes[0].proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    config.vhosts[0].routes[0].cache = Some(native_proxy_memory_cache_config());
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/static/forbidden-header.png").await;

    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response.ends_with("wasm cache store trap\n"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
}

#[tokio::test]
async fn native_wasm_cache_policy_example_matches_documented_behavior() {
    let fixture = WasmRouteFixture::new(&[
        ("cache_lookup", WasmPluginBody::CacheLookupPolicyExample),
        ("cache_store", WasmPluginBody::CacheStorePolicyExample),
    ]);
    let upstream = super::upstream_cacheable_sequence(&[
        ("/static/example.png", "mobile-body"),
        ("/static/example.png", "desktop-body"),
        ("/static/example.png", "mobile-refill"),
    ])
    .await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![
            wasm_attachment_phase(
                "cache_lookup",
                "route",
                100,
                fluxheim_config::WasmPluginPhase::CacheLookup,
            ),
            wasm_attachment_phase(
                "cache_store",
                "route",
                100,
                fluxheim_config::WasmPluginPhase::CacheStore,
            ),
        ],
    );
    config.vhosts[0].routes[0].path_exact = None;
    config.vhosts[0].routes[0].path_prefix = Some("/".to_owned());
    config.vhosts[0].routes[0].redirect = None;
    config.vhosts[0].routes[0].proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    config.vhosts[0].routes[0].cache = Some(native_proxy_memory_cache_config());
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let mobile = downstream_request(
        proxy,
        "GET /static/example.png HTTP/1.1\r\nHost: route.test\r\nX-Device-Class: mobile\r\nConnection: close\r\n\r\n",
    )
    .await;
    let desktop = downstream_request(
        proxy,
        "GET /static/example.png HTTP/1.1\r\nHost: route.test\r\nX-Device-Class: desktop\r\nConnection: close\r\n\r\n",
    )
    .await;
    let mobile_hit = downstream_request(
        proxy,
        "GET /static/example.png HTTP/1.1\r\nHost: route.test\r\nX-Device-Class: mobile\r\nConnection: close\r\n\r\n",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let mobile_expired = downstream_request(
        proxy,
        "GET /static/example.png HTTP/1.1\r\nHost: route.test\r\nX-Device-Class: mobile\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(
        mobile.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected mobile response: {mobile:?}"
    );
    assert!(mobile.ends_with("mobile-body"));
    assert_eq!(
        response_header(&mobile, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(response_header(&mobile, "x-fluxheim-cache-policy"), None);

    assert!(
        desktop.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected desktop response: {desktop:?}"
    );
    assert!(desktop.ends_with("desktop-body"));
    assert_eq!(
        response_header(&desktop, "x-cache-status").as_deref(),
        Some("MISS")
    );

    assert!(
        mobile_hit.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected mobile hit response: {mobile_hit:?}"
    );
    assert!(mobile_hit.ends_with("mobile-body"));
    assert_eq!(
        response_header(&mobile_hit, "x-cache-status").as_deref(),
        Some("HIT")
    );
    assert_eq!(
        response_header(&mobile_hit, "x-fluxheim-cache-policy").as_deref(),
        Some("wasm")
    );

    assert!(
        mobile_expired.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected expired mobile response: {mobile_expired:?}"
    );
    assert!(mobile_expired.ends_with("mobile-refill"));
    assert_eq!(
        response_header(&mobile_expired, "x-cache-status").as_deref(),
        Some("MISS")
    );
}

#[tokio::test]
async fn native_wasm_cache_policy_example_leaves_non_image_store_metadata_unchanged() {
    let fixture = WasmRouteFixture::new(&[
        ("cache_lookup", WasmPluginBody::CacheLookupPolicyExample),
        ("cache_store", WasmPluginBody::CacheStorePolicyExample),
    ]);
    let upstream = super::upstream_cacheable_content_type_sequence(&[(
        "/static/non-image.png",
        "text/plain",
        "text-body",
    )])
    .await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![
            wasm_attachment_phase(
                "cache_lookup",
                "route",
                100,
                fluxheim_config::WasmPluginPhase::CacheLookup,
            ),
            wasm_attachment_phase(
                "cache_store",
                "route",
                100,
                fluxheim_config::WasmPluginPhase::CacheStore,
            ),
        ],
    );
    config.vhosts[0].routes[0].path_exact = None;
    config.vhosts[0].routes[0].path_prefix = Some("/".to_owned());
    config.vhosts[0].routes[0].redirect = None;
    config.vhosts[0].routes[0].proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    let mut cache = native_proxy_memory_cache_config();
    cache.content_types.push("text/plain".to_owned());
    config.vhosts[0].routes[0].cache = Some(cache);
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let first = downstream_get(proxy, "/static/non-image.png").await;
    let hit = downstream_get(proxy, "/static/non-image.png").await;

    assert!(
        first.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected text first response: {first:?}"
    );
    assert!(first.ends_with("text-body"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(response_header(&first, "x-fluxheim-cache-policy"), None);

    assert!(
        hit.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected text hit response: {hit:?}"
    );
    assert!(hit.ends_with("text-body"));
    assert_eq!(
        response_header(&hit, "x-cache-status").as_deref(),
        Some("HIT")
    );
    assert_eq!(response_header(&hit, "x-fluxheim-cache-policy"), None);
}

#[tokio::test]
async fn native_wasm_cache_slice_key_includes_bounded_key_components() {
    let fixture = WasmRouteFixture::new(&[("cache", WasmPluginBody::CacheLookupDeviceKey)]);
    let upstream = super::upstream_slice_response_sequence(&[
        (
            "/static/slice.png",
            "bytes=0-3",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\netag: \"mobile-v1\"\r\ncontent-range: bytes 0-3/10\r\ncontent-length: 4\r\n\r\nM012",
        ),
        (
            "/static/slice.png",
            "bytes=4-7",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\netag: \"mobile-v1\"\r\ncontent-range: bytes 4-7/10\r\ncontent-length: 4\r\n\r\n3456",
        ),
        (
            "/static/slice.png",
            "bytes=0-3",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\netag: \"desktop-v1\"\r\ncontent-range: bytes 0-3/10\r\ncontent-length: 4\r\n\r\nDABC",
        ),
        (
            "/static/slice.png",
            "bytes=4-7",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\netag: \"desktop-v1\"\r\ncontent-range: bytes 4-7/10\r\ncontent-length: 4\r\n\r\nDEFG",
        ),
    ])
    .await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![wasm_attachment_phase(
            "cache",
            "route",
            100,
            fluxheim_config::WasmPluginPhase::CacheLookup,
        )],
    );
    config.vhosts[0].routes[0].path_exact = None;
    config.vhosts[0].routes[0].path_prefix = Some("/".to_owned());
    config.vhosts[0].routes[0].redirect = None;
    config.vhosts[0].routes[0].proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    let mut cache = native_proxy_memory_cache_config();
    cache.range.enabled = true;
    cache.range.slice.enabled = true;
    cache.range.slice.fill_missing = true;
    cache.range.slice.size_bytes = fluxheim_config::ByteSize::from_bytes(4);
    cache.range.slice.max_slices = 4;
    config.vhosts[0].routes[0].cache = Some(cache);
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let mobile = downstream_request(
        proxy,
        "GET /static/slice.png HTTP/1.1\r\nHost: route.test\r\nX-Device-Class: mobile\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n",
    )
    .await;
    let desktop = downstream_request(
        proxy,
        "GET /static/slice.png HTTP/1.1\r\nHost: route.test\r\nX-Device-Class: desktop\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n",
    )
    .await;
    let mobile_hit = downstream_request(
        proxy,
        "GET /static/slice.png HTTP/1.1\r\nHost: route.test\r\nX-Device-Class: mobile\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(mobile.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(mobile.ends_with("1234"));
    assert_eq!(
        response_header(&mobile, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(
        response_header(&mobile, "x-cache-reason").as_deref(),
        Some("slice-fill")
    );
    assert!(desktop.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(desktop.ends_with("BCDE"));
    assert_eq!(
        response_header(&desktop, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(
        response_header(&desktop, "x-cache-reason").as_deref(),
        Some("slice-fill")
    );
    assert!(mobile_hit.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(mobile_hit.ends_with("1234"));
    assert_eq!(
        response_header(&mobile_hit, "x-cache-status").as_deref(),
        Some("HIT")
    );
    assert_eq!(
        response_header(&mobile_hit, "x-cache-reason").as_deref(),
        Some("slice")
    );
}

#[tokio::test]
async fn native_wasm_cache_lookup_forbidden_key_component_fails_closed() {
    let fixture = WasmRouteFixture::new(&[("cache", WasmPluginBody::CacheLookupForbiddenKey)]);
    let upstream =
        super::upstream_cacheable_sequence(&[("/static/forbidden-key.png", "hidden")]).await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![wasm_attachment_phase(
            "cache",
            "route",
            100,
            fluxheim_config::WasmPluginPhase::CacheLookup,
        )],
    );
    config.vhosts[0].routes[0].path_exact = None;
    config.vhosts[0].routes[0].path_prefix = Some("/".to_owned());
    config.vhosts[0].routes[0].redirect = None;
    config.vhosts[0].routes[0].proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    config.vhosts[0].routes[0].cache = Some(native_proxy_memory_cache_config());
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/static/forbidden-key.png").await;

    assert!(
        response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
        "unexpected forbidden key response: {response:?}"
    );
    assert!(response.ends_with("wasm cache lookup trap\n"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
}

#[tokio::test]
async fn native_wasm_cache_lookup_duplicate_key_component_across_hooks_fails_closed() {
    let fixture = WasmRouteFixture::new(&[
        ("left", WasmPluginBody::CacheLookupDeviceKey),
        ("right", WasmPluginBody::CacheLookupDeviceKey),
    ]);
    let upstream =
        super::upstream_cacheable_sequence(&[("/static/duplicate-key.png", "hidden")]).await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![
            wasm_attachment_phase(
                "left",
                "route",
                100,
                fluxheim_config::WasmPluginPhase::CacheLookup,
            ),
            wasm_attachment_phase(
                "right",
                "route",
                101,
                fluxheim_config::WasmPluginPhase::CacheLookup,
            ),
        ],
    );
    config.vhosts[0].routes[0].path_exact = None;
    config.vhosts[0].routes[0].path_prefix = Some("/".to_owned());
    config.vhosts[0].routes[0].redirect = None;
    config.vhosts[0].routes[0].proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    config.vhosts[0].routes[0].cache = Some(native_proxy_memory_cache_config());
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_request(
        proxy,
        "GET /static/duplicate-key.png HTTP/1.1\r\nHost: route.test\r\nX-Device-Class: mobile\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response.ends_with("duplicate wasm cache key component\n"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
}

#[tokio::test]
async fn native_wasm_cache_store_forbidden_ttl_fails_closed() {
    wasm_cache_store_failure_response(WasmPluginBody::CacheStoreForbiddenTtl, "ttl")
        .await
        .assert_service_unavailable();
}

#[tokio::test]
async fn native_wasm_cache_store_duplicate_ttl_fails_closed() {
    wasm_cache_store_failure_response(WasmPluginBody::CacheStoreDuplicateTtl, "ttl-duplicate")
        .await
        .assert_service_unavailable();
}

#[tokio::test]
async fn native_wasm_cache_store_forbidden_tag_fails_closed() {
    wasm_cache_store_failure_response(WasmPluginBody::CacheStoreForbiddenTag, "tag")
        .await
        .assert_service_unavailable();
}

#[tokio::test]
async fn native_wasm_cache_store_duplicate_header_fails_closed() {
    wasm_cache_store_failure_response(
        WasmPluginBody::CacheStoreDuplicateHeader,
        "header-duplicate",
    )
    .await
    .assert_service_unavailable();
}

#[tokio::test]
async fn native_wasm_cache_store_deny_wins_over_earlier_skip() {
    let fixture = WasmRouteFixture::new(&[
        ("skip", WasmPluginBody::CacheStoreSkip),
        ("deny", WasmPluginBody::CacheStoreDeny),
    ]);
    let upstream =
        super::upstream_cacheable_sequence(&[("/static/store-chain.png", "chain-origin")]).await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![
            wasm_attachment_phase(
                "skip",
                "route",
                10,
                fluxheim_config::WasmPluginPhase::CacheStore,
            ),
            wasm_attachment_phase(
                "deny",
                "route",
                20,
                fluxheim_config::WasmPluginPhase::CacheStore,
            ),
        ],
    );
    config.vhosts[0].routes[0].path_exact = None;
    config.vhosts[0].routes[0].path_prefix = Some("/".to_owned());
    config.vhosts[0].routes[0].redirect = None;
    config.vhosts[0].routes[0].proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    config.vhosts[0].routes[0].cache = Some(native_proxy_memory_cache_config());
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/static/store-chain.png").await;

    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response.ends_with("wasm cache store denied\n"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&response, "x-cache-reason").as_deref(),
        Some("wasm-store-deny")
    );
}

#[cfg(feature = "php-fpm")]
#[tokio::test]
async fn native_wasm_response_headers_apply_to_php_fpm_fallback() {
    let fixture = WasmRouteFixture::new(&[("headers", WasmPluginBody::HeaderPolicy)]);
    let fpm = fastcgi_responder(
        b"Status: 200 OK\r\nContent-Type: text/plain\r\nX-Powered-By: php\r\n\r\nphp-policy",
    )
    .await;
    let root = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(root.path().join("gold")).unwrap();
    std::fs::write(
        root.path().join("gold").join("index.php"),
        b"<?php echo 'ok';",
    )
    .unwrap();
    let mut vhost = native_route_proxy_test_vhost();
    vhost.php = fluxheim_config::PhpConfig {
        enabled: true,
        root: Some(root.path().to_path_buf()),
        fpm: fluxheim_config::PhpFpmConfig {
            tcp: Some(fpm.to_string()),
            allow_private_tcp_upstreams: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut config = fluxheim_config::Config {
        vhosts: vec![vhost],
        ..Default::default()
    };
    config.server.default_vhost = Some("route.test".to_owned());
    config.wasm = fluxheim_config::WasmConfig {
        enabled: true,
        plugin_roots: vec![fixture.root.clone()],
        plugins: fixture.plugins.clone(),
        attachments: vec![wasm_vhost_attachment_all("headers", 100)],
        ..Default::default()
    };
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, "/gold/index.php").await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&response, "x-fluxheim-policy-branch").as_deref(),
        Some("gold")
    );
    assert_eq!(response_header(&response, "x-powered-by"), None);
    assert!(response.ends_with("php-policy"));
}

struct WasmCacheStoreFailureResponse(String);

impl WasmCacheStoreFailureResponse {
    fn assert_service_unavailable(&self) {
        assert!(
            self.0.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
            "unexpected wasm cache-store failure response: {:?}",
            self.0
        );
        assert!(self.0.ends_with("wasm cache store trap\n"));
        assert_eq!(
            response_header(&self.0, "x-cache-status").as_deref(),
            Some("BYPASS")
        );
    }
}

async fn wasm_cache_store_failure_response(
    body: WasmPluginBody,
    path_suffix: &str,
) -> WasmCacheStoreFailureResponse {
    let fixture = WasmRouteFixture::new(&[("cache", body)]);
    let responses: &'static [(&'static str, &'static str)] = match path_suffix {
        "ttl" => &[("/static/store-ttl.png", "hidden")],
        "ttl-duplicate" => &[("/static/store-ttl-duplicate.png", "hidden")],
        "tag" => &[("/static/store-tag.png", "hidden")],
        "header-duplicate" => &[("/static/store-header-duplicate.png", "hidden")],
        _ => &[("/static/store-failure.png", "hidden")],
    };
    let path = responses[0].0;
    let upstream = super::upstream_cacheable_sequence(responses).await;
    let mut config = fixture.config_with_attachments(
        upstream,
        vec![wasm_attachment_phase(
            "cache",
            "route",
            100,
            fluxheim_config::WasmPluginPhase::CacheStore,
        )],
    );
    config.vhosts[0].routes[0].path_exact = None;
    config.vhosts[0].routes[0].path_prefix = Some("/".to_owned());
    config.vhosts[0].routes[0].redirect = None;
    config.vhosts[0].routes[0].proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    config.vhosts[0].routes[0].cache = Some(native_proxy_memory_cache_config());
    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;
    WasmCacheStoreFailureResponse(downstream_get(proxy, path).await)
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
    RouteDecision,
    CacheLookup,
    CacheLookupDeviceKey,
    CacheLookupForbiddenKey,
    CacheLookupDeny,
    CacheLookupBusy,
    CacheStoreSkip,
    CacheStoreDeny,
    CacheStoreShortTtl,
    CacheStoreForbiddenTtl,
    CacheStoreDuplicateTtl,
    CacheStoreForbiddenTag,
    CacheStoreHeader,
    CacheStoreForbiddenHeader,
    CacheStoreDuplicateHeader,
    CacheLookupPolicyExample,
    CacheStorePolicyExample,
    Trap,
    #[cfg(feature = "wasm-proxy-abi")]
    ProxyPreviewLogCall,
    WasiRandomGranted,
    WasiRandomDenied,
    WasiForbiddenFdWrite,
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
            Self::RouteDecision => {
                r#"
                (module
                  (import "fluxheim_policy_v1" "context" (func $context (param i32 i32) (result i32)))
                  (func (export "fluxheim_route_decision") (result i32)
                    i32.const 3
                    i32.const 0
                    call $context
                    i32.const 1
                    i32.eq
                    if (result i32)
                      i32.const 3
                    else
                      i32.const 2
                      i32.const 0
                      call $context
                      i32.const 1
                      i32.eq
                      if (result i32)
                        i32.const 1
                      else
                        i32.const 0
                      end
                    end))
                "#
                .to_owned()
            }
            Self::CacheLookup => {
                r#"
                (module
                  (import "fluxheim_policy_v1" "context" (func $context (param i32 i32) (result i32)))
                  (func (export "fluxheim_cache_lookup") (result i32)
                    i32.const 1
                    i32.const 0
                    call $context
                    i32.const 1
                    i32.eq
                    if (result i32)
                      i32.const 1
                    else
                      i32.const 0
                    end))
                "#
                .to_owned()
            }
            Self::CacheLookupDeny => {
                r#"(module (func (export "fluxheim_cache_lookup") (result i32) i32.const 3))"#
                    .to_owned()
            }
            Self::CacheLookupDeviceKey => {
                r#"
                (module
                  (import "fluxheim_policy_v1" "context" (func $context (param i32 i32) (result i32)))
                  (import "fluxheim_policy_v1" "set_cache_key_component" (func $set_cache_key_component (param i32 i32) (result i32)))
                  (func (export "fluxheim_cache_lookup") (result i32)
                    (local $device_class i32)
                    i32.const 5
                    i32.const 0
                    call $context
                    local.set $device_class
                    local.get $device_class
                    i32.const 0
                    i32.ne
                    if
                      i32.const 1
                      local.get $device_class
                      call $set_cache_key_component
                      drop
                    end
                    i32.const 0))
                "#
                .to_owned()
            }
            Self::CacheLookupForbiddenKey => {
                r#"
                (module
                  (import "fluxheim_policy_v1" "set_cache_key_component" (func $set_cache_key_component (param i32 i32) (result i32)))
                  (func (export "fluxheim_cache_lookup") (result i32)
                    i32.const 99
                    i32.const 99
                    call $set_cache_key_component
                    drop
                    i32.const 0))
                "#
                .to_owned()
            }
            Self::CacheLookupBusy => {
                r#"(module (func (export "fluxheim_cache_lookup") (result i32) (loop br 0) i32.const 0))"#
                    .to_owned()
            }
            Self::CacheStoreSkip => {
                r#"
                (module
                  (import "fluxheim_policy_v1" "context" (func $context (param i32 i32) (result i32)))
                  (func (export "fluxheim_cache_store") (result i32)
                    i32.const 4
                    i32.const 0
                    call $context
                    i32.const 200
                    i32.eq
                    if (result i32)
                      i32.const 1
                    else
                      i32.const 0
                    end))
                "#
                .to_owned()
            }
            Self::CacheStoreDeny => {
                r#"(module (func (export "fluxheim_cache_store") (result i32) i32.const 2))"#
                    .to_owned()
            }
            Self::CacheStoreShortTtl => {
                r#"
                (module
                  (import "fluxheim_policy_v1" "set_cache_ttl" (func $set_cache_ttl (param i32 i32) (result i32)))
                  (import "fluxheim_policy_v1" "add_cache_tag" (func $add_cache_tag (param i32 i32) (result i32)))
                  (func (export "fluxheim_cache_store") (result i32)
                    i32.const 1
                    i32.const 0
                    call $set_cache_ttl
                    drop
                    i32.const 1
                    i32.const 0
                    call $add_cache_tag
                    drop
                    i32.const 0))
                "#
                .to_owned()
            }
            Self::CacheStoreForbiddenTtl => {
                r#"
                (module
                  (import "fluxheim_policy_v1" "set_cache_ttl" (func $set_cache_ttl (param i32 i32) (result i32)))
                  (func (export "fluxheim_cache_store") (result i32)
                    i32.const 99
                    i32.const 0
                    call $set_cache_ttl
                    drop
                    i32.const 0))
                "#
                .to_owned()
            }
            Self::CacheStoreDuplicateTtl => {
                r#"
                (module
                  (import "fluxheim_policy_v1" "set_cache_ttl" (func $set_cache_ttl (param i32 i32) (result i32)))
                  (func (export "fluxheim_cache_store") (result i32)
                    i32.const 1
                    i32.const 0
                    call $set_cache_ttl
                    drop
                    i32.const 2
                    i32.const 0
                    call $set_cache_ttl
                    drop
                    i32.const 0))
                "#
                .to_owned()
            }
            Self::CacheStoreForbiddenTag => {
                r#"
                (module
                  (import "fluxheim_policy_v1" "add_cache_tag" (func $add_cache_tag (param i32 i32) (result i32)))
                  (func (export "fluxheim_cache_store") (result i32)
                    i32.const 99
                    i32.const 0
                    call $add_cache_tag
                    drop
                    i32.const 0))
                "#
                .to_owned()
            }
            Self::CacheStoreHeader => {
                r#"
                (module
                  (import "fluxheim_policy_v1" "set_cache_store_header" (func $set_cache_store_header (param i32 i32) (result i32)))
                  (func (export "fluxheim_cache_store") (result i32)
                    i32.const 1
                    i32.const 1
                    call $set_cache_store_header
                    drop
                    i32.const 0))
                "#
                .to_owned()
            }
            Self::CacheStoreForbiddenHeader => {
                r#"
                (module
                  (import "fluxheim_policy_v1" "set_cache_store_header" (func $set_cache_store_header (param i32 i32) (result i32)))
                  (func (export "fluxheim_cache_store") (result i32)
                    i32.const 99
                    i32.const 99
                    call $set_cache_store_header
                    drop
                    i32.const 0))
                "#
                .to_owned()
            }
            Self::CacheStoreDuplicateHeader => {
                r#"
                (module
                  (import "fluxheim_policy_v1" "set_cache_store_header" (func $set_cache_store_header (param i32 i32) (result i32)))
                  (func (export "fluxheim_cache_store") (result i32)
                    i32.const 1
                    i32.const 1
                    call $set_cache_store_header
                    drop
                    i32.const 1
                    i32.const 2
                    call $set_cache_store_header
                    drop
                    i32.const 0))
                "#
                .to_owned()
            }
            Self::CacheLookupPolicyExample => {
                include_str!("../../../../examples/wasm/cache-lookup-policy.wat").to_owned()
            }
            Self::CacheStorePolicyExample => {
                include_str!("../../../../examples/wasm/cache-store-policy.wat").to_owned()
            }
            Self::Trap => {
                r#"(module (func (export "fluxheim_access_decision") (result i32) unreachable))"#
                    .to_owned()
            }
            #[cfg(feature = "wasm-proxy-abi")]
            Self::ProxyPreviewLogCall => {
                r#"
                (module
                  (import "env" "proxy_log" (func $proxy_log (param i32 i32 i32) (result i32)))
                  (func (export "fluxheim_access_decision") (result i32)
                    i32.const 1
                    i32.const 0
                    i32.const 0
                    call $proxy_log
                    drop
                    i32.const 1))
                "#
                .to_owned()
            }
            Self::WasiRandomGranted | Self::WasiRandomDenied => {
                r#"
                (module
                  (import "wasi_snapshot_preview1" "random_get"
                    (func $random_get (param i32 i32) (result i32)))
                  (memory (export "memory") 1)
                  (func (export "fluxheim_access_decision") (result i32)
                    i32.const 0
                    i32.const 16
                    call $random_get))
                "#
                .to_owned()
            }
            Self::WasiForbiddenFdWrite => {
                r#"
                (module
                  (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                  (memory (export "memory") 1)
                  (func (export "fluxheim_access_decision") (result i32)
                    i32.const 1
                    i32.const 0
                    i32.const 0
                    i32.const 0
                    call $fd_write))
                "#
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
    let limits = if matches!(
        body,
        WasmPluginBody::BusyLoop | WasmPluginBody::CacheLookupBusy
    ) {
        Some(fluxheim_config::WasmSandboxLimitsConfig {
            fuel: fluxheim_config::config_wasm::MAX_WASM_FUEL,
            timeout_ms: 50,
            compile_timeout_ms: 5_000,
            ..Default::default()
        })
    } else {
        Some(fluxheim_config::WasmSandboxLimitsConfig {
            timeout_ms: 500,
            compile_timeout_ms: 5_000,
            ..Default::default()
        })
    };
    #[cfg(feature = "wasm-proxy-abi")]
    let proxy_preview = matches!(body, WasmPluginBody::ProxyPreviewLogCall);
    #[cfg(not(feature = "wasm-proxy-abi"))]
    let proxy_preview = false;
    let wasi_preview = matches!(
        body,
        WasmPluginBody::WasiRandomGranted
            | WasmPluginBody::WasiRandomDenied
            | WasmPluginBody::WasiForbiddenFdWrite
    );
    fluxheim_config::WasmPluginConfig {
        name: name.to_owned(),
        path,
        sha256: Some(sha256_hex(&bytes)),
        abi: if proxy_preview {
            fluxheim_config::WasmPluginAbi::ProxyWasmPreview
        } else if wasi_preview {
            fluxheim_config::WasmPluginAbi::WasiPreview
        } else {
            fluxheim_config::WasmPluginAbi::FluxheimPolicyV1
        },
        host_call_namespace: if proxy_preview {
            fluxheim_config::WasmHostCallNamespace::ProxyWasmPreview
        } else if wasi_preview {
            fluxheim_config::WasmHostCallNamespace::WasiPreview
        } else {
            fluxheim_config::WasmHostCallNamespace::FluxheimPolicyV1
        },
        wasi: fluxheim_config::WasmWasiCapabilitiesConfig {
            clocks: matches!(body, WasmPluginBody::WasiForbiddenFdWrite),
            randomness: matches!(
                body,
                WasmPluginBody::WasiRandomGranted | WasmPluginBody::WasiForbiddenFdWrite
            ),
        },
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
        WasmPluginBody::RouteDecision => vec![fluxheim_config::WasmPluginPhase::RouteDecision],
        WasmPluginBody::CacheLookup
        | WasmPluginBody::CacheLookupDeviceKey
        | WasmPluginBody::CacheLookupForbiddenKey
        | WasmPluginBody::CacheLookupDeny
        | WasmPluginBody::CacheLookupBusy => {
            vec![fluxheim_config::WasmPluginPhase::CacheLookup]
        }
        WasmPluginBody::CacheStoreSkip
        | WasmPluginBody::CacheStoreDeny
        | WasmPluginBody::CacheStoreShortTtl
        | WasmPluginBody::CacheStoreForbiddenTtl
        | WasmPluginBody::CacheStoreDuplicateTtl
        | WasmPluginBody::CacheStoreForbiddenTag
        | WasmPluginBody::CacheStoreHeader
        | WasmPluginBody::CacheStoreForbiddenHeader
        | WasmPluginBody::CacheStoreDuplicateHeader => {
            vec![fluxheim_config::WasmPluginPhase::CacheStore]
        }
        WasmPluginBody::CacheLookupPolicyExample => {
            vec![fluxheim_config::WasmPluginPhase::CacheLookup]
        }
        WasmPluginBody::CacheStorePolicyExample => {
            vec![fluxheim_config::WasmPluginPhase::CacheStore]
        }
        WasmPluginBody::Decision(_)
        | WasmPluginBody::Trap
        | WasmPluginBody::WasiRandomGranted
        | WasmPluginBody::WasiRandomDenied
        | WasmPluginBody::WasiForbiddenFdWrite
        | WasmPluginBody::BusyLoop => vec![fluxheim_config::WasmPluginPhase::AccessDecision],
        #[cfg(feature = "wasm-proxy-abi")]
        WasmPluginBody::ProxyPreviewLogCall => {
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

#[cfg(feature = "php-fpm")]
fn wasm_vhost_attachment_all(plugin: &str, priority: u32) -> fluxheim_config::WasmAttachmentConfig {
    fluxheim_config::WasmAttachmentConfig {
        plugin: plugin.to_owned(),
        vhost: "route.test".to_owned(),
        route: None,
        phases: vec![
            fluxheim_config::WasmPluginPhase::RequestHeaders,
            fluxheim_config::WasmPluginPhase::ResponseHeaders,
        ],
        priority,
        admission: None,
    }
}

fn wasm_vhost_attachment_phase(
    plugin: &str,
    priority: u32,
    phase: fluxheim_config::WasmPluginPhase,
) -> fluxheim_config::WasmAttachmentConfig {
    fluxheim_config::WasmAttachmentConfig {
        plugin: plugin.to_owned(),
        vhost: "route.test".to_owned(),
        route: None,
        phases: vec![phase],
        priority,
        admission: None,
    }
}

fn wasm_vhost_attachment_all_phases(
    plugin: &str,
    priority: u32,
    phases: &[fluxheim_config::WasmPluginPhase],
) -> fluxheim_config::WasmAttachmentConfig {
    fluxheim_config::WasmAttachmentConfig {
        plugin: plugin.to_owned(),
        vhost: "route.test".to_owned(),
        route: None,
        phases: phases.to_vec(),
        priority,
        admission: None,
    }
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

fn named_proxy_route(
    name: &str,
    prefix: &str,
    upstream: std::net::SocketAddr,
) -> fluxheim_config::RouteConfig {
    let mut route = native_route_proxy_test_route();
    route.name = name.to_owned();
    route.path_exact = None;
    route.path_prefix = Some(prefix.to_owned());
    route.redirect = None;
    route.proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    route
}

#[cfg(feature = "load-balancer")]
fn named_load_balanced_route(
    name: &str,
    prefix: &str,
    upstreams: &[std::net::SocketAddr],
) -> fluxheim_config::RouteConfig {
    let mut route = native_route_proxy_test_route();
    route.name = name.to_owned();
    route.path_exact = None;
    route.path_prefix = Some(prefix.to_owned());
    route.redirect = None;
    route.proxy = Some(fluxheim_config::ProxyConfig {
        upstreams: upstreams
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        load_balance: fluxheim_config::LoadBalanceConfig {
            health_check: fluxheim_config::LoadBalanceHealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    });
    route
}

#[cfg(feature = "load-balancer")]
fn named_persistent_load_balanced_route(
    name: &str,
    prefix: &str,
    upstreams: &[std::net::SocketAddr],
) -> fluxheim_config::RouteConfig {
    let mut route = named_load_balanced_route(name, prefix, upstreams);
    if let Some(proxy) = route.proxy.as_mut() {
        proxy.load_balance.persistence = fluxheim_config::LoadBalancePersistenceConfig {
            enabled: true,
            mode: fluxheim_config::LoadBalancePersistenceMode::ManagedCookie,
            cookie: Some("fluxheim_wasm_lb".to_owned()),
            ttl_secs: 60,
            managed_cookie_path: Some("/".to_owned()),
            managed_cookie_max_age_secs: Some(60),
            ..Default::default()
        };
    }
    route
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
fn named_proxy_route_with_mirror(
    name: &str,
    prefix: &str,
    upstream: std::net::SocketAddr,
    mirror: std::net::SocketAddr,
) -> fluxheim_config::RouteConfig {
    let mut route = named_proxy_route(name, prefix, upstream);
    if let Some(proxy) = route.proxy.as_mut() {
        proxy.mirror = fluxheim_config::TrafficMirrorConfig {
            enabled: true,
            base_url: Some(format!("http://{mirror}/copy")),
            sample_per_mille: 1000,
            methods: vec!["GET".to_owned()],
            timeout_secs: 2,
            max_response_bytes: fluxheim_config::ByteSize::from_bytes(1024),
            max_in_flight: 1,
            ..Default::default()
        };
    }
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

async fn upstream_expect_policy_header(expected_path: &'static str) -> std::net::SocketAddr {
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
            request.starts_with(&format!("GET {expected_path} HTTP/1.1\r\n")),
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

async fn upstream_expect_policy_header_cacheable_sequence(
    responses: &'static [(&'static str, &'static str)],
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for (expected_path, body) in responses {
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
                request.starts_with(&format!("GET {expected_path} HTTP/1.1\r\n")),
                "unexpected upstream request: {request:?}"
            );
            assert!(
                request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("x-policy-tier: gold")),
                "missing wasm policy header in upstream request: {request:?}"
            );
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\nx-powered-by: origin\r\ncontent-length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
    });
    addr
}

async fn upstream_expect_body(
    expected_path: &'static str,
    body: &'static str,
) -> std::net::SocketAddr {
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
            request.starts_with(&format!("GET {expected_path} HTTP/1.1\r\n")),
            "unexpected upstream request: {request:?}"
        );
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

#[cfg(feature = "load-balancer")]
async fn upstream_body_loop(body: &'static str, responses: usize) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
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
    addr
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
async fn mirror_endpoint() -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
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
        let _ = tx.send(String::from_utf8(request).unwrap());
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    (addr, rx)
}

#[cfg(feature = "php-fpm")]
async fn fastcgi_responder(stdout: &'static [u8]) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request_id = 1_u16;
        let mut params_done = false;
        let mut stdin_done = false;
        while !(params_done && stdin_done) {
            let (record_type, id, content) = read_fastcgi_record(&mut stream).await;
            request_id = id;
            match record_type {
                4 if content.is_empty() => params_done = true,
                5 if content.is_empty() => stdin_done = true,
                _ => {}
            }
        }
        write_fastcgi_record(&mut stream, 6, request_id, stdout)
            .await
            .unwrap();
        write_fastcgi_record(&mut stream, 6, request_id, b"")
            .await
            .unwrap();
        write_fastcgi_record(&mut stream, 3, request_id, &[0, 0, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    addr
}

#[cfg(feature = "php-fpm")]
async fn read_fastcgi_record(stream: &mut tokio::net::TcpStream) -> (u8, u16, Vec<u8>) {
    let mut header = [0_u8; 8];
    stream.read_exact(&mut header).await.unwrap();
    let record_type = header[1];
    let request_id = u16::from_be_bytes([header[2], header[3]]);
    let content_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    let padding_len = header[6] as usize;
    let mut content = vec![0_u8; content_len];
    if content_len > 0 {
        stream.read_exact(&mut content).await.unwrap();
    }
    if padding_len > 0 {
        let mut padding = vec![0_u8; padding_len];
        stream.read_exact(&mut padding).await.unwrap();
    }
    (record_type, request_id, content)
}

#[cfg(feature = "php-fpm")]
async fn write_fastcgi_record(
    stream: &mut tokio::net::TcpStream,
    record_type: u8,
    request_id: u16,
    content: &[u8],
) -> std::io::Result<()> {
    let len = u16::try_from(content.len()).unwrap();
    let mut header = [0_u8; 8];
    header[0] = 1;
    header[1] = record_type;
    header[2..4].copy_from_slice(&request_id.to_be_bytes());
    header[4..6].copy_from_slice(&len.to_be_bytes());
    stream.write_all(&header).await?;
    stream.write_all(content).await
}
