use crate::{NativeHttp1ProxyConfigError, NativeHttp1ProxyCutoverStatus, ServerPlan};
use fluxheim_config::Config;

use super::{native_proxy_route, native_proxy_vhost};

#[test]
fn server_plan_collects_native_http1_proxy_candidates() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert_eq!(plan.native_http1_proxy_candidates().len(), 1);
    assert_eq!(plan.native_http1_proxy_candidates()[0].scope(), "proxy");
    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
    let summary = plan.native_http1_proxy_cutover_summary();
    assert_eq!(summary.status(), NativeHttp1ProxyCutoverStatus::NativeReady);
    assert_eq!(summary.total(), 1);
    assert_eq!(summary.eligible(), 1);
    assert_eq!(summary.unsupported(), 0);

    config.proxy.upstream_tls = true;
    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::UpstreamTls)
    );
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::UpstreamTlsPolicy)
    );
}

#[test]
fn server_plan_accepts_root_response_header_policy_candidate() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config
        .headers
        .response
        .set
        .insert("x-root-response".to_owned(), "native".to_owned());
    config.headers.response.append.insert(
        "x-root-append".to_owned(),
        fluxheim_config::HeaderValues::Many(vec!["one".to_owned()]),
    );

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::NativeReady
    );
}

#[test]
fn server_plan_accepts_disabled_root_request_header_policy_candidate() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.headers.request.enabled = false;

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::NativeReady
    );
}

#[test]
fn server_plan_accepts_plain_upstream_http2_candidate() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.proxy.upstream_http_version = fluxheim_config::UpstreamHttpVersion::Http2;
    config.proxy.upstream_h2_max_streams = Some(64);

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::NativeReady
    );

    config.proxy.upstream_h2_ping_interval_secs = Some(30);
    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );

    config.proxy.upstream_h2_ping_interval_secs = None;
    config.proxy.upstream_http_version = fluxheim_config::UpstreamHttpVersion::Http1AndHttp2;
    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::UpstreamHttp2)
    );

    config.proxy.upstream_tls = true;
    config.proxy.upstream_sni = Some("localhost".to_owned());
    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::UpstreamHttp2)
    );
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
}

#[test]
fn server_plan_accepts_root_websocket_native_http1_proxy() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.proxy.websocket = true;

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::NativeReady
    );
}

#[test]
fn server_plan_accepts_vhost_websocket_native_http1_proxy() {
    let mut config = Config::default();
    let mut vhost = native_proxy_vhost();
    vhost.proxy.websocket = true;
    config.vhosts = vec![vhost];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::NativeReady
    );
}

#[test]
fn server_plan_accepts_route_websocket_native_http1_proxy() {
    let mut config = Config::default();
    let mut vhost = native_proxy_vhost();
    vhost.proxy = fluxheim_config::ProxyConfig::disabled();
    let mut route = native_proxy_route();
    route.proxy.as_mut().unwrap().websocket = true;
    vhost.routes = vec![route];
    config.vhosts = vec![vhost];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(plan.native_http1_proxy_candidates().len(), 1);
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].scope(),
        "vhost \"native.test\" route \"api\" proxy"
    );
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        None
    );
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::NativeReady
    );
}

#[test]
fn server_plan_rejects_websocket_http2_upstream_mode() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.proxy.websocket = true;
    config.proxy.upstream_http_version = fluxheim_config::UpstreamHttpVersion::Http2;

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::WebSocket)
    );
    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        NativeHttp1ProxyCutoverStatus::CompatibilityRequired
    );
}

#[test]
fn server_plan_tracks_auth_request_native_feature_support() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.proxy.auth_request = fluxheim_config::AuthRequestConfig {
        enabled: true,
        url: Some("http://127.0.0.1:3002/auth".to_owned()),
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    #[cfg(not(feature = "auth-request"))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::AuthRequest)
    );
    #[cfg(feature = "auth-request")]
    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
}

#[test]
fn server_plan_tracks_traffic_mirror_native_feature_support() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.proxy.mirror = fluxheim_config::TrafficMirrorConfig {
        enabled: true,
        base_url: Some("http://127.0.0.1:3002/shadow".to_owned()),
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    #[cfg(not(all(feature = "traffic-mirror", not(feature = "privacy-mode"))))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::TrafficMirror)
    );
    #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
}
