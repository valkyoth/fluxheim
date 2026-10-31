use std::time::Duration;

use crate::native_http1_route_matcher::{NativeHttp1RouteMatcher, NativeRegexRouteMatcher};
use crate::{NativeHttp1RouteProxy, NativeHttp1RouteProxyRoute};

use super::{
    downstream_get, native_route_proxy_test_route, proxy_for, route_proxy_listener_with_shutdown,
    upstream_expect_path,
};

async fn shortened_target(pattern: &str, template: &str, path: &str) {
    let upstream = upstream_expect_path("/internal/?keep=1", "shortened").await;
    let mut config = native_route_proxy_test_route();
    config.path_exact = None;
    config.path_regex = Some(pattern.to_owned());
    config.rewrite_template = Some(template.to_owned());
    config.redirect = None;
    config.proxy = Some(fluxheim_config::ProxyConfig {
        upstream: None,
        upstreams: vec![upstream.to_string()],
        ..Default::default()
    });
    config.validate("route.test", true).unwrap();
    let route =
        NativeHttp1RouteProxyRoute::from_config(&config, Some(proxy_for(upstream))).unwrap();
    let (proxy, stop, task) =
        route_proxy_listener_with_shutdown(NativeHttp1RouteProxy::new(vec![route], None)).await;
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        downstream_get(proxy, &format!("{path}?keep=1")),
    )
    .await;
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
    let response = response.unwrap();
    // documented contract: unavailable captures silently disappear instead of rejecting.
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.ends_with("shortened"));
}

#[tokio::test]
async fn regex_rewrite_currently_accepts_missing_capture_name() {
    shortened_target(
        r"^/users/(?P<id>[a-z]+)$",
        "/internal/{route.regex.typo}",
        "/users/alice",
    )
    .await;
}

#[tokio::test]
async fn regex_rewrite_currently_drops_oversized_capture() {
    shortened_target(
        r"^/users/(?P<id>[a-z]+)$",
        "/internal/{route.regex.id}",
        &format!("/users/{}", "a".repeat(257)),
    )
    .await;
}

#[tokio::test]
async fn regex_rewrite_currently_drops_unmatched_optional_capture() {
    shortened_target(
        r"^/users/(?P<id>[a-z]+)?$",
        "/internal/{route.regex.id}",
        "/users/",
    )
    .await;
}

#[test]
fn regex_header_capture_collection_currently_disagrees_with_rewrite_bounds() {
    let matcher = NativeHttp1RouteMatcher::Regex(
        NativeRegexRouteMatcher::from_pattern(r"^/(?P<id>[a-z]+)$").unwrap(),
    );
    let path = format!("/{}", "a".repeat(257));
    assert!(matcher.capture_value(&path, "route.regex.id").is_none());
    let headers = matcher.header_captures(&path);
    assert!(
        headers
            .iter()
            .any(|(key, value)| key == "route.regex.id" && value.len() == 257)
    );
    assert!(!headers.iter().any(|(key, _)| key == "route.regex.0"));

    let pattern = format!("^/{}$", "(a)".repeat(17));
    fluxheim_config::config_route::validate_route_regex(&pattern).unwrap();
    let matcher =
        NativeHttp1RouteMatcher::Regex(NativeRegexRouteMatcher::from_pattern(&pattern).unwrap());
    let headers = matcher.header_captures(&format!("/{}", "a".repeat(17)));
    assert_eq!(headers.len(), 17);
    assert!(headers.iter().any(|(key, _)| key == "route.regex.16"));
}
