use crate::{DownstreamHttp1Policy, NativeHttp1RouteProxy};

#[cfg(feature = "acme")]
use crate::NativeHttp1AcmeHttp01Store;

#[cfg(feature = "acme")]
use super::downstream_request;
use super::{downstream_get, response_header, route_proxy_listener, upstream_expect_path};

#[tokio::test]
async fn native_route_proxy_builds_vhost_acme_and_redirect_routes_from_config() {
    let acme_upstream =
        upstream_expect_path("/.well-known/acme-challenge/token", "acme-route").await;
    let vhost = fluxheim_config::VhostConfig {
        name: "route.test".to_owned(),
        hosts: vec!["route.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: Default::default(),
        acme_challenge: fluxheim_config::VhostAcmeChallengeConfig {
            enabled: true,
            upstream: Some(acme_upstream.to_string()),
            ..Default::default()
        },
        redirect: fluxheim_config::VhostRedirectConfig {
            enabled: true,
            to: Some("https://target.example{uri}".to_owned()),
            status: 308,
        },
        proxy: Default::default(),
        cache: Default::default(),
        compression: None,
        headers: Default::default(),
        php: Default::default(),
        web: Default::default(),
        routes: Vec::new(),
    };
    let route_proxy = NativeHttp1RouteProxy::from_vhost_config(
        &vhost,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = route_proxy_listener(route_proxy).await;

    let acme_response = downstream_get(proxy, "/.well-known/acme-challenge/token").await;
    let redirect_response = downstream_get(proxy, "/docs?x=1").await;

    assert!(acme_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(acme_response.ends_with("acme-route"));
    assert!(redirect_response.starts_with("HTTP/1.1 308 Permanent Redirect\r\n"));
    assert_eq!(
        response_header(&redirect_response, "location").as_deref(),
        Some("https://target.example/docs?x=1")
    );
}

#[cfg(feature = "acme")]
#[tokio::test]
async fn native_route_proxy_serves_managed_acme_http_01_locally() {
    let storage = tempfile::tempdir().unwrap();
    let store = NativeHttp1AcmeHttp01Store::new(storage.path(), "route.test");
    std::fs::create_dir_all(store.root_for_tests()).unwrap();
    std::fs::write(
        store.root_for_tests().join("token_123"),
        b"token.key.authorization\n",
    )
    .unwrap();

    let mut config = fluxheim_config::Config::default();
    config.tls.acme.enabled = true;
    config.tls.acme.storage = Some(storage.path().to_path_buf());
    let vhost = fluxheim_config::VhostConfig {
        name: "route.test".to_owned(),
        hosts: vec!["route.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: fluxheim_config::VhostTlsConfig {
            enabled: true,
            acme: fluxheim_config::VhostAcmeConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        },
        acme_challenge: Default::default(),
        redirect: fluxheim_config::VhostRedirectConfig {
            enabled: true,
            to: Some("https://target.example{uri}".to_owned()),
            status: 308,
        },
        proxy: Default::default(),
        cache: Default::default(),
        compression: None,
        headers: Default::default(),
        php: Default::default(),
        web: Default::default(),
        routes: Vec::new(),
    };
    config.vhosts = vec![vhost.clone()];
    let route_proxy = NativeHttp1RouteProxy::from_config(
        &config,
        &vhost,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = route_proxy_listener(route_proxy).await;

    let response = downstream_get(proxy, "/.well-known/acme-challenge/token_123").await;
    let head_response = downstream_request(
        proxy,
        "HEAD /.well-known/acme-challenge/token_123 HTTP/1.1\r\nHost: route.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    let post_response = downstream_request(
        proxy,
        "POST /.well-known/acme-challenge/token_123 HTTP/1.1\r\nHost: route.test\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&response, "content-type").as_deref(),
        Some("text/plain")
    );
    assert_eq!(
        response_header(&response, "cache-control").as_deref(),
        Some("no-store")
    );
    assert!(response.ends_with("token.key.authorization"));
    assert!(head_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&head_response, "content-length").as_deref(),
        Some("23")
    );
    assert!(head_response.ends_with("\r\n\r\n"));
    assert!(post_response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
    assert_eq!(
        response_header(&post_response, "allow").as_deref(),
        Some("GET, HEAD")
    );
}

#[cfg(feature = "acme")]
#[tokio::test]
async fn native_route_proxy_serves_managed_acme_http_01_for_alias_vhost() {
    let storage = tempfile::tempdir().unwrap();
    let store = NativeHttp1AcmeHttp01Store::new(storage.path(), "primary.test");
    std::fs::create_dir_all(store.root_for_tests()).unwrap();
    std::fs::write(
        store.root_for_tests().join("token_456"),
        b"alias.key.authorization\n",
    )
    .unwrap();

    let owner = fluxheim_config::VhostConfig {
        name: "primary.test".to_owned(),
        hosts: vec!["primary.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: fluxheim_config::VhostTlsConfig {
            enabled: true,
            acme: fluxheim_config::VhostAcmeConfig {
                enabled: true,
                domains: vec!["alias.test".to_owned()],
                ..Default::default()
            },
            ..Default::default()
        },
        acme_challenge: Default::default(),
        redirect: Default::default(),
        proxy: Default::default(),
        cache: Default::default(),
        compression: None,
        headers: Default::default(),
        php: Default::default(),
        web: Default::default(),
        routes: Vec::new(),
    };
    let alias = fluxheim_config::VhostConfig {
        name: "alias.test".to_owned(),
        hosts: vec!["alias.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: Default::default(),
        acme_challenge: Default::default(),
        redirect: fluxheim_config::VhostRedirectConfig {
            enabled: true,
            to: Some("https://primary.test{uri}".to_owned()),
            status: 308,
        },
        proxy: Default::default(),
        cache: Default::default(),
        compression: None,
        headers: Default::default(),
        php: Default::default(),
        web: Default::default(),
        routes: Vec::new(),
    };
    let mut config = fluxheim_config::Config::default();
    config.tls.acme.enabled = true;
    config.tls.acme.storage = Some(storage.path().to_path_buf());
    config.vhosts = vec![owner, alias.clone()];
    let route_proxy = NativeHttp1RouteProxy::from_config(
        &config,
        &alias,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = route_proxy_listener(route_proxy).await;

    let response = downstream_get(proxy, "/.well-known/acme-challenge/token_456").await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("alias.key.authorization"));
}
