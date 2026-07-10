#[cfg(not(feature = "privacy-mode"))]
use crate::ProxyProtocolTrustedSource;
use crate::{
    DownstreamHttp1Policy, NativeHttp1GeoContext, NativeHttp1Handler, NativeHttp1RouteProxy,
    NativeHttp1RouteProxyRoute, NativeHttp1TlsClientIdentity,
};

use super::{
    downstream_get, proxy_for, route_proxy_listener, route_test_request, upstream_expect_path,
};
#[cfg(not(feature = "privacy-mode"))]
use super::{downstream_request, response_header};

#[tokio::test]
async fn native_route_proxy_vhost_access_denies_before_redirect() {
    let vhost = fluxheim_config::VhostConfig {
        name: "route.test".to_owned(),
        hosts: vec!["route.test".to_owned()],
        max_request_body_bytes: None,
        access: fluxheim_config::AccessPolicyConfig {
            deny: vec!["127.0.0.1".to_owned()],
            ..Default::default()
        },
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: Default::default(),
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
    let route_proxy = NativeHttp1RouteProxy::from_vhost_config(
        &vhost,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = route_proxy_listener(route_proxy).await;

    let response = downstream_get(proxy, "/blocked").await;

    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response.ends_with("forbidden\n"));
}

#[tokio::test]
async fn native_route_proxy_route_access_denies_before_route_action() {
    let route = fluxheim_config::RouteConfig {
        name: "admin".to_owned(),
        path_exact: Some("/admin".to_owned()),
        path_prefix: None,
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: fluxheim_config::AccessPolicyConfig {
            deny: vec!["127.0.0.1".to_owned()],
            ..Default::default()
        },
        rate_limit: Default::default(),
        concurrency: Default::default(),
        grpc: Default::default(),
        redirect: Some(fluxheim_config::RouteRedirectConfig {
            to: "https://target.example/admin".to_owned(),
            status: 302,
        }),
        proxy: None,
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: Default::default(),
    };
    let route = NativeHttp1RouteProxyRoute::from_config(&route, None).unwrap();
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/admin").await;

    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response.ends_with("forbidden\n"));
}

#[tokio::test]
async fn native_route_proxy_route_access_checks_decoded_policy_path() {
    let protected = fluxheim_config::RouteConfig {
        name: "admin".to_owned(),
        path_exact: Some("/admin".to_owned()),
        path_prefix: None,
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: fluxheim_config::AccessPolicyConfig {
            deny: vec!["127.0.0.1".to_owned()],
            ..Default::default()
        },
        rate_limit: Default::default(),
        concurrency: Default::default(),
        grpc: Default::default(),
        redirect: Some(fluxheim_config::RouteRedirectConfig {
            to: "https://target.example/admin".to_owned(),
            status: 302,
        }),
        proxy: None,
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: Default::default(),
    };
    let fallback = fluxheim_config::RouteConfig {
        name: "fallback".to_owned(),
        path_exact: None,
        path_prefix: None,
        path_regex: None,
        methods: Vec::new(),
        fallback: true,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        grpc: Default::default(),
        redirect: Some(fluxheim_config::RouteRedirectConfig {
            to: "https://target.example/fallback".to_owned(),
            status: 302,
        }),
        proxy: None,
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: Default::default(),
    };
    let protected = NativeHttp1RouteProxyRoute::from_config(&protected, None).unwrap();
    let fallback = NativeHttp1RouteProxyRoute::from_config(&fallback, None).unwrap();
    let proxy =
        route_proxy_listener(NativeHttp1RouteProxy::new(vec![protected, fallback], None)).await;

    let response = downstream_get(proxy, "/%61dmin").await;

    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response.ends_with("forbidden\n"));
}

#[cfg(not(feature = "privacy-mode"))]
#[tokio::test]
async fn native_route_proxy_vhost_access_uses_trusted_forwarded_chain() {
    let vhost = fluxheim_config::VhostConfig {
        name: "route.test".to_owned(),
        hosts: vec!["route.test".to_owned()],
        max_request_body_bytes: None,
        access: fluxheim_config::AccessPolicyConfig {
            allow: vec!["203.0.113.5".to_owned()],
            ..Default::default()
        },
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: Default::default(),
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
    let route_proxy = NativeHttp1RouteProxy::from_vhost_config_with_trusted_sources(
        &vhost,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
        &[ProxyProtocolTrustedSource::Ip("127.0.0.1".parse().unwrap())],
    )
    .unwrap();
    let proxy = route_proxy_listener(route_proxy).await;

    let allowed = downstream_request(
        proxy,
        "GET /trusted HTTP/1.1\r\n\
         Host: route.test\r\n\
         X-Forwarded-For: 203.0.113.5\r\n\
         Connection: close\r\n\r\n",
    )
    .await;
    let denied = downstream_request(
        proxy,
        "GET /trusted HTTP/1.1\r\n\
         Host: route.test\r\n\
         X-Forwarded-For: 203.0.113.6\r\n\
         Connection: close\r\n\r\n",
    )
    .await;
    let duplicate_header_denied = downstream_request(
        proxy,
        "GET /trusted HTTP/1.1\r\n\
         Host: route.test\r\n\
         X-Forwarded-For: 203.0.113.5\r\n\
         X-Forwarded-For: 203.0.113.6\r\n\
         Connection: close\r\n\r\n",
    )
    .await;
    let duplicate_header_allowed = downstream_request(
        proxy,
        "GET /trusted HTTP/1.1\r\n\
         Host: route.test\r\n\
         X-Forwarded-For: 203.0.113.6\r\n\
         X-Forwarded-For: 203.0.113.5\r\n\
         Connection: close\r\n\r\n",
    )
    .await;

    assert!(allowed.starts_with("HTTP/1.1 308 Permanent Redirect\r\n"));
    assert_eq!(
        response_header(&allowed, "location").as_deref(),
        Some("https://target.example/trusted")
    );
    assert!(denied.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(duplicate_header_denied.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(duplicate_header_allowed.starts_with("HTTP/1.1 308 Permanent Redirect\r\n"));
}

#[tokio::test]
async fn native_route_proxy_access_policy_checks_tls_client_identity() {
    let allowed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let denied = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let upstream = upstream_expect_path("/mtls", "mtls-ok").await;
    let route_config = fluxheim_config::RouteConfig {
        name: "mtls".to_owned(),
        path_prefix: Some("/mtls".to_owned()),
        path_exact: None,
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: fluxheim_config::AccessPolicyConfig {
            require_client_cert: true,
            allow_client_cert_sha256: vec![allowed.to_owned()],
            deny_client_cert_sha256: vec![denied.to_owned()],
            ..Default::default()
        },
        rate_limit: Default::default(),
        concurrency: Default::default(),
        grpc: Default::default(),
        redirect: None,
        proxy: Some(fluxheim_config::ProxyConfig {
            upstreams: vec![upstream.to_string()],
            ..Default::default()
        }),
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: Default::default(),
    };
    let route =
        NativeHttp1RouteProxyRoute::from_config(&route_config, Some(proxy_for(upstream))).unwrap();
    let proxy = NativeHttp1RouteProxy::new(vec![route], None);

    let mut allowed_request = route_test_request("/mtls");
    allowed_request.tls_identity = Some(NativeHttp1TlsClientIdentity {
        cert_sha256: Some(allowed.to_ascii_uppercase()),
        ..Default::default()
    });
    let mut denied_request = route_test_request("/mtls");
    denied_request.tls_identity = Some(NativeHttp1TlsClientIdentity {
        cert_sha256: Some(denied.to_owned()),
        ..Default::default()
    });
    let mut unknown_request = route_test_request("/mtls");
    unknown_request.tls_identity = Some(NativeHttp1TlsClientIdentity {
        cert_sha256: Some(
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
        ),
        ..Default::default()
    });

    let allowed_response = proxy.handle(allowed_request).await;
    let denied_response = proxy.handle(denied_request).await;
    let unknown_response = proxy.handle(unknown_request).await;
    let missing_response = proxy.handle(route_test_request("/mtls")).await;

    assert_eq!(allowed_response.status(), 200);
    assert_eq!(allowed_response.body(), b"mtls-ok");
    assert_eq!(denied_response.status(), 403);
    assert_eq!(unknown_response.status(), 403);
    assert_eq!(missing_response.status(), 403);
}

#[tokio::test]
async fn native_route_proxy_access_policy_checks_geo_context() {
    let upstream = upstream_expect_path("/geo", "geo-ok").await;
    let route_config = fluxheim_config::RouteConfig {
        name: "geo".to_owned(),
        path_prefix: Some("/geo".to_owned()),
        path_exact: None,
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: fluxheim_config::AccessPolicyConfig {
            allow_countries: vec!["SE".to_owned()],
            deny_asns: vec![64512],
            ..Default::default()
        },
        rate_limit: Default::default(),
        concurrency: Default::default(),
        grpc: Default::default(),
        redirect: None,
        proxy: Some(fluxheim_config::ProxyConfig {
            upstreams: vec![upstream.to_string()],
            ..Default::default()
        }),
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: Default::default(),
    };
    let route =
        NativeHttp1RouteProxyRoute::from_config(&route_config, Some(proxy_for(upstream))).unwrap();
    let proxy = NativeHttp1RouteProxy::new(vec![route], None);

    let mut allowed_request = route_test_request("/geo");
    allowed_request.geo_context = Some(NativeHttp1GeoContext {
        country_iso: Some("se".to_owned()),
        asn: Some(12552),
    });
    let mut denied_country_request = route_test_request("/geo");
    denied_country_request.geo_context = Some(NativeHttp1GeoContext {
        country_iso: Some("NO".to_owned()),
        asn: Some(12552),
    });
    let mut denied_asn_request = route_test_request("/geo");
    denied_asn_request.geo_context = Some(NativeHttp1GeoContext {
        country_iso: Some("SE".to_owned()),
        asn: Some(64512),
    });

    let allowed_response = proxy.handle(allowed_request).await;
    let denied_country_response = proxy.handle(denied_country_request).await;
    let denied_asn_response = proxy.handle(denied_asn_request).await;
    let missing_response = proxy.handle(route_test_request("/geo")).await;

    assert_eq!(allowed_response.status(), 200);
    assert_eq!(allowed_response.body(), b"geo-ok");
    assert_eq!(denied_country_response.status(), 403);
    assert_eq!(denied_asn_response.status(), 403);
    assert_eq!(missing_response.status(), 403);
}
