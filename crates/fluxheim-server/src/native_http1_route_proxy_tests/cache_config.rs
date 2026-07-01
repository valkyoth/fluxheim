use crate::{
    DownstreamHttp1Policy, NativeHttp1Proxy, NativeHttp1ProxyConfigError, NativeHttp1RouteProxy,
    NativeHttp1RouteProxyConfigError, NativeHttp1RouteProxyRoute, NativeHttp1Upstream,
};

use super::{
    native_proxy_memory_cache_config, native_route_proxy_test_route, native_route_proxy_test_vhost,
};

#[test]
fn native_route_proxy_builds_redirect_route_from_config_without_proxy() {
    let route = fluxheim_config::RouteConfig {
        name: "redirect".to_owned(),
        path_exact: Some("/old".to_owned()),
        path_prefix: None,
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
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
            to: "https://new.example{uri}".to_owned(),
            status: 308,
        }),
        proxy: None,
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: Default::default(),
    };

    let route = NativeHttp1RouteProxyRoute::from_config(&route, None).unwrap();

    assert!(route.is_redirect());
    assert!(route.proxy().is_none());
}

#[test]
fn native_route_proxy_rejects_vhost_cache_policy_until_native_adapter_exists() {
    let mut vhost = native_route_proxy_test_vhost();
    vhost.cache.enabled = true;

    let error = NativeHttp1RouteProxy::from_vhost_config(
        &vhost,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::CachePolicy)
    );
}

#[test]
fn native_route_proxy_accepts_vhost_memory_proxy_cache() {
    let mut vhost = native_route_proxy_test_vhost();
    vhost.proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    };
    vhost.cache = native_proxy_memory_cache_config();

    let proxy = NativeHttp1RouteProxy::from_vhost_config(
        &vhost,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();

    assert!(proxy.fallback().is_some());
}

#[test]
fn native_route_proxy_rejects_vhost_php_without_root() {
    let mut vhost = native_route_proxy_test_vhost();
    vhost.php.enabled = true;

    let error = NativeHttp1RouteProxy::from_vhost_config(
        &vhost,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::PhpFpm)
    );
}

#[test]
fn native_route_proxy_rejects_route_cache_policy_until_native_adapter_exists() {
    let mut route = native_route_proxy_test_route();
    route.cache = Some(fluxheim_config::CacheConfig {
        enabled: true,
        ..Default::default()
    });

    let error = NativeHttp1RouteProxyRoute::from_config(&route, None).unwrap_err();

    assert_eq!(
        error,
        NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::CachePolicy)
    );
}

#[test]
fn native_route_proxy_accepts_route_memory_proxy_cache() {
    let mut route = native_route_proxy_test_route();
    route.redirect = None;
    route.proxy = Some(fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    });
    route.cache = Some(native_proxy_memory_cache_config());

    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new("127.0.0.1:3000"));
    let route = NativeHttp1RouteProxyRoute::from_config(&route, Some(proxy)).unwrap();

    assert!(route.proxy().is_some());
}

#[test]
fn native_route_proxy_accepts_route_memory_proxy_cache_with_origin_protection() {
    let mut route = native_route_proxy_test_route();
    route.redirect = None;
    route.proxy = Some(fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    });
    let mut cache = native_proxy_memory_cache_config();
    cache.origin_protection.enabled = true;
    cache.origin_protection.max_concurrent_fills = 1;
    route.cache = Some(cache);

    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new("127.0.0.1:3000"));
    let route = NativeHttp1RouteProxyRoute::from_config(&route, Some(proxy)).unwrap();

    assert!(route.proxy().is_some());
}

#[test]
fn native_route_proxy_accepts_route_memory_proxy_cache_with_range_policy() {
    let mut route = native_route_proxy_test_route();
    route.redirect = None;
    route.proxy = Some(fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    });
    let mut cache = native_proxy_memory_cache_config();
    cache.range.enabled = true;
    route.cache = Some(cache);

    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new("127.0.0.1:3000"));
    let route = NativeHttp1RouteProxyRoute::from_config(&route, Some(proxy)).unwrap();

    assert!(route.proxy().is_some());
}

#[test]
fn native_route_proxy_accepts_route_memory_proxy_cache_with_predictor_policy() {
    let mut route = native_route_proxy_test_route();
    route.redirect = None;
    route.proxy = Some(fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    });
    let mut cache = native_proxy_memory_cache_config();
    cache.predictor.enabled = true;
    cache.min_uses = 2;
    cache.pass_uncacheable_after = 1;
    route.cache = Some(cache);

    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new("127.0.0.1:3000"));
    let route = NativeHttp1RouteProxyRoute::from_config(&route, Some(proxy)).unwrap();

    assert!(route.proxy().is_some());
}

#[test]
fn native_route_proxy_accepts_route_memory_proxy_cache_with_stale_while_revalidate() {
    let mut route = native_route_proxy_test_route();
    route.redirect = None;
    route.proxy = Some(fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    });
    let mut cache = native_proxy_memory_cache_config();
    cache.stale_while_revalidate_secs = Some(60);
    route.cache = Some(cache);

    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new("127.0.0.1:3000"));
    let route = NativeHttp1RouteProxyRoute::from_config(&route, Some(proxy)).unwrap();

    assert!(route.proxy().is_some());
}

#[test]
fn native_route_proxy_accepts_route_memory_proxy_cache_with_http_peer_fill() {
    let mut route = native_route_proxy_test_route();
    route.redirect = None;
    route.proxy = Some(fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    });
    let mut cache = native_proxy_memory_cache_config();
    cache.peer_fill.enabled = true;
    cache.peer_fill.allow_insecure_http = true;
    cache.peer_fill.peers = vec![fluxheim_config::CachePeerConfig {
        name: "local-peer".to_owned(),
        base_url: "http://127.0.0.1:3001".to_owned(),
    }];
    route.cache = Some(cache);

    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new("127.0.0.1:3000"));
    let route = NativeHttp1RouteProxyRoute::from_config(&route, Some(proxy)).unwrap();

    assert!(route.proxy().is_some());
}

#[test]
fn native_route_proxy_accepts_loopback_http_peer_fill_without_insecure_opt_in() {
    let mut route = native_route_proxy_test_route();
    route.redirect = None;
    route.proxy = Some(fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    });
    let mut cache = native_proxy_memory_cache_config();
    cache.peer_fill.enabled = true;
    cache.peer_fill.peers = vec![fluxheim_config::CachePeerConfig {
        name: "local-peer".to_owned(),
        base_url: "http://localhost:3001".to_owned(),
    }];
    route.cache = Some(cache);

    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new("127.0.0.1:3000"));
    let route = NativeHttp1RouteProxyRoute::from_config(&route, Some(proxy)).unwrap();

    assert!(route.proxy().is_some());
}

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
#[test]
fn native_route_proxy_accepts_route_memory_proxy_cache_with_https_peer_fill() {
    let mut route = native_route_proxy_test_route();
    route.redirect = None;
    route.proxy = Some(fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    });
    let mut cache = native_proxy_memory_cache_config();
    cache.peer_fill.enabled = true;
    cache.peer_fill.peers = vec![fluxheim_config::CachePeerConfig {
        name: "secure-peer".to_owned(),
        base_url: "https://localhost:3001".to_owned(),
    }];
    route.cache = Some(cache);

    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new("127.0.0.1:3000"));
    let route = NativeHttp1RouteProxyRoute::from_config(&route, Some(proxy)).unwrap();

    assert!(route.proxy().is_some());
}

#[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
#[test]
fn native_route_proxy_rejects_route_memory_proxy_cache_with_https_peer_fill_without_tls_backend() {
    let mut route = native_route_proxy_test_route();
    route.redirect = None;
    route.proxy = Some(fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    });
    let mut cache = native_proxy_memory_cache_config();
    cache.peer_fill.enabled = true;
    cache.peer_fill.peers = vec![fluxheim_config::CachePeerConfig {
        name: "secure-peer".to_owned(),
        base_url: "https://localhost:3001".to_owned(),
    }];
    route.cache = Some(cache);

    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new("127.0.0.1:3000"));
    let error = NativeHttp1RouteProxyRoute::from_config(&route, Some(proxy)).unwrap_err();

    assert_eq!(
        error,
        NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::CachePolicy)
    );
}
