use tempfile::TempDir;

use crate::{DownstreamHttp1Policy, NativeHttp1HostRouter, NativeHttp1HostRouterConfigError};

fn storage_bin_cache(path: &std::path::Path) -> fluxheim_config::CacheConfig {
    let mut cache = fluxheim_config::CacheConfig {
        enabled: true,
        ..Default::default()
    };
    cache.disk.enabled = true;
    cache.disk.backend = fluxheim_config::CacheDiskBackend::StorageBin;
    cache.disk.path = Some(path.to_path_buf());
    cache
}

fn vhost(name: &str, upstream: std::net::SocketAddr) -> fluxheim_config::VhostConfig {
    let mut proxy = fluxheim_config::ProxyConfig::disabled();
    proxy.upstream = Some(upstream.to_string());
    fluxheim_config::VhostConfig {
        name: name.to_owned(),
        hosts: vec![format!("{name}.test")],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: Default::default(),
        acme_challenge: Default::default(),
        redirect: Default::default(),
        proxy,
        cache: Default::default(),
        compression: None,
        headers: Default::default(),
        php: Default::default(),
        web: Default::default(),
        routes: Vec::new(),
    }
}

fn cached_proxy_route(
    name: &str,
    path: &str,
    upstream: std::net::SocketAddr,
    cache_root: &std::path::Path,
) -> fluxheim_config::RouteConfig {
    let mut proxy = fluxheim_config::ProxyConfig::disabled();
    proxy.upstream = Some(upstream.to_string());
    fluxheim_config::RouteConfig {
        name: name.to_owned(),
        path_exact: Some(path.to_owned()),
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
        redirect: None,
        proxy: Some(proxy),
        web: None,
        php: None,
        cache: Some(storage_bin_cache(cache_root)),
        compression: None,
        headers: Default::default(),
    }
}

#[test]
fn native_host_router_rejects_duplicate_storage_bin_roots() {
    let root = TempDir::new().unwrap();
    let cache_root = root.path().join("shared-cache");
    let upstream = "127.0.0.1:3000".parse().unwrap();
    let mut first = vhost("first", upstream);
    first.cache = storage_bin_cache(&cache_root);
    let mut second = vhost("second", upstream);
    second.cache = storage_bin_cache(&cache_root);
    let config = fluxheim_config::Config {
        vhosts: vec![first, second],
        ..Default::default()
    };

    assert!(matches!(
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0),
        Err(NativeHttp1HostRouterConfigError::DuplicateStorageBinRoot { .. })
    ));
}

#[test]
fn native_host_router_rejects_duplicate_route_storage_bin_roots() {
    let root = TempDir::new().unwrap();
    let cache_root = root.path().join("shared-route-cache");
    let upstream = "127.0.0.1:3000".parse().unwrap();
    let mut app = vhost("app", upstream);
    app.routes = vec![
        cached_proxy_route("first", "/first", upstream, &cache_root),
        cached_proxy_route("second", "/second", upstream, &cache_root),
    ];
    let config = fluxheim_config::Config {
        vhosts: vec![app],
        ..Default::default()
    };

    assert!(matches!(
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0),
        Err(NativeHttp1HostRouterConfigError::DuplicateStorageBinRoot { .. })
    ));
}
