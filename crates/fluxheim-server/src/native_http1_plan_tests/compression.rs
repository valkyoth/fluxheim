#[cfg(not(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
)))]
use crate::NativeHttp1ProxyConfigError;
use crate::ServerPlan;
use fluxheim_config::{CacheConfig, Config, RouteConfig, VhostConfig};

#[test]
fn server_plan_tracks_root_compression_native_feature_support() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.compression.enabled = true;

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    #[cfg(not(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    )))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::HttpPolicy)
    );
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
}

#[test]
fn server_plan_tracks_vhost_compression_native_feature_support() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "native.test".to_owned(),
            hosts: vec!["native.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: Default::default(),
            acme_challenge: Default::default(),
            redirect: Default::default(),
            proxy: fluxheim_config::ProxyConfig {
                upstreams: vec!["127.0.0.1:3001".to_owned()],
                ..Default::default()
            },
            cache: CacheConfig::default(),
            compression: Some(fluxheim_config::CompressionConfig {
                enabled: true,
                gzip: true,
                ..Default::default()
            }),
            headers: Default::default(),
            php: Default::default(),
            web: Default::default(),
            routes: Vec::new(),
        }],
        ..Default::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    #[cfg(not(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    )))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::HttpPolicy)
    );
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
}

#[test]
fn server_plan_tracks_route_compression_native_feature_support() {
    let config = route_compression_config();

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    #[cfg(not(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    )))]
    assert_eq!(
        plan.native_http1_proxy_candidates()[0].unsupported_reason(),
        Some(NativeHttp1ProxyConfigError::HttpPolicy)
    );
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    assert!(plan.native_http1_proxy_candidates()[0].is_eligible());
}

fn route_compression_config() -> Config {
    Config {
        vhosts: vec![VhostConfig {
            name: "native.test".to_owned(),
            hosts: vec!["native.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: Default::default(),
            acme_challenge: Default::default(),
            redirect: Default::default(),
            proxy: fluxheim_config::ProxyConfig::disabled(),
            cache: CacheConfig::default(),
            compression: None,
            headers: Default::default(),
            php: Default::default(),
            web: Default::default(),
            routes: vec![RouteConfig {
                name: "api".to_owned(),
                path_exact: None,
                path_prefix: Some("/api/".to_owned()),
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
                proxy: Some(fluxheim_config::ProxyConfig {
                    upstreams: vec!["127.0.0.1:3002".to_owned()],
                    ..Default::default()
                }),
                web: None,
                php: None,
                cache: None,
                compression: Some(fluxheim_config::CompressionConfig {
                    enabled: true,
                    gzip: true,
                    ..Default::default()
                }),
                headers: Default::default(),
            }],
        }],
        ..Default::default()
    }
}
