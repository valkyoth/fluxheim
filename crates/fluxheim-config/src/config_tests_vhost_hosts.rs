use super::*;
use crate::{GeoIpConfig, StreamConfig, TlsConfig, UdpConfig, VhostTlsConfig};

#[test]
fn rejects_duplicate_vhost_hosts() {
    let config = Config {
        server: ServerConfig::default(),
        admin: AdminConfig::default(),
        metrics: MetricsConfig::default(),
        tracing: TracingConfig::default(),
        logging: LoggingConfig::default(),
        headers: HeaderPolicyConfig::default(),
        tls: TlsConfig::default(),
        proxy: ProxyConfig::default(),
        compression: CompressionConfig::default(),
        cache: CacheConfig::default(),
        cache_purger: CachePurgerConfig::default(),
        web: WebConfig::default(),
        geoip: GeoIpConfig::default(),
        stream: StreamConfig::default(),
        udp: UdpConfig::default(),
        wasm: WasmConfig::default(),
        vhosts: vec![
            VhostConfig {
                name: "first.example".to_owned(),
                hosts: vec!["Example.com".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            },
            VhostConfig {
                name: "second.example".to_owned(),
                hosts: vec!["example.com:443".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            },
        ],
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::DuplicateVhostHost {
            host: "example.com".to_owned()
        })
    );
}

#[test]
fn rejects_unknown_default_vhost() {
    let config = Config {
        server: ServerConfig {
            listen: vec!["127.0.0.1:8080".to_owned()],
            tls_listen: Vec::new(),
            default_vhost: Some("missing".to_owned()),
            trusted_proxies: Vec::new(),
            limits: ServerLimitsConfig::default(),
            ..ServerConfig::default()
        },
        vhosts: vec![VhostConfig {
            name: "known".to_owned(),
            hosts: vec!["known.example".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }],
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::UnknownDefaultVhost {
            name: "missing".to_owned()
        })
    );
    let message = config.validate().unwrap_err().to_string();
    assert!(message.contains("include_conf_d = true"));
    assert!(message.contains("validate the config directory"));
}

#[test]
fn accepts_wildcard_vhost_host() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "wild".to_owned(),
            hosts: vec!["*.example.com".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }],
        ..Config::default()
    };

    assert_eq!(
        config.vhosts[0].normalized_hosts(),
        ["*.example.com".to_owned()]
    );
    config.validate().unwrap();
}
