use super::*;
use crate::{
    GeoIpConfig, StaticCertificateConfig, StreamConfig, TlsConfig, UdpConfig,
    VhostAcmeChallengeConfig, VhostRedirectConfig,
};

#[test]
fn parses_server_limits() {
    let config: Config = toml::from_str(
        r#"
            [server]
            trusted_proxies = ["127.0.0.1", "10.0.0.0/8", "2001:db8::/32", "2a06:98c0::/29"]
            proxy_protocol = "v2"

            [server.limits]
            max_request_header_bytes = "32KiB"
            max_uri_bytes = 4096
            max_request_headers = 32
            max_request_body_bytes = "2MiB"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.server.limits.max_request_header_bytes,
        ByteSize::from_bytes(32 * 1024)
    );
    assert_eq!(
        config.server.limits.max_uri_bytes,
        ByteSize::from_bytes(4096)
    );
    assert_eq!(config.server.limits.max_request_headers, 32);
    assert_eq!(
        config.server.limits.max_request_body_bytes,
        ByteSize::from_bytes(2 * 1024 * 1024)
    );
    assert_eq!(
        config.server.trusted_proxies,
        ["127.0.0.1", "10.0.0.0/8", "2001:db8::/32", "2a06:98c0::/29"]
    );
    assert_eq!(config.server.proxy_protocol, DownstreamProxyProtocol::V2);
    config.validate().unwrap();
}

#[test]
fn rejects_invalid_trusted_proxy_range() {
    let config: Config = toml::from_str(
        r#"
            [server]
            trusted_proxies = ["10.0.0.0/99"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTrustedProxy {
            value: "10.0.0.0/99".to_owned()
        })
    );
}

#[test]
fn rejects_overbroad_trusted_proxy_ranges() {
    for value in [
        "0.0.0.0/0",
        "0.0.0.0",
        "10.0.0.0/7",
        "::/0",
        "::",
        "2001:db8::/28",
    ] {
        let config: Config = toml::from_str(&format!(
            r#"
                [server]
                trusted_proxies = ["{value}"]
                "#
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTrustedProxy {
                value: value.to_owned()
            })
        );
    }
}

#[test]
fn rejects_proxy_protocol_without_trusted_proxies() {
    let config: Config = toml::from_str(
        r#"
            [server]
            proxy_protocol = "v1"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidServerProxyProtocolPolicy {
            reason: "server.proxy_protocol requires server.trusted_proxies so client identity cannot be spoofed by direct peers"
        })
    );
}

#[test]
fn rejects_zero_server_limits() {
    let config: Config = toml::from_str(
        r#"
            [server.limits]
            max_uri_bytes = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidLimit {
            field: "server.limits.max_uri_bytes"
        })
    );
}

#[test]
fn rejects_empty_listeners() {
    let config = Config {
        server: ServerConfig {
            listen: vec![],
            tls_listen: Vec::new(),
            default_vhost: None,
            trusted_proxies: Vec::new(),
            limits: ServerLimitsConfig::default(),
            ..ServerConfig::default()
        },
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
        vhosts: vec![],
    };

    assert_eq!(config.validate(), Err(ConfigError::EmptyListeners));
}

#[test]
fn parses_strict_host_routing_mode() {
    let config: Config = toml::from_str(
        r#"
            [server.host_routing]
            strict = true
            "#,
    )
    .unwrap();

    assert!(config.server.host_routing.strict);
    config.validate().unwrap();
}

#[test]
fn rejects_invalid_tls_listener() {
    let config = Config {
        server: ServerConfig {
            tls_listen: vec!["localhost:8443".to_owned()],
            ..ServerConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidListenAddress {
            address: "localhost:8443".to_owned()
        })
    );
}

#[test]
fn parses_https_redirect_config() {
    let config: Config = toml::from_str(
        r#"
            [server]
            listen = ["127.0.0.1:8080"]
            tls_listen = ["127.0.0.1:8443"]

            [server.https_redirect]
            enabled = true
            status = 301
            target_port = 8443

            [tls]
            enabled = true

            [[tls.certificates]]
            cert_path = "fullchain.pem"
            key_path = "key.pem"
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert!(config.server.https_redirect.enabled);
    assert_eq!(config.server.https_redirect.status, 301);
    assert_eq!(config.server.https_redirect.target_port, Some(8443));
}

#[test]
fn rejects_https_redirect_without_tls_listener() {
    let config: Config = toml::from_str(
        r#"
            [server.https_redirect]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::HttpsRedirectWithoutTlsListener)
    );
}

#[test]
fn rejects_invalid_https_redirect_status() {
    let config: Config = toml::from_str(
        r#"
            [server]
            tls_listen = ["127.0.0.1:8443"]

            [server.https_redirect]
            enabled = true
            status = 200
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHttpsRedirectStatus { status: 200 })
    );
}

#[test]
fn rejects_invalid_https_redirect_target_port() {
    let config: Config = toml::from_str(
        r#"
            [server]
            tls_listen = ["127.0.0.1:8443"]

            [server.https_redirect]
            enabled = true
            target_port = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHttpsRedirectTargetPort)
    );
}

#[test]
fn rejects_tls_listener_without_tls_enabled() {
    let config = Config {
        server: ServerConfig {
            tls_listen: vec!["127.0.0.1:8443".to_owned()],
            ..ServerConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(config.validate(), Err(ConfigError::TlsListenerWithoutTls));
}

#[test]
fn rejects_tls_listener_without_static_certificate() {
    let config = Config {
        server: ServerConfig {
            tls_listen: vec!["127.0.0.1:8443".to_owned()],
            ..ServerConfig::default()
        },
        tls: TlsConfig {
            enabled: true,
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::TlsListenerWithoutStaticCertificate)
    );
}

#[test]
fn accepts_tls_listener_with_static_certificate() {
    let config = Config {
        server: ServerConfig {
            tls_listen: vec!["127.0.0.1:8443".to_owned()],
            ..ServerConfig::default()
        },
        tls: TlsConfig {
            enabled: true,
            certificates: vec![StaticCertificateConfig {
                cert_path: PathBuf::from("fullchain.pem"),
                key_path: PathBuf::from("key.pem"),
            }],
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn accepts_tls_listener_with_default_vhost_static_certificate() {
    let certificate = StaticCertificateConfig {
        cert_path: PathBuf::from("fullchain.pem"),
        key_path: PathBuf::from("key.pem"),
    };
    let config = Config {
        server: ServerConfig {
            tls_listen: vec!["127.0.0.1:8443".to_owned()],
            default_vhost: Some("example".to_owned()),
            ..ServerConfig::default()
        },
        tls: TlsConfig {
            enabled: true,
            ..TlsConfig::default()
        },
        vhosts: vec![VhostConfig {
            name: "example".to_owned(),
            hosts: vec!["example.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: VhostTlsConfig {
                enabled: true,
                certificate: Some(certificate),
                ..VhostTlsConfig::default()
            },
            acme_challenge: VhostAcmeChallengeConfig::default(),
            redirect: VhostRedirectConfig::default(),
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

    config.validate().unwrap();
}

#[cfg(feature = "acme")]
#[test]
fn accepts_tls_listener_with_default_vhost_acme_certificate_source() {
    let storage = secure_test_dir("config-default-vhost-acme-source");
    let config = Config {
        server: ServerConfig {
            tls_listen: vec!["127.0.0.1:8443".to_owned()],
            default_vhost: Some("example".to_owned()),
            ..ServerConfig::default()
        },
        tls: TlsConfig {
            enabled: true,
            acme: AcmeConfig {
                enabled: true,
                storage: Some(storage),
                contact_email: Some("admin@example.test".to_owned()),
                ..AcmeConfig::default()
            },
            ..TlsConfig::default()
        },
        vhosts: vec![VhostConfig {
            name: "example".to_owned(),
            hosts: vec!["example.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: VhostTlsConfig {
                enabled: true,
                acme: VhostAcmeConfig {
                    enabled: true,
                    issuer: None,
                    domains: Vec::new(),
                },
                ..VhostTlsConfig::default()
            },
            acme_challenge: VhostAcmeChallengeConfig::default(),
            redirect: VhostRedirectConfig::default(),
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

    config.validate().unwrap();
}
