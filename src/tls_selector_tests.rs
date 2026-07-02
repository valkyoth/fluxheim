use std::path::PathBuf;

#[cfg(feature = "acme")]
use crate::config::AcmeConfig;
use crate::config::{
    CacheConfig, Config, ProxyConfig, ServerConfig, StaticCertificateConfig, TlsConfig,
    VhostConfig, VhostHeaderPolicyConfig, VhostTlsConfig, WebConfig,
};

use super::downstream_certificate_selector;

#[test]
fn downstream_certificate_selector_uses_vhost_sni() {
    let default_cert = StaticCertificateConfig {
        cert_path: PathBuf::from("/tls/default.pem"),
        key_path: PathBuf::from("/tls/default.key"),
    };
    let exact_cert = StaticCertificateConfig {
        cert_path: PathBuf::from("/tls/exact.pem"),
        key_path: PathBuf::from("/tls/exact.key"),
    };
    let wildcard_cert = StaticCertificateConfig {
        cert_path: PathBuf::from("/tls/wildcard.pem"),
        key_path: PathBuf::from("/tls/wildcard.key"),
    };
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            certificates: vec![default_cert.clone()],
            ..TlsConfig::default()
        },
        vhosts: vec![
            VhostConfig {
                name: "exact".to_owned(),
                hosts: vec!["Example.TEST".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: VhostTlsConfig {
                    enabled: true,
                    certificate: Some(exact_cert.clone()),
                    ..VhostTlsConfig::default()
                },
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            },
            VhostConfig {
                name: "wildcard".to_owned(),
                hosts: vec!["*.api.example.test".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: VhostTlsConfig {
                    enabled: true,
                    certificate: Some(wildcard_cert.clone()),
                    ..VhostTlsConfig::default()
                },
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            },
        ],
        ..Config::default()
    };

    let selector = downstream_certificate_selector(&config).unwrap();

    assert!(selector.has_sni_certificates());
    assert_eq!(
        selector.certificate_for_sni(Some("example.test")),
        &exact_cert
    );
    assert_eq!(
        selector.certificate_for_sni(Some("service.api.example.test")),
        &wildcard_cert
    );
    assert_eq!(
        selector.certificate_for_sni(Some("deep.service.api.example.test")),
        &default_cert
    );
    assert_eq!(selector.certificate_for_sni(None), &default_cert);
}

#[test]
fn downstream_certificate_selector_uses_default_vhost_without_global_certificate() {
    let default_cert = StaticCertificateConfig {
        cert_path: PathBuf::from("/tls/default-vhost.pem"),
        key_path: PathBuf::from("/tls/default-vhost.key"),
    };
    let other_cert = StaticCertificateConfig {
        cert_path: PathBuf::from("/tls/other.pem"),
        key_path: PathBuf::from("/tls/other.key"),
    };
    let config = Config {
        server: ServerConfig {
            default_vhost: Some("default".to_owned()),
            ..ServerConfig::default()
        },
        tls: TlsConfig {
            enabled: true,
            ..TlsConfig::default()
        },
        vhosts: vec![
            VhostConfig {
                name: "default".to_owned(),
                hosts: vec!["default.example.test".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: VhostTlsConfig {
                    enabled: true,
                    certificate: Some(default_cert.clone()),
                    ..VhostTlsConfig::default()
                },
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            },
            VhostConfig {
                name: "other".to_owned(),
                hosts: vec!["other.example.test".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: VhostTlsConfig {
                    enabled: true,
                    certificate: Some(other_cert.clone()),
                    ..VhostTlsConfig::default()
                },
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            },
        ],
        ..Config::default()
    };

    let selector = downstream_certificate_selector(&config).unwrap();

    assert_eq!(selector.certificate_for_sni(None), &default_cert);
    assert_eq!(
        selector.certificate_for_sni(Some("default.example.test")),
        &default_cert
    );
    assert_eq!(
        selector.certificate_for_sni(Some("other.example.test")),
        &other_cert
    );
}

#[cfg(feature = "acme")]
#[test]
fn downstream_certificate_selector_uses_managed_acme_certificate_paths() {
    let storage = PathBuf::from("/var/lib/fluxheim/acme");
    let config = Config {
        server: ServerConfig {
            default_vhost: Some("default".to_owned()),
            ..ServerConfig::default()
        },
        tls: TlsConfig {
            enabled: true,
            acme: AcmeConfig {
                enabled: true,
                storage: Some(storage.clone()),
                ..AcmeConfig::default()
            },
            ..TlsConfig::default()
        },
        vhosts: vec![
            VhostConfig {
                name: "default".to_owned(),
                hosts: vec!["default.example.test".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: VhostTlsConfig {
                    enabled: true,
                    acme: crate::config::VhostAcmeConfig {
                        enabled: true,
                        issuer: None,
                        domains: vec![
                            "default.example.test".to_owned(),
                            "www.default.example.test".to_owned(),
                        ],
                    },
                    ..VhostTlsConfig::default()
                },
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            },
            VhostConfig {
                name: "www-default".to_owned(),
                hosts: vec!["www.default.example.test".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: VhostTlsConfig {
                    enabled: true,
                    ..VhostTlsConfig::default()
                },
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            },
            VhostConfig {
                name: "other".to_owned(),
                hosts: vec!["other.example.test".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: VhostTlsConfig {
                    enabled: true,
                    acme: crate::config::VhostAcmeConfig {
                        enabled: true,
                        issuer: None,
                        domains: Vec::new(),
                    },
                    ..VhostTlsConfig::default()
                },
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            },
        ],
        ..Config::default()
    };

    let selector = downstream_certificate_selector(&config).unwrap();
    let default_paths = crate::acme::managed_certificate_paths(&storage, "default");
    let other_paths = crate::acme::managed_certificate_paths(&storage, "other");

    assert_eq!(
        selector.certificate_for_sni(None),
        &StaticCertificateConfig {
            cert_path: default_paths.cert_path.clone(),
            key_path: default_paths.key_path.clone(),
        }
    );
    assert_eq!(
        selector.certificate_for_sni(Some("www.default.example.test")),
        &StaticCertificateConfig {
            cert_path: default_paths.cert_path.clone(),
            key_path: default_paths.key_path.clone(),
        }
    );
    assert_eq!(
        selector.certificate_for_sni(Some("other.example.test")),
        &StaticCertificateConfig {
            cert_path: other_paths.cert_path,
            key_path: other_paths.key_path,
        }
    );
}
