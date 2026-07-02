use super::super::*;

#[test]
fn rejects_too_many_proxy_upstreams() {
    let upstreams = (0..=crate::MAX_PROXY_UPSTREAMS)
        .map(|index| format!("\"origin-{index}.example.test:8080\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [proxy]
            upstreams = [{upstreams}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::TooManyProxyUpstreams {
            max: crate::MAX_PROXY_UPSTREAMS
        })
    );
}

#[test]
fn rejects_duplicate_proxy_upstreams() {
    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["origin.example.test:8080", "ORIGIN.example.test:8080"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::DuplicateProxyUpstream {
            upstream: "ORIGIN.example.test:8080".to_owned()
        })
    );
}

#[test]
fn rejects_inconsistent_proxy_upstream_tls_verification_policy() {
    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstream_tls = true
            upstream_verify_cert = false
            upstream_verify_hostname = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProxyTlsPolicy {
            reason: "upstream_verify_hostname must be false when upstream_verify_cert = false"
        })
    );
}

#[test]
fn rejects_verified_proxy_tls_ip_upstream_without_sni() {
    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "10.0.1.5:443"
            upstream_tls = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProxyTlsPolicy {
            reason: "IP-addressed upstreams with upstream_tls and upstream_verify_cert require explicit upstream_sni"
        })
    );

    let explicit_sni: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "10.0.1.5:443"
            upstream_tls = true
            upstream_sni = "origin.example.test"
            "#,
    )
    .unwrap();
    explicit_sni.validate().unwrap();

    let explicitly_unverified: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "10.0.1.5:443"
            upstream_tls = true
            upstream_verify_cert = false
            upstream_verify_hostname = false
            "#,
    )
    .unwrap();
    explicitly_unverified.validate().unwrap();
}

#[test]
fn rejects_invalid_proxy_upstream_alternative_cn() {
    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstream_tls = true
            upstream_sni = "origin.example.test"
            upstream_alternative_cn = "*.example.test"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProxyTlsPolicy {
            reason: "upstream_alternative_cn must not contain wildcards"
        })
    );
}

#[test]
fn vhost_without_proxy_does_not_inherit_legacy_default_upstream() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "static"
            hosts = ["static.example.test"]

            [vhosts.web]
            root = "/srv/static"
            "#,
    )
    .unwrap();

    assert!(!config.vhosts[0].proxy.has_configured_upstream());
    assert_eq!(config.proxy.primary_upstream(), "127.0.0.1:3000");
}
