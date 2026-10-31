use crate::{AccessPolicyConfig, Config};

#[test]
fn ip_access_recipe_validates_with_both_scopes() {
    let config: Config = toml::from_str(include_str!("../../../examples/access/ip.toml")).unwrap();
    config.validate().unwrap();
    assert!(config.server.trusted_proxies.is_empty());
    assert_eq!(config.vhosts[0].access.allow.len(), 2);
    assert!(config.vhosts[0].routes[0].methods.is_empty());
}

#[test]
fn access_rule_syntax_and_bounds_are_checked_even_when_disabled() {
    for invalid in [
        "localhost",
        "127.0.0.1:80",
        " 127.0.0.1",
        "192.0.2.0/33",
        "::/129",
    ] {
        let policy = AccessPolicyConfig {
            enabled: false,
            allow: vec![invalid.into()],
            ..Default::default()
        };
        assert!(policy.validate("vhosts.access").is_err(), "{invalid}");
    }
    let mut policy = AccessPolicyConfig {
        allow: vec!["127.0.0.1".into(); 257],
        ..Default::default()
    };
    assert!(policy.validate("vhosts.access").is_err());
    policy.allow = vec!["127.0.0.1".into(); 2];
    assert!(policy.validate("vhosts.access").is_err());
    policy.allow.clear();
    policy.allow_client_cert_sha256 = vec!["ab".repeat(32), "AB".repeat(32)];
    assert!(policy.validate("vhosts.access").is_err());
    for invalid in ["ab:".repeat(32), "a".repeat(63), "g".repeat(64)] {
        policy.allow_client_cert_sha256 = vec![invalid];
        assert!(policy.validate("vhosts.access").is_err());
    }
    policy.allow_client_cert_sha256 = vec!["AB".repeat(32)];
    policy.validate("vhosts.access").unwrap();
}

#[test]
fn deny_only_certificate_policy_does_not_imply_required_authentication() {
    let policy: AccessPolicyConfig = toml::from_str(&format!(
        "deny_client_cert_sha256 = [\"{}\"]",
        "ab".repeat(32)
    ))
    .unwrap();
    policy.validate("vhosts.access").unwrap();
    assert!(!policy.require_client_cert);
    assert!(policy.allow_client_cert_sha256.is_empty());
}
