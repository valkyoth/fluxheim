use super::*;

fn policy(config: AccessPolicyConfig) -> NativeIpAccessPolicy {
    config.validate("vhosts.access").unwrap();
    NativeIpAccessPolicy::from_config(&config).unwrap()
}

#[test]
fn ip_rules_deny_first_and_missing_identity_fails_closed() {
    let config = AccessPolicyConfig {
        allow: vec!["192.0.2.0/24".into(), "2001:db8::/32".into()],
        deny: vec!["192.0.2.10".into()],
        ..Default::default()
    };
    let access = policy(config);
    for (ip, allowed) in [
        ("192.0.2.11", true),
        ("::ffff:192.0.2.11", true),
        ("2001:db8::1", true),
        ("192.0.2.10", false),
        ("198.51.100.1", false),
    ] {
        assert_eq!(
            access.allows(Some(ip.parse().unwrap()), None, None),
            allowed,
            "{ip}"
        );
    }
    assert!(!access.allows(None, None, None));
    let deny_only = policy(AccessPolicyConfig {
        deny: vec!["192.0.2.10".into()],
        ..Default::default()
    });
    assert!(!deny_only.allows(None, None, None));
}

#[test]
fn mapped_cidr_validates_but_does_not_match_normalized_ipv4_clients() {
    let exact = policy(AccessPolicyConfig {
        deny: vec!["::ffff:192.0.2.10".into()],
        ..Default::default()
    });
    let cidr = policy(AccessPolicyConfig {
        deny: vec!["::ffff:192.0.2.10/128".into()],
        ..Default::default()
    });
    for ip in ["192.0.2.10", "::ffff:192.0.2.10"] {
        let ip = Some(ip.parse().unwrap());
        assert!(!exact.allows(ip, None, None));
        assert!(cidr.allows(ip, None, None));
    }
}

#[test]
fn disabled_policy_bypasses_only_its_own_rules() {
    let access = policy(AccessPolicyConfig {
        enabled: false,
        deny: vec!["0.0.0.0/0".into()],
        require_client_cert: true,
        ..Default::default()
    });
    assert!(access.allows(None, None, None));
}

#[test]
fn certificate_and_ip_allowlists_must_both_pass() {
    let access = policy(AccessPolicyConfig {
        allow: vec!["192.0.2.10".into()],
        allow_client_cert_sha256: vec!["ab".repeat(32)],
        ..Default::default()
    });
    let identity = crate::NativeHttp1TlsClientIdentity {
        cert_sha256: Some("AB".repeat(32)),
        ..Default::default()
    };
    let ip = Some("192.0.2.10".parse().unwrap());
    assert!(access.allows(ip, Some(&identity), None));
    assert!(!access.allows(ip, None, None));
    assert!(!access.allows(Some("192.0.2.11".parse().unwrap()), Some(&identity), None));
}
