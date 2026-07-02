use super::*;
use crate::MAX_ACME_CHALLENGE_UPSTREAMS;

#[test]
fn rejects_enabled_acme_challenge_without_upstream() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [vhosts.acme_challenge]
            enabled = true
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::MissingAcmeChallengeUpstream { vhost }) if vhost == "gateway"
    ));
}

#[test]
fn rejects_too_many_acme_challenge_upstreams() {
    let upstreams = (0..=MAX_ACME_CHALLENGE_UPSTREAMS)
        .map(|index| format!("\"acme-{index}.example.test:8080\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [vhosts.acme_challenge]
            enabled = true
            upstreams = [{upstreams}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::TooManyAcmeChallengeUpstreams {
            vhost: "gateway".to_owned(),
            max: MAX_ACME_CHALLENGE_UPSTREAMS,
        })
    );
}

#[test]
fn rejects_duplicate_acme_challenge_upstreams() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [vhosts.acme_challenge]
            enabled = true
            upstreams = ["acme.example.test:8080", "ACME.example.test:8080"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::DuplicateAcmeChallengeUpstream {
            vhost: "gateway".to_owned(),
            upstream: "ACME.example.test:8080".to_owned(),
        })
    );
}

#[test]
fn rejects_enabled_vhost_redirect_without_target() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "www"
            hosts = ["www.example.test"]

            [vhosts.redirect]
            enabled = true
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::MissingVhostRedirectTarget { vhost }) if vhost == "www"
    ));
}

#[test]
fn rejects_vhost_redirect_with_explicit_fallback_route() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "www"
            hosts = ["www.example.test"]

            [vhosts.redirect]
            enabled = true
            to = "https://example.test{uri}"

            [[vhosts.routes]]
            name = "fallback"
            fallback = true

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:3000"]
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::VhostRedirectConflictsWithFallback { vhost }) if vhost == "www"
    ));
}
