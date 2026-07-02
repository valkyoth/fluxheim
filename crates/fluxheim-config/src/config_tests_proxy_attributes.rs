use super::super::*;

#[test]
fn rejects_ambiguous_proxy_upstream_aliases() {
    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            upstreams = ["127.0.0.1:3001"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::ConflictingProxyUpstreams)
    );
}

#[test]
fn loading_config_rejects_ambiguous_proxy_upstream_aliases_before_fragment_merge() {
    let dir = TestDir::new("config-file-conflicting-proxy-upstreams");
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            upstreams = ["127.0.0.1:3001"]
            "#,
    )
    .unwrap();

    assert!(matches!(
        Config::load(Some(&dir.child("fluxheim.toml"))),
        Err(ConfigLoadError::Validate(
            ConfigError::ConflictingProxyUpstreams
        ))
    ));
}

#[test]
fn rejects_invalid_proxy_upstream_weights() {
    let mismatch: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_weights = [1]
            "#,
    )
    .unwrap();
    assert!(matches!(
        mismatch.validate(),
        Err(ConfigError::InvalidProxyUpstreamWeights { .. })
    ));

    let zero: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_weights = [1, 0]
            "#,
    )
    .unwrap();
    assert!(matches!(
        zero.validate(),
        Err(ConfigError::InvalidProxyUpstreamWeights { .. })
    ));
}

#[test]
fn rejects_invalid_proxy_upstream_priority_groups() {
    let mismatch: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_priority_groups = [100]
            "#,
    )
    .unwrap();
    assert!(matches!(
        mismatch.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_priority_groups",
            ..
        })
    ));

    let too_large: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_priority_groups = [100, 1001]
            "#,
    )
    .unwrap();
    assert!(matches!(
        too_large.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_priority_groups",
            ..
        })
    ));

    let min_active_without_groups: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_priority_group_min_active = 2
            "#,
    )
    .unwrap();
    assert!(matches!(
        min_active_without_groups.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_priority_group_min_active",
            ..
        })
    ));

    let min_active_too_large: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_priority_groups = [100, 50]
            upstream_priority_group_min_active = 3
            "#,
    )
    .unwrap();
    assert!(matches!(
        min_active_too_large.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_priority_group_min_active",
            ..
        })
    ));
}

#[test]
fn rejects_invalid_proxy_upstream_localities() {
    let mismatch: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_localities = ["site-a"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        mismatch.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_localities",
            ..
        })
    ));

    let invalid_label: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_localities = ["site/a", "site-b"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_label.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_localities",
            ..
        })
    ));

    let preferred_without_localities: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            preferred_upstream_localities = ["site-a"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        preferred_without_localities.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.preferred_upstream_localities",
            ..
        })
    ));

    let unknown_preferred: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_localities = ["site-a", "site-b"]
            preferred_upstream_localities = ["site-c"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        unknown_preferred.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.preferred_upstream_localities",
            ..
        })
    ));

    let duplicate_preferred: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_localities = ["site-a", "site-b"]
            preferred_upstream_localities = ["site-a", "SITE-A"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        duplicate_preferred.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.preferred_upstream_localities",
            ..
        })
    ));
}

#[test]
fn rejects_invalid_proxy_upstream_tags() {
    let mismatch: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_tags = [["blue"]]
            "#,
    )
    .unwrap();
    assert!(matches!(
        mismatch.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_tags",
            ..
        })
    ));

    let invalid_label: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_tags = [["blue"], ["bad/tag"]]
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_label.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_tags",
            ..
        })
    ));

    let duplicate_tag: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_tags = [["blue", "BLUE"], ["green"]]
            "#,
    )
    .unwrap();
    assert!(matches!(
        duplicate_tag.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_tags",
            ..
        })
    ));
}

#[test]
fn rejects_invalid_proxy_upstream_max_in_flight() {
    let mismatch: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_max_in_flight = [100]
            "#,
    )
    .unwrap();
    assert!(matches!(
        mismatch.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_max_in_flight",
            ..
        })
    ));

    let zero: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_max_in_flight = [100, 0]
            "#,
    )
    .unwrap();
    assert!(matches!(
        zero.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_max_in_flight",
            ..
        })
    ));

    let too_large: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_max_in_flight = [100, 1000001]
            "#,
    )
    .unwrap();
    assert!(matches!(
        too_large.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_max_in_flight",
            ..
        })
    ));
}

#[test]
fn rejects_invalid_proxy_upstream_aliases() {
    let mismatch: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_aliases = ["origin-a"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        mismatch.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_aliases",
            ..
        })
    ));

    let unsafe_alias: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_aliases = ["origin/a", "origin-b"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        unsafe_alias.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_aliases",
            ..
        })
    ));

    let duplicate: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_aliases = ["origin-a", "ORIGIN-A"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        duplicate.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_aliases",
            ..
        })
    ));
}
