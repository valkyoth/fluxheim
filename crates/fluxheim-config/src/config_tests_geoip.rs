use super::*;

const GEOIP_GUIDE_BASE: &str = include_str!("../../../examples/geoip/local.toml");

#[test]
fn geoip_guide_base_matches_feature_contract() {
    let config: Config = toml::from_str(GEOIP_GUIDE_BASE).unwrap();
    #[cfg(all(feature = "geoip", not(feature = "privacy-mode")))]
    config.validate().unwrap();
    #[cfg(any(not(feature = "geoip"), feature = "privacy-mode"))]
    assert!(config.validate().is_err());
}

#[cfg(all(feature = "geoip", not(feature = "privacy-mode")))]
#[test]
fn geoip_guide_fragments_validate_with_the_complete_base() {
    let base: Config = toml::from_str(GEOIP_GUIDE_BASE).unwrap();
    let deny: toml::Value =
        toml::from_str(include_str!("../../../examples/geoip/deny-only.toml")).unwrap();
    let mut config = base.clone();
    config.vhosts[0].access = deny["vhosts"]["access"].clone().try_into().unwrap();
    config.validate().unwrap();
    let databases: toml::Value =
        toml::from_str(include_str!("../../../examples/geoip/two-databases.toml")).unwrap();
    config.geoip = databases["geoip"].clone().try_into().unwrap();
    config.validate().unwrap();
    config.geoip.fallback_enabled = false;
    config.validate().unwrap();
    let with_route = format!(
        "{GEOIP_GUIDE_BASE}\n{}",
        include_str!("../../../examples/geoip/route.toml")
    );
    let mut config: Config = toml::from_str(&with_route).unwrap();
    config.validate().unwrap();
    config.vhosts[0].routes[0].access.enabled = false;
    config.validate().unwrap();
}

#[cfg(all(feature = "geoip", not(feature = "privacy-mode")))]
#[test]
fn geoip_guide_disabling_policy_does_not_skip_validation() {
    let mut config: Config = toml::from_str(GEOIP_GUIDE_BASE).unwrap();
    config.vhosts[0].access.enabled = false;
    config.geoip.enabled = false;
    assert!(config.validate().is_err());
    config.vhosts[0].access.allow_countries.clear();
    config.vhosts[0].access.allow_asns.clear();
    config.validate().unwrap();
}

#[cfg(all(feature = "geoip", not(feature = "privacy-mode")))]
#[test]
fn geoip_guide_rejects_invalid_policy_values_and_database_counts() {
    let base: Config = toml::from_str(GEOIP_GUIDE_BASE).unwrap();
    for countries in [vec!["us"], vec!["USA"], vec!["US", "US"]] {
        let mut config = base.clone();
        config.vhosts[0].access.allow_countries =
            countries.into_iter().map(str::to_owned).collect();
        assert!(config.validate().is_err());
    }
    for asns in [vec![0], vec![13335, 13335], (1..=2049).collect()] {
        let mut config = base.clone();
        config.vhosts[0].access.allow_asns = asns;
        assert!(config.validate().is_err());
    }
    let mut config = base.clone();
    config.vhosts[0].access.allow_asns = vec![1, u32::MAX];
    config.validate().unwrap();
    for count in [0, 9] {
        let mut config = base.clone();
        config.geoip.databases = vec![base.geoip.databases[0].clone(); count];
        assert!(config.validate().is_err());
    }
    let mut config = base;
    config.geoip.databases[0].path = PathBuf::new();
    assert!(config.validate().is_err());
}

#[cfg(feature = "geoip")]
#[test]
fn geoip_config_accepts_local_mmdb_providers() {
    let config: Config = toml::from_str(
        r#"
            [geoip]
            enabled = true
            fallback_enabled = true

            [[geoip.databases]]
            provider = "maxmind"
            path = "/var/lib/fluxheim/geo/GeoLite2-Country.mmdb"

            [[geoip.databases]]
            provider = "circl-geo-open"
            path = "/var/lib/fluxheim/geo/circl-country.mmdb"
            "#,
    )
    .unwrap();

    config.validate().unwrap();
}

#[cfg(not(feature = "geoip"))]
#[test]
fn geoip_enabled_requires_geoip_feature() {
    let config: Config = toml::from_str(
        r#"
            [geoip]
            enabled = true
            fallback_enabled = true

            [[geoip.databases]]
            provider = "maxmind"
            path = "/var/lib/fluxheim/geo/GeoLite2-Country.mmdb"
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::GeoIpNotCompiled)
    ));
}

#[test]
fn geoip_access_rules_require_global_geoip() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "app"
            hosts = ["example.test"]

            [vhosts.access]
            deny_countries = ["RU"]
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidGeoIpPolicy {
            field: "vhosts.access",
            ..
        })
    ));
}
