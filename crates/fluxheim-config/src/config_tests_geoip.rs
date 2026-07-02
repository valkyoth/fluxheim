use super::*;

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
