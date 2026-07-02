use super::super::*;

#[cfg(not(feature = "privacy-mode"))]
#[test]
fn parses_managed_cookie_load_balance_persistence() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            mode = "managed-cookie"
            cookie = "fluxheim_lb"
            ttl_secs = 600
            table_max_entries = 4096
            managed_cookie_domain = "example.test"
            managed_cookie_path = "/app"
            managed_cookie_secure = true
            managed_cookie_http_only = true
            managed_cookie_same_site = "strict"
            managed_cookie_max_age_secs = 300
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert!(config.proxy.load_balance.persistence.enabled);
    assert_eq!(
        config.proxy.load_balance.persistence.mode,
        LoadBalancePersistenceMode::ManagedCookie
    );
    assert_eq!(
        config.proxy.load_balance.persistence.cookie.as_deref(),
        Some("fluxheim_lb")
    );
    assert_eq!(
        config
            .proxy
            .load_balance
            .persistence
            .managed_cookie_domain
            .as_deref(),
        Some("example.test")
    );
    assert_eq!(
        config
            .proxy
            .load_balance
            .persistence
            .managed_cookie_path
            .as_deref(),
        Some("/app")
    );
    assert_eq!(
        config
            .proxy
            .load_balance
            .persistence
            .managed_cookie_same_site,
        LoadBalanceManagedCookieSameSite::Strict
    );
    assert_eq!(
        config
            .proxy
            .load_balance
            .persistence
            .managed_cookie_max_age_secs,
        Some(300)
    );
}

#[cfg(not(feature = "privacy-mode"))]
#[test]
fn rejects_invalid_load_balance_persistence() {
    let invalid_ttl: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            ttl_secs = 0
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_ttl.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.ttl_secs must be between 1 and 86400"
        })
    );

    let invalid_table: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            table_max_entries = 0
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_table.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.table_max_entries must be between 1 and 1000000"
        })
    );

    let missing_header: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            mode = "header"
            "#,
    )
    .unwrap();
    assert_eq!(
        missing_header.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.header is required when mode = \"header\""
        })
    );

    let header_with_source_ip: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            mode = "source-ip"
            header = "x-session"
            "#,
    )
    .unwrap();
    assert_eq!(
        header_with_source_ip.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.header can only be used with mode = \"header\""
        })
    );

    let invalid_header: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            mode = "header"
            header = "bad header"
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_header.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "proxy.load_balance.persistence.header",
            name: "bad header".to_owned()
        })
    );

    let missing_cookie: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            mode = "cookie"
            "#,
    )
    .unwrap();
    assert_eq!(
        missing_cookie.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.cookie is required when mode = \"cookie\" or \"managed-cookie\""
        })
    );

    let cookie_with_source_ip: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            mode = "source-ip"
            cookie = "sid"
            "#,
    )
    .unwrap();
    assert_eq!(
        cookie_with_source_ip.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.cookie can only be used with mode = \"cookie\" or \"managed-cookie\""
        })
    );

    let invalid_cookie: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            mode = "cookie"
            cookie = "bad cookie"
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_cookie.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.cookie must be a valid cookie name"
        })
    );

    let invalid_managed_cookie_path: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            mode = "managed-cookie"
            cookie = "fluxheim_lb"
            managed_cookie_path = "relative"
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_managed_cookie_path.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.managed_cookie_path must be an absolute ASCII cookie path without controls, ';', or ','"
        })
    );

    let non_ascii_managed_cookie_path: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            mode = "managed-cookie"
            cookie = "fluxheim_lb"
            managed_cookie_path = "/例え"
            "#,
    )
    .unwrap();
    assert_eq!(
        non_ascii_managed_cookie_path.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.managed_cookie_path must be an absolute ASCII cookie path without controls, ';', or ','"
        })
    );

    let non_ascii_managed_cookie_domain: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            mode = "managed-cookie"
            cookie = "fluxheim_lb"
            managed_cookie_domain = "例え.jp"
            "#,
    )
    .unwrap();
    assert_eq!(
        non_ascii_managed_cookie_domain.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.managed_cookie_domain must be a non-empty ASCII cookie domain without controls, ';', or ','"
        })
    );

    let same_site_none_without_secure: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            mode = "managed-cookie"
            cookie = "fluxheim_lb"
            managed_cookie_same_site = "none"
            managed_cookie_secure = false
            "#,
    )
    .unwrap();
    assert_eq!(
        same_site_none_without_secure.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.managed_cookie_same_site = \"none\" requires managed_cookie_secure = true"
        })
    );
}

#[cfg(feature = "privacy-mode")]
#[test]
fn rejects_load_balance_persistence_in_privacy_mode() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence is not available in privacy-mode builds"
        })
    );
}
