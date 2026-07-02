use super::super::*;

#[test]
fn rejects_invalid_proxy_error_pages() {
    let config: Config = toml::from_str(
        r#"
            [[proxy.error_pages]]
            status = 302
            path = "/302.html"

            [proxy.error_pages.web]
            root = "/srv/fluxheim/errors"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProxyErrorPageStatus { status: 302 })
    );

    let config: Config = toml::from_str(
        r#"
            [[proxy.error_pages]]
            status = 502
            path = "/502.html"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::MissingProxyErrorPageRoot { status: 502 })
    );
}

#[test]
fn rejects_too_many_proxy_error_pages() {
    let error_pages = (0..=crate::MAX_PROXY_ERROR_PAGES)
        .map(|index| crate::ProxyErrorPageConfig {
            status: 400 + (index % 100) as u16,
            path: format!("/error-{index}.html"),
            web: WebConfig::default(),
        })
        .collect();
    let config = Config {
        proxy: ProxyConfig {
            error_pages,
            ..ProxyConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::TooManyProxyErrorPages {
            max: crate::MAX_PROXY_ERROR_PAGES
        })
    );
}

#[test]
fn upstreams_can_be_used_as_primary_proxy_targets() {
    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["origin-a.example.test:443", "origin-b.example.test:443"]
            upstream_tls = true
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert_eq!(config.proxy.primary_upstream(), "origin-a.example.test:443");
    assert_eq!(config.proxy.upstream_sni(), "origin-a.example.test");
}
