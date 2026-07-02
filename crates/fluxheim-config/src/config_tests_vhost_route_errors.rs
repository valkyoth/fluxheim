use super::*;

#[test]
fn rejects_invalid_vhost_routes() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_exact = "/one"
            path_prefix = "/one/"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteMatcher {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );

    let config: Config = toml::from_str(
        r#"
            [server]
            regex_enabled = true

            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_prefix = "/api/"
            path_regex = "^/api/v[0-9]+/"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteMatcher {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );

    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_prefix = "/api/"
            methods = ["GET", "get"]

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidRouteMethods {
            vhost,
            route,
            ..
        }) if vhost == "gateway" && route == "bad"
    ));

    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_prefix = "/one/"

            [vhosts.routes.redirect]
            to = "https://gateway.example{uri}"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteAction {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );

    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_prefix = "/one/"
            rewrite_prefix = "/upstream/"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteRewritePrefix {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );

    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_prefix = "/one/"
            strip_prefix = "/one/"
            rewrite_prefix = "/upstream/%2e%2e/"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteRewritePrefix {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );

    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_prefix = "/one/"
            strip_prefix = "/one/"
            rewrite_prefix = "/upstream/./"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteRewritePrefix {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );

    let config: Config = toml::from_str(
        r#"
            [server]
            regex_enabled = true

            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_prefix = "/api/"
            rewrite_template = "/internal/{route.regex.1}"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteRewriteTemplate {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );

    let config: Config = toml::from_str(
        r#"
            [server]
            regex_enabled = true

            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_regex = "^/api/(.*)$"
            rewrite_template = "/internal/{path}"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteRewriteTemplate {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );
}
