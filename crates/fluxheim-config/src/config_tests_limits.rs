use super::*;
use crate::{
    MAX_ROUTE_NAME_BYTES, MAX_SERVER_LISTENERS, MAX_TRUSTED_PROXIES, MAX_VHOST_HOSTS,
    MAX_VHOST_NAME_BYTES, MAX_VHOST_ROUTES, MAX_VHOSTS,
};

#[test]
fn rejects_too_many_server_listeners() {
    let listen = (0..=MAX_SERVER_LISTENERS)
        .map(|index| format!("\"127.0.0.1:{}\"", 10_000 + index))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [server]
            listen = [{listen}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "server.listen".to_owned(),
            max: MAX_SERVER_LISTENERS,
        })
    );
}

#[test]
fn rejects_too_many_tls_listeners() {
    let tls_listen = (0..=MAX_SERVER_LISTENERS)
        .map(|index| format!("\"127.0.0.1:{}\"", 20_000 + index))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [server]
            tls_listen = [{tls_listen}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "server.tls_listen".to_owned(),
            max: MAX_SERVER_LISTENERS,
        })
    );
}

#[test]
fn rejects_too_many_trusted_proxies() {
    let trusted_proxies = (0..=MAX_TRUSTED_PROXIES)
        .map(|index| format!("\"10.{}.0.0/16\"", index % 256))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [server]
            trusted_proxies = [{trusted_proxies}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "server.trusted_proxies".to_owned(),
            max: MAX_TRUSTED_PROXIES,
        })
    );
}

#[test]
fn rejects_too_many_vhosts() {
    let vhosts = (0..=MAX_VHOSTS)
        .map(|index| {
            format!(
                r#"
                    [[vhosts]]
                    name = "site-{index}"
                    hosts = ["site-{index}.example.test"]
                    "#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let config: Config = toml::from_str(&vhosts).unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "vhosts".to_owned(),
            max: MAX_VHOSTS,
        })
    );
}

#[test]
fn rejects_oversized_vhost_name() {
    let name = "v".repeat(MAX_VHOST_NAME_BYTES + 1);
    let config: Config = toml::from_str(&format!(
        r#"
            [[vhosts]]
            name = {name:?}
            hosts = ["gateway.example.test"]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigNameLength {
            field: "vhosts.name",
            max: MAX_VHOST_NAME_BYTES,
        })
    );
}

#[test]
fn rejects_too_many_vhost_hosts() {
    let hosts = (0..=MAX_VHOST_HOSTS)
        .map(|index| format!("\"alias-{index}.example.test\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = [{hosts}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "vhost \"gateway\".hosts".to_owned(),
            max: MAX_VHOST_HOSTS,
        })
    );
}

#[test]
fn rejects_too_many_vhost_routes() {
    let routes = (0..=MAX_VHOST_ROUTES)
        .map(|index| {
            format!(
                r#"
                    [[vhosts.routes]]
                    name = "route-{index}"
                    path_prefix = "/route-{index}/"
                    "#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let config: Config = toml::from_str(&format!(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]
            {routes}
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "vhost \"gateway\".routes".to_owned(),
            max: MAX_VHOST_ROUTES,
        })
    );
}

#[test]
fn rejects_oversized_route_name() {
    let route_name = "r".repeat(MAX_ROUTE_NAME_BYTES + 1);
    let config: Config = toml::from_str(&format!(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [[vhosts.routes]]
            name = {route_name:?}
            path_prefix = "/assets/"

            [vhosts.routes.web]
            root = "/srv/assets"
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigNameLength {
            field: "vhosts.routes.name",
            max: MAX_ROUTE_NAME_BYTES,
        })
    );
}
