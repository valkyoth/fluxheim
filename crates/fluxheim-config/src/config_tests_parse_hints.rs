use super::*;

#[test]
fn conf_d_parse_error_reports_source_file() {
    let dir = TestDir::new("config-file-with-bad-conf-d");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [server]
            listen = ["127.0.0.1:19090"]
            "#,
    )
    .unwrap();
    let bad_config = dir.child("conf.d/10-bad.toml");
    fs::write(
        &bad_config,
        "[vhosts.proxy.error_pages.web]\nroot = \"/tmp\"\n",
    )
    .unwrap();

    let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();
    let message = error.to_string();

    assert!(message.contains(&bad_config.display().to_string()));
    assert!(message.contains("failed to parse config"));
    assert!(message.contains("define [[vhosts.proxy.error_pages]]"));
}

#[test]
fn config_parse_error_hints_route_proxy_error_page_array() {
    let dir = TestDir::new("config-route-proxy-error-page-table");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [[vhosts.routes]]
            name = "app"
            path_prefix = "/"

            [vhosts.routes.proxy.error_pages.web]
            root = "/srv/fluxheim/errors"
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"), "{message}");
    assert!(
        message.contains("define [[vhosts.routes.proxy.error_pages]]"),
        "{message}"
    );
}

#[test]
fn config_parse_error_hints_singular_vhost_typo() {
    let dir = TestDir::new("config-singular-vhost-typo");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhost]]
            name = "bad"
            hosts = ["bad.example"]
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"));
    assert!(message.contains("hint: virtual hosts are configured with [[vhosts]]"));
}

#[test]
fn config_parse_error_hints_vhost_table_before_array() {
    let dir = TestDir::new("config-vhost-table-before-array");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [vhosts.proxy]
            upstreams = ["127.0.0.1:3000"]
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"), "{message}");
    assert!(
        message.contains("start each virtual host with [[vhosts]]"),
        "{message}"
    );
}

#[test]
fn config_parse_error_hints_proxy_array_table() {
    let dir = TestDir::new("config-vhost-proxy-array-table");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [[vhosts.proxy]]
            upstreams = ["127.0.0.1:3000"]
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"), "{message}");
    assert!(
        message.contains("uses [vhosts.proxy], not [[vhosts.proxy]]"),
        "{message}"
    );
}

#[test]
fn config_parse_error_hints_route_action_field() {
    let dir = TestDir::new("config-route-action-field");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [[vhosts.routes]]
            name = "app"
            path_prefix = "/"
            action = "proxy"
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"), "{message}");
    assert!(
        message.contains("routes select their action by defining one nested table"),
        "{message}"
    );
}

#[test]
fn config_parse_error_hints_route_table_before_array() {
    let dir = TestDir::new("config-route-table-before-array");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:3000"]
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"), "{message}");
    assert!(
        message.contains("start each route with [[vhosts.routes]]"),
        "{message}"
    );
}

#[test]
fn config_parse_error_hints_route_web_table_before_array() {
    let dir = TestDir::new("config-route-web-table-before-array");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [vhosts.routes.web]
            root = "/srv/sites/site"
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"), "{message}");
    assert!(
        message.contains("start each route with [[vhosts.routes]]"),
        "{message}"
    );
}

#[test]
fn config_parse_error_hints_route_proxy_array_table() {
    let dir = TestDir::new("config-route-proxy-array-table");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [[vhosts.routes]]
            name = "app"
            path_prefix = "/"

            [[vhosts.routes.proxy]]
            upstreams = ["127.0.0.1:3000"]
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"), "{message}");
    assert!(
        message.contains("route action/config tables use single-bracket tables"),
        "{message}"
    );
}

#[test]
fn config_parse_error_hints_route_web_array_table() {
    let dir = TestDir::new("config-route-web-array-table");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [[vhosts.routes]]
            name = "assets"
            path_prefix = "/assets/"

            [[vhosts.routes.web]]
            root = "/srv/sites/site/assets"
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"), "{message}");
    assert!(
        message.contains("route action/config tables use single-bracket tables"),
        "{message}"
    );
}

#[test]
fn config_parse_error_hints_plural_vhost_tls_certificate_table() {
    let dir = TestDir::new("config-plural-vhost-tls-certificates");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [vhosts.tls]
            enabled = true

            [[vhosts.tls.certificates]]
            cert_path = "/etc/fluxheim/tls/site/fullchain.pem"
            key_path = "/etc/fluxheim/tls/site/privkey.pem"
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"));
    assert!(message.contains("hint: vhost TLS uses [vhosts.tls.certificate]"));
}
