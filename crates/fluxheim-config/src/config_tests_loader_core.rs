use super::*;

#[test]
fn loads_config_directory_in_sorted_order() {
    let dir = TestDir::new("config-dir");
    fs::create_dir_all(dir.child("site")).unwrap();
    fs::write(
        dir.child("00-server.toml"),
        r#"
            [server]
            listen = ["127.0.0.1:19090"]
            default_vhost = "example"
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("10-vhost.toml"),
        r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.web]
            root = "site"
            "#,
    )
    .unwrap();
    fs::write(dir.child(".ignored.toml"), "this is not toml").unwrap();
    fs::write(dir.child("ignored.txt"), "ignored").unwrap();

    let config = Config::load(Some(dir.path())).unwrap();

    assert_eq!(config.server.listen, ["127.0.0.1:19090"]);
    assert_eq!(config.server.default_vhost, Some("example".to_owned()));
    assert_eq!(config.vhosts.len(), 1);
    assert_eq!(config.vhosts[0].web.root, Some(dir.child("site")));
}

#[test]
fn loading_main_config_file_also_loads_sibling_conf_d() {
    let dir = TestDir::new("config-file-with-conf-d");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::create_dir_all(dir.child("conf.d/site")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [server]
            listen = ["127.0.0.1:19090"]
            default_vhost = "example"
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/10-vhost.toml"),
        r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.web]
            root = "site"
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(config.server.default_vhost, Some("example".to_owned()));
    assert_eq!(config.vhosts.len(), 1);
    assert_eq!(config.vhosts[0].web.root, Some(dir.child("conf.d/site")));
}

#[test]
fn conf_d_server_trusted_proxies_extend_without_replacing_main_list() {
    let dir = TestDir::new("config-file-with-conf-d-trusted-proxies");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [server]
            listen = ["127.0.0.1:19090"]
            trusted_proxies = ["10.0.0.1/32"]
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/10-proxies.toml"),
        r#"
            [server]
            trusted_proxies = ["10.0.0.2/32", "10.0.0.1/32"]
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(
        config.server.trusted_proxies,
        ["10.0.0.1/32", "10.0.0.2/32"]
    );
}

#[test]
fn conf_d_server_trusted_proxies_reject_global_replacement_attempt() {
    let dir = TestDir::new("config-file-with-conf-d-global-trusted-proxy");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [server]
            listen = ["127.0.0.1:19090"]
            trusted_proxies = ["10.0.0.1/32"]
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/99-broad-trust.toml"),
        r#"
            [server]
            trusted_proxies = ["0.0.0.0/0"]
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();
    assert!(error.to_string().contains("0.0.0.0/0"));
}
