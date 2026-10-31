use super::*;

fn fragments(main: &str, extra: &str) -> (TestDir, Config) {
    let dir = TestDir::new("loader-guide-fragments");
    fs::create_dir(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        format!("include_conf_d = true\n{main}"),
    )
    .unwrap();
    fs::write(dir.child("conf.d/10-extra.toml"), extra).unwrap();
    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();
    (dir, config)
}

#[test]
fn documented_single_and_split_configuration_examples_load() {
    let dir = TestDir::new("loader-guide-examples");
    fs::create_dir_all(dir.child("site")).unwrap();
    fs::create_dir_all(dir.child("split/conf.d/site")).unwrap();
    for (path, contents) in [
        (
            "single.toml",
            include_str!("../../../examples/configuration/single.toml"),
        ),
        (
            "split/fluxheim.toml",
            include_str!("../../../examples/configuration/split/fluxheim.toml"),
        ),
        (
            "split/conf.d/10-site.toml",
            include_str!("../../../examples/configuration/split/conf.d/10-site.toml"),
        ),
    ] {
        fs::write(dir.child(path), contents).unwrap();
    }
    let single = Config::load(Some(&dir.child("single.toml"))).unwrap();
    assert_eq!(single.vhosts[0].web.root, Some(dir.child("site")));
    let file = Config::load(Some(&dir.child("split/fluxheim.toml"))).unwrap();
    let directory = Config::load(Some(&dir.child("split"))).unwrap();
    assert_eq!(file, directory);
    assert_eq!(
        file.vhosts[0].web.root,
        Some(dir.child("split/conf.d/site"))
    );
}

#[test]
fn documented_consolidated_limit_fragment_preserves_both_settings() {
    let guide = include_str!("../../../docs/guides/configuration.md");
    let fragment = guide
        .split("# Replace the earlier server.limits table with this complete policy.\n")
        .nth(1)
        .unwrap()
        .split("```")
        .next()
        .unwrap();
    let dir = TestDir::new("loader-guide-consolidated-limits");
    fs::create_dir(dir.child("site")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        format!(
            "{}\n{fragment}",
            include_str!("../../../examples/configuration/single.toml")
        ),
    )
    .unwrap();
    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();
    assert_eq!(config.server.limits.max_request_headers, 25);
    assert_eq!(
        config.server.limits.max_request_body_bytes.as_u64(),
        4 * 1024 * 1024
    );
}

#[test]
fn named_file_include_limit_counts_children_separately_from_main() {
    let dir = TestDir::new("loader-guide-include-bound");
    fs::create_dir(dir.child("conf.d")).unwrap();
    fs::write(dir.child("fluxheim.toml"), "include_conf_d = true\n").unwrap();
    for index in 0..crate::config_loader::MAX_CONFIG_DIRECTORY_FILES {
        fs::write(
            dir.child(&format!("conf.d/{index:03}.toml")),
            "# empty fragment\n",
        )
        .unwrap();
    }
    assert!(Config::load(Some(&dir.child("fluxheim.toml"))).is_ok());
    assert!(Config::load(Some(dir.path())).is_err());
    fs::write(dir.child("conf.d/999.toml"), "# one too many\n").unwrap();
    assert!(Config::load(Some(&dir.child("fluxheim.toml"))).is_err());
}

#[test]
fn directory_order_is_top_level_then_child_without_recursive_includes() {
    let dir = TestDir::new("loader-guide-order");
    fs::create_dir_all(dir.child("conf.d/conf.d")).unwrap();
    fs::write(
        dir.child("99-main.toml"),
        "[server]\nlisten = ['127.0.0.1:18080']",
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/00-child.TOML"),
        "include_conf_d = true\n[server]\nlisten = ['127.0.0.1:18081']",
    )
    .unwrap();
    for ignored in [".hidden.toml", "backup.toml.bak", "conf.d/conf.d/bad.toml"] {
        fs::write(dir.child(ignored), "not valid TOML").unwrap();
    }
    let config = Config::load(Some(dir.path())).unwrap();
    assert_eq!(config.server.listen, ["127.0.0.1:18081"]);
}

#[test]
fn named_file_does_not_read_sibling_top_level_toml() {
    let dir = TestDir::new("loader-guide-siblings");
    fs::write(dir.child("fluxheim.toml"), "include_conf_d = true\n").unwrap();
    fs::write(dir.child("backup.toml"), "not valid TOML").unwrap();
    assert!(Config::load(Some(&dir.child("fluxheim.toml"))).is_ok());
    assert!(Config::load(Some(dir.path())).is_err());
}

#[test]
fn repeated_vhost_declarations_are_not_patches() {
    let dir = TestDir::new("loader-guide-duplicate-vhost");
    for name in ["10-site.toml", "20-site.toml"] {
        fs::write(
            dir.child(name),
            "[[vhosts]]\nname = 'site'\nhosts = ['site.test']",
        )
        .unwrap();
    }
    assert!(matches!(
        Config::load(Some(dir.path())),
        Err(ConfigLoadError::Validate(_))
    ));
}

#[test]
fn empty_trusted_proxy_fragment_does_not_clear_earlier_entries() {
    let (_dir, config) = fragments(
        "[server]\ntrusted_proxies = ['127.0.0.1']",
        "[server]\ntrusted_proxies = []",
    );
    assert_eq!(config.server.trusted_proxies, ["127.0.0.1"]);
}

#[test]
fn relative_paths_are_literal_and_resolved_per_fragment() {
    let (dir, config) = fragments("", "[web]\nroot = '${SITE_ROOT}/public'");
    assert_eq!(
        config.web.root,
        Some(dir.child("conf.d").join("${SITE_ROOT}/public"))
    );
}

// documented contract: characterize replacement until the planned merge correction.
#[test]
fn partial_server_limits_fragment_resets_omitted_body_limit() {
    let (_dir, config) = fragments(
        "[server.limits]\nmax_request_body_bytes = 4",
        "[server.limits]\nmax_request_headers = 25",
    );
    assert_eq!(config.server.limits.max_request_headers, 25);
    assert_eq!(
        config.server.limits.max_request_body_bytes,
        ServerLimitsConfig::default().max_request_body_bytes
    );
    assert_ne!(config.server.limits.max_request_body_bytes.as_u64(), 4);
}

#[test]
fn partial_metrics_fragment_resets_omitted_token_setting() {
    let (_dir, config) = fragments(
        "[metrics]\ntoken_file = 'metrics.token'",
        "[metrics]\nlisten = '127.0.0.1:19091'",
    );
    assert_eq!(config.metrics.listen, "127.0.0.1:19091");
    assert_eq!(config.metrics.token_file, None);
}

#[test]
fn partial_logging_fragment_resets_omitted_format() {
    let (_dir, config) = fragments("[logging]\nformat = 'json'", "[logging]\nlevel = 'warn'");
    assert_eq!(config.logging.format, LoggingConfig::default().format);
    assert_eq!(config.logging.level, crate::LoggingLevel::Warn);
}

#[test]
fn partial_process_fragment_resets_explicit_pid_path() {
    let (_dir, config) = fragments(
        "[server.process]\npid_file = 'custom.pid'",
        "[server.process]\nthreads = 2",
    );
    assert_eq!(config.server.process.threads, 2);
    assert_eq!(
        config.server.process.pid_file,
        ServerConfig::default().process.pid_file
    );
}
