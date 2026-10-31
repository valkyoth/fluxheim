use super::*;

#[test]
fn documented_service_lifecycle_example_loads_with_relative_paths() {
    let dir = TestDir::new("process-guide-example");
    fs::create_dir(dir.child("site")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        include_str!("../../../examples/service-lifecycle/fluxheim.toml"),
    )
    .unwrap();
    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();
    let process = &config.server.process;
    assert_eq!(process.threads, 2);
    assert_eq!(process.upstream_keepalive_pool_size, 128);
    assert_eq!(process.grace_period_seconds, Some(2));
    assert_eq!(process.graceful_shutdown_timeout_seconds, Some(5));
    assert_eq!(process.pid_file, dir.child("fluxheim.pid"));
    assert_eq!(process.upgrade_sock, dir.child("upgrade.sock"));
    assert_eq!(process.certificate_reload_sock, dir.child("reload.sock"));
    assert_eq!(config.vhosts[0].web.root, Some(dir.child("site")));
    assert!(!config.cache.enabled);
}

#[test]
fn documented_process_numeric_bounds_are_enforced() {
    for (field, low, high) in [
        ("threads", 1, 1024),
        ("listener_tasks_per_fd", 1, 1024),
        ("upstream_keepalive_pool_size", 1, 16384),
        ("max_retries", 0, 1024),
    ] {
        for value in [low, high] {
            let config: Config =
                toml::from_str(&format!("[server.process]\n{field} = {value}")).unwrap();
            config.validate().unwrap();
        }
        for value in [low - 1, high + 1] {
            let source = format!("[server.process]\n{field} = {value}");
            if value < 0 {
                assert!(toml::from_str::<Config>(&source).is_err());
            } else {
                let config: Config = toml::from_str(&source).unwrap();
                assert!(matches!(
                    config.validate(),
                    Err(ConfigError::InvalidProcessSetting { .. })
                ));
            }
        }
    }
    for field in ["grace_period_seconds", "graceful_shutdown_timeout_seconds"] {
        for (value, accepted) in [(0, false), (1, true), (3600, true)] {
            let config: Config =
                toml::from_str(&format!("[server.process]\n{field} = {value}")).unwrap();
            assert_eq!(config.validate().is_ok(), accepted, "{field}={value}");
        }
    }
    let process = ServerConfig::default().process;
    assert_eq!(process.grace_period_seconds, None);
    assert_eq!(process.graceful_shutdown_timeout_seconds, None);
}
