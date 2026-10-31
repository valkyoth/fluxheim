use super::super::*;

const LOCAL: &str = include_str!("../../../examples/cache/local.toml");

#[test]
fn cache_guide_memory_and_disk_recipes_validate() {
    for overlay in [
        "",
        include_str!("../../../examples/cache/filesystem.toml"),
        include_str!("../../../examples/cache/storage-bin.toml"),
    ] {
        let mut config: Config = toml::from_str(&format!("{LOCAL}\n{overlay}")).unwrap();
        let root = secure_test_dir("cache-guide-disk");
        if config.cache.disk.enabled {
            config.cache.disk.path = Some(root.clone());
        }
        config.validate().unwrap();
        if config.cache.disk.enabled {
            config.cache.memory.enabled = false;
            config.validate().unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn cache_guide_policy_overlay_preserves_admission_and_tier() {
    let mut value: toml::Value = toml::from_str(LOCAL).unwrap();
    let overlay: toml::Value =
        toml::from_str(include_str!("../../../examples/cache/policy.toml")).unwrap();
    for (key, field) in overlay["cache"].as_table().unwrap() {
        value["cache"]
            .as_table_mut()
            .unwrap()
            .insert(key.clone(), field.clone());
    }
    let config: Config = toml::from_str(&toml::to_string(&value).unwrap()).unwrap();
    config.validate().unwrap();
    assert!(config.cache.enabled && config.cache.memory.enabled);
    assert_eq!(config.cache.bypass_request_headers, ["cookie"]);
    assert_eq!(config.cache.min_uses, 2);
    assert_eq!(config.cache.status_ttls.get(&404), Some(&15));
    assert_eq!(config.cache.origin_protection.max_concurrent_fills, 4);
}

#[test]
fn cache_guide_static_recipe_validates() {
    let mut config: Config =
        toml::from_str(include_str!("../../../examples/cache/static.toml")).unwrap();
    let root = secure_test_dir("cache-guide-static");
    config.web.root = Some(root.clone());
    config.validate().unwrap();
    assert!(config.cache.local_static && config.cache.memory.enabled);
    assert!(!config.cache.disk.enabled);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cache_guide_rejects_no_tier_and_sensitive_variance() {
    let mut config: Config = toml::from_str(LOCAL).unwrap();
    config.cache.memory.enabled = false;
    assert!(config.validate().is_err());
    config.cache.memory.enabled = true;
    for header in ["cookie", "authorization", "proxy-authorization"] {
        config.cache.vary_request_headers = vec![header.to_owned()];
        assert!(config.validate().is_err(), "{header}");
    }
}

#[test]
fn cache_guide_phase_error_settings_are_accepted() {
    let mut config: Config = toml::from_str(LOCAL).unwrap();
    config.cache.stale_if_error_secs = Some(60);
    for kind in [
        CacheStaleErrorKind::Read,
        CacheStaleErrorKind::Write,
        CacheStaleErrorKind::Tls,
    ] {
        config.cache.stale_if_error_on = vec![kind];
        config.validate().unwrap();
    }
}

#[test]
fn cache_guide_advanced_checked_in_examples_validate() {
    for (name, recipe) in [
        (
            "slice",
            include_str!("../../../examples/cache-slice-range.toml"),
        ),
        (
            "peer",
            include_str!("../../../examples/cache-peer-fill.toml"),
        ),
        (
            "local-key",
            include_str!("../../../examples/cache-encryption-local.toml"),
        ),
        (
            "openbao",
            include_str!("../../../examples/cache-encryption-openbao.toml"),
        ),
    ] {
        let mut config: Config = toml::from_str(recipe).unwrap();
        assert!(
            config.vhosts[0].cache.enabled,
            "{name}: named vhost must own its cache"
        );
        let root = secure_test_dir("cache-advanced-guide");
        if config.cache.disk.enabled {
            config.cache.disk.path = Some(root.clone());
        }
        for vhost in &mut config.vhosts {
            if vhost.cache.disk.enabled {
                vhost.cache.disk.path = Some(root.clone());
            }
        }
        if name == "peer" && !cfg!(feature = "cache") {
            assert!(matches!(config.validate(), Err(ConfigError::VhostSection {
                section: "cache", source, ..
            }) if matches!(*source, ConfigError::CachePeerFillNotCompiled)));
        } else {
            config
                .validate()
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        }
        if name == "slice" {
            assert!(config.vhosts[0].cache.memory.enabled && !config.vhosts[0].cache.disk.enabled);
            assert_eq!(config.vhosts[0].proxy.upstreams.len(), 1);
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn cache_guide_operations_explicitly_configures_vhost_tiers() {
    let mut config: Config = toml::from_str(&format!(
        "{LOCAL}\n{}",
        include_str!("../../../examples/cache/operations.toml")
    ))
    .unwrap();
    let root = secure_test_dir("cache-guide-operations");
    config.vhosts[0].cache.disk.path = Some(root.clone());
    config.validate().unwrap();
    let cache = &config.vhosts[0].cache;
    assert!(cache.enabled && cache.memory.enabled && cache.disk.enabled);
    assert_eq!(cache.bypass_request_headers, ["cookie"]);
    assert_eq!(cache.status_ttls.get(&200), Some(&120));
    fs::remove_dir_all(root).unwrap();
}
