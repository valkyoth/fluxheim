use super::super::*;

const LOCAL: &str = include_str!("../../../examples/load-balancer/local.toml");

#[test]
fn load_balancer_guide_selectors_validate_with_required_keys() {
    for selection in [
        "round-robin",
        "least-connections",
        "least-sessions",
        "least-time",
        "power-of-two",
        "source-hash",
        "uri-hash",
        "header-hash",
        "cookie-hash",
        "consistent-source-hash",
        "consistent-uri-hash",
        "consistent-header-hash",
        "consistent-cookie-hash",
        "bounded-load-consistent-source-hash",
        "bounded-load-consistent-uri-hash",
        "bounded-load-consistent-header-hash",
        "bounded-load-consistent-cookie-hash",
        "nginx-consistent-source-hash",
        "nginx-consistent-uri-hash",
        "nginx-consistent-header-hash",
        "nginx-consistent-cookie-hash",
        "maglev-source-hash",
        "maglev-uri-hash",
        "maglev-header-hash",
        "maglev-cookie-hash",
        "weighted-least-connections",
        "ratio-least-connections",
        "least-session",
        "power-of-two-choices",
        "two-choice",
        "weighted-two-choice",
        "weighted-random-two-choice",
        "ketama",
        "ketama-source-hash",
        "nginx-consistent-hash",
        "ketama-uri-hash",
        "ketama-header-hash",
        "ketama-cookie-hash",
        "maglev",
        "maglev-hash",
    ] {
        let mut value: toml::Value = toml::from_str(LOCAL).unwrap();
        value["proxy"]["load_balance"]["selection"] = selection.into();
        let mut config: Config = value.try_into().unwrap();
        let _process_root = crate::config::tests::prepare_guide_process_paths(&mut config);
        if selection.contains("header-hash") {
            config.proxy.load_balance.hash_header = Some("x-session".to_owned());
        }
        if selection.contains("cookie-hash") {
            config.proxy.load_balance.hash_cookie = Some("session".to_owned());
        }
        if selection.starts_with("least-session") {
            config.proxy.load_balance.persistence.enabled = true;
            if cfg!(feature = "privacy-mode") {
                assert!(config.validate().is_err());
                continue;
            }
        }
        config
            .validate()
            .unwrap_or_else(|error| panic!("{selection}: {error}"));
    }
}

fn merge(base: &mut toml::Value, fragment: toml::Value) {
    match (base, fragment) {
        (toml::Value::Table(base), toml::Value::Table(fragment)) => {
            for (key, value) in fragment {
                if let Some(existing) = base.get_mut(&key) {
                    merge(existing, value);
                } else {
                    base.insert(key, value);
                }
            }
        }
        (base, fragment) => *base = fragment,
    }
}

#[test]
fn load_balancer_guide_local_and_merged_recipes_validate() {
    let base: toml::Value = toml::from_str(LOCAL).unwrap();
    let mut config: Config = base.clone().try_into().unwrap();
    let _process_root = crate::config::tests::prepare_guide_process_paths(&mut config);
    config.validate().unwrap();
    for recipe in [
        include_str!("../../../examples/load-balancer/pool-policy.toml"),
        include_str!("../../../examples/load-balancer/queue-passive.toml"),
        include_str!("../../../examples/load-balancer/http-health.toml"),
        include_str!("../../../examples/load-balancer/retry-contract.toml"),
    ] {
        let mut value = base.clone();
        merge(&mut value, toml::from_str(recipe).unwrap());
        let mut config: Config = value.try_into().unwrap();
        let _process_root = crate::config::tests::prepare_guide_process_paths(&mut config);
        config.validate().unwrap();
    }
}

#[test]
#[cfg(not(feature = "privacy-mode"))]
fn load_balancer_guide_managed_cookie_recipe_validates() {
    let mut value: toml::Value = toml::from_str(LOCAL).unwrap();
    merge(
        &mut value,
        toml::from_str(include_str!(
            "../../../examples/load-balancer/managed-cookie.toml"
        ))
        .unwrap(),
    );
    let mut config: Config = value.try_into().unwrap();
    let _process_root = crate::config::tests::prepare_guide_process_paths(&mut config);
    config.validate().unwrap();
}

#[test]
fn load_balancer_guide_discovery_recipes_replace_static_pool() {
    for recipe in [
        include_str!("../../../examples/load-balancer/discovery-file.toml"),
        include_str!("../../../examples/load-balancer/discovery-http.toml"),
        include_str!("../../../examples/load-balancer/discovery-dns.toml"),
    ] {
        let mut base: toml::Value = toml::from_str(LOCAL).unwrap();
        let fragment: toml::Value = toml::from_str(recipe).unwrap();
        base["proxy"] = fragment["proxy"].clone();
        let mut config: Config = base.try_into().unwrap();
        let _process_root = crate::config::tests::prepare_guide_process_paths(&mut config);
        let root = secure_test_dir("lb-guide-discovery");
        if config.proxy.upstreams_file.is_some() {
            let path = safe_child_path(&root, "backends.txt");
            fs::write(
                &path,
                include_str!("../../../examples/load-balancer/backends.txt"),
            )
            .unwrap();
            config.proxy.upstreams_file = Some(path);
        }
        #[cfg(feature = "load-balancer")]
        config.validate().unwrap();
        #[cfg(not(feature = "load-balancer"))]
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn load_balancer_guide_invalid_overlays_are_rejected() {
    for recipe in [
        "[proxy]\nupstream_weights = [1]",
        "[proxy.load_balance.queue]\nmax_waiting = 1\ntimeout_ms = 0",
        "[proxy.load_balance.retry]\nenabled = true\nbudget_per_window = 1\nmethods = ['POST']",
        "[proxy.load_balance]\nselection = 'header-hash'",
        "[proxy.load_balance.persistence]\nmode = 'managed-cookie'\ncookie = 'affinity'\nmanaged_cookie_same_site = 'none'\nmanaged_cookie_secure = false",
    ] {
        let mut value: toml::Value = toml::from_str(LOCAL).unwrap();
        merge(&mut value, toml::from_str(recipe).unwrap());
        let mut config: Config = value.try_into().unwrap();
        let _process_root = crate::config::tests::prepare_guide_process_paths(&mut config);
        assert!(
            config.validate().is_err(),
            "accepted invalid recipe: {recipe}"
        );
    }
}
