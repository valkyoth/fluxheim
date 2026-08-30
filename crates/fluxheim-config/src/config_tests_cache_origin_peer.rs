use super::super::*;

#[test]
#[cfg(feature = "cache")]
fn parses_cache_origin_protection_config() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            enabled = true
            max_object_bytes = "8MiB"

            [cache.memory]
            enabled = true
            max_size_bytes = "16MiB"

            [cache.origin_protection]
            enabled = true
            max_concurrent_fills = 8
            "#,
    )
    .unwrap();

    assert_eq!(
        config.cache.origin_protection,
        CacheOriginProtectionConfig {
            enabled: true,
            max_concurrent_fills: 8,
        }
    );
    config.validate().unwrap();
}

#[test]
#[cfg(feature = "cache")]
fn rejects_cache_origin_protection_without_enabled_cache_policy() {
    let config: Config = toml::from_str(
        r#"
            [cache.origin_protection]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheOriginProtectionPolicy {
            scope: "cache",
            field: "origin_protection.enabled",
            reason: "origin protection requires the cache policy to be enabled",
        })
    );
}

#[test]
#[cfg(feature = "cache")]
fn rejects_invalid_cache_origin_protection_fill_budget() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            enabled = true

            [cache.memory]
            enabled = true
            max_size_bytes = "16MiB"

            [cache.origin_protection]
            enabled = true
            max_concurrent_fills = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheOriginProtectionPolicy {
            scope: "cache",
            field: "origin_protection.max_concurrent_fills",
            reason: "max concurrent fills must be between 1 and 1024",
        })
    );
}

#[test]
#[cfg(feature = "cache")]
fn parses_cache_peer_fill_config() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "/var/cache/fluxheim/example"

            [cache.peer_fill]
            enabled = true
            connect_timeout_secs = 3
            read_timeout_secs = 12
            max_object_bytes = "64MiB"
            max_concurrent_requests = 32
            shared_secret_file = "/run/secrets/fluxheim-peer-fill"
            fail_open = false

            [[cache.peer_fill.peers]]
            name = "node-a"
            base_url = "https://node-a.example.internal:8443"

            [[cache.peer_fill.peers]]
            name = "local"
            base_url = "http://127.0.0.1:8080"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.cache.peer_fill,
        CachePeerFillConfig {
            enabled: true,
            peers: vec![
                CachePeerConfig {
                    name: "node-a".to_owned(),
                    base_url: "https://node-a.example.internal:8443".to_owned(),
                },
                CachePeerConfig {
                    name: "local".to_owned(),
                    base_url: "http://127.0.0.1:8080".to_owned(),
                },
            ],
            connect_timeout_secs: 3,
            read_timeout_secs: 12,
            max_object_bytes: Some(ByteSize(64 * 1024 * 1024)),
            max_concurrent_requests: 32,
            allow_insecure_http: false,
            shared_secret_file: Some("/run/secrets/fluxheim-peer-fill".into()),
            fail_open: false,
        }
    );
}

#[test]
#[cfg(feature = "cache")]
fn rejects_cache_peer_fill_without_enabled_cache_policy() {
    let config: Config = toml::from_str(
        r#"
            [cache.peer_fill]
            enabled = true

            [[cache.peer_fill.peers]]
            name = "node-a"
            base_url = "https://node-a.example.internal:8443"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCachePeerFillPolicy {
            scope: "cache",
            field: "peer_fill.enabled",
            reason: "peer fill requires the cache policy to be enabled",
        })
    );
}

#[test]
#[cfg(feature = "cache")]
fn rejects_unsafe_cache_peer_fill_peers() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            enabled = true

            [cache.memory]
            enabled = true

            [cache.peer_fill]
            enabled = true

            [[cache.peer_fill.peers]]
            name = "node-a"
            base_url = "http://node-a.example.internal:8080"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCachePeerFillPeer {
            scope: "cache",
            peer: "node-a".to_owned(),
            reason: "http peer base_url is allowed only for loopback peers unless allow_insecure_http = true",
        })
    );

    let shared_secret_file = safe_child_path(
        &secure_test_dir("cache-peer-duplicate-name-secret"),
        "shared-secret",
    );
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.memory]
            enabled = true

            [cache.peer_fill]
            enabled = true
            allow_insecure_http = true
            shared_secret_file = '{}'

            [[cache.peer_fill.peers]]
            name = "node-a"
            base_url = "http://node-a.example.internal:8080"

            [[cache.peer_fill.peers]]
            name = "node-a"
            base_url = "https://node-b.example.internal:8443"
            "#,
        shared_secret_file.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::DuplicateCachePeerFillPeerName {
            scope: "cache",
            name: "node-a".to_owned(),
        })
    );
}

#[test]
#[cfg(feature = "cache")]
fn rejects_non_loopback_http_cache_peer_fill_without_shared_secret() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            enabled = true

            [cache.memory]
            enabled = true

            [cache.peer_fill]
            enabled = true
            allow_insecure_http = true

            [[cache.peer_fill.peers]]
            name = "node-a"
            base_url = "http://node-a.example.internal:8080"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCachePeerFillPeer {
            scope: "cache",
            peer: "node-a".to_owned(),
            reason: "non-loopback http peer base_url requires peer_fill.shared_secret_file",
        })
    );
}

#[test]
#[cfg(feature = "cache")]
fn parses_cache_purger_config() {
    let config: Config = toml::from_str(
        r#"
            [cache_purger]
            enabled = true
            interval_secs = 60
            limit = 1000
            batches = 4
            "#,
    )
    .unwrap();

    assert_eq!(
        config.cache_purger,
        CachePurgerConfig {
            enabled: true,
            interval_secs: 60,
            limit: 1000,
            batches: 4,
        }
    );
    config.validate().unwrap();
}

#[test]
fn rejects_invalid_cache_purger_limits() {
    let config: Config = toml::from_str(
        r#"
            [cache_purger]
            interval_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCachePurgerPolicy {
            field: "cache_purger.interval_secs",
            reason: "interval must be between 1 and 86400 seconds",
        })
    );

    let config: Config = toml::from_str(
        r#"
            [cache_purger]
            limit = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCachePurgerPolicy {
            field: "cache_purger.limit",
            reason: "limit must be between 1 and 100000 indexed entries",
        })
    );

    let config: Config = toml::from_str(
        r#"
            [cache_purger]
            batches = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCachePurgerPolicy {
            field: "cache_purger.batches",
            reason: "batches must be between 1 and 100",
        })
    );
}

#[test]
#[cfg(not(feature = "cache"))]
fn rejects_enabled_cache_purger_without_cache_feature() {
    let config: Config = toml::from_str(
        r#"
            [cache_purger]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(config.validate(), Err(ConfigError::CachePurgerNotCompiled));
}
