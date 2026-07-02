use super::super::*;

#[test]
fn rejects_zero_memory_cache_size_when_enabled() {
    let config: Config = toml::from_str(
        r#"
            [cache.memory]
            enabled = true
            max_size_bytes = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheTierMaxSize {
            field: "cache.memory.max_size_bytes".to_owned()
        })
    );
}

#[test]
fn rejects_cache_tier_smaller_than_max_object() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            max_object_bytes = "64MiB"

            [cache.memory]
            enabled = true
            max_size_bytes = "32MiB"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::CacheTierSmallerThanMaxObject {
            tier: "cache.memory".to_owned()
        })
    );
}
