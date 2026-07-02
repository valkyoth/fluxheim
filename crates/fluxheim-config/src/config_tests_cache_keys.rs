use super::super::*;

#[test]
fn rejects_invalid_cache_key_namespace() {
    for namespace in ["", "bad namespace", "bad/namespace", "bad;namespace"]
        .into_iter()
        .map(str::to_owned)
        .chain(std::iter::once("x".repeat(129)))
    {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                key_namespace = {namespace:?}
                "#
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheKeyNamespace {
                scope: "cache",
                namespace: namespace.to_owned(),
            }),
            "{namespace:?}"
        );
    }
}

#[test]
fn rejects_empty_cache_key_parts() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            key_parts = []
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::EmptyCacheKeyParts { scope: "cache" })
    );
}

#[test]
fn rejects_too_many_cache_key_parts() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            key_parts = ["method", "host", "path", "query", "path"]
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("cache.key_parts"), "{error}");
    assert!(error.contains("at most 4 entries"), "{error}");
}

#[test]
fn route_cache_wraps_too_many_key_parts() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [[vhosts.routes]]
            name = "assets"
            path_prefix = "/assets/"

            [vhosts.routes.proxy]
            upstream = "127.0.0.1:3000"

            [vhosts.routes.cache]
            key_parts = ["method", "host", "path", "query", "path"]
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("vhost \"gateway\" route \"assets\" cache:"),
        "{error}"
    );
    assert!(error.contains("vhosts.routes.cache.key_parts"), "{error}");
    assert!(error.contains("at most 4 entries"), "{error}");
}

#[test]
fn rejects_duplicate_cache_key_parts() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            key_parts = ["method", "path", "path"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::DuplicateCacheKeyPart {
            scope: "cache",
            part: CacheKeyPart::Path,
        })
    );
}

#[test]
fn rejects_cache_key_parts_without_path() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            key_parts = ["method", "host"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::MissingCacheKeyPath { scope: "cache" })
    );
}

#[test]
fn rejects_invalid_cache_status_ttl() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            status_ttls = { "99" = 60 }
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheStatusTtl {
            scope: "cache",
            status: 99,
            ttl_secs: 60,
        })
    );

    let config: Config = toml::from_str(
        r#"
            [cache]
            status_ttls = { "200" = 0 }
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheStatusTtl {
            scope: "cache",
            status: 200,
            ttl_secs: 0,
        })
    );
}

#[test]
fn rejects_invalid_cache_min_uses() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            min_uses = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheMinUses { scope: "cache" })
    );
}

#[test]
fn rejects_zero_cache_range_max_bytes() {
    let config: Config = toml::from_str(
        r#"
            [cache.range]
            max_bytes = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheRangePolicy {
            scope: "cache",
            field: "range.max_bytes",
            reason: "max bytes must be greater than zero",
        })
    );
}

#[test]
fn rejects_cache_range_larger_than_cache_object_limit() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            max_object_bytes = "1MiB"

            [cache.range]
            enabled = true
            max_bytes = "2MiB"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheRangePolicy {
            scope: "cache",
            field: "range.max_bytes",
            reason: "max bytes must not exceed max_object_bytes",
        })
    );
}

#[test]
fn rejects_invalid_cache_default_status_ttl() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            default_status_ttl_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheDefaultStatusTtl { scope: "cache" })
    );
}

#[test]
fn rejects_invalid_cache_stale_if_error_ttl() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            stale_if_error_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheStaleIfErrorTtl { scope: "cache" })
    );
}

#[test]
fn rejects_empty_cache_stale_if_error_on_when_error_stale_is_enabled() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            stale_if_error_secs = 30
            stale_if_error_on = []
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::EmptyCacheStaleIfErrorOn { scope: "cache" })
    );
}

#[test]
fn rejects_invalid_cache_stale_if_error_statuses() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            stale_if_error_statuses = [404]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheStaleIfErrorStatus {
            scope: "cache",
            status: 404,
        })
    );
}

#[test]
fn rejects_invalid_cache_stale_while_revalidate_ttl() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            stale_while_revalidate_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheStaleWhileRevalidateTtl { scope: "cache" })
    );
}

#[test]
fn rejects_duplicate_cache_tag_headers() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            tag_headers = ["Surrogate-Key", "surrogate-key"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::DuplicateCacheTagHeader {
            scope: "cache",
            header: "surrogate-key".to_owned(),
        })
    );
}

#[test]
fn rejects_invalid_cache_content_type() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            content_types = []
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::EmptyCacheContentTypes { scope: "cache" })
    );

    for content_type in ["image", "*/json", "image/p*ng", "text/html; charset=utf-8"] {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                content_types = [{content_type:?}]
                "#
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheContentType {
                scope: "cache",
                content_type: content_type.to_owned(),
            }),
            "{content_type}"
        );
    }
}

#[test]
fn rejects_invalid_cache_lock_timeout() {
    let config: Config = toml::from_str(
        r#"
            [cache.lock]
            age_timeout_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheLockTimeout {
            field: "cache.lock.age_timeout_secs".to_owned()
        })
    );

    let config: Config = toml::from_str(
        r#"
            [cache.lock]
            wait_timeout_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheLockTimeout {
            field: "cache.lock.wait_timeout_secs".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_cache_predictor_capacity() {
    let config: Config = toml::from_str(
        r#"
            [cache.predictor]
            enabled = true
            capacity = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCachePredictorCapacity { scope: "cache" })
    );
}
