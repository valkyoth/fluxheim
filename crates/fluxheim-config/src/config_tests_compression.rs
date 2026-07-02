use super::*;

#[test]
fn compression_config_validates_bounds() {
    let config: Config = toml::from_str(
        r#"
            [compression]
            enabled = true
            gzip = true
            zstd = true
            brotli = true
            min_bytes = "2KiB"
            max_input_bytes = "4KiB"
            max_output_bytes = "8KiB"
            gzip_level = 6
            zstd_level = 5
            brotli_quality = 5
            "#,
    )
    .unwrap();

    assert_eq!(config.compression.min_bytes.as_u64(), 2048);
    assert_eq!(config.compression.max_output_bytes.as_u64(), 8192);
    assert!(config.compression.zstd);
    assert!(config.compression.brotli);
    assert_eq!(config.compression.zstd_level, 5);
    assert_eq!(config.compression.brotli_quality, 5);
    config.validate().unwrap();

    let invalid_level: Config = toml::from_str(
        r#"
            [compression]
            enabled = true
            gzip_level = 10
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_level.validate(),
        Err(ConfigError::InvalidCompressionPolicy {
            field: "compression.gzip_level"
        })
    ));

    let invalid_zstd_level: Config = toml::from_str(
        r#"
            [compression]
            enabled = true
            zstd_level = 20
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_zstd_level.validate(),
        Err(ConfigError::InvalidCompressionPolicy {
            field: "compression.zstd_level"
        })
    ));

    let invalid_brotli_quality: Config = toml::from_str(
        r#"
            [compression]
            enabled = true
            brotli_quality = 12
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_brotli_quality.validate(),
        Err(ConfigError::InvalidCompressionPolicy {
            field: "compression.brotli_quality"
        })
    ));

    let invalid_bounds: Config = toml::from_str(
        r#"
            [compression]
            enabled = true
            min_bytes = "8KiB"
            max_input_bytes = "4KiB"
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_bounds.validate(),
        Err(ConfigError::InvalidCompressionPolicy {
            field: "compression.min_bytes"
        })
    ));

    let invalid_output_bounds: Config = toml::from_str(
        r#"
            [compression]
            enabled = true
            min_bytes = "8KiB"
            max_input_bytes = "16KiB"
            max_output_bytes = "4KiB"
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_output_bounds.validate(),
        Err(ConfigError::InvalidCompressionPolicy {
            field: "compression.max_output_bytes"
        })
    ));

    let vhost_override: Config = toml::from_str(
        r#"
            [compression]
            enabled = false

            [[vhosts]]
            name = "docs"
            hosts = ["docs.example"]

            [vhosts.compression]
            enabled = true
            gzip = false
            zstd = true
            min_bytes = "1KiB"
            max_input_bytes = "2MiB"
            "#,
    )
    .unwrap();
    vhost_override.validate().unwrap();
    let compression = vhost_override.vhosts[0].compression.as_ref().unwrap();
    assert!(compression.enabled);
    assert!(!compression.gzip);
    assert!(compression.zstd);

    let route_override: Config = toml::from_str(
        r#"
            [compression]
            enabled = false

            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [vhosts.compression]
            enabled = false

            [[vhosts.routes]]
            name = "uploads"
            path_prefix = "/wp-content/uploads/"

            [vhosts.routes.proxy]
            upstream = "127.0.0.1:8080"

            [vhosts.routes.compression]
            enabled = true
            gzip = true
            min_bytes = "1KiB"
            max_input_bytes = "2MiB"
            "#,
    )
    .unwrap();
    route_override.validate().unwrap();
    let route_compression = route_override.vhosts[0].routes[0]
        .compression
        .as_ref()
        .unwrap();
    assert!(route_compression.enabled);
    assert!(route_compression.gzip);
}
