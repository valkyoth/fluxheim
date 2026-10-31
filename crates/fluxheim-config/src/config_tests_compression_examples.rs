use crate::{ByteSize, Config};

#[test]
fn compression_recipe_validates_and_bounds_every_enabled_policy() {
    let config: Config =
        toml::from_str(include_str!("../../../examples/compression/local.toml")).unwrap();
    config.validate().unwrap();
    assert!(config.vhosts[0].compression.is_none());
    assert!(config.vhosts[0].routes[0].compression.is_none());
    assert!(
        !config.vhosts[0].routes[1]
            .compression
            .as_ref()
            .unwrap()
            .enabled
    );
    for case in 0..9 {
        let mut invalid = config.clone();
        let policy = &mut invalid.compression;
        match case {
            0 => policy.gzip = false,
            1 => policy.min_bytes = ByteSize::from_bytes(0),
            2 => policy.min_bytes = ByteSize::from_bytes(2 * 1024 * 1024),
            3 => policy.max_input_bytes = ByteSize::from_bytes(64 * 1024 * 1024 + 1),
            4 => policy.max_output_bytes = ByteSize::from_bytes(128 * 1024 * 1024 + 1),
            5 => policy.max_output_bytes = ByteSize::from_bytes(1),
            6 => policy.gzip_level = 10,
            7 => policy.zstd_level = 20,
            _ => policy.brotli_quality = 12,
        }
        assert!(invalid.validate().is_err(), "case {case}");
    }
}

#[test]
fn declaring_a_child_compression_block_uses_defaults_not_parent_fields() {
    let source = include_str!("../../../examples/compression/local.toml")
        .replace("gzip_level = 4", "gzip_level = 8")
        .replace(
            "[vhosts.routes.compression]\nenabled = false",
            "[vhosts.routes.compression]\nenabled = true",
        );
    let config: Config = toml::from_str(&source).unwrap();
    config.validate().unwrap();
    assert_eq!(config.compression.gzip_level, 8);
    assert_eq!(
        config.vhosts[0].routes[1]
            .compression
            .as_ref()
            .unwrap()
            .gzip_level,
        4
    );
}
