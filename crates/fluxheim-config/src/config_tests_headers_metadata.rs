use super::super::*;
use crate::{ResponseMetadataConfig, ResponseMetadataOverlayConfig};

#[test]
fn parses_opt_in_response_metadata_policy() {
    let config: Config = toml::from_str(
        r#"
            [headers.response.metadata]
            identifier = "edge-gateway"
            cache_status = true
            proxy_status = true
            content_digest = true
            repr_digest = true
        "#,
    )
    .unwrap();

    let metadata = &config.headers.response.metadata;
    assert_eq!(metadata.identifier.as_deref(), Some("edge-gateway"));
    assert!(metadata.cache_status);
    assert!(metadata.proxy_status);
    assert!(metadata.content_digest);
    assert!(metadata.repr_digest);
    config.validate().unwrap();
}

#[test]
fn rejects_status_metadata_without_deployment_identifier() {
    let config: Config = toml::from_str(
        r#"
            [headers.response.metadata]
            proxy_status = true
        "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidResponseHeaderValue {
            field: "headers.response.metadata"
        })
    ));
}

#[test]
fn response_metadata_overlay_inherits_identifier_and_overrides_fields() {
    let mut base = ResponseMetadataConfig {
        identifier: Some("edge-gateway".to_owned()),
        cache_status: true,
        ..ResponseMetadataConfig::default()
    };
    base.apply_overlay(&ResponseMetadataOverlayConfig {
        cache_status: Some(false),
        content_digest: Some(true),
        ..ResponseMetadataOverlayConfig::default()
    });

    assert_eq!(base.identifier.as_deref(), Some("edge-gateway"));
    assert!(!base.cache_status);
    assert!(base.content_digest);
}

#[test]
fn rejects_non_token_response_metadata_identifier() {
    let config: Config = toml::from_str(
        r#"
            [headers.response.metadata]
            identifier = "edge gateway"
            cache_status = true
        "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidResponseHeaderValue {
            field: "headers.response.metadata"
        })
    ));
}
