use super::*;

#[test]
fn rejects_invalid_response_header_value() {
    let config: Config = toml::from_str(
        r#"
            [headers.response]
            x_frame_options = "DENY\nx-bad: injected"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidResponseHeaderValue {
            field: "headers.response.x_frame_options"
        })
    );
}

#[test]
fn rejects_invalid_generic_header_name() {
    let config: Config = toml::from_str(
        r#"
            [headers.response.set]
            "bad header" = "value"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "headers.response",
            name: "bad header".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_generic_header_value() {
    let config: Config = toml::from_str(
        r#"
            [headers.request.set]
            x-test = "ok\nx-bad: injected"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderValue {
            field: "headers.request",
            name: "x-test".to_owned()
        })
    );
}

#[test]
fn rejects_tab_in_static_header_values() {
    let config: Config = toml::from_str(
        r#"
            [headers.request.set]
            x-test = "field1\tfield2"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderValue {
            field: "headers.request",
            name: "x-test".to_owned()
        })
    );
}
