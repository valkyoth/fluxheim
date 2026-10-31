use crate::Config;

const RECIPE: &str = include_str!("../../../examples/headers/request.toml");

#[test]
fn request_header_recipe_and_modes_validate() {
    for mode in ["off", "replace", "append"] {
        let source = RECIPE.replace(
            "x_forwarded_for = \"replace\"",
            &format!("x_forwarded_for = \"{mode}\""),
        );
        let config: Config = toml::from_str(&source).unwrap();
        config.validate().unwrap();
        assert!(config.server.trusted_proxies.is_empty());
    }
}

#[test]
fn request_header_guide_rejects_invalid_and_unsafe_templates() {
    for value in ["{unknown}", "{http.bad name}", "{host", "bad\nvalue"] {
        let mut config: Config = toml::from_str(RECIPE).unwrap();
        config
            .headers
            .request
            .add
            .insert("x-test".into(), value.into());
        assert!(config.validate().is_err(), "{value:?}");
    }
    for value in [
        "{tls.cipher}",
        "{tls.version}",
        "{tls.client_cert_sha256}",
        "{tls.client_cert_organization}",
    ] {
        let mut config: Config = toml::from_str(RECIPE).unwrap();
        config
            .headers
            .request
            .append
            .insert("x-tls".into(), crate::HeaderValues::One(value.into()));
        assert!(config.validate().is_err(), "{value}");
    }
}

#[test]
fn request_header_unsupported_native_templates_currently_validate() {
    let mut config: Config = toml::from_str(RECIPE).unwrap();
    for (name, value) in [
        ("x-agent", "{http.user-agent}"),
        ("x-cipher", "{tls.cipher}"),
        ("x-organization", "{tls.client_cert_organization}"),
        ("host", "{host}"),
    ] {
        config.headers.request.add.insert(name.into(), value.into());
    }
    config.validate().unwrap();
}
