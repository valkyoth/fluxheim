use crate::Config;

const RECIPE: &str = include_str!("../../../examples/headers/response.toml");

#[test]
fn response_header_recipe_and_browser_profiles_validate() {
    let config: Config = toml::from_str(RECIPE).unwrap();
    config.validate().unwrap();
    for profile in ["off", "baseline", "cross-origin-isolated"] {
        let source = RECIPE.replace(
            "profile = \"baseline\"",
            &format!("profile = \"{profile}\""),
        );
        let config: Config = toml::from_str(&source).unwrap();
        config.validate().unwrap();
    }
}

#[test]
fn response_browser_policy_values_and_raw_hsts_withdrawal_validate() {
    for (field, original, values) in [
        (
            "cross_origin_opener_policy",
            "same-origin",
            &["unsafe-none", "same-origin-allow-popups", "same-origin"][..],
        ),
        (
            "cross_origin_resource_policy",
            "same-origin",
            &["same-site", "same-origin", "cross-origin"][..],
        ),
        (
            "cross_origin_embedder_policy",
            "require-corp",
            &["unsafe-none", "require-corp", "credentialless"][..],
        ),
        (
            "x_permitted_cross_domain_policies",
            "none",
            &["none", "master-only", "by-content-type", "all"][..],
        ),
    ] {
        for value in values {
            let source = RECIPE.replace(
                &format!("{field} = \"{original}\""),
                &format!("{field} = \"{value}\""),
            );
            let config: Config = toml::from_str(&source).unwrap();
            config.validate().unwrap();
        }
    }
    let source = RECIPE.replace("profile = \"deny-sensitive\"", "profile = \"deny-all\"");
    let mut config: Config = toml::from_str(&source).unwrap();
    config.validate().unwrap();
    config.headers.response.strict_transport_security = Some("max-age=0".into());
    assert!(config.validate().is_err());
    config.headers.response.hsts = None;
    config.validate().unwrap();
}

#[test]
fn response_header_recipe_rejects_invalid_policy_inputs() {
    for (from, to) in [
        ("max_age_secs = 300", "max_age_secs = 0"),
        (
            "referrer_policy = \"no-referrer\"",
            "referrer_policy = \"\"",
        ),
        ("x-edge = \"demo\"", "x-edge = \"bad\\r\\nfield\""),
        ("x-edge = \"demo\"", "x-edge = \"{unknown}\""),
        (
            "https://reports.example.test/csp",
            "http://reports.example.test/csp",
        ),
        ("identifier = \"edge-demo\"", "identifier = \"bad token\""),
        ("from = \"/internal/\"", "from = \"//internal/\""),
        (
            "to = \"public.example.test\"",
            "to = \"public;example.test\"",
        ),
    ] {
        let source = RECIPE.replace(from, to);
        assert_ne!(source, RECIPE);
        let config: Config = toml::from_str(&source).unwrap();
        assert!(config.validate().is_err(), "{from} -> {to}");
    }
}

#[test]
fn response_header_parent_add_currently_conflicts_with_child_override() {
    let source = RECIPE.replace("x-route = \"child\"", "x-edge = \"child\"");
    let config: Config = toml::from_str(&source).unwrap();
    // documented contract: merging the child into set retains the parent's add alias.
    assert!(config.validate().is_err());
    let source = source.replace("[headers.response.add]", "[headers.response.set]");
    let config: Config = toml::from_str(&source).unwrap();
    config.validate().unwrap();
}
