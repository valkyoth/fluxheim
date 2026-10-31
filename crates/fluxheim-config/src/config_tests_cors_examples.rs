use crate::Config;

fn recipe() -> Config {
    toml::from_str(include_str!("../../../examples/headers/cors.toml")).unwrap()
}

#[test]
fn cors_recipe_validates_and_route_lists_replace_parent_lists() {
    let config = recipe();
    config.validate().unwrap();
    let vhost = &config.vhosts[0];
    let effective = config
        .headers
        .with_vhost_overlay(&vhost.headers)
        .with_vhost_overlay(&vhost.routes[0].headers);
    assert_eq!(
        effective.cors.allow_origins,
        ["https://reports.example.test"]
    );
    assert_eq!(effective.cors.allow_methods, ["POST"]);
    assert_eq!(effective.cors.allow_headers, ["content-type"]);
    assert!(effective.cors.expose_headers.is_empty());
    assert!(effective.cors.allow_credentials);
    assert_eq!(effective.cors.max_age_secs, Some(0));
}

#[test]
fn cors_documented_limits_and_invalid_values_are_rejected() {
    for case in 0..16 {
        let mut config = recipe();
        let cors = &mut config.headers.cors;
        match case {
            0 => cors.allow_origins.clear(),
            1 => cors.allow_methods.clear(),
            2 => cors.allow_origins = vec!["*".into()],
            3 => cors.allow_origins.push("*".into()),
            4 => cors.allow_origins = vec!["null".into()],
            5 => cors.allow_origins = vec!["https://app.example.test/".into()],
            6 => cors.allow_origins = vec!["https://user:secret@app.example.test".into()],
            7 => cors.allow_methods = vec!["get".into()],
            8 => cors.allow_headers.push("Content-Type".into()),
            9 => cors.expose_headers = vec!["bad name".into()],
            10 => cors.max_age_secs = Some(86_401),
            11 => {
                cors.allow_origins = (0..65)
                    .map(|n| format!("https://{n}.example.test"))
                    .collect()
            }
            12 => cors.allow_methods = (0..33).map(|n| format!("METHOD{n}")).collect(),
            13 => cors.allow_headers = (0..65).map(|n| format!("x-{n}")).collect(),
            14 => cors.expose_headers = (0..65).map(|n| format!("x-{n}")).collect(),
            _ => cors.allow_origins.push("https://APP.example.test".into()),
        }
        assert!(config.validate().is_err(), "case {case}");
    }
}

#[test]
fn cors_wildcard_tokens_currently_pass_config_validation() {
    let mut config = recipe();
    config.headers.cors.allow_credentials = false;
    config.headers.cors.allow_methods = vec!["*".into()];
    config.headers.cors.allow_headers = vec!["*".into()];
    config.headers.cors.expose_headers = vec!["*".into()];
    config.validate().unwrap();
}
