use crate::Config;

#[test]
fn routing_guide_template_validates_and_rejects_ambiguous_policies() {
    let root = super::super::secure_test_dir("routing-guide");
    let mut config: Config =
        toml::from_str(include_str!("../../../examples/routing/local.toml")).unwrap();
    for vhost in &mut config.vhosts {
        for route in &mut vhost.routes {
            route.resolve_relative_paths(&root);
        }
    }
    config.validate().unwrap();
    assert!(config.server.host_routing.strict);
    let mut invalid = config.clone();
    invalid.server.regex_enabled = false;
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.vhosts[0].routes[0].path_exact = Some("/api".into());
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    let mut fallback = invalid.vhosts[0].routes.last().unwrap().clone();
    fallback.name = "second-fallback".into();
    invalid.vhosts[0].routes.push(fallback);
    assert!(matches!(
        invalid.validate(),
        Err(crate::ConfigError::DuplicateFallbackRoute { .. })
    ));
    let mut invalid = config.clone();
    invalid.vhosts[0].routes[0].methods = vec!["post".into()];
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.vhosts[0].routes[0].strip_prefix = None;
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.vhosts[0].routes[0].rewrite_template = Some("/x/{route.regex.id}".into());
    assert!(invalid.validate().is_err());
    std::fs::remove_dir_all(root).unwrap();
}
