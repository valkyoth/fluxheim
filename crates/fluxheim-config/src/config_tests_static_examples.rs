use crate::Config;

#[test]
fn static_guide_examples_validate_and_reject_invalid_fields() {
    for source in [
        include_str!("../../../examples/web/static.toml"),
        include_str!("../../../examples/web/listing.toml"),
    ] {
        let config: Config = toml::from_str(source).unwrap();
        config.validate().unwrap();
        let mut invalid = config;
        let web = if invalid.vhosts.is_empty() {
            &mut invalid.web
        } else {
            &mut invalid.vhosts[0].web
        };
        web.cache_control = "public\r\nx-injected: yes".into();
        assert!(invalid.validate().is_err());
    }
    let source = include_str!("../../../examples/web/static.toml");
    assert!(
        toml::from_str::<Config>(
            &source.replace("[vhosts.web]\n", "[vhosts.web]\nenabled = true\n")
        )
        .is_err()
    );
    for index in ["[]", "[\"../secret\"]", "[\"\"]"] {
        let source = source.replace("[\"index.html\", \"default.html\"]", index);
        assert!(
            toml::from_str::<Config>(&source)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}
