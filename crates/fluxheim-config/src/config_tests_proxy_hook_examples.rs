use crate::Config;

#[test]
fn auth_guide_validates_and_rejects_invalid_policies() {
    let config: Config = toml::from_str(include_str!("../../../examples/proxy/auth.toml")).unwrap();
    config.validate().unwrap();
    for kind in 0..5 {
        let mut invalid = config.clone();
        let auth = &mut invalid.vhosts[0].routes[0]
            .proxy
            .as_mut()
            .unwrap()
            .auth_request;
        match kind {
            0 => auth.url = Some("http://127.0.0.1:9002/check?token=secret".into()),
            1 => auth.max_in_flight = 0,
            2 => auth.max_response_bytes = crate::ByteSize::from_bytes(1024 * 1024 + 1),
            3 => auth.forward_headers = vec!["cookie".into(), "Cookie".into()],
            _ => auth.read_timeout_secs = 0,
        }
        assert!(invalid.validate().is_err(), "case {kind}");
    }
}

#[test]
fn mirror_guide_respects_feature_and_privacy_gates() {
    let config: Config =
        toml::from_str(include_str!("../../../examples/proxy/mirror.toml")).unwrap();
    if cfg!(feature = "traffic-mirror") && !cfg!(feature = "privacy-mode") {
        config.validate().unwrap();
        for kind in 0..4 {
            let mut invalid = config.clone();
            let mirror = &mut invalid.vhosts[0].proxy.mirror;
            match kind {
                0 => mirror.methods = vec!["POST".into()],
                1 => mirror.sample_per_mille = 0,
                2 => mirror.max_in_flight = 1025,
                _ => mirror.base_url = Some("http://user:password@127.0.0.1:9003/".into()),
            }
            assert!(invalid.validate().is_err(), "case {kind}");
        }
    } else {
        assert!(config.validate().is_err());
    }
}
