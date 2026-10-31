use crate::{Config, UpstreamHttpVersion};

#[test]
fn cloudflare_proposal_tables_are_not_accepted_configuration() {
    for enabled in [false, true] {
        for source in [
            format!("[cloudflare]\nenabled = {enabled}\n"),
            format!(
                "[[vhosts]]\nname = 'site'\nhosts = ['site.example.test']\n\
                 [vhosts.cloudflare]\nenabled = {enabled}\n"
            ),
        ] {
            let error = toml::from_str::<Config>(&source).unwrap_err();
            assert!(error.to_string().contains("unknown field `cloudflare`"));
        }
    }
}

#[test]
fn protocol_guide_templates_validate_and_reject_unsafe_combinations() {
    let mut websocket: Config =
        toml::from_str(include_str!("../../../examples/proxy/websocket.toml")).unwrap();
    let _websocket_root = crate::config::tests::prepare_guide_process_paths(&mut websocket);
    websocket.validate().unwrap();
    let mut invalid = websocket;
    invalid.vhosts[0].routes[0]
        .proxy
        .as_mut()
        .unwrap()
        .upstream_http_version = UpstreamHttpVersion::Http2;
    assert!(invalid.validate().is_err());

    let mut grpc: Config =
        toml::from_str(include_str!("../../../examples/proxy/grpc.toml")).unwrap();
    let _grpc_root = crate::config::tests::prepare_guide_process_paths(&mut grpc);
    grpc.validate().unwrap();
    for case in 0..4 {
        let mut invalid = grpc.clone();
        let route = &mut invalid.vhosts[0].routes[0];
        match case {
            0 => route.grpc.require_content_type = false,
            1 => route.proxy.as_mut().unwrap().upstream_http_version = UpstreamHttpVersion::Http1,
            2 => route.cache.as_mut().unwrap().enabled = true,
            _ => route.proxy = None,
        }
        assert!(invalid.validate().is_err(), "case {case}");
    }
    let mut proxy: Config =
        toml::from_str(include_str!("../../../examples/proxy/proxy-protocol.toml")).unwrap();
    let _proxy_root = crate::config::tests::prepare_guide_process_paths(&mut proxy);
    proxy.validate().unwrap();
    let mut invalid = proxy.clone();
    invalid.server.trusted_proxies.clear();
    assert!(invalid.validate().is_err());
    let mut invalid = proxy;
    invalid.server.trusted_proxies = vec!["0.0.0.0/0".into()];
    assert!(invalid.validate().is_err());
}
