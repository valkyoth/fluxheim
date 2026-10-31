use super::*;

fn mirror() -> NativeTrafficMirror {
    NativeTrafficMirror::from_config(&fluxheim_config::TrafficMirrorConfig {
        enabled: true,
        base_url: Some("http://127.0.0.1:9002/shadow".into()),
        forward_headers: vec!["cookie".into()],
        ..Default::default()
    })
    .unwrap()
}

#[test]
fn mirror_currently_selects_body_bearing_get_and_comma_joins_cookies() {
    let mut request = NativeHttp1Request {
        method: "GET".into(),
        target: "/shadow".into(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![("host".into(), "proxy.test".into())],
        body: crate::NativeHttp1RequestBody::from_vec(b"not-bodyless".to_vec()),
        trailers: Vec::new(),
    };
    request.headers.extend([
        ("cookie".into(), "a=1".into()),
        ("cookie".into(), "b=2".into()),
    ]);
    // documented contract: projection omits the body instead of rejecting the request.
    let selected = mirror().request(&request).unwrap();
    assert_eq!(selected.headers, [("cookie".into(), "a=1, b=2".into())]);
}

#[test]
fn mirror_budget_key_is_shared_by_equal_destinations() {
    let first = mirror();
    let second = mirror();
    assert_eq!(first.slot_key, second.slot_key);
    assert_eq!(first.slot_key, "http://127.0.0.1:9002/shadow");
}
