use super::*;

fn request() -> NativeHttp1Request {
    NativeHttp1Request {
        method: "GET".into(),
        target: "/asset.css".into(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![
            ("host".into(), "cache.test".into()),
            ("x-edition".into(), "one".into()),
            ("X-Edition".into(), "two".into()),
            ("cookie".into(), "session=private".into()),
            ("authorization".into(), "Bearer private".into()),
            ("x-unconfigured".into(), "private".into()),
            ("x-api-key".into(), "private".into()),
            ("connection".into(), "close".into()),
        ],
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        body: crate::NativeHttp1RequestBody::empty(),
        trailers: Vec::new(),
    }
}

fn peer() -> NativePeerFillPeer {
    NativePeerFillPeer {
        name: "peer".into(),
        base_path: String::new(),
        upstream: NativeHttp1Upstream::new("127.0.0.1:8080"),
    }
}

#[test]
fn peer_request_forwards_only_selected_public_context() {
    let config = CacheConfig {
        vary_request_headers: vec!["x-edition".into()],
        ..Default::default()
    };
    let forwarded = native_peer_fill_request(&peer(), &config, &request(), None).unwrap();
    assert_eq!(
        native_request_header_values(&forwarded, "x-edition").collect::<Vec<_>>(),
        ["one", "two"]
    );
    for name in [
        "cookie",
        "authorization",
        "x-api-key",
        "x-unconfigured",
        "connection",
    ] {
        assert!(native_request_header(&forwarded, name).is_none(), "{name}");
    }
    assert_eq!(
        native_request_header(&forwarded, "cache-control"),
        Some("only-if-cached")
    );
    assert!(native_request_is_peer_fill(&forwarded));
}

#[test]
fn peer_request_refuses_ambiguous_hop_by_hop_and_oversized_contexts() {
    let mut config = CacheConfig {
        vary_request_headers: vec!["x-edition".into()],
        ..Default::default()
    };
    let mut nominated = request();
    nominated
        .headers
        .push(("Connection".into(), "X-Edition".into()));
    assert!(native_peer_fill_request(&peer(), &config, &nominated, None).is_none());
    let mut duplicate_host = request();
    duplicate_host
        .headers
        .push(("Host".into(), "other.test".into()));
    assert!(native_peer_fill_request(&peer(), &config, &duplicate_host, None).is_none());
    let mut oversized = request();
    oversized
        .headers
        .push(("x-edition".into(), "x".repeat(8193)));
    assert!(native_peer_fill_request(&peer(), &config, &oversized, None).is_none());
    config.vary_request_headers = vec!["authorization".into()];
    assert!(native_peer_fill_request(&peer(), &config, &request(), None).is_none());
}
