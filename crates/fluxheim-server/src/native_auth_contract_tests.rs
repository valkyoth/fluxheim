use super::*;

fn auth() -> NativeAuthRequest {
    NativeAuthRequest::from_config(&fluxheim_config::AuthRequestConfig {
        enabled: true,
        url: Some("http://127.0.0.1:4180/auth".into()),
        forward_headers: vec!["x-real-ip".into()],
        ..Default::default()
    })
    .unwrap()
}

fn request() -> NativeHttp1Request {
    NativeHttp1Request {
        method: "GET".into(),
        target: "/private".into(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![("host".into(), "proxy.test".into())],
        body: crate::NativeHttp1RequestBody::empty(),
        trailers: Vec::new(),
    }
}

#[test]
fn auth_context_currently_falls_back_to_inbound_ip_when_synthesis_is_unavailable() {
    let mut request = request();
    request
        .headers
        .push(("x-real-ip".into(), "192.0.2.123".into()));
    let input = auth().input(&request);
    // documented contract: None is treated as permission to copy the original header.
    assert_eq!(input.headers.len(), 1);
    input.headers[0]
        .1
        .try_with_secret(|value| assert_eq!(value, "192.0.2.123"))
        .unwrap();
}

#[cfg(feature = "privacy-mode")]
#[test]
fn privacy_auth_context_currently_copies_allowlisted_inbound_ip_even_with_peer() {
    let mut request = request();
    request.peer_addr = Some("127.0.0.1:12345".parse().unwrap());
    request
        .headers
        .push(("x-real-ip".into(), "192.0.2.123".into()));
    let input = auth().input(&request);
    assert_eq!(input.headers.len(), 1);
    input.headers[0]
        .1
        .try_with_secret(|value| assert_eq!(value, "192.0.2.123"))
        .unwrap();
}

#[test]
fn auth_timeout_currently_collapses_phase_budgets() {
    let make = |connect_timeout_secs, read_timeout_secs| {
        NativeAuthRequest::from_config(&fluxheim_config::AuthRequestConfig {
            enabled: true,
            url: Some("http://127.0.0.1:4180/auth".into()),
            connect_timeout_secs,
            read_timeout_secs,
            ..Default::default()
        })
        .unwrap()
    };
    // documented contract: reversing phase budgets produces identical runtime policy.
    assert_eq!(make(1, 5), make(5, 1));
    assert_eq!(make(1, 5).timeout, Duration::from_secs(6));
}
