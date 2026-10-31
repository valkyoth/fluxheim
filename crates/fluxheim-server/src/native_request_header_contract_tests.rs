use super::*;
use crate::{NativeHttp1RequestBody, NativeHttp1TlsClientIdentity};

fn request() -> NativeHttp1Request {
    NativeHttp1Request {
        method: "GET".into(),
        peer_addr: Some("127.0.0.1:1234".parse().unwrap()),
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: true,
        tls_identity: Some(NativeHttp1TlsClientIdentity {
            cipher: Some("TLS_AES_128_GCM_SHA256".into()),
            version: Some("TLSv1.3".into()),
            organization: Some("Fixture Organization".into()),
            serial_number: Some("1234".into()),
            cert_sha256: Some("ab".repeat(32)),
        }),
        geo_context: None,
        target: "/item?q=1".into(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![
            ("host".into(), "public.example.test".into()),
            ("user-agent".into(), "fixture".into()),
            ("x-request-id".into(), "inbound-diagnostic".into()),
            ("x-real-ip".into(), "198.51.100.9".into()),
        ],
        body: NativeHttp1RequestBody::empty(),
        trailers: Vec::new(),
    }
}

#[test]
fn populated_tls_cipher_and_organization_are_not_resolved_by_native_templates() {
    let request = request();
    for value in [
        "{tls.cipher}",
        "{tls.client_cert_organization}",
        "{http.user-agent}",
    ] {
        assert_eq!(
            render_native_request_header_template(value, &request, None),
            ""
        );
    }
    assert_eq!(
        render_native_request_header_template(
            "{tls.version}:{tls.client_cert_serial}",
            &request,
            None
        ),
        "TLSv1.3:1234"
    );
    assert_eq!(
        render_native_request_header_template("{tls.client_cert_sha256}", &request, None),
        "ab".repeat(32)
    );
}

#[test]
fn same_header_template_reads_after_removal_not_original_request() {
    let mut request = request();
    let mut config = RequestHeaderPolicyConfig::default();
    config.add.insert("host".into(), "{host}".into());
    config.add.insert("x-later-host".into(), "{host}".into());
    NativeRouteRequestHeaderPolicy::from_policy(&config).apply(&mut request, None);
    assert!(request_header_value(&request, "host").is_none());
    assert!(request_header_value(&request, "x-later-host").is_none());
}

#[test]
fn diagnostic_template_is_a_header_read_not_independent_identity() {
    assert_eq!(
        render_native_request_header_template("{request_id}", &request(), None),
        "inbound-diagnostic"
    );
}

#[cfg(feature = "privacy-mode")]
#[test]
fn privacy_strips_known_identity_fields_but_is_not_a_custom_header_anonymizer() {
    for enabled in [false, true] {
        let mut request = request();
        request
            .headers
            .push(("x-custom-client".into(), "application-value".into()));
        let config = RequestHeaderPolicyConfig {
            enabled,
            strip_inbound_client_ip_headers: false,
            ..Default::default()
        };
        NativeRouteRequestHeaderPolicy::from_policy(&config).apply(&mut request, None);
        assert!(request_header_value(&request, "x-real-ip").is_none());
        assert_eq!(
            request_header_value(&request, "x-custom-client"),
            Some("application-value")
        );
        assert_eq!(
            render_native_request_header_template("{remote_addr}", &request, None),
            ""
        );
    }
}
