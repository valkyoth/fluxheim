use super::apply_native_response_compression;
use crate::NativeHttp1Response;
use crate::native_http1_client_tests::request;
use fluxheim_config::{ByteSize, CompressionConfig};

fn policy() -> CompressionConfig {
    CompressionConfig {
        enabled: true,
        min_bytes: ByteSize::from_bytes(1),
        ..Default::default()
    }
}

fn response() -> NativeHttp1Response {
    NativeHttp1Response::new(200, "OK", b"public text public text public text".repeat(16))
        .with_header("content-type", "text/plain")
        .with_header("cache-control", "public, max-age=60")
}

fn header<'a>(response: &'a NativeHttp1Response, name: &str) -> Option<&'a str> {
    response
        .headers()
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

// documented contract: current identity response is reusable without an encoding key.
#[test]
fn identity_lacks_vary_while_compressed_variant_has_it() {
    let mut req = request();
    req.headers
        .push(("accept-encoding".into(), "identity".into()));
    let mut plain = response();
    apply_native_response_compression(&req, &mut plain, &policy());
    assert_eq!(header(&plain, "vary"), None);
    req.headers.retain(|(name, _)| name != "accept-encoding");
    req.headers.push(("accept-encoding".into(), "gzip".into()));
    let mut encoded = response();
    apply_native_response_compression(&req, &mut encoded, &policy());
    assert_eq!(header(&encoded, "vary"), Some("accept-encoding"));
    assert_eq!(header(&encoded, "content-encoding"), Some("gzip"));
}

// documented contract: invert when identity is included in the negotiation decision.
#[test]
fn explicitly_forbidden_identity_is_still_served() {
    for value in ["gzip;q=0, identity;q=0, *;q=0", "*;q=0"] {
        let mut req = request();
        req.headers.push(("accept-encoding".into(), value.into()));
        let mut actual = response();
        let expected = actual.clone();
        apply_native_response_compression(&req, &mut actual, &policy());
        assert_eq!(actual, expected);
    }
}

#[test]
fn output_limit_failure_preserves_the_entire_identity_response() {
    let mut req = request();
    req.headers
        .push(("accept-encoding".into(), "gzip, identity;q=0".into()));
    let mut actual = response().with_header("etag", "\"plain\"");
    let expected = actual.clone();
    let mut config = policy();
    config.max_output_bytes = ByteSize::from_bytes(1);
    config.validate().unwrap();
    apply_native_response_compression(&req, &mut actual, &config);
    assert_eq!(actual, expected);
}

#[test]
fn buffered_response_without_original_content_length_can_be_compressed() {
    let mut req = request();
    req.headers.push(("accept-encoding".into(), "gzip".into()));
    let mut actual = response();
    assert_eq!(actual.content_length(), None);
    apply_native_response_compression(&req, &mut actual, &policy());
    assert_eq!(header(&actual, "content-encoding"), Some("gzip"));
}
