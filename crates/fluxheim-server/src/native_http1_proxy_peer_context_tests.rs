use super::*;
use crate::native_http1_proxy_peer_fill_auth::*;
use sanitization::SecretVec;
use std::sync::Arc;

fn request() -> NativeHttp1Request {
    NativeHttp1Request {
        method: "GET".into(),
        target: "/asset.css".into(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![
            ("host".into(), "cache.test".into()),
            ("cache-control".into(), "only-if-cached".into()),
            (VERSION.into(), "2".into()),
            (
                CONTEXT.into(),
                "accept,accept-encoding,accept-language,x-edition".into(),
            ),
            ("accept".into(), "text/css".into()),
            ("accept-encoding".into(), "identity".into()),
            ("accept-language".into(), "en".into()),
            ("x-edition".into(), "special".into()),
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

fn auth() -> NativePeerFillAuth {
    NativePeerFillAuth {
        secret: Arc::new(SecretVec::from_vec(vec![42; 32])),
    }
}

fn sign(request: &mut NativeHttp1Request) {
    request.headers.retain(|(name, _)| {
        name != NATIVE_PEER_FILL_REQUEST_SIGNATURE_HEADER && name != NATIVE_PEER_FILL_NONCE_HEADER
    });
    let nonce = native_peer_fill_nonce();
    let signature =
        native_peer_fill_request_signature(&auth(), &request.target, &request.headers, &nonce);
    request
        .headers
        .push((NATIVE_PEER_FILL_NONCE_HEADER.into(), nonce));
    request
        .headers
        .push((NATIVE_PEER_FILL_REQUEST_SIGNATURE_HEADER.into(), signature));
}

#[test]
fn peer_context_authenticates_every_variant_and_nonce_in_both_directions() {
    let mut original = request();
    sign(&mut original);
    let mut response = NativeHttp1Response::new(200, "OK", b"edition".to_vec());
    prepare_response(&original, &mut response, &CacheConfig::default());
    native_peer_fill_sign_response(&auth(), &original, &mut response);
    assert!(native_peer_fill_response_signature_matches(
        &auth(),
        &original,
        &response
    ));
    for name in [
        "host",
        "accept",
        "accept-encoding",
        "accept-language",
        "x-edition",
        VERSION,
        CONTEXT,
        NATIVE_PEER_FILL_NONCE_HEADER,
    ] {
        let mut changed = original.metadata_snapshot();
        for (key, value) in &mut changed.headers {
            if key == name {
                value.push('x');
            }
        }
        assert!(
            !native_peer_fill_request_signature_matches(&auth(), &changed),
            "{name}"
        );
        assert!(
            !native_peer_fill_response_signature_matches(&auth(), &changed, &response),
            "{name}"
        );
    }
    let mut replay = original.metadata_snapshot();
    sign(&mut replay);
    assert!(!native_peer_fill_response_signature_matches(
        &auth(),
        &replay,
        &response
    ));
    let other = NativePeerFillAuth {
        secret: Arc::new(SecretVec::from_vec(vec![43; 32])),
    };
    assert!(!native_peer_fill_request_signature_matches(
        &other, &original
    ));
    assert!(!native_peer_fill_response_signature_matches(
        &other, &original, &response
    ));
}

#[test]
fn peer_context_missing_empty_repeated_and_order_are_distinct() {
    let mut base = request();
    base.headers.retain(|(name, _)| name != "x-edition");
    let missing = canonical_context(&base.headers).unwrap();
    base.headers.push(("x-edition".into(), "".into()));
    let empty = canonical_context(&base.headers).unwrap();
    assert_ne!(missing, empty);
    base.headers.push(("X-Edition".into(), "special".into()));
    let repeated = canonical_context(&base.headers).unwrap();
    assert_ne!(empty, repeated);
    let last = base.headers.len() - 1;
    base.headers.swap(last, last - 1);
    assert_ne!(repeated, canonical_context(&base.headers).unwrap());
    sign(&mut base);
    assert!(native_peer_fill_request_signature_matches(&auth(), &base));
    base.headers.swap(last, last - 1);
    assert!(!native_peer_fill_request_signature_matches(&auth(), &base));
}

#[test]
fn peer_context_rejects_unsupported_version_bounds_and_ambiguity() {
    for (name, value) in [
        (VERSION, "1"),
        (CONTEXT, "accept,accept-language"),
        (CONTEXT, "accept,accept-encoding,accept-language,cookie"),
        (
            CONTEXT,
            "accept,accept-encoding,accept-language,x-edition,x-edition",
        ),
        ("x-edition", " bad"),
        ("x-edition", "bad\r\n"),
    ] {
        let mut invalid = request();
        for (key, old) in &mut invalid.headers {
            if key == name {
                *old = value.into();
            }
        }
        assert!(
            canonical_context(&invalid.headers).is_none(),
            "{name}: {value}"
        );
    }
    for name in [VERSION, CONTEXT, "host"] {
        let mut invalid = request();
        invalid.headers.push((name.into(), "duplicate".into()));
        assert!(canonical_context(&invalid.headers).is_none());
    }
    let mut oversized = request();
    oversized
        .headers
        .push(("x-edition".into(), "a".repeat(8192)));
    assert!(canonical_context(&oversized.headers).is_none());
    let mut repeated = request();
    repeated
        .headers
        .extend((0..64).map(|_| ("x-edition".into(), "".into())));
    assert!(canonical_context(&repeated.headers).is_none());
}

#[test]
fn peer_context_only_explicit_safe_custom_fields_are_selected() {
    let mut config = CacheConfig::default();
    assert_eq!(selected_fields(&config).unwrap().len(), 3);
    config.vary_request_headers = vec!["X-Edition".into()];
    assert!(
        selected_fields(&config)
            .unwrap()
            .contains(&"x-edition".into())
    );
    for field in [
        "cookie",
        "authorization",
        "proxy-authorization",
        "connection",
        "content-length",
        "x-api-key",
        "x-token",
        "x-forwarded-for",
        "traceparent",
        "x-fluxheim-peer-fill",
        "if-match",
        "range",
    ] {
        config.vary_request_headers = vec![field.into()];
        assert!(selected_fields(&config).is_none(), "{field}");
    }
}

#[test]
fn peer_response_rejects_unpreserved_origin_and_configured_variants_and_old_peers() {
    let mut request = request();
    request.headers.retain(|(name, _)| name != CONTEXT);
    request.headers.push((
        CONTEXT.into(),
        "accept,accept-encoding,accept-language".into(),
    ));
    let config = CacheConfig::default();
    let mut response = NativeHttp1Response::new(200, "OK", b"default".to_vec());
    assert!(!response_context_matches(&request, &response, &config));
    prepare_response(&request, &mut response, &config);
    assert!(response_context_matches(&request, &response, &config));
    response.push_header("vary", "X-Edition");
    prepare_response(&request, &mut response, &config);
    assert!(!response_context_matches(&request, &response, &config));
    response.remove_header("vary");
    let configured = CacheConfig {
        vary_request_headers: vec!["x-edition".into()],
        ..Default::default()
    };
    prepare_response(&request, &mut response, &configured);
    assert!(!response_context_matches(&request, &response, &config));
    prepare_response(&request, &mut response, &config);
    response.push_header(VERSION, "2");
    assert!(!response_context_matches(&request, &response, &config));
}

#[test]
fn peer_response_authenticates_cache_date_age_and_variant_metadata() {
    let mut request = request();
    sign(&mut request);
    let mut response = NativeHttp1Response::new(200, "OK", b"body".to_vec())
        .with_header("date", "Wed, 11 Nov 2026 00:00:00 GMT")
        .with_header("age", "20")
        .with_header("vary", "X-Edition");
    prepare_response(&request, &mut response, &CacheConfig::default());
    native_peer_fill_sign_response(&auth(), &request, &mut response);
    for field in [DATE, VERSION, VARIANTS, CONTEXT, "age", "vary"] {
        let mut changed = response.clone();
        changed.remove_header(field);
        changed.push_header(field, "changed");
        assert!(
            !native_peer_fill_response_signature_matches(&auth(), &request, &changed),
            "{field}"
        );
    }
    // Simulate exactly the HTTP/1 writer's regenerated fields.
    response.remove_header("date");
    response.push_header("date", "Wed, 11 Nov 2026 00:00:20 GMT");
    response.push_header("content-length", "4");
    assert!(native_peer_fill_response_signature_matches(
        &auth(),
        &request,
        &response
    ));
    let clean = native_peer_fill_response_without_cache_status(response, &CacheConfig::default());
    assert_eq!(
        native_response_single_header_value(&clean, "date"),
        Some("Wed, 11 Nov 2026 00:00:00 GMT")
    );
    assert_eq!(
        native_response_single_header_value(&clean, "age"),
        Some("20")
    );
    assert!(
        !clean
            .headers()
            .iter()
            .any(|(name, _)| name.starts_with("x-fluxheim-peer-fill"))
    );
}
