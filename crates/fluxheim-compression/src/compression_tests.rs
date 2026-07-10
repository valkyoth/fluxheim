use super::{
    accept_encoding_allows, accept_encoding_quality, cache_control_directive_blocks_compression,
    content_encoding_value_is_active, content_type_is_compressible,
    input_length_within_compression_bounds, parse_accept_encoding_qvalue,
};

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
use std::io;

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
use bytes::Bytes;

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
use super::{ResponseCompressionEncoder, ResponseCompressionEncoderInner};

#[test]
fn parses_accept_encoding_qvalues() {
    assert_eq!(parse_accept_encoding_qvalue("0"), Some(0));
    assert_eq!(parse_accept_encoding_qvalue("0.125"), Some(125));
    assert_eq!(parse_accept_encoding_qvalue("1"), Some(1000));
    assert_eq!(parse_accept_encoding_qvalue("1.000"), Some(1000));
    assert_eq!(parse_accept_encoding_qvalue("1.001"), None);
    assert_eq!(parse_accept_encoding_qvalue("0.0000"), None);
    assert_eq!(parse_accept_encoding_qvalue("NaN"), None);
}

#[test]
fn parses_complete_accept_encoding_policy() {
    assert_eq!(accept_encoding_quality(["GZIP;q=0.5"], "gzip"), Some(500));
    assert_eq!(accept_encoding_quality(["*;q=0.5"], "br"), Some(500));
    assert!(!accept_encoding_allows("br;q=0", "br"));
    assert!(!accept_encoding_allows("gzip;q=banana", "gzip"));
    assert!(!accept_encoding_allows("br", "gzip"));
}

#[test]
fn accept_encoding_fails_closed_and_honors_specific_precedence() {
    assert!(!accept_encoding_allows("gzip;q", "gzip"));
    assert!(!accept_encoding_allows("gzip;q=0, *;q=1", "gzip"));
    assert!(!accept_encoding_allows("gzip;level=9", "gzip"));
    assert!(!accept_encoding_allows("gzip;q=1;q=0", "gzip"));
    assert!(!accept_encoding_allows("gzip,,br", "gzip"));
    assert_eq!(
        accept_encoding_quality(["br;q=0.5", "GZip;Q=0.75, *;q=0.1"], "gzip"),
        Some(750)
    );
}

#[test]
fn classifies_compression_response_policy_tokens() {
    assert!(cache_control_directive_blocks_compression("no-transform"));
    assert!(cache_control_directive_blocks_compression("PRIVATE"));
    assert!(cache_control_directive_blocks_compression(
        r#"private="Set-Cookie""#
    ));
    assert!(cache_control_directive_blocks_compression(
        " PRIVATE = \"X-User\" "
    ));
    assert!(!cache_control_directive_blocks_compression("max-age=60"));

    assert!(content_type_is_compressible("text/plain; charset=utf-8"));
    assert!(content_type_is_compressible("application/json"));
    assert!(content_type_is_compressible("image/svg+xml"));
    assert!(!content_type_is_compressible("image/png"));

    assert!(!content_encoding_value_is_active("identity"));
    assert!(!content_encoding_value_is_active(" IDENTITY "));
    assert!(content_encoding_value_is_active("gzip"));

    assert!(input_length_within_compression_bounds(1024, 512, 2048));
    assert!(!input_length_within_compression_bounds(128, 512, 2048));
    assert!(!input_length_within_compression_bounds(4096, 512, 2048));
}

#[cfg(feature = "gzip")]
#[test]
fn gzip_encoder_releases_retained_output_between_chunks() {
    let mut encoder = ResponseCompressionEncoder::gzip(0, 4096);
    let first = encoder
        .encode_chunk(Some(&Bytes::from(vec![b'a'; 1024])), false)
        .expect("first gzip chunk should encode");
    assert!(!first.is_empty());
    assert!(encoder.total_output_bytes >= first.len());
    let ResponseCompressionEncoderInner::Gzip(Some(gzip)) = &encoder.inner else {
        panic!("expected gzip encoder");
    };
    assert_eq!(gzip.get_ref().buffer_len(), 0);

    let second = encoder
        .encode_chunk(Some(&Bytes::from(vec![b'b'; 1024])), false)
        .expect("second gzip chunk should encode");
    assert!(!second.is_empty());
    assert!(encoder.total_output_bytes >= first.len() + second.len());
    let ResponseCompressionEncoderInner::Gzip(Some(gzip)) = &encoder.inner else {
        panic!("expected gzip encoder");
    };
    assert_eq!(gzip.get_ref().buffer_len(), 0);
}

#[cfg(feature = "gzip")]
#[test]
fn gzip_limit_failure_discards_encoder() {
    let mut encoder = ResponseCompressionEncoder::gzip(0, 1);
    assert_limit_failure_discards_encoder(&mut encoder);
    assert!(matches!(
        &encoder.inner,
        ResponseCompressionEncoderInner::Gzip(None)
    ));
}

#[cfg(feature = "brotli")]
#[test]
fn brotli_limit_failure_discards_encoder() {
    let mut encoder = ResponseCompressionEncoder::brotli(5, 1);
    assert_limit_failure_discards_encoder(&mut encoder);
    assert!(matches!(
        &encoder.inner,
        ResponseCompressionEncoderInner::Brotli(slot) if slot.is_none()
    ));
}

#[cfg(feature = "zstd")]
#[test]
fn zstd_limit_failure_discards_encoder() {
    let mut encoder = ResponseCompressionEncoder::zstd(3, 1).unwrap();
    assert_limit_failure_discards_encoder(&mut encoder);
    assert!(matches!(
        &encoder.inner,
        ResponseCompressionEncoderInner::Zstd(None)
    ));
}

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
fn assert_limit_failure_discards_encoder(encoder: &mut ResponseCompressionEncoder) {
    let input = Bytes::from(vec![b'x'; 4096]);
    let error = encoder
        .encode_chunk(Some(&input), true)
        .expect_err("encoded output must be rejected before exceeding the limit");
    assert_eq!(error.io_kind(), Some(io::ErrorKind::InvalidData));
    assert!(encoder.encode_chunk(Some(&input), true).unwrap().is_empty());
}
