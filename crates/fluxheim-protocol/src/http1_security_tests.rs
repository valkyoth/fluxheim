use super::{
    Http1ChunkLimits, Http1ChunkedDecode, Http1ChunkedDecoder, Http1HeadLimits, Http1Header,
    Http1ParseError, Http1Version, decode_http1_chunked_body, http1_connection_options,
    http1_request_body_framing, http1_required_host, parse_http1_request_head,
};

fn header<'a>(name: &'a str, value: &'a str) -> Http1Header<'a> {
    Http1Header::new(name, value).expect("valid test header")
}

#[test]
fn canonical_authority_rejects_conflicting_or_malformed_host() {
    let parsed = parse_http1_request_head(
        b"GET http://public.example/secret HTTP/1.1\r\nHost: internal.example\r\n\r\n",
        Http1HeadLimits::default(),
    )
    .unwrap()
    .expect("complete head");
    assert_eq!(
        parsed.effective_authority(),
        Err(Http1ParseError::ConflictingAuthority)
    );
    assert_eq!(
        parsed.validate_message(),
        Err(Http1ParseError::ConflictingAuthority)
    );

    for host in [
        "user@example.test",
        "example.test:invalid",
        "example.test:99999",
        "example.test,internal.test",
        "[2001:db8::1",
        "[not-ipv6]:443",
    ] {
        assert_eq!(
            http1_required_host(&[header("Host", host)]),
            Err(Http1ParseError::InvalidHost),
            "host {host:?} must be rejected"
        );
    }
}

#[test]
fn absolute_form_authority_is_canonical_when_host_matches() {
    let parsed = parse_http1_request_head(
        b"GET https://PUBLIC.example:443/path HTTP/1.1\r\nHost: public.example:443\r\n\r\n",
        Http1HeadLimits::default(),
    )
    .unwrap()
    .expect("complete head");
    assert_eq!(parsed.effective_authority(), Ok("PUBLIC.example:443"));
    assert_eq!(
        parsed
            .validate_message()
            .map(|validated| validated.effective_authority),
        Ok(Some("PUBLIC.example:443"))
    );
}

#[test]
fn http10_transfer_encoding_is_rejected_before_persistence_decision() {
    let parsed = parse_http1_request_head(
        b"POST / HTTP/1.0\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
        Http1HeadLimits::default(),
    )
    .unwrap()
    .expect("complete head");
    assert_eq!(
        parsed.validate_message(),
        Err(Http1ParseError::UnsupportedTransferEncoding)
    );
    assert_eq!(
        http1_request_body_framing(Http1Version::Http10, &parsed.headers),
        Err(Http1ParseError::UnsupportedTransferEncoding)
    );
}

#[test]
fn public_header_constructor_enforces_network_parser_invariants() {
    assert_eq!(
        Http1Header::new("bad name", "value"),
        Err(Http1ParseError::InvalidHeaderName)
    );
    assert_eq!(
        Http1Header::new("x-test", "bad\r\nvalue"),
        Err(Http1ParseError::InvalidHeaderValue)
    );
    let valid = Http1Header::new("x-test", " value ").expect("valid header");
    assert_eq!(valid.name(), "x-test");
    assert_eq!(valid.value(), "value");
}

#[test]
fn connection_options_identify_standard_and_nominated_hop_headers() {
    let headers = [header("Connection", "x-internal, keep-alive")];
    let options = http1_connection_options(&headers).expect("valid options");
    assert!(options.contains("X-Internal"));
    assert!(options.identifies_hop_by_hop_header("x-internal"));
    assert!(options.identifies_hop_by_hop_header("Proxy-Connection"));
    assert!(options.identifies_hop_by_hop_header("Transfer-Encoding"));
    assert!(!options.identifies_hop_by_hop_header("content-type"));
}

#[test]
fn incremental_chunked_decoder_preserves_state_across_single_byte_fragments() {
    let encoded = b"4;name=value\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\nnext";
    let mut decoder = Http1ChunkedDecoder::new(Http1ChunkLimits::default());
    let mut complete = None;
    for byte in encoded {
        complete = decoder.push(std::slice::from_ref(byte)).unwrap();
        if complete.is_some() {
            break;
        }
    }
    assert_eq!(decoder.decoded_body(), b"Wikipedia");
    assert_eq!(
        complete,
        Some(Http1ChunkedDecode {
            decoded_len: 9,
            consumed_len: 35,
        })
    );
}

#[test]
fn chunked_decoder_bounds_and_validates_encoded_metadata() {
    let mut output = [0u8; 32];
    let cases = [
        (
            b"000000001;name=value\r\na\r\n0\r\n\r\n".as_slice(),
            Http1ChunkLimits {
                max_chunk_line_bytes: 8,
                ..Http1ChunkLimits::default()
            },
            Http1ParseError::ChunkMetadataTooLarge,
        ),
        (
            b"1;bad extension\r\na\r\n0\r\n\r\n".as_slice(),
            Http1ChunkLimits::default(),
            Http1ParseError::InvalidChunk,
        ),
        (
            b"1;a=1\r\na\r\n1;b=2\r\nb\r\n0\r\n\r\n".as_slice(),
            Http1ChunkLimits {
                max_chunk_extension_bytes: 6,
                ..Http1ChunkLimits::default()
            },
            Http1ParseError::ChunkMetadataTooLarge,
        ),
        (
            b"1\r\na\r\n1\r\nb\r\n0\r\n\r\n".as_slice(),
            Http1ChunkLimits {
                max_chunk_count: 2,
                ..Http1ChunkLimits::default()
            },
            Http1ParseError::ChunkMetadataTooLarge,
        ),
        (
            b"1\r\na\r\n0\r\n\r\n".as_slice(),
            Http1ChunkLimits {
                max_encoded_bytes: 8,
                ..Http1ChunkLimits::default()
            },
            Http1ParseError::EncodedBodyTooLarge,
        ),
    ];
    for (encoded, limits, expected) in cases {
        assert_eq!(
            decode_http1_chunked_body(encoded, &mut output, limits),
            Err(expected)
        );
    }
}

#[test]
fn chunked_decoder_rejects_invalid_chunk_shapes() {
    let mut output = [0u8; 16];
    assert_eq!(
        decode_http1_chunked_body(b"g\r\nbad\r\n", &mut output, Http1ChunkLimits::default()),
        Err(Http1ParseError::InvalidChunkSize)
    );
    assert_eq!(
        decode_http1_chunked_body(b"4\r\nWikiXX", &mut output, Http1ChunkLimits::default()),
        Err(Http1ParseError::InvalidChunk)
    );
    assert_eq!(
        decode_http1_chunked_body(
            b"5\r\nhello\r\n0\r\n\r\n",
            &mut output,
            Http1ChunkLimits {
                max_chunk_size: 4,
                ..Http1ChunkLimits::default()
            }
        ),
        Err(Http1ParseError::ChunkTooLarge)
    );
    assert_eq!(
        decode_http1_chunked_body(
            b"ffffffffffffffff\r\n",
            &mut output,
            Http1ChunkLimits::default()
        ),
        Err(Http1ParseError::ChunkTooLarge)
    );
}
