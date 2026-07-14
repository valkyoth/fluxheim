use super::{
    Http1ChunkLimits, Http1ChunkedDecode, Http1ChunkedDecoder, Http1HeadLimits, Http1Header,
    Http1ParseError, decode_http1_chunked_body, http1_connection_options, http1_request_target,
    http1_required_host, parse_http1_request_head,
};

fn header<'a>(name: &'a str, value: &'a str) -> Http1Header<'a> {
    Http1Header::new(name, value).expect("valid test header")
}

#[test]
fn canonical_authority_rejects_conflicting_or_malformed_host() {
    assert_eq!(
        parse_http1_request_head(
            b"GET http://public.example/secret HTTP/1.1\r\nHost: internal.example\r\n\r\n",
            Http1HeadLimits::default(),
        ),
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
fn accepts_rfc3986_path_and_query_characters_or_percent_encoding() {
    assert!(
        http1_request_target(
            "GET",
            "/a-z_A-Z~!$&'()*+,;=:@/%7Bvalue%7D?q=/path?next&x=%E2%82%AC"
        )
        .is_ok()
    );
}

#[test]
fn absolute_form_authority_is_canonical_when_host_matches() {
    let parsed = parse_http1_request_head(
        b"GET https://PUBLIC.example:443/path HTTP/1.1\r\nHost: public.example:443\r\n\r\n",
        Http1HeadLimits::default(),
    )
    .unwrap()
    .expect("complete head");
    assert_eq!(parsed.effective_authority(), Some("PUBLIC.example:443"));
}

#[test]
fn http10_transfer_encoding_is_rejected_before_persistence_decision() {
    assert_eq!(
        parse_http1_request_head(
            b"POST / HTTP/1.0\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
            Http1HeadLimits::default(),
        ),
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
fn connection_option_parsing_scales_with_many_unique_tokens() {
    let value = (0..16_384)
        .map(|index| format!("x-hop-{index}"))
        .collect::<Vec<_>>()
        .join(",");
    let headers = [header("Connection", &value)];
    let options = http1_connection_options(&headers).expect("valid options");

    assert!(options.contains("x-hop-0"));
    assert!(options.contains("X-HOP-16383"));
    assert!(!options.contains("x-hop-16384"));
}

#[test]
fn incremental_chunked_decoder_preserves_state_across_single_byte_fragments() {
    let encoded = b"4;name=value\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\nnext";
    let mut decoder = Http1ChunkedDecoder::new(Http1ChunkLimits::default());
    let mut output = Vec::new();
    let mut complete = None;
    for byte in encoded {
        complete = decoder
            .push(std::slice::from_ref(byte), &mut output)
            .unwrap();
        if complete.is_some() {
            break;
        }
    }
    assert_eq!(output, b"Wikipedia");
    assert_eq!(
        complete,
        Some(Http1ChunkedDecode {
            decoded_len: 9,
            consumed_len: 35,
        })
    );
}

#[test]
fn fragmented_chunk_metadata_is_scanned_incrementally() {
    let mut encoded = Vec::from("1;".as_bytes());
    encoded.extend(std::iter::repeat_n(b'a', 8_000));
    encoded.extend_from_slice(b"\r\na\r\n0\r\n\r\n");
    let mut decoder = Http1ChunkedDecoder::new(Http1ChunkLimits::default());
    let mut output = Vec::new();
    let mut complete = None;

    for byte in &encoded {
        complete = decoder
            .push(std::slice::from_ref(byte), &mut output)
            .expect("valid fragmented body");
    }

    assert_eq!(output, b"a");
    assert_eq!(complete.expect("complete body").consumed_len, encoded.len());
}

#[test]
fn incremental_decoder_does_not_retain_the_full_encoded_body() {
    let mut encoded = Vec::new();
    for _ in 0..20_000 {
        encoded.extend_from_slice(b"1\r\na\r\n");
    }
    encoded.extend_from_slice(b"0\r\n\r\n");
    let limits = Http1ChunkLimits {
        max_chunk_count: 20_001,
        ..Http1ChunkLimits::default()
    };
    let mut decoder = Http1ChunkedDecoder::new(limits);
    let mut output = Vec::new();

    let decoded = decoder
        .push(&encoded, &mut output)
        .expect("valid encoded body")
        .expect("complete body");

    assert_eq!(decoded.decoded_len, 20_000);
    assert_eq!(output.len(), 20_000);
    assert!(decoder.buffered_len() <= 8 * 1024);
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
