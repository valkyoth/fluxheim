use super::{
    DEFAULT_HTTP1_MAX_BODY_BYTES, Http1BodyFraming, Http1ChunkLimits, Http1ChunkedDecode,
    Http1ConnectionDirective, Http1HeadBuffer, Http1HeadLimits, Http1Header, Http1ParseError,
    Http1RequestTarget, Http1Version, decode_http1_chunked_body, http1_connection_directive,
    http1_request_body_framing, http1_request_target, http1_required_host,
    parse_http1_request_head,
};

fn header<'a>(name: &'a str, value: &'a str) -> Http1Header<'a> {
    Http1Header { name, value }
}

#[test]
fn parses_bounded_http11_request_head() {
    let input = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\nbody";
    let parsed = parse_http1_request_head(input, Http1HeadLimits::default())
        .unwrap()
        .expect("complete head");

    assert_eq!(parsed.method, "GET");
    assert_eq!(parsed.target, "/index.html");
    assert_eq!(parsed.version, Http1Version::Http11);
    assert_eq!(parsed.head_len, input.len() - 4);
    assert_eq!(
        parsed.headers,
        vec![
            header("Host", "example.test"),
            header("Connection", "close")
        ]
    );
}

#[test]
fn returns_none_for_incomplete_head() {
    assert_eq!(
        parse_http1_request_head(
            b"GET / HTTP/1.1\r\nHost: example",
            Http1HeadLimits::default()
        )
        .unwrap(),
        None
    );
}

#[test]
fn buffers_fragmented_request_head_until_complete() {
    let mut buffer = Http1HeadBuffer::new(Http1HeadLimits::default());

    assert_eq!(buffer.append(b"GET / HT").unwrap(), None);
    assert_eq!(buffer.buffered_len(), 8);
    let parsed = buffer
        .append(b"TP/1.1\r\nHost: example.test\r\n\r\n")
        .unwrap()
        .expect("complete head");

    assert_eq!(parsed.method, "GET");
    assert_eq!(parsed.target, "/");
    assert_eq!(parsed.headers, vec![header("Host", "example.test")]);
}

#[test]
fn incremental_buffer_rejects_unbounded_head_without_storing_full_chunk() {
    let limits = Http1HeadLimits {
        max_head_bytes: 16,
        ..Http1HeadLimits::default()
    };
    let mut buffer = Http1HeadBuffer::new(limits);
    let chunk = vec![b'a'; 1024];

    assert_eq!(buffer.append(&chunk), Err(Http1ParseError::HeadTooLarge));
    assert!(buffer.buffered_len() <= limits.max_head_bytes);
}

#[test]
fn rejects_head_when_delimiter_exceeds_limit() {
    let limits = Http1HeadLimits {
        max_head_bytes: 17,
        ..Http1HeadLimits::default()
    };

    assert_eq!(
        parse_http1_request_head(b"GET / HTTP/1.1\r\n\r\n", limits),
        Err(Http1ParseError::HeadTooLarge)
    );
}

#[test]
fn rejects_oversized_head_before_completion() {
    let limits = Http1HeadLimits {
        max_head_bytes: 16,
        ..Http1HeadLimits::default()
    };

    assert_eq!(
        parse_http1_request_head(b"GET / HTTP/1.1\r\nHost: example", limits),
        Err(Http1ParseError::HeadTooLarge)
    );
}

#[test]
fn rejects_header_count_over_limit() {
    let limits = Http1HeadLimits {
        max_header_count: 1,
        ..Http1HeadLimits::default()
    };

    assert_eq!(
        parse_http1_request_head(b"GET / HTTP/1.1\r\nA: b\r\nC: d\r\n\r\n", limits),
        Err(Http1ParseError::HeaderCountExceeded)
    );
}

#[test]
fn rejects_obsolete_line_folding_and_bad_controls() {
    assert_eq!(
        parse_http1_request_head(
            b"GET / HTTP/1.1\r\n folded: nope\r\n\r\n",
            Http1HeadLimits::default()
        ),
        Err(Http1ParseError::ObsoleteLineFolding)
    );
    assert_eq!(
        parse_http1_request_head(
            b"GET / HTTP/1.1\r\nX: bad\x7f\r\n\r\n",
            Http1HeadLimits::default()
        ),
        Err(Http1ParseError::InvalidHeaderValue)
    );
    assert_eq!(
        parse_http1_request_head(
            "GET / HTTP/1.1\r\nX: bad\u{80}\r\n\r\n".as_bytes(),
            Http1HeadLimits::default()
        ),
        Err(Http1ParseError::InvalidHeaderValue)
    );
}

#[test]
fn rejects_unsupported_version_and_invalid_method() {
    assert_eq!(
        parse_http1_request_head(b"GET / HTTP/2.0\r\n\r\n", Http1HeadLimits::default()),
        Err(Http1ParseError::UnsupportedVersion)
    );
    assert_eq!(
        parse_http1_request_head(b"BAD METHOD / HTTP/1.1\r\n\r\n", Http1HeadLimits::default()),
        Err(Http1ParseError::InvalidRequestLine)
    );
}

#[test]
fn classifies_http1_request_target_forms() {
    assert_eq!(
        http1_request_target("GET", "/items?kind=book"),
        Ok(Http1RequestTarget::Origin {
            raw: "/items?kind=book",
            path: "/items",
            query: Some("kind=book")
        })
    );
    assert_eq!(
        http1_request_target("GET", "https://example.test/items?q=1"),
        Ok(Http1RequestTarget::AbsoluteUri {
            raw: "https://example.test/items?q=1",
            scheme: "https",
            authority: Some("example.test"),
            path: Some("/items"),
            query: Some("q=1")
        })
    );
    assert_eq!(
        http1_request_target("CONNECT", "example.test:443"),
        Ok(Http1RequestTarget::Authority {
            raw: "example.test:443",
            port: 443
        })
    );
    assert_eq!(
        http1_request_target("OPTIONS", "*"),
        Ok(Http1RequestTarget::Asterisk)
    );
}

#[test]
fn rejects_invalid_http1_request_target_forms() {
    assert_eq!(
        http1_request_target("GET", "//authority-like/path"),
        Err(Http1ParseError::InvalidRequestTarget)
    );
    assert_eq!(
        http1_request_target("GET", "/bad#fragment"),
        Err(Http1ParseError::InvalidRequestTarget)
    );
    assert_eq!(
        http1_request_target("GET", "/bad%xx"),
        Err(Http1ParseError::InvalidRequestTarget)
    );
    assert_eq!(
        http1_request_target("POST", "*"),
        Err(Http1ParseError::InvalidRequestTarget)
    );
    assert_eq!(
        http1_request_target("CONNECT", "https://example.test"),
        Err(Http1ParseError::InvalidRequestTarget)
    );
    assert_eq!(
        http1_request_target("CONNECT", "example.test"),
        Err(Http1ParseError::InvalidRequestTarget)
    );
    assert_eq!(
        http1_request_target("CONNECT", "user@example.test:443"),
        Err(Http1ParseError::InvalidRequestTarget)
    );
    assert_eq!(
        http1_request_target("GET", "http://user@example.test/path"),
        Err(Http1ParseError::InvalidRequestTarget)
    );
}

#[test]
fn parsed_head_exposes_request_target_decision() {
    let parsed = parse_http1_request_head(
        b"GET /items?kind=book HTTP/1.1\r\nHost: example.test\r\n\r\n",
        Http1HeadLimits::default(),
    )
    .unwrap()
    .expect("complete head");

    assert_eq!(
        parsed.request_target(),
        Ok(Http1RequestTarget::Origin {
            raw: "/items?kind=book",
            path: "/items",
            query: Some("kind=book")
        })
    );
}

#[test]
fn classifies_content_length_and_chunked_body_framing() {
    assert_eq!(
        http1_request_body_framing(&[]),
        Ok(Http1BodyFraming::NoBody)
    );
    assert_eq!(
        http1_request_body_framing(&[header("Content-Length", "0")]),
        Ok(Http1BodyFraming::NoBody)
    );
    assert_eq!(
        http1_request_body_framing(&[header("Content-Length", "42")]),
        Ok(Http1BodyFraming::ContentLength(42))
    );
    assert_eq!(
        http1_request_body_framing(&[header("Transfer-Encoding", "chunked")]),
        Ok(Http1BodyFraming::Chunked)
    );
}

#[test]
fn rejects_ambiguous_or_invalid_body_framing() {
    assert_eq!(
        http1_request_body_framing(&[
            header("Transfer-Encoding", "chunked"),
            header("Content-Length", "1")
        ]),
        Err(Http1ParseError::ConflictingBodyFraming)
    );
    assert_eq!(
        http1_request_body_framing(&[header("Content-Length", "1"), header("Content-Length", "2")]),
        Err(Http1ParseError::DuplicateContentLength)
    );
    assert_eq!(
        http1_request_body_framing(&[header("Content-Length", "1"), header("Content-Length", "1")]),
        Err(Http1ParseError::DuplicateContentLength)
    );
    assert_eq!(
        http1_request_body_framing(&[header("Content-Length", "1x")]),
        Err(Http1ParseError::InvalidContentLength)
    );
    assert_eq!(
        http1_request_body_framing(&[header("Transfer-Encoding", "chunked, gzip")]),
        Err(Http1ParseError::UnsupportedTransferEncoding)
    );
    assert_eq!(
        http1_request_body_framing(&[header("Transfer-Encoding", "gzip, chunked")]),
        Err(Http1ParseError::UnsupportedTransferEncoding)
    );
}

#[test]
fn parsed_head_exposes_body_framing_decision() {
    let parsed = parse_http1_request_head(
        b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello",
        Http1HeadLimits::default(),
    )
    .unwrap()
    .expect("complete head");

    assert_eq!(
        parsed.body_framing(),
        Ok(Http1BodyFraming::ContentLength(5))
    );
}

#[test]
fn validates_required_http11_host_boundary() {
    assert_eq!(
        http1_required_host(&[header("Host", "example.test")]),
        Ok("example.test")
    );
    assert_eq!(http1_required_host(&[]), Err(Http1ParseError::MissingHost));
    assert_eq!(
        http1_required_host(&[header("Host", "example.test"), header("Host", "other.test")]),
        Err(Http1ParseError::DuplicateHost)
    );
    assert_eq!(
        http1_required_host(&[header("Host", "")]),
        Err(Http1ParseError::InvalidHost)
    );
    assert_eq!(
        http1_required_host(&[header("Host", "bad host")]),
        Err(Http1ParseError::InvalidHost)
    );
}

#[test]
fn parsed_head_exposes_required_host_decision() {
    let parsed = parse_http1_request_head(
        b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
        Http1HeadLimits::default(),
    )
    .unwrap()
    .expect("complete head");

    assert_eq!(parsed.host(), Ok("example.test"));
}

#[test]
fn classifies_connection_persistence_by_version_and_header() {
    assert_eq!(
        http1_connection_directive(Http1Version::Http11, &[]),
        Ok(Http1ConnectionDirective::Persistent)
    );
    assert_eq!(
        http1_connection_directive(Http1Version::Http10, &[]),
        Ok(Http1ConnectionDirective::Close)
    );
    assert_eq!(
        http1_connection_directive(Http1Version::Http10, &[header("Connection", "keep-alive")]),
        Ok(Http1ConnectionDirective::Persistent)
    );
    assert_eq!(
        http1_connection_directive(Http1Version::Http11, &[header("Connection", "close")]),
        Ok(Http1ConnectionDirective::Close)
    );
    assert_eq!(
        http1_connection_directive(
            Http1Version::Http11,
            &[header("Connection", "keep-alive, close")]
        ),
        Ok(Http1ConnectionDirective::Close)
    );
}

#[test]
fn rejects_invalid_connection_tokens() {
    assert_eq!(
        http1_connection_directive(Http1Version::Http11, &[header("Connection", "keep alive")]),
        Err(Http1ParseError::InvalidConnection)
    );
    assert_eq!(
        http1_connection_directive(Http1Version::Http11, &[header("Connection", "")]),
        Err(Http1ParseError::InvalidConnection)
    );
}

#[test]
fn parsed_head_exposes_connection_directive() {
    let parsed = parse_http1_request_head(
        b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
        Http1HeadLimits::default(),
    )
    .unwrap()
    .expect("complete head");

    assert_eq!(
        parsed.connection_directive(),
        Ok(Http1ConnectionDirective::Close)
    );
}

#[test]
fn decodes_complete_chunked_body_into_caller_buffer() {
    let mut output = [0u8; 16];
    let decoded = decode_http1_chunked_body(
        b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\nextra",
        &mut output,
        Http1ChunkLimits::default(),
    )
    .unwrap()
    .expect("complete body");

    assert_eq!(
        decoded,
        Http1ChunkedDecode {
            decoded_len: 9,
            consumed_len: 24
        }
    );
    assert_eq!(&output[..decoded.decoded_len], b"Wikipedia");
}

#[test]
fn chunked_decoder_reports_incomplete_without_error() {
    let mut output = [0u8; 16];

    assert_eq!(
        decode_http1_chunked_body(b"4\r\nWi", &mut output, Http1ChunkLimits::default()).unwrap(),
        None
    );
    assert_eq!(
        decode_http1_chunked_body(b"0\r\n", &mut output, Http1ChunkLimits::default()).unwrap(),
        None
    );
}

#[test]
fn chunked_decoder_enforces_output_and_body_limits() {
    let mut short_output = [0u8; 4];
    assert_eq!(
        decode_http1_chunked_body(
            b"5\r\nhello\r\n0\r\n\r\n",
            &mut short_output,
            Http1ChunkLimits::default()
        ),
        Err(Http1ParseError::OutputTooSmall)
    );

    let mut output = [0u8; 16];
    assert_eq!(
        decode_http1_chunked_body(
            b"5\r\nhello\r\n0\r\n\r\n",
            &mut output,
            Http1ChunkLimits {
                max_body_bytes: 4,
                ..Http1ChunkLimits::default()
            }
        ),
        Err(Http1ParseError::BodyTooLarge)
    );
}

#[test]
fn chunked_decoder_default_body_limit_is_bounded() {
    assert_eq!(
        Http1ChunkLimits::default().max_body_bytes,
        DEFAULT_HTTP1_MAX_BODY_BYTES
    );
    assert!(Http1ChunkLimits::default().max_body_bytes < usize::MAX);
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
