use super::{
    Http1HeadLimits, Http1Header, Http1ParseError, Http1Version, parse_http1_response_head,
};

fn header<'a>(name: &'a str, value: &'a str) -> Http1Header<'a> {
    Http1Header { name, value }
}

#[test]
fn parses_bounded_http1_response_head() {
    let input = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody";
    let parsed = parse_http1_response_head(input, Http1HeadLimits::default())
        .unwrap()
        .expect("complete response head");

    assert_eq!(parsed.version, Http1Version::Http11);
    assert_eq!(parsed.status, 200);
    assert_eq!(parsed.reason, "OK");
    assert_eq!(parsed.head_len, input.len() - 4);
    assert_eq!(parsed.headers, vec![header("Content-Type", "text/plain")]);
}

#[test]
fn returns_none_for_incomplete_response_head() {
    assert_eq!(
        parse_http1_response_head(
            b"HTTP/1.1 200 OK\r\nServer: test",
            Http1HeadLimits::default()
        )
        .unwrap(),
        None
    );
}

#[test]
fn rejects_invalid_response_status_line() {
    assert_eq!(
        parse_http1_response_head(b"HTTP/2.0 200 OK\r\n\r\n", Http1HeadLimits::default()),
        Err(Http1ParseError::UnsupportedVersion)
    );
    assert_eq!(
        parse_http1_response_head(b"HTTP/1.1 20 OK\r\n\r\n", Http1HeadLimits::default()),
        Err(Http1ParseError::InvalidStatusCode)
    );
    assert_eq!(
        parse_http1_response_head(b"HTTP/1.1 200 bad\x7f\r\n\r\n", Http1HeadLimits::default()),
        Err(Http1ParseError::InvalidResponseLine)
    );
    assert_eq!(
        parse_http1_response_head(
            "HTTP/1.1 200 bad\u{80}\r\n\r\n".as_bytes(),
            Http1HeadLimits::default()
        ),
        Err(Http1ParseError::InvalidResponseLine)
    );
}

#[test]
fn response_head_reuses_strict_header_bounds() {
    let limits = Http1HeadLimits {
        max_header_count: 1,
        ..Http1HeadLimits::default()
    };

    assert_eq!(
        parse_http1_response_head(b"HTTP/1.1 200 OK\r\nA: b\r\nC: d\r\n\r\n", limits),
        Err(Http1ParseError::HeaderCountExceeded)
    );
    assert_eq!(
        parse_http1_response_head(
            b"HTTP/1.1 200 OK\r\n folded: nope\r\n\r\n",
            Http1HeadLimits::default()
        ),
        Err(Http1ParseError::ObsoleteLineFolding)
    );
}
