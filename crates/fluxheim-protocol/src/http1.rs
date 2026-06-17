use crate::http_token_valid;

pub const DEFAULT_HTTP1_MAX_HEAD_BYTES: usize = 64 * 1024;
pub const DEFAULT_HTTP1_MAX_HEADER_COUNT: usize = 100;
pub const DEFAULT_HTTP1_MAX_HEADER_LINE_BYTES: usize = 8 * 1024;
pub const DEFAULT_HTTP1_MAX_START_LINE_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http1HeadLimits {
    pub max_head_bytes: usize,
    pub max_header_count: usize,
    pub max_header_line_bytes: usize,
    pub max_start_line_bytes: usize,
}

impl Default for Http1HeadLimits {
    fn default() -> Self {
        Self {
            max_head_bytes: DEFAULT_HTTP1_MAX_HEAD_BYTES,
            max_header_count: DEFAULT_HTTP1_MAX_HEADER_COUNT,
            max_header_line_bytes: DEFAULT_HTTP1_MAX_HEADER_LINE_BYTES,
            max_start_line_bytes: DEFAULT_HTTP1_MAX_START_LINE_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http1Version {
    Http10,
    Http11,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http1Header<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http1RequestHead<'a> {
    pub method: &'a str,
    pub target: &'a str,
    pub version: Http1Version,
    pub headers: Vec<Http1Header<'a>>,
    pub head_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http1HeadBuffer {
    bytes: Vec<u8>,
    limits: Http1HeadLimits,
}

impl Http1HeadBuffer {
    pub fn new(limits: Http1HeadLimits) -> Self {
        Self {
            bytes: Vec::new(),
            limits,
        }
    }

    pub fn buffered_len(&self) -> usize {
        self.bytes.len()
    }

    pub fn append(
        &mut self,
        chunk: &[u8],
    ) -> Result<Option<Http1RequestHead<'_>>, Http1ParseError> {
        if self.bytes.len() > self.limits.max_head_bytes {
            return Err(Http1ParseError::HeadTooLarge);
        }
        let search_cap = self.limits.max_head_bytes;
        let remaining = search_cap.saturating_sub(self.bytes.len());
        self.bytes
            .extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        match parse_http1_request_head(&self.bytes, self.limits) {
            Ok(Some(head)) => Ok(Some(head)),
            Ok(None)
                if chunk.len() > remaining || self.bytes.len() > self.limits.max_head_bytes =>
            {
                Err(Http1ParseError::HeadTooLarge)
            }
            Ok(None) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn clear(&mut self) {
        self.bytes.clear();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Http1ParseError {
    HeaderCountExceeded,
    HeaderLineTooLong,
    HeadTooLarge,
    InvalidHeaderName,
    InvalidHeaderValue,
    InvalidRequestLine,
    InvalidUtf8,
    ObsoleteLineFolding,
    StartLineTooLong,
    UnsupportedVersion,
}

pub fn parse_http1_request_head(
    input: &[u8],
    limits: Http1HeadLimits,
) -> Result<Option<Http1RequestHead<'_>>, Http1ParseError> {
    let Some(head_len) = complete_head_len(input, limits.max_head_bytes)? else {
        return Ok(None);
    };
    let head = std::str::from_utf8(&input[..head_len]).map_err(|_| Http1ParseError::InvalidUtf8)?;
    let mut lines = head.split("\r\n");
    let start_line = lines.next().ok_or(Http1ParseError::InvalidRequestLine)?;
    if start_line.len() > limits.max_start_line_bytes {
        return Err(Http1ParseError::StartLineTooLong);
    }
    let (method, target, version) = parse_request_line(start_line)?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.len() > limits.max_header_line_bytes {
            return Err(Http1ParseError::HeaderLineTooLong);
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(Http1ParseError::ObsoleteLineFolding);
        }
        if headers.len() >= limits.max_header_count {
            return Err(Http1ParseError::HeaderCountExceeded);
        }
        headers.push(parse_header_line(line)?);
    }

    Ok(Some(Http1RequestHead {
        method,
        target,
        version,
        headers,
        head_len,
    }))
}

fn complete_head_len(
    input: &[u8],
    max_head_bytes: usize,
) -> Result<Option<usize>, Http1ParseError> {
    let search_len = input.len().min(max_head_bytes.saturating_add(4));
    for index in 0..search_len.saturating_sub(3) {
        if &input[index..index + 4] == b"\r\n\r\n" {
            let head_len = index + 4;
            if head_len > max_head_bytes {
                return Err(Http1ParseError::HeadTooLarge);
            }
            return Ok(Some(head_len));
        }
    }
    if input.len() > max_head_bytes {
        return Err(Http1ParseError::HeadTooLarge);
    }
    Ok(None)
}

fn parse_request_line(line: &str) -> Result<(&str, &str, Http1Version), Http1ParseError> {
    let mut parts = line.split(' ');
    let method = parts.next().ok_or(Http1ParseError::InvalidRequestLine)?;
    let target = parts.next().ok_or(Http1ParseError::InvalidRequestLine)?;
    let version = parts.next().ok_or(Http1ParseError::InvalidRequestLine)?;
    if parts.next().is_some() || method.is_empty() || target.is_empty() {
        return Err(Http1ParseError::InvalidRequestLine);
    }
    if !http_token_valid(method) {
        return Err(Http1ParseError::InvalidRequestLine);
    }
    let version = match version {
        "HTTP/1.0" => Http1Version::Http10,
        "HTTP/1.1" => Http1Version::Http11,
        _ => return Err(Http1ParseError::UnsupportedVersion),
    };
    Ok((method, target, version))
}

fn parse_header_line(line: &str) -> Result<Http1Header<'_>, Http1ParseError> {
    let Some((name, value)) = line.split_once(':') else {
        return Err(Http1ParseError::InvalidHeaderName);
    };
    if !http_token_valid(name) {
        return Err(Http1ParseError::InvalidHeaderName);
    }
    if value
        .bytes()
        .any(|byte| matches!(byte, 0x00..=0x08 | 0x0a..=0x1f | 0x7f))
    {
        return Err(Http1ParseError::InvalidHeaderValue);
    }
    Ok(Http1Header {
        name,
        value: value.trim(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bounded_http11_request_head() {
        let input =
            b"GET /index.html HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\nbody";
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
                Http1Header {
                    name: "Host",
                    value: "example.test"
                },
                Http1Header {
                    name: "Connection",
                    value: "close"
                }
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
        assert_eq!(
            parsed.headers,
            vec![Http1Header {
                name: "Host",
                value: "example.test"
            }]
        );
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
}
