use crate::http_token_valid;
use crate::http1_target::{Http1RequestTarget, http1_request_target};

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

impl<'a> Http1RequestHead<'a> {
    pub fn body_framing(&self) -> Result<Http1BodyFraming, Http1ParseError> {
        http1_request_body_framing(&self.headers)
    }

    pub fn host(&self) -> Result<&'a str, Http1ParseError> {
        http1_required_host(&self.headers)
    }

    pub fn connection_directive(&self) -> Result<Http1ConnectionDirective, Http1ParseError> {
        http1_connection_directive(self.version, &self.headers)
    }

    pub fn request_target(&self) -> Result<Http1RequestTarget<'a>, Http1ParseError> {
        http1_request_target(self.method, self.target)
    }
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
    BodyTooLarge,
    ChunkTooLarge,
    ConflictingBodyFraming,
    DuplicateContentLength,
    DuplicateHost,
    HeaderCountExceeded,
    HeaderLineTooLong,
    HeadTooLarge,
    InvalidConnection,
    InvalidContentLength,
    InvalidChunk,
    InvalidChunkSize,
    InvalidHost,
    InvalidHeaderName,
    InvalidHeaderValue,
    InvalidRequestLine,
    InvalidRequestTarget,
    InvalidUtf8,
    MissingHost,
    ObsoleteLineFolding,
    OutputTooSmall,
    StartLineTooLong,
    UnsupportedTransferEncoding,
    UnsupportedVersion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http1BodyFraming {
    NoBody,
    ContentLength(u64),
    Chunked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http1ConnectionDirective {
    Close,
    Persistent,
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

pub fn http1_request_body_framing(
    headers: &[Http1Header<'_>],
) -> Result<Http1BodyFraming, Http1ParseError> {
    let mut content_length = None;
    let mut transfer_encoding = None;

    for header in headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            let parsed = parse_content_length(header.value)?;
            if let Some(existing) = content_length {
                if existing != parsed {
                    return Err(Http1ParseError::DuplicateContentLength);
                }
            } else {
                content_length = Some(parsed);
            }
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding.is_some() {
                return Err(Http1ParseError::UnsupportedTransferEncoding);
            }
            transfer_encoding = Some(parse_transfer_encoding(header.value)?);
        }
    }

    match (transfer_encoding, content_length) {
        (Some(_), Some(_)) => Err(Http1ParseError::ConflictingBodyFraming),
        (Some(framing), None) => Ok(framing),
        (None, Some(0)) | (None, None) => Ok(Http1BodyFraming::NoBody),
        (None, Some(length)) => Ok(Http1BodyFraming::ContentLength(length)),
    }
}

pub fn http1_required_host<'a>(headers: &[Http1Header<'a>]) -> Result<&'a str, Http1ParseError> {
    let mut host = None;
    for header in headers {
        if header.name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return Err(Http1ParseError::DuplicateHost);
            }
            let value = header.value.trim();
            if value.is_empty() || value.bytes().any(|byte| matches!(byte, b' ' | b'\t')) {
                return Err(Http1ParseError::InvalidHost);
            }
            host = Some(value);
        }
    }
    host.ok_or(Http1ParseError::MissingHost)
}

pub fn http1_connection_directive(
    version: Http1Version,
    headers: &[Http1Header<'_>],
) -> Result<Http1ConnectionDirective, Http1ParseError> {
    let mut close = false;
    let mut keep_alive = false;

    for header in headers {
        if !header.name.eq_ignore_ascii_case("connection") {
            continue;
        }
        for token in header.value.split(',') {
            let token = token.trim();
            if !http_token_valid(token) {
                return Err(Http1ParseError::InvalidConnection);
            }
            if token.eq_ignore_ascii_case("close") {
                close = true;
            } else if token.eq_ignore_ascii_case("keep-alive") {
                keep_alive = true;
            }
        }
    }

    if close {
        return Ok(Http1ConnectionDirective::Close);
    }
    if version == Http1Version::Http11 || keep_alive {
        Ok(Http1ConnectionDirective::Persistent)
    } else {
        Ok(Http1ConnectionDirective::Close)
    }
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

fn parse_content_length(value: &str) -> Result<u64, Http1ParseError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Http1ParseError::InvalidContentLength);
    }
    trimmed
        .parse::<u64>()
        .map_err(|_| Http1ParseError::InvalidContentLength)
}

fn parse_transfer_encoding(value: &str) -> Result<Http1BodyFraming, Http1ParseError> {
    let mut codings = 0usize;
    let mut chunked = false;
    for coding in value.split(',') {
        let coding = coding.trim();
        if coding.is_empty() || !http_token_valid(coding) {
            return Err(Http1ParseError::UnsupportedTransferEncoding);
        }
        codings = codings.saturating_add(1);
        chunked = coding.eq_ignore_ascii_case("chunked");
    }
    if codings == 1 && chunked {
        return Ok(Http1BodyFraming::Chunked);
    }
    Err(Http1ParseError::UnsupportedTransferEncoding)
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
    http1_request_target(method, target)?;
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
