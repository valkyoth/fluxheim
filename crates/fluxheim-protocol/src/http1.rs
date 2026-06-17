use crate::http_token_valid;

pub const DEFAULT_HTTP1_MAX_HEAD_BYTES: usize = 64 * 1024;
pub const DEFAULT_HTTP1_MAX_HEADER_COUNT: usize = 100;
pub const DEFAULT_HTTP1_MAX_HEADER_LINE_BYTES: usize = 8 * 1024;
pub const DEFAULT_HTTP1_MAX_START_LINE_BYTES: usize = 8 * 1024;
pub const DEFAULT_HTTP1_MAX_CHUNK_SIZE: usize = 1024 * 1024;

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
    InvalidUtf8,
    MissingHost,
    ObsoleteLineFolding,
    OutputTooSmall,
    StartLineTooLong,
    UnsupportedTransferEncoding,
    UnsupportedVersion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http1ChunkLimits {
    pub max_chunk_size: usize,
    pub max_body_bytes: usize,
}

impl Default for Http1ChunkLimits {
    fn default() -> Self {
        Self {
            max_chunk_size: DEFAULT_HTTP1_MAX_CHUNK_SIZE,
            max_body_bytes: usize::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http1ChunkedDecode {
    pub decoded_len: usize,
    pub consumed_len: usize,
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

pub fn decode_http1_chunked_body(
    input: &[u8],
    output: &mut [u8],
    limits: Http1ChunkLimits,
) -> Result<Option<Http1ChunkedDecode>, Http1ParseError> {
    let mut input_offset = 0usize;
    let mut output_offset = 0usize;

    loop {
        let Some(line_end) = find_crlf(input, input_offset) else {
            return Ok(None);
        };
        let size = parse_chunk_size_line(&input[input_offset..line_end], limits.max_chunk_size)?;
        input_offset = line_end
            .checked_add(2)
            .ok_or(Http1ParseError::InvalidChunk)?;

        if size == 0 {
            let Some(end) = input.get(input_offset..input_offset.saturating_add(2)) else {
                return Ok(None);
            };
            if end != b"\r\n" {
                return Err(Http1ParseError::InvalidChunk);
            }
            return Ok(Some(Http1ChunkedDecode {
                decoded_len: output_offset,
                consumed_len: input_offset + 2,
            }));
        }

        let data_end = input_offset
            .checked_add(size)
            .ok_or(Http1ParseError::ChunkTooLarge)?;
        let chunk_end = data_end
            .checked_add(2)
            .ok_or(Http1ParseError::InvalidChunk)?;
        if chunk_end > input.len() {
            return Ok(None);
        }
        if &input[data_end..chunk_end] != b"\r\n" {
            return Err(Http1ParseError::InvalidChunk);
        }
        let output_end = output_offset
            .checked_add(size)
            .ok_or(Http1ParseError::BodyTooLarge)?;
        if output_end > limits.max_body_bytes {
            return Err(Http1ParseError::BodyTooLarge);
        }
        if output_end > output.len() {
            return Err(Http1ParseError::OutputTooSmall);
        }
        output[output_offset..output_end].copy_from_slice(&input[input_offset..data_end]);
        output_offset = output_end;
        input_offset = chunk_end;
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

fn find_crlf(input: &[u8], offset: usize) -> Option<usize> {
    let mut index = offset;
    while index + 1 < input.len() {
        if &input[index..index + 2] == b"\r\n" {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn parse_chunk_size_line(line: &[u8], max_chunk_size: usize) -> Result<usize, Http1ParseError> {
    let size_end = line
        .iter()
        .position(|byte| *byte == b';')
        .unwrap_or(line.len());
    if size_end == 0 {
        return Err(Http1ParseError::InvalidChunkSize);
    }
    let mut size = 0usize;
    for byte in &line[..size_end] {
        let Some(value) = hex_value(*byte) else {
            return Err(Http1ParseError::InvalidChunkSize);
        };
        size = size
            .checked_mul(16)
            .and_then(|current| current.checked_add(value))
            .ok_or(Http1ParseError::ChunkTooLarge)?;
        if size > max_chunk_size {
            return Err(Http1ParseError::ChunkTooLarge);
        }
    }
    Ok(size)
}

fn hex_value(byte: u8) -> Option<usize> {
    match byte {
        b'0'..=b'9' => Some((byte - b'0') as usize),
        b'a'..=b'f' => Some((byte - b'a' + 10) as usize),
        b'A'..=b'F' => Some((byte - b'A' + 10) as usize),
        _ => None,
    }
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
