use crate::http1::Http1ParseError;

pub const DEFAULT_HTTP1_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_HTTP1_MAX_CHUNK_SIZE: usize = 1024 * 1024;
pub const DEFAULT_HTTP1_MAX_ENCODED_BYTES: usize = 72 * 1024 * 1024;
pub const DEFAULT_HTTP1_MAX_CHUNK_LINE_BYTES: usize = 8 * 1024;
pub const DEFAULT_HTTP1_MAX_CHUNK_COUNT: usize = 1024 * 1024;
pub const DEFAULT_HTTP1_MAX_CHUNK_EXTENSION_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http1ChunkLimits {
    pub max_chunk_size: usize,
    pub max_body_bytes: usize,
    pub max_encoded_bytes: usize,
    pub max_chunk_line_bytes: usize,
    pub max_chunk_count: usize,
    pub max_chunk_extension_bytes: usize,
}

impl Default for Http1ChunkLimits {
    fn default() -> Self {
        Self {
            max_chunk_size: DEFAULT_HTTP1_MAX_CHUNK_SIZE,
            max_body_bytes: DEFAULT_HTTP1_MAX_BODY_BYTES,
            max_encoded_bytes: DEFAULT_HTTP1_MAX_ENCODED_BYTES,
            max_chunk_line_bytes: DEFAULT_HTTP1_MAX_CHUNK_LINE_BYTES,
            max_chunk_count: DEFAULT_HTTP1_MAX_CHUNK_COUNT,
            max_chunk_extension_bytes: DEFAULT_HTTP1_MAX_CHUNK_EXTENSION_BYTES,
        }
    }
}

impl Http1ChunkLimits {
    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        let metadata_allowance = DEFAULT_HTTP1_MAX_ENCODED_BYTES - DEFAULT_HTTP1_MAX_BODY_BYTES;
        self.max_body_bytes = max_body_bytes;
        self.max_encoded_bytes = max_body_bytes.saturating_add(metadata_allowance);
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http1ChunkedDecode {
    pub decoded_len: usize,
    pub consumed_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Http1ChunkedDecodeState {
    Size,
    Data(usize),
    End,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http1ChunkedDecoder {
    limits: Http1ChunkLimits,
    input: Vec<u8>,
    output: Vec<u8>,
    input_offset: usize,
    chunk_count: usize,
    extension_bytes: usize,
    state: Http1ChunkedDecodeState,
    complete: Option<Http1ChunkedDecode>,
}

impl Http1ChunkedDecoder {
    pub fn new(limits: Http1ChunkLimits) -> Self {
        Self {
            limits,
            input: Vec::new(),
            output: Vec::new(),
            input_offset: 0,
            chunk_count: 0,
            extension_bytes: 0,
            state: Http1ChunkedDecodeState::Size,
            complete: None,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<Option<Http1ChunkedDecode>, Http1ParseError> {
        if let Some(complete) = self.complete {
            return Ok(Some(complete));
        }
        let encoded_len = self
            .input
            .len()
            .checked_add(chunk.len())
            .ok_or(Http1ParseError::EncodedBodyTooLarge)?;
        if encoded_len > self.limits.max_encoded_bytes {
            return Err(Http1ParseError::EncodedBodyTooLarge);
        }
        self.input
            .try_reserve(chunk.len())
            .map_err(|_| Http1ParseError::EncodedBodyTooLarge)?;
        self.input.extend_from_slice(chunk);
        self.process()
    }

    pub fn decoded_body(&self) -> &[u8] {
        &self.output
    }

    fn process(&mut self) -> Result<Option<Http1ChunkedDecode>, Http1ParseError> {
        loop {
            match self.state {
                Http1ChunkedDecodeState::Size => {
                    let Some(line_end) = find_crlf(&self.input, self.input_offset) else {
                        if self.input.len().saturating_sub(self.input_offset)
                            > self.limits.max_chunk_line_bytes
                        {
                            return Err(Http1ParseError::ChunkMetadataTooLarge);
                        }
                        return Ok(None);
                    };
                    let line = &self.input[self.input_offset..line_end];
                    if line.len() > self.limits.max_chunk_line_bytes {
                        return Err(Http1ParseError::ChunkMetadataTooLarge);
                    }
                    self.chunk_count = self
                        .chunk_count
                        .checked_add(1)
                        .ok_or(Http1ParseError::ChunkMetadataTooLarge)?;
                    if self.chunk_count > self.limits.max_chunk_count {
                        return Err(Http1ParseError::ChunkMetadataTooLarge);
                    }
                    let (size, extension_bytes) =
                        parse_chunk_size_line(line, self.limits.max_chunk_size)?;
                    self.extension_bytes = self
                        .extension_bytes
                        .checked_add(extension_bytes)
                        .ok_or(Http1ParseError::ChunkMetadataTooLarge)?;
                    if self.extension_bytes > self.limits.max_chunk_extension_bytes {
                        return Err(Http1ParseError::ChunkMetadataTooLarge);
                    }
                    self.input_offset = line_end
                        .checked_add(2)
                        .ok_or(Http1ParseError::InvalidChunk)?;
                    if size == 0 {
                        self.state = Http1ChunkedDecodeState::End;
                        continue;
                    }
                    self.state = Http1ChunkedDecodeState::Data(size);
                }
                Http1ChunkedDecodeState::Data(size) => {
                    let data_end = self
                        .input_offset
                        .checked_add(size)
                        .ok_or(Http1ParseError::ChunkTooLarge)?;
                    let chunk_end = data_end
                        .checked_add(2)
                        .ok_or(Http1ParseError::InvalidChunk)?;
                    if chunk_end > self.input.len() {
                        return Ok(None);
                    }
                    if &self.input[data_end..chunk_end] != b"\r\n" {
                        return Err(Http1ParseError::InvalidChunk);
                    }
                    let output_end = self
                        .output
                        .len()
                        .checked_add(size)
                        .ok_or(Http1ParseError::BodyTooLarge)?;
                    if output_end > self.limits.max_body_bytes {
                        return Err(Http1ParseError::BodyTooLarge);
                    }
                    self.output
                        .try_reserve(size)
                        .map_err(|_| Http1ParseError::BodyTooLarge)?;
                    self.output
                        .extend_from_slice(&self.input[self.input_offset..data_end]);
                    self.input_offset = chunk_end;
                    self.state = Http1ChunkedDecodeState::Size;
                }
                Http1ChunkedDecodeState::End => {
                    let Some(end) = self
                        .input
                        .get(self.input_offset..self.input_offset.saturating_add(2))
                    else {
                        return Ok(None);
                    };
                    if end != b"\r\n" {
                        return Err(Http1ParseError::InvalidChunk);
                    }
                    let consumed_len = self
                        .input_offset
                        .checked_add(2)
                        .ok_or(Http1ParseError::InvalidChunk)?;
                    let complete = Http1ChunkedDecode {
                        decoded_len: self.output.len(),
                        consumed_len,
                    };
                    self.complete = Some(complete);
                    return Ok(Some(complete));
                }
            }
        }
    }
}

pub fn decode_http1_chunked_body(
    input: &[u8],
    output: &mut [u8],
    limits: Http1ChunkLimits,
) -> Result<Option<Http1ChunkedDecode>, Http1ParseError> {
    let mut decoder = Http1ChunkedDecoder::new(limits);
    let Some(decoded) = decoder.push(input)? else {
        return Ok(None);
    };
    if decoded.decoded_len > output.len() {
        return Err(Http1ParseError::OutputTooSmall);
    }
    output[..decoded.decoded_len].copy_from_slice(decoder.decoded_body());
    Ok(Some(decoded))
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

fn parse_chunk_size_line(
    line: &[u8],
    max_chunk_size: usize,
) -> Result<(usize, usize), Http1ParseError> {
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
    let extension_bytes = line.len().saturating_sub(size_end);
    validate_chunk_extensions(&line[size_end..])?;
    Ok((size, extension_bytes))
}

fn validate_chunk_extensions(mut extensions: &[u8]) -> Result<(), Http1ParseError> {
    while !extensions.is_empty() {
        if extensions.first() != Some(&b';') {
            return Err(Http1ParseError::InvalidChunk);
        }
        extensions = &extensions[1..];
        let name_len = extensions
            .iter()
            .position(|byte| matches!(byte, b';' | b'='))
            .unwrap_or(extensions.len());
        if name_len == 0
            || !extensions[..name_len]
                .iter()
                .all(|byte| crate::http_token_valid(std::str::from_utf8(&[*byte]).unwrap_or("")))
        {
            return Err(Http1ParseError::InvalidChunk);
        }
        extensions = &extensions[name_len..];
        if extensions.first() != Some(&b'=') {
            continue;
        }
        extensions = &extensions[1..];
        if extensions.first() == Some(&b'"') {
            extensions = &extensions[1..];
            let mut escaped = false;
            let mut close = None;
            for (index, byte) in extensions.iter().copied().enumerate() {
                if escaped {
                    if matches!(byte, 0x00..=0x1f | 0x7f..=0xff) {
                        return Err(Http1ParseError::InvalidChunk);
                    }
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    close = Some(index);
                    break;
                } else if matches!(byte, 0x00..=0x1f | 0x7f..=0xff) {
                    return Err(Http1ParseError::InvalidChunk);
                }
            }
            let close = close.ok_or(Http1ParseError::InvalidChunk)?;
            extensions = &extensions[close + 1..];
            if !extensions.is_empty() && extensions.first() != Some(&b';') {
                return Err(Http1ParseError::InvalidChunk);
            }
        } else {
            let value_len = extensions
                .iter()
                .position(|byte| *byte == b';')
                .unwrap_or(extensions.len());
            let value = std::str::from_utf8(&extensions[..value_len])
                .map_err(|_| Http1ParseError::InvalidChunk)?;
            if !crate::http_token_valid(value) {
                return Err(Http1ParseError::InvalidChunk);
            }
            extensions = &extensions[value_len..];
        }
    }
    Ok(())
}

fn hex_value(byte: u8) -> Option<usize> {
    match byte {
        b'0'..=b'9' => Some((byte - b'0') as usize),
        b'a'..=b'f' => Some((byte - b'a' + 10) as usize),
        b'A'..=b'F' => Some((byte - b'A' + 10) as usize),
        _ => None,
    }
}
