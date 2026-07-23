use crate::http1::Http1ParseError;

pub const DEFAULT_HTTP1_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_HTTP1_MAX_CHUNK_SIZE: usize = 1024 * 1024;
pub const DEFAULT_HTTP1_MAX_ENCODED_BYTES: usize = 72 * 1024 * 1024;
pub const DEFAULT_HTTP1_MAX_CHUNK_LINE_BYTES: usize = 8 * 1024;
pub const DEFAULT_HTTP1_MAX_CHUNK_COUNT: usize = 1024 * 1024;
pub const DEFAULT_HTTP1_MAX_CHUNK_EXTENSION_BYTES: usize = 64 * 1024;
const HTTP1_CHUNK_INPUT_FRAGMENT_BYTES: usize = 8 * 1024;
const HTTP1_CHUNK_COMPACT_THRESHOLD_BYTES: usize = 4 * 1024;

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

#[derive(Debug, Eq, PartialEq)]
pub struct Http1ChunkedDecoder {
    limits: Http1ChunkLimits,
    input: Vec<u8>,
    input_offset: usize,
    line_scan_offset: usize,
    compacted_len: usize,
    received_len: usize,
    decoded_len: usize,
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
            input_offset: 0,
            line_scan_offset: 0,
            compacted_len: 0,
            received_len: 0,
            decoded_len: 0,
            chunk_count: 0,
            extension_bytes: 0,
            state: Http1ChunkedDecodeState::Size,
            complete: None,
        }
    }

    pub fn push(
        &mut self,
        chunk: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<Option<Http1ChunkedDecode>, Http1ParseError> {
        if output.len() != self.decoded_len {
            return Err(Http1ParseError::InvalidChunk);
        }
        self.push_with_sink(chunk, output)
    }

    pub fn push_to<S: Http1ChunkSink>(
        &mut self,
        chunk: &[u8],
        output: &mut S,
    ) -> Result<Option<Http1ChunkedDecode>, Http1ParseError> {
        if output.len() != self.decoded_len {
            return Err(Http1ParseError::InvalidChunk);
        }
        self.push_with_sink(chunk, output)
    }

    pub fn buffered_len(&self) -> usize {
        self.input.len()
    }

    fn push_with_sink<S: Http1ChunkSink>(
        &mut self,
        chunk: &[u8],
        output: &mut S,
    ) -> Result<Option<Http1ChunkedDecode>, Http1ParseError> {
        if let Some(complete) = self.complete {
            return Ok(Some(complete));
        }
        if chunk.is_empty() {
            return self.process(output);
        }
        let mut offset = 0usize;
        while offset < chunk.len() {
            let remaining_limit = self
                .limits
                .max_encoded_bytes
                .saturating_sub(self.received_len);
            if remaining_limit == 0 {
                return Err(Http1ParseError::EncodedBodyTooLarge);
            }
            let fragment_len = (chunk.len() - offset)
                .min(HTTP1_CHUNK_INPUT_FRAGMENT_BYTES)
                .min(remaining_limit);
            let end = offset
                .checked_add(fragment_len)
                .ok_or(Http1ParseError::EncodedBodyTooLarge)?;
            self.input
                .try_reserve(fragment_len)
                .map_err(|_| Http1ParseError::EncodedBodyTooLarge)?;
            self.input.extend_from_slice(&chunk[offset..end]);
            self.received_len = self
                .received_len
                .checked_add(fragment_len)
                .ok_or(Http1ParseError::EncodedBodyTooLarge)?;
            if let Some(complete) = self.process(output)? {
                return Ok(Some(complete));
            }
            offset = end;
        }
        Ok(None)
    }

    fn process<S: Http1ChunkSink>(
        &mut self,
        output: &mut S,
    ) -> Result<Option<Http1ChunkedDecode>, Http1ParseError> {
        loop {
            match self.state {
                Http1ChunkedDecodeState::Size => {
                    let Some(line_end) = find_crlf(&self.input, self.line_scan_offset) else {
                        let pending = self
                            .input
                            .get(self.input_offset..)
                            .ok_or(Http1ParseError::InvalidChunk)?;
                        let pending_line_len = pending
                            .len()
                            .saturating_sub(usize::from(pending.last() == Some(&b'\r')));
                        if pending_line_len > self.limits.max_chunk_line_bytes {
                            return Err(Http1ParseError::ChunkMetadataTooLarge);
                        }
                        self.line_scan_offset =
                            self.input.len().saturating_sub(1).max(self.input_offset);
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
                    self.line_scan_offset = self.input_offset;
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
                        .decoded_len
                        .checked_add(size)
                        .ok_or(Http1ParseError::BodyTooLarge)?;
                    if output_end > self.limits.max_body_bytes {
                        return Err(Http1ParseError::BodyTooLarge);
                    }
                    output.append(&self.input[self.input_offset..data_end])?;
                    self.decoded_len = output_end;
                    self.input_offset = chunk_end;
                    self.line_scan_offset = self.input_offset;
                    self.state = Http1ChunkedDecodeState::Size;
                    self.compact_consumed()?;
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
                        .compacted_len
                        .checked_add(self.input_offset)
                        .and_then(|value| value.checked_add(2))
                        .ok_or(Http1ParseError::InvalidChunk)?;
                    let complete = Http1ChunkedDecode {
                        decoded_len: self.decoded_len,
                        consumed_len,
                    };
                    self.complete = Some(complete);
                    return Ok(Some(complete));
                }
            }
        }
    }

    fn compact_consumed(&mut self) -> Result<(), Http1ParseError> {
        if self.input_offset == 0 {
            return Ok(());
        }
        if self.input_offset != self.input.len()
            && (self.input_offset < HTTP1_CHUNK_COMPACT_THRESHOLD_BYTES
                || self.input_offset < self.input.len() / 2)
        {
            return Ok(());
        }
        let consumed = self.input_offset;
        self.compacted_len = self
            .compacted_len
            .checked_add(consumed)
            .ok_or(Http1ParseError::EncodedBodyTooLarge)?;
        self.input.copy_within(consumed.., 0);
        self.input.truncate(self.input.len() - consumed);
        self.input_offset = 0;
        self.line_scan_offset = self.line_scan_offset.saturating_sub(consumed);
        Ok(())
    }
}

impl Drop for Http1ChunkedDecoder {
    fn drop(&mut self) {
        sanitization::wipe::vec(&mut self.input);
    }
}

pub trait Http1ChunkSink {
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), Http1ParseError>;
}

impl Http1ChunkSink for Vec<u8> {
    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), Http1ParseError> {
        self.try_reserve(bytes.len())
            .map_err(|_| Http1ParseError::BodyTooLarge)?;
        self.extend_from_slice(bytes);
        Ok(())
    }
}

struct Http1SliceChunkSink<'a> {
    output: &'a mut [u8],
    len: usize,
}

impl Http1ChunkSink for Http1SliceChunkSink<'_> {
    fn len(&self) -> usize {
        self.len
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), Http1ParseError> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(Http1ParseError::OutputTooSmall)?;
        let destination = self
            .output
            .get_mut(self.len..end)
            .ok_or(Http1ParseError::OutputTooSmall)?;
        destination.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

pub fn decode_http1_chunked_body(
    input: &[u8],
    output: &mut [u8],
    limits: Http1ChunkLimits,
) -> Result<Option<Http1ChunkedDecode>, Http1ParseError> {
    let mut decoder = Http1ChunkedDecoder::new(limits);
    let mut sink = Http1SliceChunkSink { output, len: 0 };
    decoder.push_with_sink(input, &mut sink)
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
