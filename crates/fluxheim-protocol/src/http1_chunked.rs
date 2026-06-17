use crate::http1::Http1ParseError;

pub const DEFAULT_HTTP1_MAX_CHUNK_SIZE: usize = 1024 * 1024;

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
