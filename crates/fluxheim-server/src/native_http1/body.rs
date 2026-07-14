use std::time::Duration;

use fluxheim_protocol::{Http1BodyFraming, Http1ChunkLimits, Http1ChunkedDecoder, Http1ParseError};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

use crate::{DownstreamHttp1Policy, NativeHttp1Error};

const READ_CHUNK_BYTES: usize = 8192;

pub(super) async fn read_body<S>(
    policy: DownstreamHttp1Policy,
    request_body_timeout: Duration,
    stream: &mut S,
    buffer: &mut Vec<u8>,
    head_len: usize,
    framing: Http1BodyFraming,
) -> Result<Vec<u8>, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    timeout(
        request_body_timeout,
        read_body_inner(stream, buffer, head_len, framing, policy.max_body_bytes()),
    )
    .await
    .map_err(|_| {
        NativeHttp1Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "request body timeout",
        ))
    })?
}

async fn read_body_inner<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    head_len: usize,
    framing: Http1BodyFraming,
    max_body_bytes: usize,
) -> Result<Vec<u8>, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    match framing {
        Http1BodyFraming::NoBody => {
            buffer.drain(..head_len);
            Ok(Vec::new())
        }
        Http1BodyFraming::ContentLength(length) => {
            let length = usize::try_from(length).map_err(|_| Http1ParseError::BodyTooLarge)?;
            if length > max_body_bytes {
                return Err(Http1ParseError::BodyTooLarge.into());
            }
            let required = head_len
                .checked_add(length)
                .ok_or(Http1ParseError::BodyTooLarge)?;
            while buffer.len() < required {
                let mut chunk = [0u8; READ_CHUNK_BYTES];
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    return Err(Http1ParseError::InvalidContentLength.into());
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            let body = buffer[head_len..required].to_vec();
            buffer.drain(..required);
            Ok(body)
        }
        Http1BodyFraming::Chunked => {
            read_chunked_body(stream, buffer, head_len, max_body_bytes).await
        }
    }
}

async fn read_chunked_body<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    head_len: usize,
    max_body_bytes: usize,
) -> Result<Vec<u8>, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    buffer.drain(..head_len);
    let limits = Http1ChunkLimits::default().with_max_body_bytes(max_body_bytes);
    let mut decoder = Http1ChunkedDecoder::new(limits);
    if let Some(decoded) = decoder.push(buffer)? {
        let body = decoder.decoded_body().to_vec();
        buffer.drain(..decoded.consumed_len);
        return Ok(body);
    }
    loop {
        let mut chunk = [0u8; READ_CHUNK_BYTES];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(Http1ParseError::InvalidChunk.into());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(decoded) = decoder.push(&chunk[..read])? {
            let body = decoder.decoded_body().to_vec();
            buffer.drain(..decoded.consumed_len);
            return Ok(body);
        }
    }
}
