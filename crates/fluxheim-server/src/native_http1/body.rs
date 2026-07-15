use std::time::Duration;

use fluxheim_protocol::{Http1BodyFraming, Http1ChunkLimits, Http1ChunkedDecoder, Http1ParseError};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

use crate::request_body_budget::NativeRequestBodyReservation;
use crate::{DownstreamHttp1Policy, NativeHttp1Error, NativeHttp1RequestBody};

const READ_CHUNK_BYTES: usize = 8192;

pub(super) async fn read_body<S>(
    policy: DownstreamHttp1Policy,
    request_body_timeout: Duration,
    stream: &mut S,
    buffer: &mut Vec<u8>,
    head_len: usize,
    framing: Http1BodyFraming,
    reservation: &mut NativeRequestBodyReservation,
) -> Result<NativeHttp1RequestBody, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    timeout(
        request_body_timeout,
        read_body_inner(
            stream,
            buffer,
            head_len,
            framing,
            policy.max_body_bytes(),
            reservation,
        ),
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
    reservation: &mut NativeRequestBodyReservation,
) -> Result<NativeHttp1RequestBody, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    match framing {
        Http1BodyFraming::NoBody => {
            sanitization::unsafe_wipe::volatile_sanitize_bytes(&mut buffer[..head_len]);
            buffer.drain(..head_len);
            Ok(NativeHttp1RequestBody::empty())
        }
        Http1BodyFraming::ContentLength(length) => {
            let length = usize::try_from(length).map_err(|_| Http1ParseError::BodyTooLarge)?;
            if length > max_body_bytes {
                return Err(Http1ParseError::BodyTooLarge.into());
            }
            let available = buffer.len().saturating_sub(head_len).min(length);
            let body_end = head_len
                .checked_add(available)
                .ok_or(Http1ParseError::BodyTooLarge)?;
            let mut initial = std::mem::take(buffer);
            let remainder = initial.split_off(body_end);
            sanitization::unsafe_wipe::volatile_sanitize_bytes(&mut initial[..head_len]);
            initial.drain(..head_len);
            *buffer = remainder;
            let mut body = NativeHttp1RequestBody::from_vec(initial);
            body.replace_capacity(length)?;
            while body.len() < length {
                let remaining = length - body.len();
                let mut chunk = [0u8; READ_CHUNK_BYTES];
                let read = stream
                    .read(&mut chunk[..remaining.min(READ_CHUNK_BYTES)])
                    .await?;
                if read == 0 {
                    return Err(Http1ParseError::InvalidContentLength.into());
                }
                let append_result = body.extend_from_slice(&chunk[..read]);
                sanitization::unsafe_wipe::volatile_sanitize_bytes(&mut chunk[..read]);
                append_result?;
            }
            Ok(body)
        }
        Http1BodyFraming::Chunked => {
            read_chunked_body(stream, buffer, head_len, max_body_bytes, reservation).await
        }
    }
}

async fn read_chunked_body<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    head_len: usize,
    max_body_bytes: usize,
    reservation: &mut NativeRequestBodyReservation,
) -> Result<NativeHttp1RequestBody, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    buffer.drain(..head_len);
    let limits = Http1ChunkLimits::default().with_max_body_bytes(max_body_bytes);
    let mut decoder = Http1ChunkedDecoder::new(limits);
    let mut body = NativeHttp1RequestBody::empty();
    let initial = NativeHttp1RequestBody::from_vec(std::mem::take(buffer));
    reserve_chunked_body_growth(&mut body, reservation, initial.len(), max_body_bytes).await?;
    if let Some(decoded) = decoder.push_to(&initial, &mut body)? {
        buffer.extend_from_slice(&initial[decoded.consumed_len..]);
        return Ok(body);
    }
    let mut fed_len = initial.len();
    loop {
        let mut chunk = [0u8; READ_CHUNK_BYTES];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(Http1ParseError::InvalidChunk.into());
        }
        let prospective_encoded = fed_len
            .checked_add(read)
            .ok_or(Http1ParseError::EncodedBodyTooLarge)?;
        reserve_chunked_body_growth(&mut body, reservation, read, max_body_bytes).await?;
        let decoded = decoder.push_to(&chunk[..read], &mut body);
        sanitization::unsafe_wipe::volatile_sanitize_bytes(&mut chunk[..read]);
        if let Some(decoded) = decoded? {
            let consumed_from_chunk = decoded
                .consumed_len
                .checked_sub(fed_len)
                .ok_or(Http1ParseError::InvalidChunk)?;
            let remainder = chunk
                .get(consumed_from_chunk..read)
                .ok_or(Http1ParseError::InvalidChunk)?;
            buffer.extend_from_slice(remainder);
            return Ok(body);
        }
        fed_len = prospective_encoded;
    }
}

async fn reserve_chunked_body_growth(
    body: &mut NativeHttp1RequestBody,
    reservation: &mut NativeRequestBodyReservation,
    possible_growth: usize,
    max_body_bytes: usize,
) -> Result<(), NativeHttp1Error> {
    let required = body
        .len()
        .checked_add(possible_growth)
        .ok_or(Http1ParseError::BodyTooLarge)?
        .min(max_body_bytes);
    if required <= body.capacity() {
        return Ok(());
    }
    let geometric = body.capacity().max(READ_CHUNK_BYTES).saturating_mul(2);
    let admitted_capacity = required.max(geometric).min(max_body_bytes);
    reservation.grow_to(admitted_capacity).await?;
    body.reserve_capacity(admitted_capacity)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NativeRequestBodyBudget;

    #[tokio::test]
    async fn content_length_moves_body_and_releases_connection_buffer_capacity() {
        let head = b"POST / HTTP/1.1\r\nHost: local.test\r\nContent-Length: 5\r\n\r\n";
        let pipeline = b"GET /next HTTP/1.1\r\nHost: local.test\r\n\r\n";
        let mut buffer = Vec::with_capacity(1024 * 1024);
        buffer.extend_from_slice(head);
        buffer.extend_from_slice(b"hello");
        buffer.extend_from_slice(pipeline);
        let original_capacity = buffer.capacity();
        let mut reservation = NativeRequestBodyBudget::new(1024).reserve(5).await.unwrap();

        let body = read_body_inner(
            &mut tokio::io::empty(),
            &mut buffer,
            head.len(),
            Http1BodyFraming::ContentLength(5),
            1024,
            &mut reservation,
        )
        .await
        .unwrap();

        assert_eq!(body.as_ref(), b"hello");
        assert_eq!(buffer, pipeline);
        assert!(buffer.capacity() < original_capacity);
        assert!(body.capacity() >= body.len());
    }
}
