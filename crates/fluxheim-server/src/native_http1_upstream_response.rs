use std::time::Duration;

use fluxheim_protocol::{
    Http1ChunkLimits, Http1ConnectionDirective, Http1HeadLimits, Http1ParseError,
    Http1ResponseHead, decode_http1_chunked_body, http1_connection_directive,
    parse_http1_response_head,
};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

use crate::{NativeHttp1Error, NativeHttp1Response};

const UPSTREAM_READ_CHUNK_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseBodyFraming {
    NoBody,
    ContentLength(usize),
    Chunked,
    CloseDelimited,
}

pub(crate) async fn read_upstream_response<S>(
    stream: &mut S,
    read_timeout: Duration,
    max_head_bytes: usize,
    max_body_bytes: usize,
    request_method: &str,
) -> Result<NativeHttp1Response, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    timeout(
        read_timeout,
        read_upstream_response_inner(
            stream,
            max_head_bytes,
            max_body_bytes,
            request_method,
            false,
        ),
    )
    .await
    .map_err(|_| timeout_error("native HTTP/1 upstream read timeout"))?
    .map(|(response, _)| response)
}

pub(crate) async fn read_upstream_response_for_pool<S>(
    stream: &mut S,
    read_timeout: Duration,
    max_head_bytes: usize,
    max_body_bytes: usize,
    request_method: &str,
) -> Result<(NativeHttp1Response, bool), NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    timeout(
        read_timeout,
        read_upstream_response_inner(stream, max_head_bytes, max_body_bytes, request_method, true),
    )
    .await
    .map_err(|_| timeout_error("native HTTP/1 upstream read timeout"))?
}

async fn read_upstream_response_inner<S>(
    stream: &mut S,
    max_head_bytes: usize,
    max_body_bytes: usize,
    request_method: &str,
    want_reusable: bool,
) -> Result<(NativeHttp1Response, bool), NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    let limits = Http1HeadLimits {
        max_head_bytes,
        ..Http1HeadLimits::default()
    };
    let mut buffer = read_upstream_response_head(stream, limits).await?;
    let head =
        parse_http1_response_head(&buffer, limits)?.ok_or(Http1ParseError::InvalidResponseLine)?;
    let head_len = head.head_len;
    let status = head.status;
    let reason = head.reason.to_owned();
    let body_framing = response_body_framing(status, request_method, &head.headers)?;
    let origin_closes = http1_connection_directive(head.version, &head.headers)
        .map(|directive| directive == Http1ConnectionDirective::Close)
        .unwrap_or(true);
    let headers = head
        .headers
        .iter()
        .filter(|header| response_header_allowed(header.name, body_framing))
        .map(|header| (header.name.to_owned(), header.value.to_owned()))
        .collect::<Vec<_>>();
    let body =
        read_response_body(stream, &mut buffer, head_len, body_framing, max_body_bytes).await?;
    let reusable = want_reusable
        && !origin_closes
        && response_body_reusable(&buffer, head_len, body_framing, body.len(), status);
    let content_length = response_content_length(&headers);
    let mut response = NativeHttp1Response::new(status, reason, body);
    if let Some(content_length) = content_length {
        response = response.with_content_length(content_length);
    }
    for (name, value) in headers {
        response = response.with_header(name, value);
    }
    Ok((response, reusable))
}

pub(crate) async fn read_upstream_response_head<S>(
    stream: &mut S,
    limits: Http1HeadLimits,
) -> Result<Vec<u8>, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(UPSTREAM_READ_CHUNK_BYTES);
    loop {
        match parse_http1_response_head(&buffer, limits) {
            Ok(Some(_)) => return Ok(buffer),
            Ok(None) => {}
            Err(error) => return Err(error.into()),
        }
        if buffer.len() >= limits.max_head_bytes {
            return Err(Http1ParseError::HeadTooLarge.into());
        }
        let mut chunk = [0u8; UPSTREAM_READ_CHUNK_BYTES];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            if buffer.is_empty() {
                return Err(NativeHttp1Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "upstream closed before response",
                )));
            }
            return Err(Http1ParseError::InvalidResponseLine.into());
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

pub(crate) fn parsed_upstream_response_head<'a>(
    buffer: &'a [u8],
    limits: Http1HeadLimits,
) -> Result<Http1ResponseHead<'a>, NativeHttp1Error> {
    parse_http1_response_head(buffer, limits)?.ok_or(NativeHttp1Error::Parse(
        Http1ParseError::InvalidResponseLine,
    ))
}

fn response_body_framing(
    status: u16,
    request_method: &str,
    headers: &[fluxheim_protocol::Http1Header<'_>],
) -> Result<ResponseBodyFraming, Http1ParseError> {
    if request_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || matches!(status, 204 | 304)
    {
        return Ok(ResponseBodyFraming::NoBody);
    }
    let mut content_length = None;
    let mut chunked = false;
    for header in headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            let parsed = header
                .value
                .trim()
                .parse::<u64>()
                .map_err(|_| Http1ParseError::InvalidContentLength)?;
            if content_length.is_some() {
                return Err(Http1ParseError::DuplicateContentLength);
            }
            content_length = Some(parsed);
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if !header
                .value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
            {
                return Err(Http1ParseError::UnsupportedTransferEncoding);
            }
            chunked = true;
        }
    }
    if chunked {
        Ok(ResponseBodyFraming::Chunked)
    } else if let Some(length) = content_length {
        Ok(ResponseBodyFraming::ContentLength(
            usize::try_from(length).map_err(|_| Http1ParseError::BodyTooLarge)?,
        ))
    } else {
        Ok(ResponseBodyFraming::CloseDelimited)
    }
}

async fn read_response_body<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    head_len: usize,
    framing: ResponseBodyFraming,
    max_body_bytes: usize,
) -> Result<Vec<u8>, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    match framing {
        ResponseBodyFraming::NoBody => Ok(Vec::new()),
        ResponseBodyFraming::CloseDelimited => {
            read_close_delimited_body(stream, buffer, head_len, max_body_bytes).await
        }
        ResponseBodyFraming::ContentLength(length) => {
            read_content_length_body(stream, buffer, head_len, length, max_body_bytes).await
        }
        ResponseBodyFraming::Chunked => {
            read_chunked_body(stream, buffer, head_len, max_body_bytes).await
        }
    }
}

async fn read_close_delimited_body<S>(
    stream: &mut S,
    buffer: &[u8],
    head_len: usize,
    max_body_bytes: usize,
) -> Result<Vec<u8>, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    let mut body = buffer[head_len..].to_vec();
    if body.len() > max_body_bytes {
        return Err(Http1ParseError::BodyTooLarge.into());
    }
    loop {
        let mut chunk = [0u8; UPSTREAM_READ_CHUNK_BYTES];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(body);
        }
        body.extend_from_slice(&chunk[..read]);
        if body.len() > max_body_bytes {
            return Err(Http1ParseError::BodyTooLarge.into());
        }
    }
}

async fn read_content_length_body<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    head_len: usize,
    length: usize,
    max_body_bytes: usize,
) -> Result<Vec<u8>, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    if length > max_body_bytes {
        return Err(Http1ParseError::BodyTooLarge.into());
    }
    let required = head_len
        .checked_add(length)
        .ok_or(Http1ParseError::BodyTooLarge)?;
    while buffer.len() < required {
        let mut chunk = [0u8; UPSTREAM_READ_CHUNK_BYTES];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(Http1ParseError::InvalidContentLength.into());
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    Ok(buffer[head_len..required].to_vec())
}

async fn read_chunked_body<S>(
    stream: &mut S,
    buffer: &[u8],
    head_len: usize,
    max_body_bytes: usize,
) -> Result<Vec<u8>, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    let mut raw = buffer[head_len..].to_vec();
    loop {
        let limits = Http1ChunkLimits {
            max_body_bytes,
            ..Http1ChunkLimits::default()
        };
        let mut output = vec![0u8; raw.len().min(max_body_bytes)];
        match decode_http1_chunked_body(&raw, &mut output, limits) {
            Ok(Some(decoded)) => return Ok(output[..decoded.decoded_len].to_vec()),
            Ok(None) => {}
            Err(Http1ParseError::OutputTooSmall) => {
                return Err(Http1ParseError::BodyTooLarge.into());
            }
            Err(error) => return Err(error.into()),
        }
        if raw.len() >= max_body_bytes {
            return Err(Http1ParseError::BodyTooLarge.into());
        }
        let mut chunk = [0u8; UPSTREAM_READ_CHUNK_BYTES];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(Http1ParseError::InvalidChunk.into());
        }
        raw.extend_from_slice(&chunk[..read]);
    }
}

fn response_content_length(headers: &[(String, String)]) -> Option<u64> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
}

fn response_body_reusable(
    buffer: &[u8],
    head_len: usize,
    framing: ResponseBodyFraming,
    body_len: usize,
    status: u16,
) -> bool {
    if (100..200).contains(&status) {
        return false;
    }
    match framing {
        ResponseBodyFraming::NoBody => buffer.len() == head_len,
        ResponseBodyFraming::ContentLength(length) => {
            length == body_len && buffer.len() == head_len.saturating_add(length)
        }
        ResponseBodyFraming::Chunked | ResponseBodyFraming::CloseDelimited => false,
    }
}

fn downstream_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn response_header_allowed(name: &str, body_framing: ResponseBodyFraming) -> bool {
    !(downstream_hop_by_hop_header(name)
        || matches!(body_framing, ResponseBodyFraming::Chunked)
            && name.eq_ignore_ascii_case("content-length"))
}

fn timeout_error(message: &'static str) -> NativeHttp1Error {
    NativeHttp1Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, message))
}
