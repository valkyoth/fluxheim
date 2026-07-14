use std::time::Duration;

use fluxheim_protocol::{
    Http1ChunkLimits, Http1ChunkedDecoder, Http1ConnectionDirective, Http1ConnectionOptions,
    Http1HeadLimits, Http1ParseError, Http1ResponseHead, http_token_valid,
    http1_connection_directive, http1_connection_options, parse_http1_response_head,
};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

use crate::{NativeHttp1Error, NativeHttp1Response};

const UPSTREAM_READ_CHUNK_BYTES: usize = 8192;
const MAX_INFORMATIONAL_RESPONSES: usize = 8;

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
    let mut buffer = Vec::with_capacity(UPSTREAM_READ_CHUNK_BYTES);
    let mut informational_responses = 0usize;
    loop {
        fill_upstream_response_head(stream, &mut buffer, limits).await?;
        let (status, head_len) = {
            let head = parse_http1_response_head(&buffer, limits)?
                .ok_or(Http1ParseError::InvalidResponseLine)?;
            (head.status, head.head_len)
        };
        if status == 101 {
            return Err(Http1ParseError::InvalidResponseLine.into());
        }
        if status >= 200 {
            break;
        }
        informational_responses = informational_responses.saturating_add(1);
        if informational_responses > MAX_INFORMATIONAL_RESPONSES {
            return Err(Http1ParseError::InvalidResponseLine.into());
        }
        buffer.drain(..head_len);
    }
    let head =
        parse_http1_response_head(&buffer, limits)?.ok_or(Http1ParseError::InvalidResponseLine)?;
    let head_len = head.head_len;
    let status = head.status;
    let reason = head.reason.to_owned();
    let body_framing = response_body_framing(status, request_method, &head.headers)?;
    let connection_options = http1_connection_options(&head.headers)?;
    let origin_closes =
        http1_connection_directive(head.version, &head.headers)? == Http1ConnectionDirective::Close;
    let headers = head
        .headers
        .iter()
        .filter(|header| response_header_allowed(header.name(), body_framing, &connection_options))
        .map(|header| (header.name().to_owned(), header.value().to_owned()))
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
    fill_upstream_response_head(stream, &mut buffer, limits).await?;
    Ok(buffer)
}

async fn fill_upstream_response_head<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    limits: Http1HeadLimits,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    loop {
        match parse_http1_response_head(buffer, limits) {
            Ok(Some(_)) => return Ok(()),
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
    let mut transfer_coding = None;
    for header in headers {
        if header.name().eq_ignore_ascii_case("content-length") {
            let parsed = header
                .value()
                .trim()
                .parse::<u64>()
                .map_err(|_| Http1ParseError::InvalidContentLength)?;
            if content_length.is_some() {
                return Err(Http1ParseError::DuplicateContentLength);
            }
            content_length = Some(parsed);
        } else if header.name().eq_ignore_ascii_case("transfer-encoding") {
            for coding in header.value().split(',').map(str::trim) {
                if coding.is_empty()
                    || !http_token_valid(coding)
                    || transfer_coding.replace(coding).is_some()
                {
                    return Err(Http1ParseError::UnsupportedTransferEncoding);
                }
            }
        }
    }
    if transfer_coding.is_some_and(|coding| coding.eq_ignore_ascii_case("chunked")) {
        Ok(ResponseBodyFraming::Chunked)
    } else if transfer_coding.is_some() {
        Err(Http1ParseError::UnsupportedTransferEncoding)
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
    let limits = Http1ChunkLimits::default().with_max_body_bytes(max_body_bytes);
    let mut decoder = Http1ChunkedDecoder::new(limits);
    let mut body = Vec::new();
    if decoder.push(&buffer[head_len..], &mut body)?.is_some() {
        return Ok(body);
    }
    loop {
        let mut chunk = [0u8; UPSTREAM_READ_CHUNK_BYTES];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(Http1ParseError::InvalidChunk.into());
        }
        if decoder.push(&chunk[..read], &mut body)?.is_some() {
            return Ok(body);
        }
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

fn response_header_allowed(
    name: &str,
    body_framing: ResponseBodyFraming,
    connection_options: &Http1ConnectionOptions,
) -> bool {
    !(connection_options.identifies_hop_by_hop_header(name)
        || matches!(body_framing, ResponseBodyFraming::Chunked)
            && name.eq_ignore_ascii_case("content-length"))
}

fn timeout_error(message: &'static str) -> NativeHttp1Error {
    NativeHttp1Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, message))
}
