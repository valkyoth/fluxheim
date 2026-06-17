use std::time::Duration;

use fluxheim_protocol::{
    Http1ChunkLimits, Http1HeadLimits, Http1ParseError, decode_http1_chunked_body,
    http_token_valid, http1_request_target, parse_http1_response_head,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::{DownstreamHttp1Policy, NativeHttp1Error, NativeHttp1Request, NativeHttp1Response};

const UPSTREAM_READ_CHUNK_BYTES: usize = 8192;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1Upstream {
    authority: String,
    connect_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
    max_head_bytes: usize,
    max_body_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseBodyFraming {
    NoBody,
    ContentLength(usize),
    Chunked,
    CloseDelimited,
}

impl NativeHttp1Upstream {
    pub fn new(authority: impl Into<String>) -> Self {
        let policy = DownstreamHttp1Policy::default();
        Self {
            authority: authority.into(),
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            max_head_bytes: policy.max_head_bytes(),
            max_body_bytes: policy.max_body_bytes(),
        }
    }

    pub fn from_policy(authority: impl Into<String>, policy: DownstreamHttp1Policy) -> Self {
        Self {
            authority: authority.into(),
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            max_head_bytes: policy.max_head_bytes(),
            max_body_bytes: policy.max_body_bytes(),
        }
    }

    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub const fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    pub const fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = timeout;
        self
    }

    pub const fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    pub async fn send(
        &self,
        request: &NativeHttp1Request,
    ) -> Result<NativeHttp1Response, NativeHttp1Error> {
        let stream = timeout(self.connect_timeout, connect_upstream(&self.authority))
            .await
            .map_err(|_| timeout_error("native HTTP/1 upstream connect timeout"))??;
        self.send_on_stream(stream, request).await
    }

    pub async fn send_on_stream<S>(
        &self,
        mut stream: S,
        request: &NativeHttp1Request,
    ) -> Result<NativeHttp1Response, NativeHttp1Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        timeout(
            self.write_timeout,
            write_upstream_request(&mut stream, &self.authority, request),
        )
        .await
        .map_err(|_| timeout_error("native HTTP/1 upstream write timeout"))??;
        read_upstream_response(
            &mut stream,
            self.read_timeout,
            self.max_head_bytes,
            self.max_body_bytes,
            &request.method,
        )
        .await
    }
}

async fn connect_upstream(authority: &str) -> Result<TcpStream, NativeHttp1Error> {
    let mut addresses = tokio::net::lookup_host(authority)
        .await
        .map_err(NativeHttp1Error::Io)?;
    let address = addresses.next().ok_or_else(|| {
        NativeHttp1Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "upstream authority did not resolve",
        ))
    })?;
    TcpStream::connect(address)
        .await
        .map_err(NativeHttp1Error::Io)
}

async fn write_upstream_request<S>(
    stream: &mut S,
    authority: &str,
    request: &NativeHttp1Request,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    let target = upstream_origin_target(request)?;
    stream
        .write_all(format!("{} {target} HTTP/1.1\r\n", request.method).as_bytes())
        .await?;
    stream
        .write_all(format!("host: {}\r\n", valid_request_host(request, authority)?).as_bytes())
        .await?;
    stream.write_all(b"connection: close\r\n").await?;
    if !request.body.is_empty() {
        stream
            .write_all(format!("content-length: {}\r\n", request.body.len()).as_bytes())
            .await?;
    }
    let connection_tokens = connection_tokens(request);
    for (name, value) in &request.headers {
        if upstream_hop_by_hop_header(name, &connection_tokens)
            || name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        if !valid_upstream_request_header(name, value) {
            return Err(Http1ParseError::InvalidHeaderValue.into());
        }
        stream
            .write_all(format!("{name}: {value}\r\n").as_bytes())
            .await?;
    }
    stream.write_all(b"\r\n").await?;
    stream.write_all(&request.body).await?;
    stream.flush().await?;
    Ok(())
}

fn upstream_origin_target(request: &NativeHttp1Request) -> Result<String, NativeHttp1Error> {
    match http1_request_target(&request.method, &request.target)? {
        fluxheim_protocol::Http1RequestTarget::Origin { .. } => Ok(request.target.clone()),
        fluxheim_protocol::Http1RequestTarget::AbsoluteUri { path, query, .. } => {
            let Some(path) = path else {
                return Ok("/".to_owned());
            };
            Ok(query
                .map(|query| format!("{path}?{query}"))
                .unwrap_or_else(|| path.to_owned()))
        }
        fluxheim_protocol::Http1RequestTarget::Authority { .. }
        | fluxheim_protocol::Http1RequestTarget::Asterisk => {
            Err(Http1ParseError::InvalidRequestTarget.into())
        }
    }
}

fn request_host(request: &NativeHttp1Request) -> Option<&str> {
    request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.as_str())
}

fn valid_request_host<'a>(
    request: &'a NativeHttp1Request,
    authority: &'a str,
) -> Result<&'a str, NativeHttp1Error> {
    let host = request_host(request).unwrap_or(authority);
    if valid_upstream_header_value(host) {
        Ok(host)
    } else {
        Err(Http1ParseError::InvalidHeaderValue.into())
    }
}

fn valid_upstream_request_header(name: &str, value: &str) -> bool {
    http_token_valid(name) && valid_upstream_header_value(value)
}

fn valid_upstream_header_value(value: &str) -> bool {
    !value
        .bytes()
        .any(|byte| matches!(byte, 0x00..=0x08 | 0x0a..=0x1f | 0x7f..=0xff))
}

fn connection_tokens(request: &NativeHttp1Request) -> Vec<String> {
    request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn upstream_hop_by_hop_header(name: &str, connection_tokens: &[String]) -> bool {
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
    ) || connection_tokens
        .iter()
        .any(|token| token.eq_ignore_ascii_case(name))
}

async fn read_upstream_response<S>(
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
        read_upstream_response_inner(stream, max_head_bytes, max_body_bytes, request_method),
    )
    .await
    .map_err(|_| timeout_error("native HTTP/1 upstream read timeout"))?
}

async fn read_upstream_response_inner<S>(
    stream: &mut S,
    max_head_bytes: usize,
    max_body_bytes: usize,
    request_method: &str,
) -> Result<NativeHttp1Response, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    let limits = Http1HeadLimits {
        max_head_bytes,
        ..Http1HeadLimits::default()
    };
    let mut buffer = read_until_response_head(stream, limits).await?;
    let head =
        parse_http1_response_head(&buffer, limits)?.ok_or(Http1ParseError::InvalidResponseLine)?;
    let head_len = head.head_len;
    let status = head.status;
    let reason = head.reason.to_owned();
    let body_framing = response_body_framing(status, request_method, &head.headers)?;
    let headers = head
        .headers
        .iter()
        .filter(|header| response_header_allowed(header.name, body_framing))
        .map(|header| (header.name.to_owned(), header.value.to_owned()))
        .collect::<Vec<_>>();
    let body =
        read_response_body(stream, &mut buffer, head_len, body_framing, max_body_bytes).await?;
    let content_length = response_content_length(&headers);
    let mut response = NativeHttp1Response::new(status, reason, body);
    if let Some(content_length) = content_length {
        response = response.with_content_length(content_length);
    }
    for (name, value) in headers {
        response = response.with_header(name, value);
    }
    Ok(response)
}

async fn read_until_response_head<S>(
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
            return Err(Http1ParseError::InvalidResponseLine.into());
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
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
            let mut body = buffer[head_len..].to_vec();
            while body.len() < max_body_bytes {
                let mut chunk = [0u8; UPSTREAM_READ_CHUNK_BYTES];
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    return Ok(body);
                }
                body.extend_from_slice(&chunk[..read]);
                if body.len() > max_body_bytes {
                    break;
                }
            }
            Err(Http1ParseError::BodyTooLarge.into())
        }
        ResponseBodyFraming::ContentLength(length) => {
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
        ResponseBodyFraming::Chunked => {
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
    }
}

fn response_content_length(headers: &[(String, String)]) -> Option<u64> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
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
    !downstream_hop_by_hop_header(name)
        && !(matches!(body_framing, ResponseBodyFraming::Chunked)
            && name.eq_ignore_ascii_case("content-length"))
}

fn timeout_error(message: &'static str) -> NativeHttp1Error {
    NativeHttp1Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, message))
}
