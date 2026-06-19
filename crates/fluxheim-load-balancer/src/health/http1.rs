use std::io;
use std::time::Duration;

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use fluxheim_common::{FluxError, FluxResult};

use super::{
    BoxedHealthIo, HTTP_HEALTH_CHECK_MAX_BODY_BYTES, HealthErrorKind, HealthHttpRequest,
    HealthHttpResponse, HttpHealthCheckError,
};

pub(super) async fn execute_http1_health_check(
    mut stream: BoxedHealthIo,
    request: &HealthHttpRequest,
    read_timeout: Duration,
) -> FluxResult<(HealthHttpResponse, Vec<u8>)> {
    let request_bytes = build_http1_health_request(request)?;
    stream
        .write_all(&request_bytes)
        .await
        .map_err(|error| FluxError::io("write HTTP health check request", error))?;
    stream
        .flush()
        .await
        .map_err(|error| FluxError::io("flush HTTP health check request", error))?;
    let (response, remainder) = read_http1_response_header(&mut stream, read_timeout).await?;
    let body =
        read_http1_response_body(&mut stream, &response.headers, remainder, read_timeout).await?;
    Ok((response, body))
}

fn build_http1_health_request(request: &HealthHttpRequest) -> FluxResult<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(request.method.as_str().as_bytes());
    output.extend_from_slice(b" ");
    output.extend_from_slice(request.path.as_bytes());
    output.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    output.extend_from_slice(request.host.as_bytes());
    output.extend_from_slice(b"\r\nUser-Agent: fluxheim-health\r\nConnection: close\r\n");
    if let Some(body) = &request.body {
        output.extend_from_slice(b"Content-Length: ");
        output.extend_from_slice(body.len().to_string().as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    for (name, value) in &request.headers {
        output.extend_from_slice(name.as_str().as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    if let Some(body) = &request.body {
        output.extend_from_slice(body);
    }
    Ok(output)
}

async fn read_http1_response_header(
    stream: &mut BoxedHealthIo,
    read_timeout: Duration,
) -> FluxResult<(HealthHttpResponse, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(index) = find_header_end(&buffer) {
            let remainder = buffer[index + 4..].to_vec();
            let response = parse_http1_response_header(&buffer[..index])?;
            return Ok((response, remainder));
        }
        if buffer.len() >= HTTP_HEALTH_CHECK_MAX_BODY_BYTES {
            return Err(HttpHealthCheckError::new(
                HealthErrorKind::ReadError,
                "HTTP health check response header exceeded maximum size",
            )
            .into_flux());
        }
        let read = tokio::time::timeout(read_timeout, stream.read(&mut chunk))
            .await
            .map_err(|_| {
                FluxError::timeout(
                    "read HTTP health check response header",
                    format!("timeout after {}s", read_timeout.as_secs()),
                )
            })?
            .map_err(|error| FluxError::io("read HTTP health check response header", error))?;
        if read == 0 {
            return Err(HttpHealthCheckError::new(
                HealthErrorKind::ReadError,
                "missing HTTP health check response header",
            )
            .into_flux());
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_http1_response_header(header_block: &[u8]) -> FluxResult<HealthHttpResponse> {
    let text = std::str::from_utf8(header_block).map_err(|error| {
        FluxError::io(
            "parse HTTP health check response header",
            io::Error::new(io::ErrorKind::InvalidData, error),
        )
    })?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| {
        HttpHealthCheckError::new(
            HealthErrorKind::ReadError,
            "missing HTTP health check response status",
        )
        .into_flux()
    })?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(HttpHealthCheckError::new(
            HealthErrorKind::ReadError,
            "invalid HTTP health check response status",
        )
        .into_flux());
    }
    let status = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .and_then(|value| StatusCode::from_u16(value).ok())
        .ok_or_else(|| {
            HttpHealthCheckError::new(
                HealthErrorKind::ReadError,
                "invalid HTTP health check response status",
            )
            .into_flux()
        })?;
    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(HttpHealthCheckError::new(
                HealthErrorKind::InvalidHttpHeader,
                "invalid HTTP health check response header",
            )
            .into_flux());
        };
        let name = HeaderName::from_bytes(name.trim().as_bytes()).map_err(|error| {
            FluxError::io(
                "parse HTTP health check response header",
                io::Error::new(io::ErrorKind::InvalidData, error),
            )
        })?;
        let value = HeaderValue::from_str(value.trim()).map_err(|error| {
            FluxError::io(
                "parse HTTP health check response header",
                io::Error::new(io::ErrorKind::InvalidData, error),
            )
        })?;
        headers.append(name, value);
    }
    Ok(HealthHttpResponse { status, headers })
}

async fn read_http1_response_body(
    stream: &mut BoxedHealthIo,
    headers: &HeaderMap,
    remainder: Vec<u8>,
    read_timeout: Duration,
) -> FluxResult<Vec<u8>> {
    if headers
        .get(header::TRANSFER_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        return read_http1_chunked_body(stream, remainder, read_timeout).await;
    }
    if let Some(length) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<usize>().ok())
    {
        if length > HTTP_HEALTH_CHECK_MAX_BODY_BYTES {
            return Err(HttpHealthCheckError::new(
                HealthErrorKind::ReadError,
                "HTTP health check response body exceeded maximum size",
            )
            .into_flux());
        }
        let mut body = remainder;
        while body.len() < length {
            read_more_body(stream, &mut body, read_timeout).await?;
        }
        body.truncate(length);
        return Ok(body);
    }
    let mut body = remainder;
    loop {
        match tokio::time::timeout(
            read_timeout,
            read_more_body(stream, &mut body, read_timeout),
        )
        .await
        {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => return Ok(body),
            Ok(Err(error)) => return Err(error),
            Err(_) => return Ok(body),
        }
    }
}

async fn read_more_body(
    stream: &mut BoxedHealthIo,
    body: &mut Vec<u8>,
    read_timeout: Duration,
) -> FluxResult<bool> {
    let mut chunk = [0u8; 1024];
    let read = tokio::time::timeout(read_timeout, stream.read(&mut chunk))
        .await
        .map_err(|_| {
            FluxError::timeout(
                "read HTTP health check response body",
                format!("timeout after {}s", read_timeout.as_secs()),
            )
        })?
        .map_err(|error| FluxError::io("read HTTP health check response body", error))?;
    if read == 0 {
        return Ok(false);
    }
    if body.len().saturating_add(read) > HTTP_HEALTH_CHECK_MAX_BODY_BYTES {
        return Err(HttpHealthCheckError::new(
            HealthErrorKind::ReadError,
            "HTTP health check response body exceeded maximum size",
        )
        .into_flux());
    }
    body.extend_from_slice(&chunk[..read]);
    Ok(true)
}

async fn read_http1_chunked_body(
    stream: &mut BoxedHealthIo,
    mut buffer: Vec<u8>,
    read_timeout: Duration,
) -> FluxResult<Vec<u8>> {
    let mut body = Vec::new();
    let mut cursor = 0usize;
    loop {
        let line_end = loop {
            if let Some(relative) = buffer[cursor..]
                .windows(2)
                .position(|window| window == b"\r\n")
            {
                break cursor + relative;
            }
            if !read_more_body(stream, &mut buffer, read_timeout).await? {
                return Err(HttpHealthCheckError::new(
                    HealthErrorKind::ReadError,
                    "truncated HTTP health check chunked response",
                )
                .into_flux());
            }
        };
        let size_line = std::str::from_utf8(&buffer[cursor..line_end]).map_err(|error| {
            FluxError::io(
                "parse HTTP health check chunk size",
                io::Error::new(io::ErrorKind::InvalidData, error),
            )
        })?;
        let size_text = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|error| {
            FluxError::io(
                "parse HTTP health check chunk size",
                io::Error::new(io::ErrorKind::InvalidData, error),
            )
        })?;
        cursor = line_end + 2;
        if size == 0 {
            return Ok(body);
        }
        while buffer.len() < cursor.saturating_add(size).saturating_add(2) {
            if !read_more_body(stream, &mut buffer, read_timeout).await? {
                return Err(HttpHealthCheckError::new(
                    HealthErrorKind::ReadError,
                    "truncated HTTP health check chunked response",
                )
                .into_flux());
            }
        }
        if &buffer[cursor + size..cursor + size + 2] != b"\r\n" {
            return Err(HttpHealthCheckError::new(
                HealthErrorKind::ReadError,
                "invalid HTTP health check chunk terminator",
            )
            .into_flux());
        }
        if body.len().saturating_add(size) > HTTP_HEALTH_CHECK_MAX_BODY_BYTES {
            return Err(HttpHealthCheckError::new(
                HealthErrorKind::ReadError,
                "HTTP health check response body exceeded maximum size",
            )
            .into_flux());
        }
        body.extend_from_slice(&buffer[cursor..cursor + size]);
        cursor += size + 2;
    }
}
