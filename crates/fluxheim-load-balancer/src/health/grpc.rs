use std::io;
use std::time::Duration;

use http::Uri;

use fluxheim_common::{FluxError, FluxResult};

use super::{
    BoxedHealthIo, HTTP_HEALTH_CHECK_MAX_BODY_BYTES, HealthErrorKind, HealthHttpRequest,
    HealthHttpResponse, HttpHealthCheckError,
};

const GRPC_SERVING_STATUS: u64 = 1;

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) async fn execute_grpc_health_check(
    stream: BoxedHealthIo,
    request: &HealthHttpRequest,
    read_timeout: Duration,
) -> FluxResult<(HealthHttpResponse, Vec<u8>)> {
    let builder = h2::client::Builder::new();
    let (mut client, connection) = tokio::time::timeout(read_timeout, builder.handshake(stream))
        .await
        .map_err(|_| {
            FluxError::timeout(
                "connect gRPC health check upstream",
                format!("timeout after {}s", read_timeout.as_secs()),
            )
        })?
        .map_err(|error| {
            FluxError::io(
                "connect gRPC health check upstream",
                io::Error::other(error.to_string()),
            )
        })?;
    let _driver = AbortOnDrop(tokio::spawn(async move {
        if let Err(error) = connection.await {
            log::warn!(
                target: "fluxheim::load_balancer",
                "gRPC health check connection closed with error: {error}"
            );
        }
    }));
    let uri: Uri = format!("{}://{}{}", "http", request.host, request.path)
        .parse()
        .map_err(|error| FluxError::io("build gRPC health check URI", io::Error::other(error)))?;
    let mut http_request = http::Request::builder()
        .method(request.method.clone())
        .uri(uri);
    for (name, value) in &request.headers {
        http_request = http_request.header(name, value);
    }
    let http_request = http_request.body(()).map_err(|error| {
        FluxError::io("build gRPC health check request", io::Error::other(error))
    })?;
    let body = request.body.clone().unwrap_or_default();
    client = tokio::time::timeout(read_timeout, client.ready())
        .await
        .map_err(|_| {
            FluxError::timeout(
                "prepare gRPC health check request",
                format!("timeout after {}s", read_timeout.as_secs()),
            )
        })?
        .map_err(|error| {
            FluxError::io(
                "prepare gRPC health check request",
                io::Error::other(error.to_string()),
            )
        })?;
    let (response_future, mut send_stream) = client
        .send_request(http_request, body.is_empty())
        .map_err(|error| {
            FluxError::io(
                "write gRPC health check request",
                io::Error::other(error.to_string()),
            )
        })?;
    if !body.is_empty() {
        send_stream.send_data(body, true).map_err(|error| {
            FluxError::io(
                "write gRPC health check request body",
                io::Error::other(error.to_string()),
            )
        })?;
    }
    drop(send_stream);
    let response = tokio::time::timeout(read_timeout, response_future)
        .await
        .map_err(|_| {
            FluxError::timeout(
                "read gRPC health check response header",
                format!("timeout after {}s", read_timeout.as_secs()),
            )
        })?
        .map_err(|error| {
            FluxError::io(
                "read gRPC health check response header",
                io::Error::other(error.to_string()),
            )
        })?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = read_h2_health_body(response.into_body(), read_timeout).await?;
    Ok((HealthHttpResponse { status, headers }, body))
}

async fn read_h2_health_body(
    mut body: h2::RecvStream,
    read_timeout: Duration,
) -> FluxResult<Vec<u8>> {
    let mut output = Vec::new();
    while let Some(chunk) = tokio::time::timeout(read_timeout, body.data())
        .await
        .map_err(|_| {
            FluxError::timeout(
                "read gRPC health check response body",
                format!("timeout after {}s", read_timeout.as_secs()),
            )
        })?
    {
        let chunk = chunk.map_err(|error| {
            FluxError::io(
                "read gRPC health check response body",
                io::Error::other(error.to_string()),
            )
        })?;
        let chunk_len = chunk.len();
        body.flow_control()
            .release_capacity(chunk_len)
            .map_err(|error| {
                FluxError::io(
                    "release gRPC health check flow control",
                    io::Error::other(error.to_string()),
                )
            })?;
        if output.len().saturating_add(chunk.len()) > HTTP_HEALTH_CHECK_MAX_BODY_BYTES {
            return Err(HttpHealthCheckError::new(
                HealthErrorKind::ReadError,
                "HTTP health check response body exceeded maximum size",
            )
            .into_flux());
        }
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}

pub(super) fn grpc_health_request_body(service: Option<&str>) -> Vec<u8> {
    let mut message = Vec::new();
    if let Some(service) = service
        && !service.is_empty()
    {
        message.push(0x0a);
        encode_grpc_varint(service.len() as u64, &mut message);
        message.extend_from_slice(service.as_bytes());
    }
    grpc_frame(&message)
}

pub(super) fn grpc_frame(message: &[u8]) -> Vec<u8> {
    let len = message.len() as u32;
    let mut frame = Vec::with_capacity(5 + message.len());
    frame.push(0);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(message);
    frame
}

fn encode_grpc_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

pub(super) fn validate_grpc_health_response_header(
    response: &HealthHttpResponse,
) -> Result<(), HttpHealthCheckError> {
    if response.status.as_u16() != 200 {
        return Err(HttpHealthCheckError::new(
            HealthErrorKind::HttpStatus(response.status.as_u16()),
            "unexpected gRPC health check HTTP status",
        ));
    }
    let content_type = response
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !content_type
        .to_ascii_lowercase()
        .starts_with("application/grpc")
    {
        return Err(HttpHealthCheckError::new(
            HealthErrorKind::InvalidHttpHeader,
            "unexpected gRPC health check content type",
        ));
    }
    Ok(())
}

pub(super) fn validate_grpc_health_response_body(body: &[u8]) -> Result<(), HttpHealthCheckError> {
    if body.len() < 5 || body[0] != 0 {
        return Err(HttpHealthCheckError::new(
            HealthErrorKind::ReadError,
            "invalid gRPC health check response frame",
        ));
    }
    let len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    if body.len() != 5 + len {
        return Err(HttpHealthCheckError::new(
            HealthErrorKind::ReadError,
            "invalid gRPC health check response length",
        ));
    }
    let status = decode_grpc_health_status(&body[5..])?;
    if status != GRPC_SERVING_STATUS {
        return Err(HttpHealthCheckError::new(
            HealthErrorKind::ReadError,
            "gRPC health check response is not SERVING",
        ));
    }
    Ok(())
}

fn decode_grpc_health_status(message: &[u8]) -> Result<u64, HttpHealthCheckError> {
    let mut offset = 0usize;
    while offset < message.len() {
        let key = decode_grpc_varint(message, &mut offset)?;
        let field = key >> 3;
        let wire_type = key & 0x07;
        match (field, wire_type) {
            (1, 0) => return decode_grpc_varint(message, &mut offset),
            (_, 0) => {
                let _ = decode_grpc_varint(message, &mut offset)?;
            }
            (_, 2) => {
                let len = decode_grpc_varint(message, &mut offset)? as usize;
                offset = offset.checked_add(len).ok_or_else(invalid_grpc_response)?;
                if offset > message.len() {
                    return Err(invalid_grpc_response());
                }
            }
            (_, 1) => {
                offset = offset.checked_add(8).ok_or_else(invalid_grpc_response)?;
                if offset > message.len() {
                    return Err(invalid_grpc_response());
                }
            }
            (_, 5) => {
                offset = offset.checked_add(4).ok_or_else(invalid_grpc_response)?;
                if offset > message.len() {
                    return Err(invalid_grpc_response());
                }
            }
            _ => return Err(invalid_grpc_response()),
        }
    }
    Err(invalid_grpc_response())
}

fn decode_grpc_varint(message: &[u8], offset: &mut usize) -> Result<u64, HttpHealthCheckError> {
    let mut value = 0u64;
    let mut shift = 0u32;
    while *offset < message.len() && shift < 64 {
        let byte = message[*offset];
        *offset += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err(invalid_grpc_response())
}

fn invalid_grpc_response() -> HttpHealthCheckError {
    HttpHealthCheckError::new(
        HealthErrorKind::ReadError,
        "invalid gRPC health check response message",
    )
}
