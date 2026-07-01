use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::native_http1_forwarded::{
    valid_upstream_header_value, valid_upstream_request_header, write_owned_proxy_headers,
};
use crate::{NativeHttp1Error, NativeHttp1Request};

pub(super) async fn write_upstream_request<S>(
    stream: &mut S,
    authority: &str,
    request: &NativeHttp1Request,
    keep_alive: bool,
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
    if keep_alive {
        stream.write_all(b"connection: keep-alive\r\n").await?;
    } else {
        stream.write_all(b"connection: close\r\n").await?;
    }
    if !request.body.is_empty() {
        stream
            .write_all(format!("content-length: {}\r\n", request.body.len()).as_bytes())
            .await?;
    }
    let connection_tokens = connection_tokens(request);
    for (name, value) in &request.headers {
        if upstream_hop_by_hop_header(name, &connection_tokens)
            || upstream_owned_header_for_request(name, request)
        {
            continue;
        }
        if !valid_upstream_request_header(name, value) {
            return Err(fluxheim_protocol::Http1ParseError::InvalidHeaderValue.into());
        }
        stream
            .write_all(format!("{name}: {value}\r\n").as_bytes())
            .await?;
    }
    write_owned_proxy_headers(stream, request).await?;
    stream.write_all(b"\r\n").await?;
    stream.write_all(&request.body).await?;
    stream.flush().await?;
    Ok(())
}

pub(super) async fn write_websocket_upgrade_request<S>(
    stream: &mut S,
    authority: &str,
    request: &NativeHttp1Request,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    if !request.body.is_empty() {
        return Err(NativeHttp1Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native WebSocket upgrade request body is not supported",
        )));
    }
    let target = upstream_origin_target(request)?;
    stream
        .write_all(format!("{} {target} HTTP/1.1\r\n", request.method).as_bytes())
        .await?;
    stream
        .write_all(format!("host: {}\r\n", valid_request_host(request, authority)?).as_bytes())
        .await?;
    stream.write_all(b"connection: Upgrade\r\n").await?;
    stream.write_all(b"upgrade: websocket\r\n").await?;
    let connection_tokens = connection_tokens(request);
    for (name, value) in &request.headers {
        if upstream_hop_by_hop_header(name, &connection_tokens)
            || upstream_websocket_owned_header_for_request(name, request)
        {
            continue;
        }
        if !valid_upstream_request_header(name, value) {
            return Err(fluxheim_protocol::Http1ParseError::InvalidHeaderValue.into());
        }
        stream
            .write_all(format!("{name}: {value}\r\n").as_bytes())
            .await?;
    }
    write_owned_proxy_headers(stream, request).await?;
    stream.write_all(b"\r\n").await?;
    stream.flush().await?;
    Ok(())
}

pub(super) fn upstream_origin_target(
    request: &NativeHttp1Request,
) -> Result<String, NativeHttp1Error> {
    match fluxheim_protocol::http1_request_target(&request.method, &request.target)? {
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
            Err(fluxheim_protocol::Http1ParseError::InvalidRequestTarget.into())
        }
    }
}

fn upstream_owned_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("via")
}

pub(super) fn upstream_owned_header_for_request(name: &str, request: &NativeHttp1Request) -> bool {
    upstream_owned_header(name)
        || (!native_client_request_is_peer_fill(request) && native_peer_fill_internal_header(name))
}

fn upstream_websocket_owned_header(name: &str) -> bool {
    upstream_owned_header(name)
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("proxy-connection")
}

fn upstream_websocket_owned_header_for_request(name: &str, request: &NativeHttp1Request) -> bool {
    upstream_websocket_owned_header(name)
        || (!native_client_request_is_peer_fill(request) && native_peer_fill_internal_header(name))
}

fn native_peer_fill_internal_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("x-fluxheim-peer-fill")
        || name.eq_ignore_ascii_case("x-fluxheim-peer-fill-nonce")
        || name.eq_ignore_ascii_case("x-fluxheim-peer-fill-request-signature")
        || name.eq_ignore_ascii_case("x-fluxheim-peer-fill-response-signature")
}

fn native_client_request_is_peer_fill(request: &NativeHttp1Request) -> bool {
    request.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("x-fluxheim-peer-fill") && value.trim() == "1"
    })
}

fn request_host(request: &NativeHttp1Request) -> Option<&str> {
    request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.as_str())
}

pub(super) fn valid_request_host<'a>(
    request: &'a NativeHttp1Request,
    authority: &'a str,
) -> Result<&'a str, NativeHttp1Error> {
    let host = request_host(request).unwrap_or(authority);
    if valid_upstream_header_value(host) {
        Ok(host)
    } else {
        Err(fluxheim_protocol::Http1ParseError::InvalidHeaderValue.into())
    }
}

pub(super) fn connection_tokens(request: &NativeHttp1Request) -> Vec<String> {
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

pub(super) fn upstream_hop_by_hop_header(name: &str, connection_tokens: &[String]) -> bool {
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
