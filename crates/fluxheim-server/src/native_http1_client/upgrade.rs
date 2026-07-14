use fluxheim_protocol::{Http1HeadLimits, Http1Header, Http1ResponseHead};

use crate::NativeHttp1Error;
use crate::native_http1_forwarded::valid_upstream_header_value;
use crate::native_http1_upstream_response::parsed_upstream_response_head;

const MAX_H2C_UPGRADE_RESPONSE_HEAD_BYTES: usize = 8192;

pub(super) fn h2c_upgrade_response_head_limits() -> Http1HeadLimits {
    Http1HeadLimits {
        max_head_bytes: MAX_H2C_UPGRADE_RESPONSE_HEAD_BYTES,
        ..Http1HeadLimits::default()
    }
}

pub(super) fn validate_h2c_upgrade_response(
    head: &[u8],
    limits: Http1HeadLimits,
) -> Result<(), NativeHttp1Error> {
    validate_switching_protocols_response(
        head,
        limits,
        "h2c",
        "native h2c upgrade was not accepted",
        "native h2c upgrade response did not confirm h2c",
    )
}

pub(super) fn websocket_upgrade_response_head_limits(max_head_bytes: usize) -> Http1HeadLimits {
    Http1HeadLimits {
        max_head_bytes,
        ..Http1HeadLimits::default()
    }
}

pub(super) fn validate_websocket_upgrade_response(
    head: &[u8],
    limits: Http1HeadLimits,
) -> Result<(), NativeHttp1Error> {
    validate_switching_protocols_response(
        head,
        limits,
        "websocket",
        "native WebSocket upgrade was not accepted",
        "native WebSocket upgrade response did not confirm websocket",
    )?;
    let head = parsed_upstream_response_head(head, limits)?;
    if !http1_headers_contain_token(&head.headers, "connection", "upgrade") {
        return Err(NativeHttp1Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native WebSocket upgrade response did not confirm connection upgrade",
        )));
    }
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn validate_switching_protocols_response(
    head: &[u8],
    limits: Http1HeadLimits,
    upgrade_token: &str,
    rejected_message: &'static str,
    missing_upgrade_message: &'static str,
) -> Result<(), NativeHttp1Error> {
    let head = parsed_upstream_response_head(head, limits)?;
    if head.status != 101 {
        return Err(NativeHttp1Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rejected_message,
        )));
    }
    if !http1_headers_contain_token(&head.headers, "upgrade", upgrade_token) {
        return Err(NativeHttp1Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            missing_upgrade_message,
        )));
    }
    Ok(())
}

fn http1_headers_contain_token(headers: &[Http1Header<'_>], name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter(|header| header.name().eq_ignore_ascii_case(name))
        .any(|header| {
            header
                .value()
                .split(',')
                .any(|candidate| candidate.trim().eq_ignore_ascii_case(token))
        })
}

pub(super) fn websocket_downstream_upgrade_response_head(
    head: &Http1ResponseHead<'_>,
) -> Result<Vec<u8>, NativeHttp1Error> {
    let mut response = Vec::new();
    response.extend_from_slice(b"HTTP/1.1 101 Switching Protocols\r\n");
    response.extend_from_slice(b"connection: Upgrade\r\n");
    response.extend_from_slice(b"upgrade: websocket\r\n");
    let mut accept_seen = false;
    for header in &head.headers {
        let Some(name) = websocket_downstream_response_header_name(header.name()) else {
            continue;
        };
        if !valid_upstream_header_value(header.value()) {
            return Err(fluxheim_protocol::Http1ParseError::InvalidHeaderValue.into());
        }
        if name.eq_ignore_ascii_case("sec-websocket-accept") {
            accept_seen = true;
        }
        response.extend_from_slice(name.as_bytes());
        response.extend_from_slice(b": ");
        response.extend_from_slice(header.value().as_bytes());
        response.extend_from_slice(b"\r\n");
    }
    if !accept_seen {
        return Err(NativeHttp1Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native WebSocket upgrade response missing Sec-WebSocket-Accept",
        )));
    }
    response.extend_from_slice(b"\r\n");
    Ok(response)
}

fn websocket_downstream_response_header_name(name: &str) -> Option<&'static str> {
    if name.eq_ignore_ascii_case("sec-websocket-accept") {
        Some("sec-websocket-accept")
    } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
        Some("sec-websocket-protocol")
    } else if name.eq_ignore_ascii_case("sec-websocket-extensions") {
        Some("sec-websocket-extensions")
    } else {
        None
    }
}
