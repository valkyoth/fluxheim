use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};

use crate::{
    DownstreamHttp2Policy, NativeHttp1Error, NativeHttp1Request, NativeHttp1Response,
    NativeHttp2StackError, NativeHttp2UpstreamRequest, NativeHttp2UpstreamResponse,
};

pub(super) fn h2c_upgrade_settings_header(policy: DownstreamHttp2Policy) -> String {
    let mut settings = Vec::with_capacity(18);
    push_h2_setting(&mut settings, 0x4, policy.initial_window_size());
    push_h2_setting(&mut settings, 0x5, policy.max_frame_size());
    push_h2_setting(&mut settings, 0x6, policy.max_header_list_size());
    base64_ng::URL_SAFE_NO_PAD.encode_string_infallible(&settings)
}

fn push_h2_setting(settings: &mut Vec<u8>, id: u16, value: u32) {
    settings.extend_from_slice(&id.to_be_bytes());
    settings.extend_from_slice(&value.to_be_bytes());
}

pub(super) fn h2c_upgrade_error_can_fallback(error: &NativeHttp1Error) -> bool {
    matches!(
        error,
        NativeHttp1Error::Io(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::InvalidData
                    | std::io::ErrorKind::Unsupported
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            )
    )
}

pub(super) fn native_http2_upstream_request(
    request: &NativeHttp1Request,
    authority: &str,
    scheme: &'static str,
) -> Result<NativeHttp2UpstreamRequest, NativeHttp1Error> {
    let method = Method::from_bytes(request.method.as_bytes())
        .map_err(|_| fluxheim_protocol::Http1ParseError::InvalidRequestLine)?;
    let target = super::request::upstream_origin_target(request)?;
    let request_authority = super::request::valid_request_host(request, authority)?;
    let uri = Uri::try_from(format!("{scheme}://{request_authority}{target}"))
        .map_err(|_| fluxheim_protocol::Http1ParseError::InvalidRequestTarget)?;
    let mut headers = HeaderMap::new();
    let connection_tokens = super::request::connection_tokens(request);
    for (name, value) in &request.headers {
        if super::request::upstream_hop_by_hop_header(name, &connection_tokens)
            || super::request::upstream_owned_header_for_request(name, request)
        {
            continue;
        }
        if !crate::native_http1_forwarded::valid_upstream_request_header(name, value) {
            return Err(fluxheim_protocol::Http1ParseError::InvalidHeaderValue.into());
        }
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| fluxheim_protocol::Http1ParseError::InvalidHeaderName)?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| fluxheim_protocol::Http1ParseError::InvalidHeaderValue)?;
        headers.append(name, value);
    }
    let via = request
        .headers
        .iter()
        .filter(|(name, value)| {
            name.eq_ignore_ascii_case("via")
                && crate::native_http1_forwarded::valid_upstream_request_header(name, value)
        })
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    headers.insert(
        http::header::VIA,
        HeaderValue::from_str(&fluxheim_protocol::append_fluxheim_via_value(&via))
            .map_err(|_| fluxheim_protocol::Http1ParseError::InvalidHeaderValue)?,
    );
    let trailers = native_http2_upstream_trailers(request)?;
    Ok(NativeHttp2UpstreamRequest {
        method,
        uri,
        headers,
        body: request.body.clone(),
        trailers,
    })
}

fn native_http2_upstream_trailers(
    request: &NativeHttp1Request,
) -> Result<Option<HeaderMap>, NativeHttp1Error> {
    if request.trailers.is_empty() {
        return Ok(None);
    }
    let mut trailers = HeaderMap::new();
    for (name, value) in &request.trailers {
        if super::request::upstream_hop_by_hop_header(name, &[])
            || super::request::upstream_owned_header_for_request(name, request)
        {
            continue;
        }
        if !crate::native_http1_forwarded::valid_upstream_request_header(name, value) {
            return Err(fluxheim_protocol::Http1ParseError::InvalidHeaderValue.into());
        }
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| fluxheim_protocol::Http1ParseError::InvalidHeaderName)?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| fluxheim_protocol::Http1ParseError::InvalidHeaderValue)?;
        trailers.append(name, value);
    }
    Ok((!trailers.is_empty()).then_some(trailers))
}

pub(super) const fn upstream_h2_scheme(upstream_tls: bool) -> &'static str {
    if upstream_tls { "https" } else { "http" }
}

pub(super) fn native_http2_response_to_http1(
    response: NativeHttp2UpstreamResponse,
) -> Result<NativeHttp1Response, NativeHttp1Error> {
    let status = response.status();
    let reason = status.canonical_reason().unwrap_or("");
    let mut native = NativeHttp1Response::new(status.as_u16(), reason, response.body().to_vec());
    for (name, value) in response.headers() {
        if native_http2_response_header_proxy_owned_or_hop_by_hop(name) {
            continue;
        }
        let value = value
            .to_str()
            .map_err(|_| fluxheim_protocol::Http1ParseError::InvalidHeaderValue)?;
        native = native.with_header(name.as_str(), value);
    }
    Ok(native)
}

fn native_http2_response_header_proxy_owned_or_hop_by_hop(name: &HeaderName) -> bool {
    name == http::header::CONTENT_LENGTH
        || name == http::header::CONNECTION
        || name == http::header::DATE
        || name == http::header::TRANSFER_ENCODING
        || name == http::header::UPGRADE
        || matches!(
            name.as_str(),
            "keep-alive" | "proxy-connection" | "te" | "trailer"
        )
}

pub(super) fn native_http2_error(error: NativeHttp2StackError) -> NativeHttp1Error {
    let kind = match error {
        NativeHttp2StackError::BodyReadTimeout
        | NativeHttp2StackError::HandshakeTimeout
        | NativeHttp2StackError::HandlerTimeout
        | NativeHttp2StackError::RequestReadyTimeout
        | NativeHttp2StackError::ResponseWriteTimeout => std::io::ErrorKind::TimedOut,
        NativeHttp2StackError::TooManyHeaders { .. }
        | NativeHttp2StackError::UriTooLarge { .. }
        | NativeHttp2StackError::InvalidContentLength
        | NativeHttp2StackError::BodyTooLarge { .. }
        | NativeHttp2StackError::ProhibitedResponseHeader { .. }
        | NativeHttp2StackError::ResponseBuild(_) => std::io::ErrorKind::InvalidData,
        NativeHttp2StackError::BodyCapacityUnavailable => std::io::ErrorKind::WouldBlock,
        NativeHttp2StackError::ResponseCapacityClosed => std::io::ErrorKind::Other,
        NativeHttp2StackError::Handshake(_)
        | NativeHttp2StackError::RequestReady(_)
        | NativeHttp2StackError::SendRequest(_)
        | NativeHttp2StackError::Stream(_)
        | NativeHttp2StackError::BodyData(_)
        | NativeHttp2StackError::BodyTrailers(_)
        | NativeHttp2StackError::SendResponse(_)
        | NativeHttp2StackError::StreamTaskJoin(_) => std::io::ErrorKind::Other,
    };
    NativeHttp1Error::Io(std::io::Error::new(kind, error.to_string()))
}

pub(super) fn native_http2_error_retry_safe(error: &NativeHttp2StackError) -> bool {
    matches!(
        error,
        NativeHttp2StackError::RequestReadyTimeout
            | NativeHttp2StackError::RequestReady(_)
            | NativeHttp2StackError::SendRequest(_)
    )
}

pub(super) fn native_http2_error_is_connection_fatal(error: &NativeHttp2StackError) -> bool {
    match error {
        NativeHttp2StackError::RequestReadyTimeout
        | NativeHttp2StackError::RequestReady(_)
        | NativeHttp2StackError::SendRequest(_) => true,
        NativeHttp2StackError::Stream(error) => error.is_go_away(),
        _ => false,
    }
}
