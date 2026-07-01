use std::future::poll_fn;
use std::task::Poll;

use bytes::Bytes;
use http::{HeaderMap, HeaderName};

use crate::{NativeHttp2Response, NativeHttp2StackError};

pub(super) async fn send_native_http2_response(
    respond: &mut h2::server::SendResponse<Bytes>,
    response: NativeHttp2Response,
) -> Result<(), NativeHttp2StackError> {
    validate_response_headers(&response.headers)?;
    if let Some(trailers) = &response.trailers {
        validate_response_headers(trailers)?;
    }
    let end_on_headers = response.body.is_empty() && response.trailers.is_none();
    let mut builder = http::Response::builder().status(response.status);
    for (name, value) in &response.headers {
        builder = builder.header(name, value);
    }
    let head = builder
        .body(())
        .map_err(NativeHttp2StackError::ResponseBuild)?;
    let mut send_stream = respond
        .send_response(head, end_on_headers)
        .map_err(NativeHttp2StackError::SendResponse)?;
    if !response.body.is_empty() {
        send_data_bounded(&mut send_stream, response.body, response.trailers.is_none()).await?;
    }
    if let Some(trailers) = response.trailers {
        send_stream
            .send_trailers(trailers)
            .map_err(NativeHttp2StackError::SendResponse)?;
    }
    Ok(())
}

pub(crate) fn validate_response_headers(headers: &HeaderMap) -> Result<(), NativeHttp2StackError> {
    for name in headers.keys() {
        if prohibited_http2_response_header(name) {
            return Err(NativeHttp2StackError::ProhibitedResponseHeader {
                name: name.as_str().to_owned(),
            });
        }
    }
    Ok(())
}

pub(crate) fn prohibited_http2_response_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
    )
}

pub(crate) async fn send_data_bounded(
    send_stream: &mut h2::SendStream<Bytes>,
    body: Bytes,
    end_of_stream: bool,
) -> Result<(), NativeHttp2StackError> {
    let mut offset = 0usize;
    while offset < body.len() {
        send_stream.reserve_capacity(body.len() - offset);
        let capacity = poll_fn(|context| match send_stream.poll_capacity(context) {
            Poll::Ready(Some(Ok(capacity))) => Poll::Ready(Ok(capacity)),
            Poll::Ready(Some(Err(error))) => {
                Poll::Ready(Err(NativeHttp2StackError::SendResponse(error)))
            }
            Poll::Ready(None) => Poll::Ready(Err(NativeHttp2StackError::ResponseCapacityClosed)),
            Poll::Pending => Poll::Pending,
        })
        .await?;
        if capacity == 0 {
            return Err(NativeHttp2StackError::ResponseCapacityClosed);
        }
        let available = capacity.min(body.len() - offset);
        let next_offset = offset + available;
        let chunk = body.slice(offset..next_offset);
        offset = next_offset;
        send_stream
            .send_data(chunk, end_of_stream && offset == body.len())
            .map_err(NativeHttp2StackError::SendResponse)?;
    }
    Ok(())
}
