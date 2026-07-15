use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinSet;
use zeroize::Zeroizing;

use crate::DownstreamHttp2Policy;
use crate::native_http2_error::NativeHttp2StackError;
use crate::native_http2_response::send_native_http2_response;
pub(crate) use crate::native_http2_response::{
    prohibited_http2_response_header, send_data_bounded, validate_response_headers,
};

const BODY_PREALLOC_HINT_BYTES: usize = 64 * 1024;
const PROBE_IDLE_TIMEOUT: Duration = Duration::from_millis(50);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp2Request {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Zeroizing<Vec<u8>>,
    pub trailers: Option<HeaderMap>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp2Response {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Bytes,
    pub(crate) trailers: Option<HeaderMap>,
}

impl NativeHttp2Response {
    pub fn new(status: StatusCode, body: impl Into<Bytes>) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: body.into(),
            trailers: None,
        }
    }

    pub fn no_content() -> Self {
        Self::new(StatusCode::NO_CONTENT, Bytes::new())
    }

    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub(crate) fn append_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.append(name, value);
        self
    }

    pub fn with_trailer(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.trailers
            .get_or_insert_with(HeaderMap::new)
            .insert(name, value);
        self
    }

    #[cfg(test)]
    pub(crate) fn headers(&self) -> &HeaderMap {
        &self.headers
    }
}

pub trait NativeHttp2Handler: Send + Sync + 'static {
    fn handle<'a>(
        &'a self,
        request: NativeHttp2Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp2Response> + Send + 'a>>;
}

impl<F, Fut> NativeHttp2Handler for F
where
    F: Fn(NativeHttp2Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = NativeHttp2Response> + Send + 'static,
{
    fn handle<'a>(
        &'a self,
        request: NativeHttp2Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp2Response> + Send + 'a>> {
        Box::pin(self(request))
    }
}

pub async fn native_http2_stack_probe<T>(
    io: T,
    policy: DownstreamHttp2Policy,
) -> Result<(), NativeHttp2StackError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    native_http2_stack_probe_with_response(io, policy, NativeHttp2Response::no_content()).await
}

pub async fn native_http2_stack_probe_with_response<T>(
    io: T,
    policy: DownstreamHttp2Policy,
    response: NativeHttp2Response,
) -> Result<(), NativeHttp2StackError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let handler = Arc::new(move |_| {
        let response = response.clone();
        async move { response }
    });
    serve_native_http2_connection_until_idle(io, policy, handler, PROBE_IDLE_TIMEOUT).await
}

pub async fn serve_native_http2_connection<T, H>(
    io: T,
    policy: DownstreamHttp2Policy,
    handler: Arc<H>,
) -> Result<(), NativeHttp2StackError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    H: NativeHttp2Handler,
{
    serve_native_http2_connection_inner(io, policy, handler, None).await
}

pub(crate) async fn serve_native_http2_connection_until_idle<T, H>(
    io: T,
    policy: DownstreamHttp2Policy,
    handler: Arc<H>,
    idle_timeout: Duration,
) -> Result<(), NativeHttp2StackError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    H: NativeHttp2Handler,
{
    serve_native_http2_connection_inner(io, policy, handler, Some(idle_timeout)).await
}

async fn serve_native_http2_connection_inner<T, H>(
    io: T,
    policy: DownstreamHttp2Policy,
    handler: Arc<H>,
    idle_timeout: Option<Duration>,
) -> Result<(), NativeHttp2StackError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    H: NativeHttp2Handler,
{
    let mut builder = h2::server::Builder::new();
    builder.max_header_list_size(policy.max_header_list_size());
    builder.max_concurrent_streams(policy.max_concurrent_streams());
    builder.initial_window_size(policy.initial_window_size());
    builder.max_frame_size(policy.max_frame_size());
    builder.max_send_buffer_size(policy.max_send_buffer_size());
    builder.max_pending_accept_reset_streams(policy.max_pending_accept_reset_streams());

    let mut connection: h2::server::Connection<T, Bytes> = builder
        .handshake(io)
        .await
        .map_err(NativeHttp2StackError::Handshake)?;

    let mut streams = JoinSet::new();
    let mut accepted_any_stream = false;
    loop {
        if accepted_any_stream
            && streams.is_empty()
            && let Some(timeout) = idle_timeout
        {
            match tokio::time::timeout(timeout, connection.accept()).await {
                Ok(Some(stream)) => {
                    spawn_native_http2_stream(stream, policy, handler.clone(), &mut streams)?;
                    accepted_any_stream = true;
                    continue;
                }
                Ok(None) | Err(_) => break,
            }
        }

        tokio::select! {
            completed = streams.join_next(), if !streams.is_empty() => {
                if let Some(completed) = completed {
                    handle_completed_native_http2_stream(completed)?;
                }
            }
            stream = connection.accept() => {
                let Some(stream) = stream else {
                    break;
                };
                spawn_native_http2_stream(stream, policy, handler.clone(), &mut streams)?;
                accepted_any_stream = true;
            }
        }
    }

    // Release the transport before waiting for handlers that can no longer
    // deliver responses. TLS generation draining depends on this prompt drop.
    drop(connection);
    while let Some(completed) = streams.join_next().await {
        handle_completed_native_http2_stream(completed)?;
    }
    Ok(())
}

fn spawn_native_http2_stream<H>(
    stream: Result<
        (
            http::Request<h2::RecvStream>,
            h2::server::SendResponse<Bytes>,
        ),
        h2::Error,
    >,
    policy: DownstreamHttp2Policy,
    handler: Arc<H>,
    streams: &mut JoinSet<Result<(), NativeHttp2StackError>>,
) -> Result<(), NativeHttp2StackError>
where
    H: NativeHttp2Handler,
{
    let (mut request, mut respond) = stream.map_err(NativeHttp2StackError::Stream)?;
    streams.spawn(async move {
        handle_native_http2_stream(&mut request, &mut respond, policy, handler).await
    });
    Ok(())
}

fn handle_completed_native_http2_stream(
    completed: Result<Result<(), NativeHttp2StackError>, tokio::task::JoinError>,
) -> Result<(), NativeHttp2StackError> {
    match completed.map_err(NativeHttp2StackError::StreamTaskJoin)? {
        Ok(()) => Ok(()),
        Err(error) => {
            log::debug!(
                target: "fluxheim::native_http2",
                "native HTTP/2 stream failed: {error}"
            );
            Ok(())
        }
    }
}

async fn handle_native_http2_stream<H>(
    request: &mut http::Request<h2::RecvStream>,
    respond: &mut h2::server::SendResponse<Bytes>,
    policy: DownstreamHttp2Policy,
    handler: Arc<H>,
) -> Result<(), NativeHttp2StackError>
where
    H: NativeHttp2Handler,
{
    if let Err(error) = validate_request(request, policy) {
        let response = native_http2_stream_error_response(&error);
        send_native_http2_response(respond, response).await?;
        return Ok(());
    }
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let body_capacity_hint = request_body_capacity_hint(request.headers(), policy.max_body_bytes());
    let (body, trailers) = match tokio::time::timeout(
        policy.request_body_timeout(),
        drain_request_body(
            request.body_mut(),
            policy.max_body_bytes(),
            body_capacity_hint,
        ),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(error @ NativeHttp2StackError::BodyTooLarge { .. })) => {
            send_native_http2_response(respond, native_http2_stream_error_response(&error)).await?;
            return Ok(());
        }
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            send_native_http2_response(
                respond,
                native_http2_stream_error_response(&NativeHttp2StackError::BodyReadTimeout),
            )
            .await?;
            return Ok(());
        }
    };
    let response = match tokio::time::timeout(
        policy.handler_timeout(),
        handler.handle(NativeHttp2Request {
            method,
            uri,
            headers,
            body,
            trailers,
        }),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => {
            send_native_http2_response(
                respond,
                native_http2_stream_error_response(&NativeHttp2StackError::HandlerTimeout),
            )
            .await?;
            return Ok(());
        }
    };
    tokio::time::timeout(
        policy.response_write_lifetime(),
        send_native_http2_response(respond, response),
    )
    .await
    .map_err(|_| NativeHttp2StackError::ResponseWriteTimeout)?
}

fn native_http2_stream_error_response(error: &NativeHttp2StackError) -> NativeHttp2Response {
    match error {
        NativeHttp2StackError::TooManyHeaders { .. } => NativeHttp2Response::new(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            Bytes::from_static(b"too many headers\n"),
        ),
        NativeHttp2StackError::UriTooLarge { .. } => NativeHttp2Response::new(
            StatusCode::URI_TOO_LONG,
            Bytes::from_static(b"uri too large\n"),
        ),
        NativeHttp2StackError::BodyReadTimeout => NativeHttp2Response::new(
            StatusCode::REQUEST_TIMEOUT,
            Bytes::from_static(b"request body timeout\n"),
        ),
        NativeHttp2StackError::BodyTooLarge { .. } => NativeHttp2Response::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            Bytes::from_static(b"request body too large\n"),
        ),
        NativeHttp2StackError::HandlerTimeout => NativeHttp2Response::new(
            StatusCode::GATEWAY_TIMEOUT,
            Bytes::from_static(b"handler timeout\n"),
        ),
        _ => NativeHttp2Response::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            Bytes::from_static(b"stream error\n"),
        ),
    }
}

fn validate_request(
    request: &http::Request<h2::RecvStream>,
    policy: DownstreamHttp2Policy,
) -> Result<(), NativeHttp2StackError> {
    let header_count = request.headers().len();
    if header_count > policy.max_header_count() {
        return Err(NativeHttp2StackError::TooManyHeaders {
            count: header_count,
            limit: policy.max_header_count(),
        });
    }
    let uri_len = request
        .uri()
        .path_and_query()
        .map_or(0, |path_and_query| path_and_query.as_str().len());
    if uri_len > policy.max_uri_bytes() {
        return Err(NativeHttp2StackError::UriTooLarge {
            len: uri_len,
            limit: policy.max_uri_bytes(),
        });
    }
    Ok(())
}

async fn drain_request_body(
    body: &mut h2::RecvStream,
    max_body_bytes: usize,
    capacity_hint: usize,
) -> Result<(Zeroizing<Vec<u8>>, Option<HeaderMap>), NativeHttp2StackError> {
    let mut total = 0usize;
    let mut buffered = Zeroizing::new(Vec::with_capacity(capacity_hint));
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(NativeHttp2StackError::BodyData)?;
        let chunk_len = chunk.len();
        total = total
            .checked_add(chunk_len)
            .filter(|bytes| *bytes <= max_body_bytes)
            .ok_or(NativeHttp2StackError::BodyTooLarge {
                limit: max_body_bytes,
            })?;
        buffered.extend_from_slice(&chunk);
        drop(chunk);
        body.flow_control()
            .release_capacity(chunk_len)
            .map_err(NativeHttp2StackError::BodyData)?;
    }
    let trailers = body
        .trailers()
        .await
        .map_err(NativeHttp2StackError::BodyTrailers)?;
    Ok((buffered, trailers))
}

fn request_body_capacity_hint(headers: &HeaderMap, max_body_bytes: usize) -> usize {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|length| *length <= max_body_bytes)
        .map_or(max_body_bytes.min(BODY_PREALLOC_HINT_BYTES), |length| {
            length.min(BODY_PREALLOC_HINT_BYTES)
        })
}
