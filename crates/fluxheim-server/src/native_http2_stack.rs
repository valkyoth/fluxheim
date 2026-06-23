use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use crate::DownstreamHttp2Policy;

const BODY_PREALLOC_HINT_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub enum NativeHttp2StackError {
    Handshake(h2::Error),
    HandshakeTimeout,
    Stream(h2::Error),
    RequestReadyTimeout,
    RequestReady(h2::Error),
    SendRequest(h2::Error),
    TooManyHeaders { count: usize, limit: usize },
    UriTooLarge { len: usize, limit: usize },
    BodyReadTimeout,
    BodyTooLarge { limit: usize },
    BodyData(h2::Error),
    BodyTrailers(h2::Error),
    HandlerTimeout,
    ProhibitedResponseHeader { name: String },
    ResponseBuild(http::Error),
    SendResponse(h2::Error),
    ResponseWriteTimeout,
    ResponseCapacityClosed,
}

impl std::fmt::Display for NativeHttp2StackError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Handshake(error) => write!(formatter, "native HTTP/2 handshake failed: {error}"),
            Self::HandshakeTimeout => write!(formatter, "native HTTP/2 handshake timed out"),
            Self::Stream(error) => write!(formatter, "native HTTP/2 stream failed: {error}"),
            Self::RequestReadyTimeout => {
                write!(
                    formatter,
                    "native HTTP/2 upstream request readiness timed out"
                )
            }
            Self::RequestReady(error) => {
                write!(
                    formatter,
                    "native HTTP/2 upstream request readiness failed: {error}"
                )
            }
            Self::SendRequest(error) => {
                write!(
                    formatter,
                    "native HTTP/2 upstream request send failed: {error}"
                )
            }
            Self::TooManyHeaders { count, limit } => write!(
                formatter,
                "native HTTP/2 request has too many decoded headers: {count} > {limit}"
            ),
            Self::UriTooLarge { len, limit } => {
                write!(formatter, "native HTTP/2 URI is too large: {len} > {limit}")
            }
            Self::BodyReadTimeout => write!(formatter, "native HTTP/2 body read timed out"),
            Self::BodyTooLarge { limit } => {
                write!(formatter, "native HTTP/2 body exceeded {limit} bytes")
            }
            Self::BodyData(error) => write!(formatter, "native HTTP/2 body read failed: {error}"),
            Self::BodyTrailers(error) => {
                write!(formatter, "native HTTP/2 body trailer read failed: {error}")
            }
            Self::HandlerTimeout => write!(formatter, "native HTTP/2 handler timed out"),
            Self::ProhibitedResponseHeader { name } => {
                write!(
                    formatter,
                    "native HTTP/2 response includes prohibited header {name:?}"
                )
            }
            Self::ResponseBuild(error) => {
                write!(formatter, "native HTTP/2 response build failed: {error}")
            }
            Self::SendResponse(error) => {
                write!(formatter, "native HTTP/2 response send failed: {error}")
            }
            Self::ResponseWriteTimeout => {
                write!(formatter, "native HTTP/2 response write timed out")
            }
            Self::ResponseCapacityClosed => {
                write!(formatter, "native HTTP/2 response capacity closed")
            }
        }
    }
}

impl std::error::Error for NativeHttp2StackError {}

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
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    trailers: Option<HeaderMap>,
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

    pub fn with_trailer(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.trailers
            .get_or_insert_with(HeaderMap::new)
            .insert(name, value);
        self
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
    serve_native_http2_connection(io, policy, handler).await
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

    let Some(stream) = connection.accept().await else {
        return Ok(());
    };
    let (mut request, mut respond) = stream.map_err(NativeHttp2StackError::Stream)?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let connection_driver = tokio::spawn(drive_connection(connection, shutdown_rx));
    let stream_result =
        handle_native_http2_stream(&mut request, &mut respond, policy, handler).await;
    if let Err(error) = stream_result {
        let _ = shutdown_tx.send(());
        connection_driver.abort();
        let _ = connection_driver.await;
        return Err(error);
    }
    let _ = shutdown_tx.send(());
    if let Err(error) = connection_driver.await {
        log::debug!(
            target: "fluxheim::native_http2",
            "native HTTP/2 probe connection driver join failed: {error}"
        );
    }
    Ok(())
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
    validate_request(request, policy)?;
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let body_capacity_hint = request_body_capacity_hint(request.headers(), policy.max_body_bytes());
    let (body, trailers) = tokio::time::timeout(
        policy.request_body_timeout(),
        drain_request_body(
            request.body_mut(),
            policy.max_body_bytes(),
            body_capacity_hint,
        ),
    )
    .await
    .map_err(|_| NativeHttp2StackError::BodyReadTimeout)??;
    let response = tokio::time::timeout(
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
    .map_err(|_| NativeHttp2StackError::HandlerTimeout)?;
    tokio::time::timeout(
        policy.response_write_lifetime(),
        send_native_http2_response(respond, response),
    )
    .await
    .map_err(|_| NativeHttp2StackError::ResponseWriteTimeout)?
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

async fn drive_connection<T>(
    mut connection: h2::server::Connection<T, Bytes>,
    mut shutdown_rx: oneshot::Receiver<()>,
) where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut shutdown_requested = false;
    loop {
        let stream = tokio::select! {
            _ = &mut shutdown_rx, if !shutdown_requested => {
                shutdown_requested = true;
                connection.graceful_shutdown();
                continue;
            }
            stream = connection.accept() => stream,
        };
        match stream {
            Some(Ok(_)) => {
                log::debug!(
                    target: "fluxheim::native_http2",
                    "native HTTP/2 probe dropped post-shutdown stream"
                );
            }
            Some(Err(error)) => {
                log::debug!(
                    target: "fluxheim::native_http2",
                    "native HTTP/2 probe post-response drain ended: {error}"
                );
                break;
            }
            None => break,
        }
    }
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

async fn send_native_http2_response(
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
