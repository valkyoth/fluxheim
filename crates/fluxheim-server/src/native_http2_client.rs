use bytes::Bytes;
use h2::client::SendRequest;
use http::{HeaderMap, Method, StatusCode, Uri};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::{AbortHandle, JoinHandle};
use zeroize::Zeroizing;

use crate::native_http2_stack::{send_data_bounded, validate_response_headers};
use crate::{DownstreamHttp2Policy, NativeHttp2StackError};

#[derive(Debug)]
pub(crate) struct NativeHttp2ConnectionDriver {
    connection: JoinHandle<()>,
    keepalive: Option<JoinHandle<()>>,
}

impl NativeHttp2ConnectionDriver {
    pub(crate) fn abort(&self) {
        self.connection.abort();
        if let Some(keepalive) = &self.keepalive {
            keepalive.abort();
        }
    }

    pub(crate) async fn abort_and_join(self) {
        self.abort();
        let _ = self.connection.await;
        if let Some(keepalive) = self.keepalive {
            let _ = keepalive.await;
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp2UpstreamRequest {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Zeroizing<Vec<u8>>,
    pub trailers: Option<HeaderMap>,
}

impl NativeHttp2UpstreamRequest {
    pub fn new(method: Method, uri: Uri) -> Self {
        Self {
            method,
            uri,
            headers: HeaderMap::new(),
            body: Zeroizing::new(Vec::new()),
            trailers: None,
        }
    }

    pub fn with_header(mut self, name: http::HeaderName, value: http::HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn with_body(mut self, body: impl AsRef<[u8]>) -> Self {
        self.body = Zeroizing::new(body.as_ref().to_vec());
        self
    }

    pub fn with_trailer(mut self, name: http::HeaderName, value: http::HeaderValue) -> Self {
        self.trailers
            .get_or_insert_with(HeaderMap::new)
            .insert(name, value);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp2UpstreamResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Zeroizing<Vec<u8>>,
    trailers: Option<HeaderMap>,
}

impl NativeHttp2UpstreamResponse {
    #[cfg(test)]
    pub(crate) fn for_test(status: StatusCode, headers: HeaderMap, body: impl AsRef<[u8]>) -> Self {
        Self {
            status,
            headers,
            body: Zeroizing::new(body.as_ref().to_vec()),
            trailers: None,
        }
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub const fn trailers(&self) -> Option<&HeaderMap> {
        self.trailers.as_ref()
    }
}

pub async fn send_native_http2_upstream_on_io<T>(
    io: T,
    policy: DownstreamHttp2Policy,
    request: NativeHttp2UpstreamRequest,
) -> Result<NativeHttp2UpstreamResponse, NativeHttp2StackError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (client, connection_driver) = native_http2_upstream_client_on_io(io, policy).await?;
    let result = send_native_http2_upstream_request(client, policy, request).await;
    // This is a one-request, one-connection helper used by tests and fallback
    // paths. Pooled upstream connections own their driver task separately.
    connection_driver.abort_and_join().await;
    result
}

pub(crate) async fn native_http2_upstream_client_on_io<T>(
    io: T,
    policy: DownstreamHttp2Policy,
) -> Result<(SendRequest<Bytes>, NativeHttp2ConnectionDriver), NativeHttp2StackError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    native_http2_upstream_client_on_io_with_keepalive(io, policy, None).await
}

pub(crate) async fn native_http2_upstream_client_on_io_with_keepalive<T>(
    io: T,
    policy: DownstreamHttp2Policy,
    keepalive_interval: Option<std::time::Duration>,
) -> Result<(SendRequest<Bytes>, NativeHttp2ConnectionDriver), NativeHttp2StackError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    native_http2_upstream_client_on_io_with_mode(
        io,
        policy,
        keepalive_interval,
        NativeHttp2ClientHandshakeMode::PriorKnowledge,
    )
    .await
}

pub(crate) async fn native_http2_upstream_client_on_h2c_upgraded_io<T>(
    io: T,
    policy: DownstreamHttp2Policy,
    keepalive_interval: Option<std::time::Duration>,
) -> Result<(SendRequest<Bytes>, NativeHttp2ConnectionDriver), NativeHttp2StackError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    native_http2_upstream_client_on_io_with_mode(
        io,
        policy,
        keepalive_interval,
        NativeHttp2ClientHandshakeMode::H2cUpgrade,
    )
    .await
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeHttp2ClientHandshakeMode {
    PriorKnowledge,
    H2cUpgrade,
}

async fn native_http2_upstream_client_on_io_with_mode<T>(
    io: T,
    policy: DownstreamHttp2Policy,
    keepalive_interval: Option<std::time::Duration>,
    mode: NativeHttp2ClientHandshakeMode,
) -> Result<(SendRequest<Bytes>, NativeHttp2ConnectionDriver), NativeHttp2StackError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let keepalive_interval = keepalive_interval.filter(|interval| !interval.is_zero());
    let mut builder = h2::client::Builder::new();
    if mode == NativeHttp2ClientHandshakeMode::H2cUpgrade {
        builder.initial_stream_id(3);
    }
    builder.max_header_list_size(policy.max_header_list_size());
    builder.max_concurrent_streams(policy.max_concurrent_streams());
    builder.initial_window_size(policy.initial_window_size());
    builder.max_frame_size(policy.max_frame_size());
    builder.max_send_buffer_size(policy.max_send_buffer_size());
    builder.max_concurrent_reset_streams(policy.max_pending_accept_reset_streams());

    let (client, mut connection) =
        tokio::time::timeout(policy.handler_timeout(), builder.handshake::<_, Bytes>(io))
            .await
            .map_err(|_| NativeHttp2StackError::HandshakeTimeout)?
            .map_err(NativeHttp2StackError::Handshake)?;
    let ping_pong = keepalive_interval.and_then(|_| connection.ping_pong());
    let connection_driver = tokio::spawn(async move {
        if let Err(error) = connection.await {
            log::debug!(
                target: "fluxheim::native_http2",
                "native HTTP/2 upstream connection ended: {error}"
            );
        }
    });
    let keepalive = match (keepalive_interval, ping_pong) {
        (Some(interval), Some(ping_pong)) => Some(spawn_native_http2_keepalive(
            ping_pong,
            interval,
            policy.handler_timeout(),
            connection_driver.abort_handle(),
        )),
        _ => None,
    };
    Ok((
        client,
        NativeHttp2ConnectionDriver {
            connection: connection_driver,
            keepalive,
        },
    ))
}

fn spawn_native_http2_keepalive(
    mut ping_pong: h2::PingPong,
    interval: std::time::Duration,
    timeout_duration: std::time::Duration,
    connection_abort: AbortHandle,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match tokio::time::timeout(timeout_duration, ping_pong.ping(h2::Ping::opaque())).await {
                Ok(Ok(_pong)) => {}
                Ok(Err(error)) => {
                    log::debug!(
                        target: "fluxheim::native_http2",
                        "native HTTP/2 upstream keepalive ping failed: {error}"
                    );
                    connection_abort.abort();
                    break;
                }
                Err(_) => {
                    log::debug!(
                        target: "fluxheim::native_http2",
                        "native HTTP/2 upstream keepalive ping timed out"
                    );
                    connection_abort.abort();
                    break;
                }
            }
        }
    })
}

pub(crate) async fn send_native_http2_upstream_request(
    client: h2::client::SendRequest<Bytes>,
    policy: DownstreamHttp2Policy,
    request: NativeHttp2UpstreamRequest,
) -> Result<NativeHttp2UpstreamResponse, NativeHttp2StackError> {
    validate_outbound_request(&request, policy)?;
    let mut client = tokio::time::timeout(policy.handler_timeout(), client.ready())
        .await
        .map_err(|_| NativeHttp2StackError::RequestReadyTimeout)?
        .map_err(NativeHttp2StackError::RequestReady)?;
    let end_on_headers = request.body.is_empty() && request.trailers.is_none();
    let head = outbound_request_head(&request)?;
    let (response, mut send_stream) = client
        .send_request(head, end_on_headers)
        .map_err(NativeHttp2StackError::SendRequest)?;
    if !end_on_headers {
        tokio::time::timeout(
            policy.response_write_lifetime(),
            send_request_body_and_trailers(&mut send_stream, request),
        )
        .await
        .map_err(|_| NativeHttp2StackError::ResponseWriteTimeout)??;
    }
    let response = tokio::time::timeout(policy.handler_timeout(), response)
        .await
        .map_err(|_| NativeHttp2StackError::HandlerTimeout)?
        .map_err(NativeHttp2StackError::Stream)?;
    validate_inbound_response(response, policy).await
}

fn outbound_request_head(
    request: &NativeHttp2UpstreamRequest,
) -> Result<http::Request<()>, NativeHttp2StackError> {
    let mut builder = http::Request::builder()
        .method(request.method.clone())
        .uri(request.uri.clone())
        .version(http::Version::HTTP_2);
    for (name, value) in &request.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(())
        .map_err(NativeHttp2StackError::ResponseBuild)
}

pub(crate) fn validate_outbound_request(
    request: &NativeHttp2UpstreamRequest,
    policy: DownstreamHttp2Policy,
) -> Result<(), NativeHttp2StackError> {
    let header_count = request.headers.len();
    if header_count > policy.max_header_count() {
        return Err(NativeHttp2StackError::TooManyHeaders {
            count: header_count,
            limit: policy.max_header_count(),
        });
    }
    let uri_len = request
        .uri
        .path_and_query()
        .map_or(0, |path_and_query| path_and_query.as_str().len());
    if uri_len > policy.max_uri_bytes() {
        return Err(NativeHttp2StackError::UriTooLarge {
            len: uri_len,
            limit: policy.max_uri_bytes(),
        });
    }
    if request.body.len() > policy.max_body_bytes() {
        return Err(NativeHttp2StackError::BodyTooLarge {
            limit: policy.max_body_bytes(),
        });
    }
    if let Some(trailers) = &request.trailers
        && trailers.len() > policy.max_header_count()
    {
        return Err(NativeHttp2StackError::TooManyHeaders {
            count: trailers.len(),
            limit: policy.max_header_count(),
        });
    }
    Ok(())
}

async fn send_request_body_and_trailers(
    send_stream: &mut h2::SendStream<Bytes>,
    request: NativeHttp2UpstreamRequest,
) -> Result<(), NativeHttp2StackError> {
    if !request.body.is_empty() {
        send_data_bounded(
            send_stream,
            Bytes::copy_from_slice(request.body.as_slice()),
            request.trailers.is_none(),
        )
        .await?;
    }
    if let Some(trailers) = request.trailers {
        send_stream
            .send_trailers(trailers)
            .map_err(NativeHttp2StackError::SendResponse)?;
    }
    Ok(())
}

async fn validate_inbound_response(
    response: http::Response<h2::RecvStream>,
    policy: DownstreamHttp2Policy,
) -> Result<NativeHttp2UpstreamResponse, NativeHttp2StackError> {
    let status = response.status();
    let headers = response.headers().clone();
    validate_response_header_count(&headers, policy)?;
    validate_response_headers(&headers)?;
    let (body, trailers) = tokio::time::timeout(
        policy.response_body_timeout(),
        drain_response_body(response.into_body(), policy.max_body_bytes()),
    )
    .await
    .map_err(|_| NativeHttp2StackError::BodyReadTimeout)??;
    if let Some(trailers) = &trailers {
        validate_response_header_count(trailers, policy)?;
        validate_response_headers(trailers)?;
    }
    Ok(NativeHttp2UpstreamResponse {
        status,
        headers,
        body,
        trailers,
    })
}

fn validate_response_header_count(
    headers: &HeaderMap,
    policy: DownstreamHttp2Policy,
) -> Result<(), NativeHttp2StackError> {
    let count = headers.len();
    if count > policy.max_header_count() {
        return Err(NativeHttp2StackError::TooManyHeaders {
            count,
            limit: policy.max_header_count(),
        });
    }
    Ok(())
}

async fn drain_response_body(
    mut body: h2::RecvStream,
    max_body_bytes: usize,
) -> Result<(Zeroizing<Vec<u8>>, Option<HeaderMap>), NativeHttp2StackError> {
    let mut total = 0usize;
    let mut buffered = Zeroizing::new(Vec::with_capacity(max_body_bytes.min(64 * 1024)));
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
