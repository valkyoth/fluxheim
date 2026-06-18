use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::native_http2_stack::{send_data_bounded, validate_response_headers};
use crate::{DownstreamHttp2Policy, NativeHttp2StackError};

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
    validate_outbound_request(&request, policy)?;

    let mut builder = h2::client::Builder::new();
    builder.max_header_list_size(policy.max_header_list_size());
    builder.max_concurrent_streams(policy.max_concurrent_streams());
    builder.initial_window_size(policy.initial_window_size());
    builder.max_frame_size(policy.max_frame_size());
    builder.max_send_buffer_size(policy.max_send_buffer_size());
    builder.max_concurrent_reset_streams(policy.max_pending_accept_reset_streams());

    let (client, connection) = builder
        .handshake::<_, Bytes>(io)
        .await
        .map_err(NativeHttp2StackError::Handshake)?;
    let connection_driver = tokio::spawn(async move {
        if let Err(error) = connection.await {
            log::debug!(
                target: "fluxheim::native_http2",
                "native HTTP/2 upstream connection ended: {error}"
            );
        }
    });

    let result = send_native_http2_upstream_request(client, policy, request).await;
    // This is a one-request, one-connection preview client. It intentionally
    // aborts the driver instead of flushing GOAWAY; do not copy this teardown
    // for future pooled HTTP/2 upstream connections.
    connection_driver.abort();
    let _ = connection_driver.await;
    result
}

async fn send_native_http2_upstream_request(
    client: h2::client::SendRequest<Bytes>,
    policy: DownstreamHttp2Policy,
    request: NativeHttp2UpstreamRequest,
) -> Result<NativeHttp2UpstreamResponse, NativeHttp2StackError> {
    let mut client = tokio::time::timeout(policy.handler_timeout(), client.ready())
        .await
        .map_err(|_| NativeHttp2StackError::HandlerTimeout)?
        .map_err(NativeHttp2StackError::Stream)?;
    let end_on_headers = request.body.is_empty() && request.trailers.is_none();
    let head = outbound_request_head(&request)?;
    let (response, mut send_stream) = client
        .send_request(head, end_on_headers)
        .map_err(NativeHttp2StackError::SendResponse)?;
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

fn validate_outbound_request(
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
