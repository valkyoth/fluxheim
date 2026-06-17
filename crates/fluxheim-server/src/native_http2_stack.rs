use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;

use crate::DownstreamHttp2Policy;

#[derive(Debug)]
pub enum NativeHttp2StackError {
    Handshake(h2::Error),
    Stream(h2::Error),
    TooManyHeaders { count: usize, limit: usize },
    UriTooLarge { len: usize, limit: usize },
    BodyReadTimeout,
    BodyTooLarge { limit: usize },
    BodyData(h2::Error),
    ResponseBuild(http::Error),
    SendResponse(h2::Error),
}

impl std::fmt::Display for NativeHttp2StackError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Handshake(error) => write!(formatter, "native HTTP/2 handshake failed: {error}"),
            Self::Stream(error) => write!(formatter, "native HTTP/2 stream failed: {error}"),
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
            Self::ResponseBuild(error) => {
                write!(formatter, "native HTTP/2 response build failed: {error}")
            }
            Self::SendResponse(error) => {
                write!(formatter, "native HTTP/2 response send failed: {error}")
            }
        }
    }
}

impl std::error::Error for NativeHttp2StackError {}

pub async fn native_http2_stack_probe<T>(
    io: T,
    policy: DownstreamHttp2Policy,
) -> Result<(), NativeHttp2StackError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
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
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let connection_driver = tokio::spawn(drive_connection(connection, shutdown_rx));
    let body_result = tokio::time::timeout(
        policy.request_body_timeout(),
        drain_request_body(request.body_mut(), policy.max_body_bytes()),
    )
    .await
    .map_err(|_| NativeHttp2StackError::BodyReadTimeout)
    .and_then(|result| result);
    if let Err(error) = body_result {
        let _ = shutdown_tx.send(());
        connection_driver.abort();
        let _ = connection_driver.await;
        return Err(error);
    }
    let response = match http::Response::builder()
        .status(http::StatusCode::NO_CONTENT)
        .body(())
    {
        Ok(response) => response,
        Err(error) => {
            let _ = shutdown_tx.send(());
            connection_driver.abort();
            let _ = connection_driver.await;
            return Err(NativeHttp2StackError::ResponseBuild(error));
        }
    };
    if let Err(error) = respond.send_response(response, true) {
        let _ = shutdown_tx.send(());
        connection_driver.abort();
        let _ = connection_driver.await;
        return Err(NativeHttp2StackError::SendResponse(error));
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
) -> Result<(), NativeHttp2StackError> {
    let mut total = 0usize;
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(NativeHttp2StackError::BodyData)?;
        let chunk_len = chunk.len();
        total = total
            .checked_add(chunk_len)
            .filter(|bytes| *bytes <= max_body_bytes)
            .ok_or(NativeHttp2StackError::BodyTooLarge {
                limit: max_body_bytes,
            })?;
        drop(chunk);
        body.flow_control()
            .release_capacity(chunk_len)
            .map_err(NativeHttp2StackError::BodyData)?;
    }
    Ok(())
}
