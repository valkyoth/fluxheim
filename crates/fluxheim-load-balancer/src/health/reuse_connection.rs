use std::io;
use std::time::Instant;

use bytes::Bytes;
use fluxheim_common::{FluxError, FluxResult};
use http::{Request, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Body;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;

use super::grpc::read_h2_health_body;
use super::{
    BoxedHealthIo, HTTP_HEALTH_CHECK_MAX_BODY_BYTES, HTTP_HEALTH_CHECK_MAX_HEADER_BYTES,
    HealthHttpRequest, HealthHttpResponse,
};

pub(super) struct AbortTask(pub(super) tokio::task::JoinHandle<()>);

impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

enum Client {
    Http(http1::SendRequest<Full<Bytes>>),
    Grpc(h2::client::SendRequest<Bytes>),
}

pub(super) struct Connection {
    client: Client,
    driver: AbortTask,
    pub(super) created: Instant,
}

pub(super) fn failure(message: &'static str) -> FluxError {
    FluxError::io("reusable health check", io::Error::other(message))
}

impl Connection {
    pub(super) async fn new(stream: BoxedHealthIo, grpc: bool) -> FluxResult<Self> {
        let (client, driver) = if grpc {
            let (client, connection) = h2::client::Builder::new()
                .enable_push(false)
                .max_header_list_size(HTTP_HEALTH_CHECK_MAX_HEADER_BYTES as u32)
                .initial_window_size(HTTP_HEALTH_CHECK_MAX_BODY_BYTES as u32)
                .initial_connection_window_size(HTTP_HEALTH_CHECK_MAX_BODY_BYTES as u32)
                .handshake(stream)
                .await
                .map_err(|_| failure("HTTP/2 handshake failed"))?;
            (
                Client::Grpc(client),
                tokio::spawn(async move {
                    let _ = connection.await;
                }),
            )
        } else {
            let (client, connection) = http1::Builder::new()
                .max_headers(64)
                .max_header_size(HTTP_HEALTH_CHECK_MAX_HEADER_BYTES)
                .max_buf_size(HTTP_HEALTH_CHECK_MAX_HEADER_BYTES)
                .handshake(TokioIo::new(stream))
                .await
                .map_err(|_| failure("HTTP/1 handshake failed"))?;
            (
                Client::Http(client),
                tokio::spawn(async move {
                    let _ = connection.await;
                }),
            )
        };
        Ok(Self {
            client,
            driver: AbortTask(driver),
            created: Instant::now(),
        })
    }

    pub(super) fn closed(&self) -> bool {
        self.driver.0.is_finished()
            || match &self.client {
                Client::Http(client) => client.is_closed(),
                Client::Grpc(_) => false,
            }
    }

    pub(super) async fn exchange(
        &mut self,
        request: &HealthHttpRequest,
        tls: bool,
        timeout: std::time::Duration,
    ) -> FluxResult<(HealthHttpResponse, Vec<u8>)> {
        let uri = if request.grpc {
            format!(
                "{}://{}{}",
                if tls { "https" } else { "http" },
                request.host,
                request.path
            )
        } else {
            request.path.clone()
        };
        let mut builder = Request::builder().method(request.method.clone()).uri(uri);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        let bytes = request.body.clone().unwrap_or_default();
        match &mut self.client {
            Client::Http(client) => {
                let outgoing = builder
                    .header(header::HOST, &request.host)
                    .body(Full::new(bytes))
                    .map_err(|_| failure("invalid probe request"))?;
                client
                    .ready()
                    .await
                    .map_err(|_| failure("HTTP/1 connection closed"))?;
                // Never retry a request: a failed exchange invalidates the entire connection.
                let response = client
                    .send_request(outgoing)
                    .await
                    .map_err(|_| failure("invalid HTTP/1 response"))?;
                if response.status().is_informational() {
                    return Err(failure("protocol upgrade is not a health response"));
                }
                let (parts, mut body) = response.into_parts();
                if body.size_hint().lower() > HTTP_HEALTH_CHECK_MAX_BODY_BYTES as u64 {
                    return Err(failure("HTTP health body exceeded maximum size"));
                }
                let mut output = Vec::new();
                while let Some(frame) = body.frame().await {
                    let frame = frame.map_err(|_| failure("invalid HTTP/1 body framing"))?;
                    if let Some(data) = frame.data_ref() {
                        if data.len()
                            > HTTP_HEALTH_CHECK_MAX_BODY_BYTES.saturating_sub(output.len())
                        {
                            return Err(failure("HTTP health body exceeded maximum size"));
                        }
                        output.extend_from_slice(data);
                    }
                    if let Some(trailers) = frame.trailers_ref() {
                        let size = trailers.iter().try_fold(0usize, |size, (name, value)| {
                            size.checked_add(name.as_str().len())?
                                .checked_add(value.len())
                        });
                        if size.is_none_or(|size| size > HTTP_HEALTH_CHECK_MAX_HEADER_BYTES) {
                            return Err(failure("HTTP health trailers exceeded maximum size"));
                        }
                    }
                }
                Ok((
                    HealthHttpResponse {
                        status: parts.status,
                        headers: parts.headers,
                    },
                    output,
                ))
            }
            Client::Grpc(client) => {
                let outgoing = builder
                    .body(())
                    .map_err(|_| failure("invalid gRPC request"))?;
                futures::future::poll_fn(|cx| client.poll_ready(cx))
                    .await
                    .map_err(|_| failure("HTTP/2 connection closed"))?;
                let (response, mut send) = client
                    .send_request(outgoing, bytes.is_empty())
                    .map_err(|_| failure("gRPC request failed"))?;
                if !bytes.is_empty() {
                    send.send_data(bytes, true)
                        .map_err(|_| failure("gRPC body failed"))?;
                }
                drop(send);
                let response = response
                    .await
                    .map_err(|_| failure("gRPC response failed"))?;
                let (parts, body) = response.into_parts();
                let body = read_h2_health_body(body, timeout).await?;
                Ok((
                    HealthHttpResponse {
                        status: parts.status,
                        headers: parts.headers,
                    },
                    body,
                ))
            }
        }
    }
}
