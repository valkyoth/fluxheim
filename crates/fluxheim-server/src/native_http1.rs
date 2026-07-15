use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use fluxheim_protocol::{
    Http1BodyFraming, Http1ConnectionDirective, Http1HeadLimits, Http1Header, Http1ParseError,
    parse_http1_request_head,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::time::timeout;
use zeroize::Zeroizing;

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
use crate::DownstreamHttp2Policy;
use crate::{DownstreamHttp1Policy, ProxyProtocolPolicy};

const READ_CHUNK_BYTES: usize = 8192;

mod body;
mod connection_tasks;
mod listener;
#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
mod openssl_listener;
mod proxy_protocol;
mod request;
mod response;
#[cfg(feature = "tls-rustls-backend")]
mod rustls_listener;
use body::read_body;
#[cfg(unix)]
pub use listener::serve_native_http1_unix_listener;
pub use listener::{serve_native_http1_listener, serve_native_http1_listener_with_proxy_protocol};
#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
pub use openssl_listener::{
    serve_native_http1_and_http2_openssl_listener, serve_native_http1_openssl_listener,
};
use proxy_protocol::read_proxy_protocol_source;
pub use request::{
    NativeHttp1GeoContext, NativeHttp1Request, NativeHttp1RequestContext,
    NativeHttp1TlsClientIdentity,
};
use response::write_response;
pub use response::{NativeHttp1Response, NativeHttp1ResponseWritePolicy};
#[cfg(feature = "tls-rustls-backend")]
pub use rustls_listener::{
    serve_native_http1_and_http2_rustls_listener, serve_native_http1_rustls_listener,
};

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeTlsHttp2Dispatch {
    pub(crate) policy: DownstreamHttp2Policy,
    pub(crate) http1_allowed: bool,
    pub(crate) http2_allowed: bool,
}

#[derive(Debug)]
pub enum NativeHttp1Error {
    Io(std::io::Error),
    Parse(Http1ParseError),
}

impl std::fmt::Display for NativeHttp1Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "HTTP/1 IO error: {error}"),
            Self::Parse(error) => write!(formatter, "HTTP/1 parse error: {error:?}"),
        }
    }
}

impl std::error::Error for NativeHttp1Error {}

impl From<std::io::Error> for NativeHttp1Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<Http1ParseError> for NativeHttp1Error {
    fn from(error: Http1ParseError) -> Self {
        Self::Parse(error)
    }
}

pub trait NativeHttp1ConnectionIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> NativeHttp1ConnectionIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type NativeHttp1ConnectionStream = Box<dyn NativeHttp1ConnectionIo>;

pub trait NativeHttp1Handler: Send + Sync + 'static {
    fn pin_request_handler(&self) -> Option<Arc<dyn NativeHttp1Handler>> {
        None
    }

    fn request_body_budget(&self) -> crate::NativeRequestBodyBudget {
        crate::NativeRequestBodyBudget::default()
    }

    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp1Response> + Send + 'a>>;

    fn handles_connection_takeover(&self, _request: &NativeHttp1Request) -> bool {
        false
    }

    fn handle_connection_takeover<'a>(
        &'a self,
        _request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        mut stream: NativeHttp1ConnectionStream,
    ) -> Pin<Box<dyn Future<Output = Result<(), NativeHttp1Error>> + Send + 'a>> {
        Box::pin(async move {
            drop(prebuffered);
            write_response(
                &mut stream,
                NativeHttp1Response::new(
                    501,
                    "Not Implemented",
                    b"connection takeover unsupported\n",
                )
                .close_connection(),
                true,
            )
            .await
        })
    }

    fn prepare_request_context(&self, _request: &mut NativeHttp1Request) {}

    fn request_body_timeout(&self, _request: &NativeHttp1Request) -> Option<Duration> {
        None
    }
}

impl<F, Fut> NativeHttp1Handler for F
where
    F: Fn(NativeHttp1Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = NativeHttp1Response> + Send + 'static,
{
    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp1Response> + Send + 'a>> {
        Box::pin(self(request))
    }
}

pub async fn serve_native_http1_connection<S, H>(
    stream: S,
    peer_addr: Option<SocketAddr>,
    policy: DownstreamHttp1Policy,
    handler: Arc<H>,
) -> Result<(), NativeHttp1Error>
where
    S: NativeHttp1ConnectionIo + 'static,
    H: NativeHttp1Handler,
{
    serve_native_http1_connection_with_context(
        stream,
        peer_addr,
        NativeHttp1RequestContext::default(),
        policy,
        handler,
    )
    .await
}

pub(super) async fn serve_native_http1_connection_with_context<S, H>(
    mut stream: S,
    peer_addr: Option<SocketAddr>,
    request_context: NativeHttp1RequestContext,
    policy: DownstreamHttp1Policy,
    handler: Arc<H>,
) -> Result<(), NativeHttp1Error>
where
    S: NativeHttp1ConnectionIo + 'static,
    H: NativeHttp1Handler,
{
    let limits = Http1HeadLimits::from(policy);
    let mut buffer = Vec::with_capacity(READ_CHUNK_BYTES);

    loop {
        let head_result = timeout(
            policy.request_head_timeout(),
            read_until_head(&mut stream, &mut buffer, limits),
        )
        .await
        .map_err(|_| {
            NativeHttp1Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "request head timeout",
            ))
        })?;
        let Some(head_len) = (match head_result {
            Ok(head_len) => head_len,
            Err(NativeHttp1Error::Parse(error)) => {
                write_request_head_error(&mut stream, &error).await?;
                return Ok(());
            }
            Err(error) => return Err(error),
        }) else {
            return Ok(());
        };
        let (close_after_response, body_framing, request) = {
            let head = match parse_http1_request_head(&buffer, limits)? {
                Some(head) => head,
                None => return Ok(()),
            };
            (
                head.connection_directive() == Http1ConnectionDirective::Close,
                head.body_framing(),
                owned_request_from_head(&head, peer_addr, &request_context),
            )
        };
        let pinned_handler = handler.pin_request_handler();
        let request_handler = pinned_handler
            .as_deref()
            .unwrap_or_else(|| handler.as_ref());
        let request_body_budget = request_handler.request_body_budget();
        let request_body_timeout = request_handler
            .request_body_timeout(&request)
            .unwrap_or(policy.request_body_timeout());
        let reservation_bytes = match body_framing {
            Http1BodyFraming::NoBody => 0,
            Http1BodyFraming::ContentLength(length) => {
                let Ok(length) = usize::try_from(length) else {
                    write_response(
                        &mut stream,
                        NativeHttp1Response::new(413, "Payload Too Large", b"payload too large\n")
                            .close_connection(),
                        true,
                    )
                    .await?;
                    return Ok(());
                };
                length
            }
            Http1BodyFraming::Chunked => 0,
        };
        let mut request_body_reservation =
            match request_body_budget.reserve(reservation_bytes).await {
                Ok(reservation) => reservation,
                Err(_) => {
                    write_response(
                        &mut stream,
                        NativeHttp1Response::new(
                            503,
                            "Service Unavailable",
                            b"request body capacity unavailable\n",
                        )
                        .with_retry_after_secs(1)
                        .close_connection(),
                        true,
                    )
                    .await?;
                    return Ok(());
                }
            };
        let body = match read_body(
            policy,
            request_body_timeout,
            &mut stream,
            &mut buffer,
            head_len,
            body_framing,
            &mut request_body_reservation,
        )
        .await
        {
            Ok(body) => body,
            Err(NativeHttp1Error::Parse(Http1ParseError::BodyTooLarge)) => {
                write_response(
                    &mut stream,
                    NativeHttp1Response::new(413, "Payload Too Large", b"payload too large\n")
                        .close_connection(),
                    true,
                )
                .await?;
                return Ok(());
            }
            Err(NativeHttp1Error::Parse(error)) => {
                write_response(
                    &mut stream,
                    NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                        .close_connection(),
                    true,
                )
                .await?;
                return Err(error.into());
            }
            Err(NativeHttp1Error::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut => {
                write_response(
                    &mut stream,
                    NativeHttp1Response::new(408, "Request Timeout", b"request timeout\n")
                        .close_connection(),
                    true,
                )
                .await?;
                return Ok(());
            }
            Err(NativeHttp1Error::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                write_response(
                    &mut stream,
                    NativeHttp1Response::new(
                        503,
                        "Service Unavailable",
                        b"request body capacity unavailable\n",
                    )
                    .with_retry_after_secs(1)
                    .close_connection(),
                    true,
                )
                .await?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let mut request = request;
        request.body = Zeroizing::new(body);
        request_handler.prepare_request_context(&mut request);
        if request_handler.handles_connection_takeover(&request) {
            let prebuffered = std::mem::take(&mut buffer);
            let stream = Box::new(stream);
            return request_handler
                .handle_connection_takeover(request, prebuffered, stream)
                .await;
        }

        let response = request_handler.handle(request).await;
        let should_close = close_after_response || response.close_requested();
        write_response(&mut stream, response, should_close).await?;
        if should_close {
            return Ok(());
        }
    }
}

pub(super) async fn serve_native_http1_proxy_protocol_connection<S, H>(
    mut stream: S,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    proxy_protocol: ProxyProtocolPolicy,
    policy: DownstreamHttp1Policy,
    handler: Arc<H>,
) -> Result<(), NativeHttp1Error>
where
    S: NativeHttp1ConnectionIo + 'static,
    H: NativeHttp1Handler,
{
    let source = timeout(
        policy.request_head_timeout(),
        read_proxy_protocol_source(&mut stream, &proxy_protocol, peer_addr),
    )
    .await
    .map_err(|_| {
        NativeHttp1Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "PROXY protocol header timeout",
        ))
    })??;
    let request_context = NativeHttp1RequestContext {
        local_addr,
        effective_client_addr: source,
        ..NativeHttp1RequestContext::default()
    };
    serve_native_http1_connection_with_context(
        stream,
        Some(peer_addr),
        request_context,
        policy,
        handler,
    )
    .await
}

async fn write_request_head_error<S>(
    stream: &mut S,
    error: &Http1ParseError,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    let response = match error {
        Http1ParseError::HeaderCountExceeded
        | Http1ParseError::HeaderLineTooLong
        | Http1ParseError::HeadTooLarge => NativeHttp1Response::new(
            431,
            "Request Header Fields Too Large",
            b"request header fields too large\n",
        ),
        Http1ParseError::StartLineTooLong => {
            NativeHttp1Response::new(414, "URI Too Long", b"uri too long\n")
        }
        _ => NativeHttp1Response::new(400, "Bad Request", b"bad request\n"),
    }
    .close_connection();
    write_response(stream, response, true).await
}

async fn read_until_head<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    limits: Http1HeadLimits,
) -> Result<Option<usize>, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    loop {
        match parse_http1_request_head(buffer, limits) {
            Ok(Some(head)) => return Ok(Some(head.head_len())),
            Ok(None) => {}
            Err(error) => return Err(error.into()),
        }
        if buffer.len() >= limits.max_head_bytes {
            return Err(Http1ParseError::HeadTooLarge.into());
        }
        let mut chunk = [0u8; READ_CHUNK_BYTES];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn owned_request_from_head(
    head: &fluxheim_protocol::ValidatedHttp1RequestHead<'_>,
    peer_addr: Option<SocketAddr>,
    request_context: &NativeHttp1RequestContext,
) -> NativeHttp1Request {
    NativeHttp1Request {
        method: head.method().to_owned(),
        peer_addr,
        local_addr: request_context.local_addr,
        effective_client_addr: request_context.effective_client_addr,
        downstream_tls: request_context.downstream_tls,
        tls_identity: request_context.tls_identity.clone(),
        geo_context: request_context.geo_context.clone(),
        target: head.target().to_owned(),
        version: head.version(),
        headers: owned_headers(head.headers(), head.effective_authority()),
        body: Zeroizing::new(Vec::new()),
        trailers: Vec::new(),
    }
}

fn owned_headers(
    headers: &[Http1Header<'_>],
    effective_authority: Option<&str>,
) -> Vec<(String, String)> {
    let mut owned = headers
        .iter()
        .filter(|header| !header.name().eq_ignore_ascii_case("host"))
        .map(|header| (header.name().to_owned(), header.value().to_owned()))
        .collect::<Vec<_>>();
    if let Some(authority) = effective_authority {
        owned.push(("host".to_owned(), authority.to_owned()));
    }
    owned
}

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
pub(super) fn sha256_hex(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(input);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
