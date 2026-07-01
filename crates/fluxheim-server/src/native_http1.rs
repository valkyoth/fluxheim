use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use fluxheim_protocol::{
    Http1BodyFraming, Http1ConnectionDirective, Http1HeadLimits, Http1Header, Http1ParseError,
    Http1Version, decode_http1_chunked_body, parse_http1_request_head,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;
#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
use tokio_openssl::SslStream;
#[cfg(feature = "tls-rustls-backend")]
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
use crate::DownstreamHttp2Policy;
use crate::{DownstreamHttp1Policy, ProxyProtocolPolicy};

const READ_CHUNK_BYTES: usize = 8192;

mod proxy_protocol;
mod request;
mod response;
use proxy_protocol::read_proxy_protocol_source;
pub use request::{
    NativeHttp1GeoContext, NativeHttp1Request, NativeHttp1RequestContext,
    NativeHttp1TlsClientIdentity,
};
use response::write_response;
pub use response::{NativeHttp1Response, NativeHttp1ResponseWritePolicy};

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

async fn serve_native_http1_connection_with_context<S, H>(
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
        let Some(head_len) = timeout(
            policy.request_head_timeout(),
            read_until_head(&mut stream, &mut buffer, limits),
        )
        .await
        .map_err(|_| {
            NativeHttp1Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "request head timeout",
            ))
        })??
        else {
            return Ok(());
        };
        let (close_after_response, body_framing, request) = {
            let head = match parse_http1_request_head(&buffer, limits)? {
                Some(head) => head,
                None => return Ok(()),
            };
            let close_after_response = match head.connection_directive() {
                Ok(directive) => directive == Http1ConnectionDirective::Close,
                Err(error) => {
                    write_bad_request(&mut stream).await?;
                    return Err(error.into());
                }
            };
            if head.version == Http1Version::Http11
                && let Err(error) = head.host()
            {
                write_bad_request(&mut stream).await?;
                return Err(error.into());
            }
            let body_framing = match head.body_framing() {
                Ok(framing) => framing,
                Err(error) => {
                    write_bad_request(&mut stream).await?;
                    return Err(error.into());
                }
            };
            (
                close_after_response,
                body_framing,
                owned_request_from_head(&head, peer_addr, &request_context),
            )
        };
        let request_body_timeout = handler
            .request_body_timeout(&request)
            .unwrap_or(policy.request_body_timeout());
        let body = match read_body(
            policy,
            request_body_timeout,
            &mut stream,
            &mut buffer,
            head_len,
            body_framing,
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
            Err(error) => return Err(error),
        };
        let mut request = request;
        request.body = Zeroizing::new(body);
        handler.prepare_request_context(&mut request);
        if handler.handles_connection_takeover(&request) {
            let prebuffered = std::mem::take(&mut buffer);
            let stream = Box::new(stream);
            return handler
                .handle_connection_takeover(request, prebuffered, stream)
                .await;
        }

        let response = handler.handle(request).await;
        let should_close = close_after_response || response.close_requested();
        write_response(&mut stream, response, should_close).await?;
        if should_close {
            return Ok(());
        }
    }
}

pub async fn serve_native_http1_listener<H, F>(
    listener: TcpListener,
    policy: DownstreamHttp1Policy,
    handler: Arc<H>,
    shutdown: F,
) -> Result<(), NativeHttp1Error>
where
    H: NativeHttp1Handler,
    F: Future<Output = ()> + Send,
{
    let semaphore = Arc::new(Semaphore::new(policy.max_connections()));
    let local_addr = listener.local_addr().ok();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted?;
                let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                    log::warn!(
                        target: "fluxheim::native_http1",
                        "HTTP/1 connection rejected: listener at capacity; peer={peer_addr}; limit={}",
                        policy.max_connections());
                    continue;
                };
                let handler = handler.clone();
                tokio::spawn(async move {
                    let request_context = NativeHttp1RequestContext {
                        local_addr,
                        ..NativeHttp1RequestContext::default()
                    };
                    let _ = serve_native_http1_connection_with_context(stream, Some(peer_addr), request_context, policy, handler).await;
                    drop(permit);
                });
            }
        }
    }
}

pub async fn serve_native_http1_listener_with_proxy_protocol<H, F>(
    listener: TcpListener,
    policy: DownstreamHttp1Policy,
    proxy_protocol: ProxyProtocolPolicy,
    handler: Arc<H>,
    shutdown: F,
) -> Result<(), NativeHttp1Error>
where
    H: NativeHttp1Handler,
    F: Future<Output = ()> + Send,
{
    let semaphore = Arc::new(Semaphore::new(policy.max_connections()));
    let local_addr = listener.local_addr().ok();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted?;
                let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                    log::warn!(
                        target: "fluxheim::native_http1",
                        "HTTP/1 PROXY-protocol connection rejected: listener at capacity; peer={peer_addr}; limit={}",
                        policy.max_connections());
                    continue;
                };
                let handler = handler.clone();
                let proxy_protocol = proxy_protocol.clone();
                tokio::spawn(async move {
                    let result = serve_native_http1_proxy_protocol_connection(
                        stream,
                        peer_addr,
                        local_addr,
                        proxy_protocol,
                        policy,
                        handler,
                    )
                    .await;
                    if let Err(error) = result {
                        log::debug!(
                            target: "fluxheim::native_http1",
                            "HTTP/1 PROXY-protocol connection failed; peer={peer_addr}; error={error}"
                        );
                    }
                    drop(permit);
                });
            }
        }
    }
}

#[cfg(unix)]
pub async fn serve_native_http1_unix_listener<H, F>(
    listener: UnixListener,
    policy: DownstreamHttp1Policy,
    handler: Arc<H>,
    shutdown: F,
) -> Result<(), NativeHttp1Error>
where
    H: NativeHttp1Handler,
    F: Future<Output = ()> + Send,
{
    let semaphore = Arc::new(Semaphore::new(policy.max_connections()));
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                    log::warn!(
                        target: "fluxheim::native_http1",
                        "HTTP/1 Unix listener connection rejected: listener at capacity; limit={}",
                        policy.max_connections());
                    continue;
                };
                let handler = handler.clone();
                tokio::spawn(async move {
                    let request_context = NativeHttp1RequestContext::default();
                    let _ = serve_native_http1_connection_with_context(
                        stream,
                        None,
                        request_context,
                        policy,
                        handler,
                    )
                    .await;
                    drop(permit);
                });
            }
        }
    }
}

#[cfg(feature = "tls-rustls-backend")]
pub async fn serve_native_http1_rustls_listener<H, F>(
    listener: TcpListener,
    policy: DownstreamHttp1Policy,
    tls_config: Arc<rustls::ServerConfig>,
    handler: Arc<H>,
    shutdown: F,
) -> Result<(), NativeHttp1Error>
where
    H: NativeHttp1Handler,
    F: Future<Output = ()> + Send,
{
    let acceptor = TlsAcceptor::from(tls_config);
    let semaphore = Arc::new(Semaphore::new(policy.max_connections()));
    let local_addr = listener.local_addr().ok();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted?;
                let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                    log::warn!(
                        target: "fluxheim::native_http1",
                        "HTTPS HTTP/1 connection rejected: listener at capacity; peer={peer_addr}; limit={}",
                        policy.max_connections());
                    continue;
                };
                let acceptor = acceptor.clone();
                let handler = handler.clone();
                tokio::spawn(async move {
                    let handshake = timeout(policy.tls_handshake_timeout(), acceptor.accept(stream)).await;
                    match handshake {
                        Ok(Ok(stream)) => {
                            let mut request_context = native_rustls_request_context(&stream);
                            request_context.local_addr = local_addr;
                            let _ = serve_native_http1_connection_with_context(stream, Some(peer_addr), request_context, policy, handler).await;
                        }
                        Ok(Err(error)) => {
                            log::debug!(
                                target: "fluxheim::native_http1",
                                "HTTPS HTTP/1 TLS handshake failed; peer={peer_addr}; error={error}"
                            );
                        }
                        Err(_) => {
                            log::debug!(
                                target: "fluxheim::native_http1",
                                "HTTPS HTTP/1 TLS handshake timed out; peer={peer_addr}; timeout_secs={}",
                                policy.tls_handshake_timeout().as_secs()
                            );
                        }
                    }
                    drop(permit);
                });
            }
        }
    }
}

#[cfg(feature = "tls-rustls-backend")]
pub async fn serve_native_http1_and_http2_rustls_listener<H, F>(
    listener: TcpListener,
    http1_policy: DownstreamHttp1Policy,
    tls_config: Arc<rustls::ServerConfig>,
    h2_dispatch: NativeTlsHttp2Dispatch,
    handler: Arc<H>,
    shutdown: F,
) -> Result<(), NativeHttp1Error>
where
    H: NativeHttp1Handler,
    F: Future<Output = ()> + Send,
{
    let acceptor = TlsAcceptor::from(tls_config);
    let semaphore = Arc::new(Semaphore::new(http1_policy.max_connections()));
    let local_addr = listener.local_addr().ok();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted?;
                let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                    log::warn!(
                        target: "fluxheim::native_http1",
                        "HTTPS connection rejected: listener at capacity; peer={peer_addr}; limit={}",
                        http1_policy.max_connections());
                    continue;
                };
                let acceptor = acceptor.clone();
                let handler = handler.clone();
                tokio::spawn(async move {
                    let handshake = timeout(http1_policy.tls_handshake_timeout(), acceptor.accept(stream)).await;
                    match handshake {
                        Ok(Ok(stream)) => {
                            let mut request_context = native_rustls_request_context(&stream);
                            request_context.local_addr = local_addr;
                            match stream.get_ref().1.alpn_protocol() {
                                Some(b"h2") if h2_dispatch.http2_allowed => {
                                    let h2_handler = Arc::new(crate::NativeHttp2RouteAdapter::new(
                                        handler,
                                        Some(peer_addr),
                                        request_context,
                                    ));
                                    if let Err(error) = crate::serve_native_http2_connection(
                                        stream,
                                        h2_dispatch.policy,
                                        h2_handler,
                                    )
                                    .await
                                    {
                                        log::debug!(
                                            target: "fluxheim::native_http2",
                                            "HTTPS HTTP/2 connection failed; peer={peer_addr}; error={error}"
                                        );
                                    }
                                }
                                Some(b"http/1.1") | None if h2_dispatch.http1_allowed => {
                                    let _ = serve_native_http1_connection_with_context(stream, Some(peer_addr), request_context, http1_policy, handler).await;
                                }
                                selected => {
                                    log::debug!(
                                        target: "fluxheim::native_http1",
                                        "HTTPS connection negotiated unsupported ALPN; peer={peer_addr}; alpn={selected:?}"
                                    );
                                }
                            }
                        }
                        Ok(Err(error)) => {
                            log::debug!(
                                target: "fluxheim::native_http1",
                                "HTTPS TLS handshake failed; peer={peer_addr}; error={error}"
                            );
                        }
                        Err(_) => {
                            log::debug!(
                                target: "fluxheim::native_http1",
                                "HTTPS TLS handshake timed out; peer={peer_addr}; timeout_secs={}",
                                http1_policy.tls_handshake_timeout().as_secs()
                            );
                        }
                    }
                    drop(permit);
                });
            }
        }
    }
}

async fn serve_native_http1_proxy_protocol_connection<S, H>(
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

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
pub async fn serve_native_http1_openssl_listener<H, F>(
    listener: TcpListener,
    policy: DownstreamHttp1Policy,
    acceptor: Arc<openssl::ssl::SslAcceptor>,
    handler: Arc<H>,
    shutdown: F,
) -> Result<(), NativeHttp1Error>
where
    H: NativeHttp1Handler,
    F: Future<Output = ()> + Send,
{
    let semaphore = Arc::new(Semaphore::new(policy.max_connections()));
    let local_addr = listener.local_addr().ok();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted?;
                let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                    log::warn!(
                        target: "fluxheim::native_http1",
                        "HTTPS HTTP/1 connection rejected: listener at capacity; peer={peer_addr}; limit={}",
                        policy.max_connections());
                    continue;
                };
                let acceptor = acceptor.clone();
                let handler = handler.clone();
                tokio::spawn(async move {
                    let stream = match native_openssl_server_stream(&acceptor, stream) {
                        Ok(stream) => stream,
                        Err(error) => {
                            log::debug!(
                                target: "fluxheim::native_http1",
                                "HTTPS HTTP/1 OpenSSL stream setup failed; peer={peer_addr}; error={error}"
                            );
                            drop(permit);
                            return;
                        }
                    };
                    let mut stream = stream;
                    let handshake =
                        timeout(policy.tls_handshake_timeout(), std::pin::Pin::new(&mut stream).accept())
                            .await;
                    match handshake {
                        Ok(Ok(())) => {
                            let mut request_context = native_openssl_request_context(&stream);
                            request_context.local_addr = local_addr;
                            let _ = serve_native_http1_connection_with_context(stream, Some(peer_addr), request_context, policy, handler).await;
                        }
                        Ok(Err(error)) => {
                            log::debug!(
                                target: "fluxheim::native_http1",
                                "HTTPS HTTP/1 TLS handshake failed; peer={peer_addr}; error={error}"
                            );
                        }
                        Err(_) => {
                            log::debug!(
                                target: "fluxheim::native_http1",
                                "HTTPS HTTP/1 TLS handshake timed out; peer={peer_addr}; timeout_secs={}",
                                policy.tls_handshake_timeout().as_secs()
                            );
                        }
                    }
                    drop(permit);
                });
            }
        }
    }
}

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
pub async fn serve_native_http1_and_http2_openssl_listener<H, F>(
    listener: TcpListener,
    http1_policy: DownstreamHttp1Policy,
    acceptor: Arc<openssl::ssl::SslAcceptor>,
    h2_dispatch: NativeTlsHttp2Dispatch,
    handler: Arc<H>,
    shutdown: F,
) -> Result<(), NativeHttp1Error>
where
    H: NativeHttp1Handler,
    F: Future<Output = ()> + Send,
{
    let semaphore = Arc::new(Semaphore::new(http1_policy.max_connections()));
    let local_addr = listener.local_addr().ok();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted?;
                let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                    log::warn!(
                        target: "fluxheim::native_http1",
                        "HTTPS connection rejected: listener at capacity; peer={peer_addr}; limit={}",
                        http1_policy.max_connections());
                    continue;
                };
                let acceptor = acceptor.clone();
                let handler = handler.clone();
                tokio::spawn(async move {
                    let stream = match native_openssl_server_stream(&acceptor, stream) {
                        Ok(stream) => stream,
                        Err(error) => {
                            log::debug!(
                                target: "fluxheim::native_http1",
                                "HTTPS OpenSSL stream setup failed; peer={peer_addr}; error={error}"
                            );
                            drop(permit);
                            return;
                        }
                    };
                    let mut stream = stream;
                    let handshake =
                        timeout(http1_policy.tls_handshake_timeout(), std::pin::Pin::new(&mut stream).accept())
                            .await;
                    match handshake {
                        Ok(Ok(())) => {
                            let mut request_context = native_openssl_request_context(&stream);
                            request_context.local_addr = local_addr;
                            match stream.ssl().selected_alpn_protocol() {
                                Some(b"h2") if h2_dispatch.http2_allowed => {
                                    let h2_handler = Arc::new(crate::NativeHttp2RouteAdapter::new(
                                        handler,
                                        Some(peer_addr),
                                        request_context,
                                    ));
                                    if let Err(error) = crate::serve_native_http2_connection(
                                        stream,
                                        h2_dispatch.policy,
                                        h2_handler,
                                    )
                                    .await
                                    {
                                        log::debug!(
                                            target: "fluxheim::native_http2",
                                            "HTTPS HTTP/2 connection failed; peer={peer_addr}; error={error}"
                                        );
                                    }
                                }
                                Some(b"http/1.1") | None if h2_dispatch.http1_allowed => {
                                    let _ = serve_native_http1_connection_with_context(stream, Some(peer_addr), request_context, http1_policy, handler).await;
                                }
                                selected => {
                                    log::debug!(
                                        target: "fluxheim::native_http1",
                                        "HTTPS connection negotiated unsupported ALPN; peer={peer_addr}; alpn={selected:?}"
                                    );
                                }
                            }
                        }
                        Ok(Err(error)) => {
                            log::debug!(
                                target: "fluxheim::native_http1",
                                "HTTPS TLS handshake failed; peer={peer_addr}; error={error}"
                            );
                        }
                        Err(_) => {
                            log::debug!(
                                target: "fluxheim::native_http1",
                                "HTTPS TLS handshake timed out; peer={peer_addr}; timeout_secs={}",
                                http1_policy.tls_handshake_timeout().as_secs()
                            );
                        }
                    }
                    drop(permit);
                });
            }
        }
    }
}

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
fn native_openssl_server_stream(
    acceptor: &openssl::ssl::SslAcceptor,
    stream: tokio::net::TcpStream,
) -> Result<SslStream<tokio::net::TcpStream>, openssl::error::ErrorStack> {
    let ssl = openssl::ssl::Ssl::new(acceptor.context())?;
    SslStream::new(ssl, stream)
}

async fn write_bad_request<S>(stream: &mut S) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    write_response(
        stream,
        NativeHttp1Response::new(400, "Bad Request", b"bad request\n").close_connection(),
        true,
    )
    .await
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
            Ok(Some(head)) => return Ok(Some(head.head_len)),
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
    head: &fluxheim_protocol::Http1RequestHead<'_>,
    peer_addr: Option<SocketAddr>,
    request_context: &NativeHttp1RequestContext,
) -> NativeHttp1Request {
    NativeHttp1Request {
        method: head.method.to_owned(),
        peer_addr,
        local_addr: request_context.local_addr,
        effective_client_addr: request_context.effective_client_addr,
        downstream_tls: request_context.downstream_tls,
        tls_identity: request_context.tls_identity.clone(),
        geo_context: request_context.geo_context.clone(),
        target: head.target.to_owned(),
        version: head.version,
        headers: owned_headers(&head.headers),
        body: Zeroizing::new(Vec::new()),
        trailers: Vec::new(),
    }
}

fn owned_headers(headers: &[Http1Header<'_>]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|header| (header.name.to_owned(), header.value.to_owned()))
        .collect()
}

#[cfg(feature = "tls-rustls-backend")]
fn native_rustls_request_context<S>(
    stream: &tokio_rustls::server::TlsStream<S>,
) -> NativeHttp1RequestContext {
    let (_, connection) = stream.get_ref();
    NativeHttp1RequestContext {
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: true,
        tls_identity: Some(NativeHttp1TlsClientIdentity {
            cipher: connection
                .negotiated_cipher_suite()
                .map(|suite| format!("{:?}", suite.suite())),
            version: connection
                .protocol_version()
                .map(|version| format!("{version:?}")),
            organization: None,
            serial_number: None,
            cert_sha256: connection
                .peer_certificates()
                .and_then(|certificates| certificates.first())
                .map(|certificate| sha256_hex(certificate.as_ref())),
        }),
        geo_context: None,
    }
}

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
fn native_openssl_request_context<S>(stream: &SslStream<S>) -> NativeHttp1RequestContext {
    let ssl = stream.ssl();
    let peer_certificate = ssl.peer_certificate();
    NativeHttp1RequestContext {
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: true,
        tls_identity: Some(NativeHttp1TlsClientIdentity {
            cipher: ssl.current_cipher().map(|cipher| cipher.name().to_owned()),
            version: Some(ssl.version_str().to_owned()),
            organization: peer_certificate
                .as_ref()
                .and_then(openssl_certificate_organization),
            serial_number: peer_certificate
                .as_ref()
                .and_then(openssl_certificate_serial),
            cert_sha256: peer_certificate
                .as_ref()
                .and_then(|certificate| certificate.to_der().ok())
                .map(|der| sha256_hex(&der)),
        }),
        geo_context: None,
    }
}

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
fn openssl_certificate_organization(certificate: &openssl::x509::X509) -> Option<String> {
    certificate
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::ORGANIZATIONNAME)
        .next()
        .and_then(|entry| entry.data().to_string().ok())
}

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
fn openssl_certificate_serial(certificate: &openssl::x509::X509) -> Option<String> {
    certificate
        .serial_number()
        .to_bn()
        .ok()
        .and_then(|serial| serial.to_hex_str().ok())
        .map(|serial| serial.to_string())
}

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
fn sha256_hex(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(input);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

async fn read_body<S>(
    policy: DownstreamHttp1Policy,
    request_body_timeout: Duration,
    stream: &mut S,
    buffer: &mut Vec<u8>,
    head_len: usize,
    framing: Http1BodyFraming,
) -> Result<Vec<u8>, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    timeout(
        request_body_timeout,
        read_body_inner(stream, buffer, head_len, framing, policy.max_body_bytes()),
    )
    .await
    .map_err(|_| {
        NativeHttp1Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "request body timeout",
        ))
    })?
}

async fn read_body_inner<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    head_len: usize,
    framing: Http1BodyFraming,
    max_body_bytes: usize,
) -> Result<Vec<u8>, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    match framing {
        Http1BodyFraming::NoBody => {
            buffer.drain(..head_len);
            Ok(Vec::new())
        }
        Http1BodyFraming::ContentLength(length) => {
            let length = usize::try_from(length).map_err(|_| Http1ParseError::BodyTooLarge)?;
            if length > max_body_bytes {
                return Err(Http1ParseError::BodyTooLarge.into());
            }
            let required = head_len
                .checked_add(length)
                .ok_or(Http1ParseError::BodyTooLarge)?;
            while buffer.len() < required {
                let mut chunk = [0u8; READ_CHUNK_BYTES];
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    return Err(Http1ParseError::InvalidContentLength.into());
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            let body = buffer[head_len..required].to_vec();
            buffer.drain(..required);
            Ok(body)
        }
        Http1BodyFraming::Chunked => {
            read_chunked_body(stream, buffer, head_len, max_body_bytes).await
        }
    }
}

async fn read_chunked_body<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    head_len: usize,
    max_body_bytes: usize,
) -> Result<Vec<u8>, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    buffer.drain(..head_len);
    loop {
        let limits = fluxheim_protocol::Http1ChunkLimits {
            max_body_bytes,
            ..fluxheim_protocol::Http1ChunkLimits::default()
        };
        let mut output = vec![0u8; buffer.len().min(max_body_bytes)];
        match decode_http1_chunked_body(buffer, &mut output, limits) {
            Ok(Some(decoded)) => {
                let body = output[..decoded.decoded_len].to_vec();
                buffer.drain(..decoded.consumed_len);
                return Ok(body);
            }
            Ok(None) => {}
            Err(Http1ParseError::OutputTooSmall) => {
                return Err(Http1ParseError::BodyTooLarge.into());
            }
            Err(error) => return Err(error.into()),
        }
        if buffer.len() >= max_body_bytes {
            return Err(Http1ParseError::BodyTooLarge.into());
        }
        let mut chunk = [0u8; READ_CHUNK_BYTES];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(Http1ParseError::InvalidChunk.into());
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}
