use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fluxheim_protocol::{
    Http1BodyFraming, Http1ConnectionDirective, Http1HeadLimits, Http1Header, Http1ParseError,
    Http1Version, decode_http1_chunked_body, http_token_valid, parse_http1_request_head,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;
#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
use tokio_openssl::SslStream;
#[cfg(feature = "tls-rustls-backend")]
use tokio_rustls::TlsAcceptor;

use crate::DownstreamHttp1Policy;

const READ_CHUNK_BYTES: usize = 8192;
const WRITE_CHUNK_BYTES: usize = 8192;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1Request {
    pub method: String,
    pub peer_addr: Option<SocketAddr>,
    pub downstream_tls: bool,
    pub target: String,
    pub version: Http1Version,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1Response {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    content_length: Option<u64>,
    body: Vec<u8>,
    close: bool,
    write_policy: NativeHttp1ResponseWritePolicy,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeHttp1ResponseWritePolicy {
    write_timeout: Option<Duration>,
    total_response_timeout: Option<Duration>,
    min_send_rate_bytes_per_sec: Option<usize>,
}

impl NativeHttp1Response {
    pub fn new(status: u16, reason: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            reason: reason.into(),
            headers: Vec::new(),
            content_length: None,
            body: body.into(),
            close: false,
            write_policy: NativeHttp1ResponseWritePolicy::default(),
        }
    }

    pub const fn with_content_length(mut self, content_length: u64) -> Self {
        self.content_length = Some(content_length);
        self
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub const fn close_connection(mut self) -> Self {
        self.close = true;
        self
    }

    pub const fn with_write_policy(mut self, policy: NativeHttp1ResponseWritePolicy) -> Self {
        self.write_policy = policy;
        self
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    pub(crate) fn remove_header(&mut self, name: &str) {
        self.headers
            .retain(|(header_name, _)| !header_name.eq_ignore_ascii_case(name));
    }

    pub(crate) fn push_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.push((name.into(), value.into()));
    }

    pub const fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    pub(crate) fn replace_body(&mut self, body: impl Into<Vec<u8>>) {
        self.body = body.into();
        self.content_length = None;
    }
}

impl NativeHttp1ResponseWritePolicy {
    pub const fn new(
        write_timeout: Option<Duration>,
        total_response_timeout: Option<Duration>,
        min_send_rate_bytes_per_sec: Option<usize>,
    ) -> Self {
        Self {
            write_timeout,
            total_response_timeout,
            min_send_rate_bytes_per_sec,
        }
    }

    pub const fn write_timeout(self) -> Option<Duration> {
        self.write_timeout
    }

    pub const fn total_response_timeout(self) -> Option<Duration> {
        self.total_response_timeout
    }

    pub const fn min_send_rate_bytes_per_sec(self) -> Option<usize> {
        self.min_send_rate_bytes_per_sec
    }
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

pub trait NativeHttp1Handler: Send + Sync + 'static {
    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp1Response> + Send + 'a>>;

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
    S: AsyncRead + AsyncWrite + Unpin,
    H: NativeHttp1Handler,
{
    serve_native_http1_connection_with_tls(stream, peer_addr, false, policy, handler).await
}

async fn serve_native_http1_connection_with_tls<S, H>(
    mut stream: S,
    peer_addr: Option<SocketAddr>,
    downstream_tls: bool,
    policy: DownstreamHttp1Policy,
    handler: Arc<H>,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
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
                owned_request_from_head(&head, peer_addr, downstream_tls),
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
            Err(error) => return Err(error),
        };
        let mut request = request;
        request.body = body;

        let response = handler.handle(request).await;
        let should_close = close_after_response || response.close;
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
                    let _ = serve_native_http1_connection(stream, Some(peer_addr), policy, handler).await;
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
                            let _ = serve_native_http1_connection_with_tls(stream, Some(peer_addr), true, policy, handler).await;
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
                            let _ = serve_native_http1_connection_with_tls(stream, Some(peer_addr), true, policy, handler).await;
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
    downstream_tls: bool,
) -> NativeHttp1Request {
    NativeHttp1Request {
        method: head.method.to_owned(),
        peer_addr,
        downstream_tls,
        target: head.target.to_owned(),
        version: head.version,
        headers: owned_headers(&head.headers),
        body: Vec::new(),
    }
}

fn owned_headers(headers: &[Http1Header<'_>]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|header| (header.name.to_owned(), header.value.to_owned()))
        .collect()
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

async fn write_response<S>(
    stream: &mut S,
    response: NativeHttp1Response,
    close: bool,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    let policy = response.write_policy;
    let write = write_response_inner(stream, response, close, policy);
    if let Some(total_response_timeout) = policy.total_response_timeout {
        timeout(total_response_timeout, write)
            .await
            .map_err(|_| timeout_error("response total timeout"))?
    } else {
        write.await
    }
}

async fn write_response_inner<S>(
    stream: &mut S,
    response: NativeHttp1Response,
    close: bool,
    policy: NativeHttp1ResponseWritePolicy,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    let reason = sanitize_reason_phrase(&response.reason).collect::<String>();
    write_all_with_policy(
        stream,
        format!("HTTP/1.1 {} {reason}\r\n", response.status).as_bytes(),
        policy,
    )
    .await?;
    write_all_with_policy(
        stream,
        format!(
            "Date: {}\r\n",
            httpdate::fmt_http_date(std::time::SystemTime::now())
        )
        .as_bytes(),
        policy,
    )
    .await?;
    write_all_with_policy(
        stream,
        format!(
            "Content-Length: {}\r\n",
            response
                .content_length
                .unwrap_or(response.body.len() as u64)
        )
        .as_bytes(),
        policy,
    )
    .await?;
    write_all_with_policy(
        stream,
        if close {
            b"Connection: close\r\n"
        } else {
            b"Connection: keep-alive\r\n"
        },
        policy,
    )
    .await?;
    for (name, value) in response.headers {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("date")
        {
            continue;
        }
        if !valid_response_header(&name, &value) {
            return Err(Http1ParseError::InvalidHeaderValue.into());
        }
        write_all_with_policy(stream, format!("{name}: {value}\r\n").as_bytes(), policy).await?;
    }
    write_all_with_policy(stream, b"\r\n", policy).await?;
    write_body_with_policy(stream, &response.body, policy).await?;
    flush_with_policy(stream, policy).await?;
    Ok(())
}

async fn write_all_with_policy<S>(
    stream: &mut S,
    bytes: &[u8],
    policy: NativeHttp1ResponseWritePolicy,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    if let Some(write_timeout) = policy.write_timeout {
        timeout(write_timeout, stream.write_all(bytes))
            .await
            .map_err(|_| timeout_error("response write timeout"))??;
    } else {
        stream.write_all(bytes).await?;
    }
    Ok(())
}

async fn flush_with_policy<S>(
    stream: &mut S,
    policy: NativeHttp1ResponseWritePolicy,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    if let Some(write_timeout) = policy.write_timeout {
        timeout(write_timeout, stream.flush())
            .await
            .map_err(|_| timeout_error("response write timeout"))??;
    } else {
        stream.flush().await?;
    }
    Ok(())
}

async fn write_body_with_policy<S>(
    stream: &mut S,
    body: &[u8],
    policy: NativeHttp1ResponseWritePolicy,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    let Some(min_send_rate) = policy.min_send_rate_bytes_per_sec else {
        return write_all_with_policy(stream, body, policy).await;
    };
    if body.is_empty() {
        return Ok(());
    }

    let started_at = Instant::now();
    let mut written = 0usize;
    for chunk in body.chunks(WRITE_CHUNK_BYTES) {
        write_all_with_policy(stream, chunk, policy).await?;
        written = written.saturating_add(chunk.len());
        let elapsed = started_at.elapsed();
        if elapsed >= Duration::from_secs(1)
            && (written as f64 / elapsed.as_secs_f64()) < min_send_rate as f64
        {
            return Err(timeout_error("response min send rate not met"));
        }
    }
    Ok(())
}

fn timeout_error(message: &'static str) -> NativeHttp1Error {
    NativeHttp1Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, message))
}

fn valid_response_header(name: &str, value: &str) -> bool {
    http_token_valid(name)
        && !value
            .bytes()
            .any(|byte| matches!(byte, 0x00..=0x08 | 0x0a..=0x1f | 0x7f..=0xff))
}

fn sanitize_reason_phrase(reason: &str) -> impl Iterator<Item = char> + '_ {
    reason
        .bytes()
        .filter(|byte| matches!(byte, 0x09 | 0x20..=0x7e))
        .map(char::from)
}
