use std::sync::Arc;
use std::time::{Duration, Instant};

use fluxheim_protocol::{Http1ParseError, http1_request_target};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::native_http1_forwarded::{
    valid_upstream_header_value, valid_upstream_request_header, write_owned_proxy_headers,
};
use crate::native_http1_upstream_response::{
    read_upstream_response, read_upstream_response_for_pool,
};
use crate::{DownstreamHttp1Policy, NativeHttp1Error, NativeHttp1Request, NativeHttp1Response};

#[derive(Clone)]
pub struct NativeHttp1Upstream {
    authority: String,
    connect_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
    max_head_bytes: usize,
    max_body_bytes: usize,
    pool: Arc<NativeHttp1Pool>,
}

#[derive(Debug, Default)]
struct NativeHttp1Pool {
    max_idle: usize,
    idle_timeout: Option<Duration>,
    idle: Mutex<Vec<IdleNativeHttp1Connection>>,
}

#[derive(Debug)]
struct IdleNativeHttp1Connection {
    stream: TcpStream,
    inserted_at: Instant,
}

impl std::fmt::Debug for NativeHttp1Upstream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeHttp1Upstream")
            .field("authority", &self.authority)
            .field("connect_timeout", &self.connect_timeout)
            .field("read_timeout", &self.read_timeout)
            .field("write_timeout", &self.write_timeout)
            .field("max_head_bytes", &self.max_head_bytes)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("pool_max_idle", &self.pool.max_idle)
            .field("pool_idle_timeout", &self.pool.idle_timeout)
            .finish_non_exhaustive()
    }
}

impl PartialEq for NativeHttp1Upstream {
    fn eq(&self, other: &Self) -> bool {
        self.authority == other.authority
            && self.connect_timeout == other.connect_timeout
            && self.read_timeout == other.read_timeout
            && self.write_timeout == other.write_timeout
            && self.max_head_bytes == other.max_head_bytes
            && self.max_body_bytes == other.max_body_bytes
            && self.pool.max_idle == other.pool.max_idle
            && self.pool.idle_timeout == other.pool.idle_timeout
    }
}

impl Eq for NativeHttp1Upstream {}

impl NativeHttp1Upstream {
    pub fn new(authority: impl Into<String>) -> Self {
        let policy = DownstreamHttp1Policy::default();
        Self {
            authority: authority.into(),
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            max_head_bytes: policy.max_head_bytes(),
            max_body_bytes: policy.max_body_bytes(),
            pool: Arc::new(NativeHttp1Pool::default()),
        }
    }

    pub fn from_policy(authority: impl Into<String>, policy: DownstreamHttp1Policy) -> Self {
        Self {
            authority: authority.into(),
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            max_head_bytes: policy.max_head_bytes(),
            max_body_bytes: policy.max_body_bytes(),
            pool: Arc::new(NativeHttp1Pool::default()),
        }
    }

    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub const fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    pub const fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = timeout;
        self
    }

    pub const fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    pub fn with_pool_max_idle(mut self, max_idle: usize) -> Self {
        self.pool = Arc::new(NativeHttp1Pool {
            max_idle,
            idle_timeout: self.pool.idle_timeout,
            idle: Mutex::new(Vec::new()),
        });
        self
    }

    pub fn with_pool_idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.pool = Arc::new(NativeHttp1Pool {
            max_idle: self.pool.max_idle,
            idle_timeout: timeout,
            idle: Mutex::new(Vec::new()),
        });
        self
    }

    pub fn pool_max_idle(&self) -> usize {
        self.pool.max_idle
    }

    pub async fn idle_connection_count(&self) -> usize {
        self.pool.idle.lock().await.len()
    }

    pub async fn send(
        &self,
        request: &NativeHttp1Request,
    ) -> Result<NativeHttp1Response, NativeHttp1Error> {
        if self.pool.max_idle == 0 {
            let stream = timeout(self.connect_timeout, connect_upstream(&self.authority))
                .await
                .map_err(|_| timeout_error("native HTTP/1 upstream connect timeout"))??;
            return self.send_on_stream(stream, request).await;
        }

        let mut stream = self.connection().await?;
        timeout(
            self.write_timeout,
            write_upstream_request(&mut stream, &self.authority, request, true),
        )
        .await
        .map_err(|_| timeout_error("native HTTP/1 upstream write timeout"))??;
        let (response, reusable) = read_upstream_response_for_pool(
            &mut stream,
            self.read_timeout,
            self.max_head_bytes,
            self.max_body_bytes,
            &request.method,
        )
        .await?;
        if reusable {
            self.return_connection(stream).await;
        }
        Ok(response)
    }

    pub async fn send_on_stream<S>(
        &self,
        mut stream: S,
        request: &NativeHttp1Request,
    ) -> Result<NativeHttp1Response, NativeHttp1Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        timeout(
            self.write_timeout,
            write_upstream_request(&mut stream, &self.authority, request, false),
        )
        .await
        .map_err(|_| timeout_error("native HTTP/1 upstream write timeout"))??;
        read_upstream_response(
            &mut stream,
            self.read_timeout,
            self.max_head_bytes,
            self.max_body_bytes,
            &request.method,
        )
        .await
    }

    async fn connection(&self) -> Result<TcpStream, NativeHttp1Error> {
        let now = Instant::now();
        let mut idle = self.pool.idle.lock().await;
        while let Some(connection) = idle.pop() {
            if self.pool.idle_timeout.is_some_and(|timeout| {
                now.saturating_duration_since(connection.inserted_at) > timeout
            }) {
                continue;
            }
            return Ok(connection.stream);
        }
        drop(idle);
        timeout(self.connect_timeout, connect_upstream(&self.authority))
            .await
            .map_err(|_| timeout_error("native HTTP/1 upstream connect timeout"))?
    }

    async fn return_connection(&self, stream: TcpStream) {
        let mut idle = self.pool.idle.lock().await;
        if idle.len() < self.pool.max_idle {
            idle.push(IdleNativeHttp1Connection {
                stream,
                inserted_at: Instant::now(),
            });
        }
    }
}

async fn connect_upstream(authority: &str) -> Result<TcpStream, NativeHttp1Error> {
    let mut addresses = tokio::net::lookup_host(authority)
        .await
        .map_err(NativeHttp1Error::Io)?;
    let address = addresses.next().ok_or_else(|| {
        NativeHttp1Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "upstream authority did not resolve",
        ))
    })?;
    TcpStream::connect(address)
        .await
        .map_err(NativeHttp1Error::Io)
}

async fn write_upstream_request<S>(
    stream: &mut S,
    authority: &str,
    request: &NativeHttp1Request,
    keep_alive: bool,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    let target = upstream_origin_target(request)?;
    stream
        .write_all(format!("{} {target} HTTP/1.1\r\n", request.method).as_bytes())
        .await?;
    stream
        .write_all(format!("host: {}\r\n", valid_request_host(request, authority)?).as_bytes())
        .await?;
    if keep_alive {
        stream.write_all(b"connection: keep-alive\r\n").await?;
    } else {
        stream.write_all(b"connection: close\r\n").await?;
    }
    if !request.body.is_empty() {
        stream
            .write_all(format!("content-length: {}\r\n", request.body.len()).as_bytes())
            .await?;
    }
    let connection_tokens = connection_tokens(request);
    for (name, value) in &request.headers {
        if upstream_hop_by_hop_header(name, &connection_tokens)
            || name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("via")
            || name.eq_ignore_ascii_case("x-forwarded-for")
        {
            continue;
        }
        if !valid_upstream_request_header(name, value) {
            return Err(Http1ParseError::InvalidHeaderValue.into());
        }
        stream
            .write_all(format!("{name}: {value}\r\n").as_bytes())
            .await?;
    }
    write_owned_proxy_headers(stream, request).await?;
    stream.write_all(b"\r\n").await?;
    stream.write_all(&request.body).await?;
    stream.flush().await?;
    Ok(())
}

fn upstream_origin_target(request: &NativeHttp1Request) -> Result<String, NativeHttp1Error> {
    match http1_request_target(&request.method, &request.target)? {
        fluxheim_protocol::Http1RequestTarget::Origin { .. } => Ok(request.target.clone()),
        fluxheim_protocol::Http1RequestTarget::AbsoluteUri { path, query, .. } => {
            let Some(path) = path else {
                return Ok("/".to_owned());
            };
            Ok(query
                .map(|query| format!("{path}?{query}"))
                .unwrap_or_else(|| path.to_owned()))
        }
        fluxheim_protocol::Http1RequestTarget::Authority { .. }
        | fluxheim_protocol::Http1RequestTarget::Asterisk => {
            Err(Http1ParseError::InvalidRequestTarget.into())
        }
    }
}

fn request_host(request: &NativeHttp1Request) -> Option<&str> {
    request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.as_str())
}

fn valid_request_host<'a>(
    request: &'a NativeHttp1Request,
    authority: &'a str,
) -> Result<&'a str, NativeHttp1Error> {
    let host = request_host(request).unwrap_or(authority);
    if valid_upstream_header_value(host) {
        Ok(host)
    } else {
        Err(Http1ParseError::InvalidHeaderValue.into())
    }
}

fn connection_tokens(request: &NativeHttp1Request) -> Vec<String> {
    request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn upstream_hop_by_hop_header(name: &str, connection_tokens: &[String]) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) || connection_tokens
        .iter()
        .any(|token| token.eq_ignore_ascii_case(name))
}

fn timeout_error(message: &'static str) -> NativeHttp1Error {
    NativeHttp1Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, message))
}
