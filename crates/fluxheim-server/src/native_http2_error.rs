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
    StreamTaskJoin(tokio::task::JoinError),
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
            Self::StreamTaskJoin(error) => {
                write!(formatter, "native HTTP/2 stream task join failed: {error}")
            }
        }
    }
}

impl std::error::Error for NativeHttp2StackError {}
