#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHttp1ProxyConfigError {
    CachePolicy,
    DynamicUpstreamDiscovery,
    ErrorPages,
    HttpPolicy,
    LoadBalancing,
    MissingUpstream,
    RecvBufferTooLarge,
    TrafficMirror,
    AuthRequest,
    PhpFpm,
    UpstreamHttp2,
    UpstreamProxyProtocol,
    UpstreamTls,
    UpstreamTlsPolicy,
    UpstreamTransportPolicy,
    WebSocket,
}

impl std::fmt::Display for NativeHttp1ProxyConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CachePolicy => {
                formatter.write_str("native HTTP/1 proxy does not yet support cache policy")
            }
            Self::DynamicUpstreamDiscovery => formatter
                .write_str("native HTTP/1 proxy does not yet support dynamic upstream discovery"),
            Self::ErrorPages => {
                formatter.write_str("native HTTP/1 proxy rejected proxy error page config")
            }
            Self::HttpPolicy => formatter
                .write_str("native HTTP/1 proxy does not yet support Fluxheim HTTP policy layers"),
            Self::LoadBalancing => formatter.write_str(
                "native HTTP/1 proxy does not yet support advanced load-balancer policy",
            ),
            Self::MissingUpstream => {
                formatter.write_str("native HTTP/1 proxy requires an upstream")
            }
            Self::RecvBufferTooLarge => {
                formatter.write_str("native HTTP/1 proxy upstream receive buffer size is too large")
            }
            Self::TrafficMirror => formatter.write_str(
                "native HTTP/1 proxy traffic mirroring requires the traffic-mirror feature and a non-privacy build",
            ),
            Self::AuthRequest => formatter.write_str(
                "native HTTP/1 proxy auth subrequests require the auth-request feature",
            ),
            Self::PhpFpm => formatter.write_str("native HTTP/1 proxy rejected PHP-FPM policy"),
            Self::UpstreamHttp2 => {
                formatter.write_str("native HTTP/1 proxy rejected unsupported upstream HTTP/2 mode")
            }
            Self::UpstreamProxyProtocol => formatter.write_str(
                "native HTTP/1 proxy only supports upstream PROXY protocol with forced HTTP/1 origins",
            ),
            Self::UpstreamTls => {
                formatter.write_str("native HTTP/1 proxy does not yet support upstream TLS")
            }
            Self::UpstreamTlsPolicy => {
                formatter.write_str("native HTTP/1 proxy rejected upstream TLS policy")
            }
            Self::UpstreamTransportPolicy => formatter.write_str(
                "native HTTP/1 proxy does not yet support advanced upstream transport policy",
            ),
            Self::WebSocket => formatter.write_str(
                "native HTTP/1 proxy only supports websocket upgrade with forced HTTP/1 static upstreams",
            ),
        }
    }
}

impl std::error::Error for NativeHttp1ProxyConfigError {}
