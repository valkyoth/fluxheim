use fluxheim_protocol::{
    DEFAULT_HTTP1_MAX_BODY_BYTES, DEFAULT_HTTP1_MAX_HEAD_BYTES, DEFAULT_HTTP1_MAX_HEADER_COUNT,
    DEFAULT_HTTP1_MAX_HEADER_LINE_BYTES, DEFAULT_HTTP1_MAX_START_LINE_BYTES, Http1HeadLimits,
};
use std::time::Duration;

pub const DEFAULT_HTTP1_REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_HTTP1_REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_HTTP1_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_HTTP1_MAX_CONNECTIONS: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DownstreamHttp1Policy {
    max_body_bytes: usize,
    max_connections: usize,
    max_head_bytes: usize,
    max_header_count: usize,
    max_header_line_bytes: usize,
    max_start_line_bytes: usize,
    request_body_timeout: Duration,
    request_head_timeout: Duration,
    tls_handshake_timeout: Duration,
}

impl Default for DownstreamHttp1Policy {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_HTTP1_MAX_BODY_BYTES,
            max_connections: DEFAULT_HTTP1_MAX_CONNECTIONS,
            max_head_bytes: DEFAULT_HTTP1_MAX_HEAD_BYTES,
            max_header_count: DEFAULT_HTTP1_MAX_HEADER_COUNT,
            max_header_line_bytes: DEFAULT_HTTP1_MAX_HEADER_LINE_BYTES,
            max_start_line_bytes: DEFAULT_HTTP1_MAX_START_LINE_BYTES,
            request_body_timeout: DEFAULT_HTTP1_REQUEST_BODY_TIMEOUT,
            request_head_timeout: DEFAULT_HTTP1_REQUEST_HEAD_TIMEOUT,
            tls_handshake_timeout: DEFAULT_HTTP1_TLS_HANDSHAKE_TIMEOUT,
        }
    }
}

impl DownstreamHttp1Policy {
    pub fn from_server_limits(limits: fluxheim_config::ServerLimitsConfig) -> Self {
        let max_head_bytes = usize::try_from(limits.max_request_header_bytes.as_u64())
            .unwrap_or(DEFAULT_HTTP1_MAX_HEAD_BYTES);
        let max_uri_bytes = usize::try_from(limits.max_uri_bytes.as_u64())
            .unwrap_or(DEFAULT_HTTP1_MAX_START_LINE_BYTES);
        let max_body_bytes = usize::try_from(limits.max_request_body_bytes.as_u64())
            .unwrap_or(DEFAULT_HTTP1_MAX_BODY_BYTES);
        Self {
            max_body_bytes,
            max_connections: DEFAULT_HTTP1_MAX_CONNECTIONS,
            max_head_bytes,
            max_header_count: limits.max_request_headers,
            max_header_line_bytes: max_head_bytes.min(DEFAULT_HTTP1_MAX_HEADER_LINE_BYTES),
            max_start_line_bytes: max_uri_bytes
                .saturating_add(32)
                .min(max_head_bytes)
                .max(32_usize.min(max_head_bytes)),
            request_body_timeout: DEFAULT_HTTP1_REQUEST_BODY_TIMEOUT,
            request_head_timeout: DEFAULT_HTTP1_REQUEST_HEAD_TIMEOUT,
            tls_handshake_timeout: DEFAULT_HTTP1_TLS_HANDSHAKE_TIMEOUT,
        }
    }

    pub const fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = if max_connections == 0 {
            DEFAULT_HTTP1_MAX_CONNECTIONS
        } else {
            max_connections
        };
        self
    }

    pub const fn with_request_body_timeout(mut self, timeout: Duration) -> Self {
        self.request_body_timeout = timeout;
        self
    }

    pub const fn with_request_head_timeout(mut self, timeout: Duration) -> Self {
        self.request_head_timeout = timeout;
        self
    }

    pub const fn with_tls_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.tls_handshake_timeout = timeout;
        self
    }

    pub const fn max_body_bytes(self) -> usize {
        self.max_body_bytes
    }

    pub const fn max_connections(self) -> usize {
        self.max_connections
    }

    pub const fn max_head_bytes(self) -> usize {
        self.max_head_bytes
    }

    pub const fn max_header_count(self) -> usize {
        self.max_header_count
    }

    pub const fn max_header_line_bytes(self) -> usize {
        self.max_header_line_bytes
    }

    pub const fn max_start_line_bytes(self) -> usize {
        self.max_start_line_bytes
    }

    pub const fn request_body_timeout(self) -> Duration {
        self.request_body_timeout
    }

    pub const fn request_head_timeout(self) -> Duration {
        self.request_head_timeout
    }

    pub const fn tls_handshake_timeout(self) -> Duration {
        self.tls_handshake_timeout
    }
}

impl From<DownstreamHttp1Policy> for Http1HeadLimits {
    fn from(policy: DownstreamHttp1Policy) -> Self {
        Self {
            max_head_bytes: policy.max_head_bytes,
            max_header_count: policy.max_header_count,
            max_header_line_bytes: policy.max_header_line_bytes,
            max_start_line_bytes: policy.max_start_line_bytes,
        }
    }
}
