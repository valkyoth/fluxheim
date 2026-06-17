use fluxheim_protocol::{
    DEFAULT_HTTP1_MAX_HEAD_BYTES, DEFAULT_HTTP1_MAX_HEADER_COUNT,
    DEFAULT_HTTP1_MAX_HEADER_LINE_BYTES, DEFAULT_HTTP1_MAX_START_LINE_BYTES, Http1HeadLimits,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DownstreamHttp1Policy {
    max_head_bytes: usize,
    max_header_count: usize,
    max_header_line_bytes: usize,
    max_start_line_bytes: usize,
}

impl Default for DownstreamHttp1Policy {
    fn default() -> Self {
        Self {
            max_head_bytes: DEFAULT_HTTP1_MAX_HEAD_BYTES,
            max_header_count: DEFAULT_HTTP1_MAX_HEADER_COUNT,
            max_header_line_bytes: DEFAULT_HTTP1_MAX_HEADER_LINE_BYTES,
            max_start_line_bytes: DEFAULT_HTTP1_MAX_START_LINE_BYTES,
        }
    }
}

impl DownstreamHttp1Policy {
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
